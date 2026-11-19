//! FIPS 186-5 Appendix A.4.1, "Conversion of a Bit String to an Integer mod n via Modular
//! Reduction" -- the "extra random bits" method both `bouncycastle-ecdsa`'s `keys_bp384r1`'s key
//! generation (Appendix A.2.1) and `bouncycastle-ecdsa`'s `ecdsa_bp384r1`'s randomised per-message
//! secret (Appendix A.3.1) use to turn a DRBG output wider than `n` into a value in `[1, n-1]` with
//! negligible bias. Identical algorithm to [`crate::hazmat::p256_extra_bits`] -- see that module's
//! docs for the full reasoning -- with brainpoolP384r1's own `n` substituted.
//!
//! # Why brainpoolP384r1 needs this at all
//!
//! Unlike P-384/P-521/secp256k1 (whose `n` is so close to a power of two that Appendix A.4.1's
//! bias bound holds with no extra bits, and which draw them only because Appendix A.3.1 demands
//! `t >= 64` -- see `crate::hazmat::p384_extra_bits`'s docs), brainpoolP384r1's `n` is not
//! close to a power of two: `2^384 - n` is about a third of `2^384`, not a small remainder --
//! identical in shape to brainpoolP256r1's own case, just at this curve's own width. FIPS 186-5
//! Appendix A.4.1 step 2's bias-bound check (`2ρ(1-ρ)(n-1) > ε·N`, `ε = 2^-64`) was evaluated
//! directly (in Python, against `n`'s actual value, not assumed by analogy to any other curve) for
//! `N = 2^l` at increasing `l`: `l = 384` (matching `n`'s own bit length) fails the check, and the
//! smallest passing `l` is `445`; `bouncycastle-ecdsa` uses `l = 448` (56 bytes, byte-aligned, three bits of
//! margin above the minimum) as `bouncycastle-ecdsa`'s `keys_bp384r1::EXTRA_BITS_DRBG_OUTPUT_LEN`.
//!
//! The reduction itself is [`crate::barrett`]'s constant-time Barrett reduction with `m = n - 1`
//! (see [`crate::hazmat::p256_extra_bits`]'s docs for the constant-time argument);
//! `bp384r1_extra_bits_tests.rs` pins known answers computed in Python and cross-checks it against
//! the bit-serial algorithm this module used to implement, kept there as an independent reference.

use crate::barrett;
use crate::hazmat::bp384r1_scalar::{Bp384r1Scalar, N_LIMBS};
use crate::nat;
use bouncycastle_utils::secret::Secret;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 6] =
    [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3], N_LIMBS[4], N_LIMBS[5]];

/// `floor(2^768 / (n-1)) - 2^384`: the low limbs of Barrett's `mu` for `m = n - 1` (whose top
/// limb is `mu`'s only other bit -- see [`crate::barrett`]), computed in Python from
/// RFC 5639 §3.4's `n`.
const MU_LOW_LIMBS: [u64; 6] = [
    0x600adcccf8a71f8d, 0x189fdb467a652109, 0xc506f2fe165031e7, 0xdda2c449cae56ee1,
    0xff25adfd3cc6fa65, 0xd1b575b16d8ec6b8,
];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the curve order: reduces the big-endian bit string
/// `bytes` modulo `n-1` and adds `1`, landing in `[1, n-1]`. `bytes` may be up to `95` bytes
/// -- `2^760 < (n-1) * 2^384`, Barrett's precondition -- which covers the 56-byte DRBG
/// output `bouncycastle-ecdsa` draws with room to spare; a longer input is a programming error and panics.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Bp384r1Scalar {
    assert!(
        bytes.len() < 96,
        "reduce_wide_bits_mod_n_minus_1 given {} bytes, more than 95",
        bytes.len()
    );
    // The DRBG output, its reduction and d itself are the key at three stages, so each is held
    // in a `Secret`, scrubbed when this function returns rather than left on the stack, and
    // every step writes into that `Secret` rather than returning the value through a slot a
    // return would stage it in; the reduction's own working values are plain locals, as
    // `barrett::reduce_into` says. What this frame leaves is the returned scalar's own move.
    let mut t = Secret::<[u64; 12]>::new();
    barrett::limbs_from_be_bytes_into::<12>(bytes, &mut t);
    let mut d = Secret::<[u64; 6]>::new();
    barrett::reduce_into::<6, 12, 7>(&t, &N_MINUS_1_LIMBS, &MU_LOW_LIMBS, &mut d);
    nat::add_assign(&mut d, &[1, 0, 0, 0, 0, 0]);
    Bp384r1Scalar::from_borrowed_limbs(&d)
}
