//! FIPS 186-5 Appendix A.4.1, "Conversion of a Bit String to an Integer mod n via Modular
//! Reduction" -- the "extra random bits" method both [`crate::keys_p384`]'s key generation
//! (Appendix A.2.1) and [`crate::ecdsa_p384`]'s randomised per-message secret (Appendix A.3.1)
//! use to turn a DRBG output wider than `n` into a value in `[1, n-1]`. Identical algorithm to
//! [`crate::extra_bits`] -- see that module's docs for the full reasoning -- with P-384's own `n`
//! substituted.
//!
//! # Why P-384 draws extra bits at all
//!
//! Not for bias. P-384's `n` is within `2^190` of `2^384`, so Appendix A.4.1 step 2's bound
//! (`2ρ(1-ρ)(n-1) <= ε·N`, `ε = 2^-64`) already holds at `l = 384` with a bias near `2^-194`, and
//! FIPS 186-5 Table A.2 accordingly gives `p384` a required and recommended DRBG output of 384
//! bits for key generation. An earlier version of this crate drew exactly 48 bytes for both key
//! generation and the randomised per-message secret on that basis, and reduced with a single
//! conditional subtraction of `n - 1`.
//!
//! Appendix A.3.1 is stricter than Table A.2, though. Its step 2 returns FAILURE if `t < 64` and
//! its step 3 says: *"Obtain a bit string of N+t returned_bits from the established DRBG"*. That
//! is a requirement on the per-message secret's draw independent of how close `n` is to a power
//! of two, and 384 bits does not meet it. So `sign_randomized` now draws `N + 64 = 448` bits (56
//! bytes, [`crate::keys_p384::EXTRA_BITS_DRBG_OUTPUT_LEN`]) and reduces them with this module.
//! Key generation draws the same 56 bytes: Table A.2's 384 is a minimum ("not less than"), so
//! the wider draw is permitted there too, and one reduction path per curve is simpler than two.
//! The extra bits satisfy the requirement rather than lower the bias: for an `n` this close to a
//! power of two, `2^l mod (n-1)` grows with `l` as fast as `2^l` does, so the bias stays near
//! `2^-193` at `l = 448` too (computed, not assumed).
//!
//! The reduction itself is [`bouncycastle_ec::barrett`]'s constant-time Barrett reduction with
//! `m = n - 1` (see [`crate::extra_bits`]'s docs for the constant-time argument); `extra_bits_p384_tests.rs`
//! pins known answers computed in Python and cross-checks it against the bit-serial algorithm this
//! module used to implement, kept there as an independent reference.

use bouncycastle_ec::barrett;
use bouncycastle_ec::nat;
use bouncycastle_ec::p384_scalar::{N_LIMBS, P384Scalar};

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 6] =
    [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3], N_LIMBS[4], N_LIMBS[5]];

/// `floor(2^768 / (n-1)) - 2^384`: the low limbs of Barrett's `mu` for `m = n - 1` (whose top
/// limb is `mu`'s only other bit -- see [`bouncycastle_ec::barrett`]), computed in Python from
/// SP 800-186 §3.2.1.4's `n`.
const MU_LOW_LIMBS: [u64; 6] = [
    0x1313e695333ad68e, 0xa7e5f24db74f5885, 0x389cb27e0bc8d220, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the curve order: reduces the big-endian bit string
/// `bytes` modulo `n-1` and adds `1`, landing in `[1, n-1]`. `bytes` may be up to `95` bytes
/// -- `2^760 < (n-1) * 2^384`, Barrett's precondition -- which covers the 56-byte DRBG
/// output this crate draws with room to spare; a longer input is a programming error and panics.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> P384Scalar {
    assert!(
        bytes.len() < 96,
        "reduce_wide_bits_mod_n_minus_1 given {} bytes, more than 95",
        bytes.len()
    );
    let t = barrett::limbs_from_be_bytes::<12>(bytes);
    let reduced = barrett::reduce::<6, 12, 7>(&t, &N_MINUS_1_LIMBS, &MU_LOW_LIMBS);
    let (plus_one, _) = nat::add(&reduced, &[1, 0, 0, 0, 0, 0]);
    P384Scalar::from_limbs(plus_one)
}
