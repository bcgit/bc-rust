//! FIPS 186-5 Appendix A.4.1, "Conversion of a Bit String to an Integer mod n via Modular
//! Reduction" -- the "extra random bits" method both [`crate::keys_bp512r1`]'s key generation
//! (Appendix A.2.1) and [`crate::ecdsa_bp512r1`]'s randomised per-message secret (Appendix A.3.1)
//! use to turn a DRBG output wider than `n` into a value in `[1, n-1]` with negligible bias.
//! Identical algorithm to [`crate::extra_bits`] -- see that module's docs for the full reasoning
//! -- with brainpoolP512r1's own `n` substituted.
//!
//! # Why brainpoolP512r1 needs this at all
//!
//! Like both other brainpool curves in this crate (and unlike P-384/P-521/secp256k1, whose `n`
//! passes Appendix A.4.1's bound with no extra bits and which draw them only for Appendix
//! A.3.1's `t >= 64` -- see `crate::extra_bits_p384`'s docs), this curve's `n` is not close to a
//! power of two. FIPS 186-5 Appendix A.4.1 step 2's bias-bound check
//! (`2ρ(1-ρ)(n-1) > ε·N`, `ε = 2^-64`) was evaluated directly (in Python, against `n`'s actual
//! value) for `N = 2^l` at increasing `l`: `l = 512` (matching `n`'s own bit length) fails the
//! check, and the smallest passing `l` is `575`; this crate uses `l = 576` (72 bytes,
//! byte-aligned) as [`crate::keys_bp512r1::EXTRA_BITS_DRBG_OUTPUT_LEN`].
//!
//! The reduction itself is [`bouncycastle_ec::barrett`]'s constant-time Barrett reduction with
//! `m = n - 1` (see [`crate::extra_bits`]'s docs for the constant-time argument); `extra_bits_bp512r1_tests.rs`
//! pins known answers computed in Python and cross-checks it against the bit-serial algorithm this
//! module used to implement, kept there as an independent reference.

use bouncycastle_ec::barrett;
use bouncycastle_ec::bp512r1_scalar::{Bp512r1Scalar, N_LIMBS};
use bouncycastle_ec::nat;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 8] = [
    N_LIMBS[0] - 1,
    N_LIMBS[1],
    N_LIMBS[2],
    N_LIMBS[3],
    N_LIMBS[4],
    N_LIMBS[5],
    N_LIMBS[6],
    N_LIMBS[7],
];

/// `floor(2^1024 / (n-1)) - 2^512`: the low limbs of Barrett's `mu` for `m = n - 1` (whose top
/// limb is `mu`'s only other bit -- see [`bouncycastle_ec::barrett`]), computed in Python from
/// RFC 5639 §3.4's `n`.
const MU_LOW_LIMBS: [u64; 8] = [
    0x2fafac64db57db3a, 0x0eaf0d9015d5c4ce, 0x9ff38f5f59ee4710, 0xdb9470c61a235d44,
    0x666ad8f2f5bf92f7, 0x8373af60cc44ef09, 0x15d5ea2f03461e1e, 0x7f8d7f4ed6daeb8a,
];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the curve order: reduces the big-endian bit string
/// `bytes` modulo `n-1` and adds `1`, landing in `[1, n-1]`. `bytes` may be up to `127` bytes
/// -- `2^1016 < (n-1) * 2^512`, Barrett's precondition -- which covers the 72-byte DRBG
/// output this crate draws with room to spare; a longer input is a programming error and panics.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Bp512r1Scalar {
    assert!(
        bytes.len() < 128,
        "reduce_wide_bits_mod_n_minus_1 given {} bytes, more than 127",
        bytes.len()
    );
    let t = barrett::limbs_from_be_bytes::<16>(bytes);
    let reduced = barrett::reduce::<8, 16, 9>(&t, &N_MINUS_1_LIMBS, &MU_LOW_LIMBS);
    let (plus_one, _) = nat::add(&reduced, &[1, 0, 0, 0, 0, 0, 0, 0]);
    Bp512r1Scalar::from_limbs(plus_one)
}
