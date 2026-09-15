//! FIPS 186-5 Appendix A.4.1, "Conversion of a Bit String to an Integer mod n via Modular
//! Reduction" -- the "extra random bits" method both [`crate::keys_bp256r1`]'s key generation
//! (Appendix A.2.1) and [`crate::ecdsa_bp256r1`]'s randomised per-message secret (Appendix A.3.1)
//! use to turn a DRBG output wider than `n` into a value in `[1, n-1]` with negligible bias.
//! Identical algorithm to [`crate::extra_bits`] -- see that module's docs for the full reasoning
//! -- with brainpoolP256r1's own `n` substituted.
//!
//! # Why brainpoolP256r1 needs this at all
//!
//! Unlike P-384/P-521/secp256k1 (each needing only a single conditional subtraction of `n-1` on
//! exactly-`n`-width input, per those curves' own `keys_*.rs` docs), brainpoolP256r1's `n` is not
//! close to a power of two: `2^256 - n` is about a third of `2^256`, not a small remainder. FIPS
//! 186-5 Appendix A.4.1 step 2's bias-bound check (`2ρ(1-ρ)(n-1) > ε·N`, `ε = 2^-64`) was
//! evaluated directly (in Python, against `n`'s actual value, not assumed by analogy to any other
//! curve) for `N = 2^l` at increasing `l`: `l = 256` (matching `n`'s own bit length, P-384/P-521/
//! secp256k1's shortcut) fails the check, and the smallest passing `l` is `319`; this crate uses
//! `l = 320` (40 bytes, one bit of margin above the minimum, byte-aligned for DRBG output) as
//! [`crate::keys_bp256r1::EXTRA_BITS_DRBG_OUTPUT_LEN`].
//!
//! Verified (not checked in) against Python's arbitrary-precision `%` operator: 5000 random trials
//! of `bits2int(X) mod (n-1)` for bit strings from 8 to 352 bits, confirming both the reduction's
//! correctness and that a single conditional subtraction per bit always suffices.

use bouncycastle_ec::bp256r1_scalar::{Bp256r1Scalar, N_LIMBS};
use bouncycastle_ec::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 4] = [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];

/// `2^256 mod (n-1)` -- the correction [`reduce_wide_bits_mod_n_minus_1`] adds back in when
/// doubling the running remainder carries out of the top limb.
const TWO_POW_256_MOD_N_MINUS_1_LIMBS: [u64; 4] =
    [0x6fe1f17d68b7a95a, 0x73c6855c4a9e5908, 0xc199f56f627c728e, 0x5604a8245e115643];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the brainpoolP256r1 curve order: reduces the
/// big-endian bit string `bytes` modulo `n-1` and adds `1`, landing in `[1, n-1]`.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Bp256r1Scalar {
    let mut acc = [0u64; 4];
    for &byte in bytes {
        for bit_idx in (0..8).rev() {
            let bit = (byte >> bit_idx) & 1;
            let (doubled, carry) = nat::add(&acc, &acc);
            let mut with_bit = doubled;
            with_bit[0] |= bit as u64;
            let (with_carry_correction, _) = nat::add(&with_bit, &TWO_POW_256_MOD_N_MINUS_1_LIMBS);
            let mut candidate = [0u64; 4];
            ct::conditional_select(
                Condition::<u64>::from_lsb(carry),
                &with_carry_correction,
                &with_bit,
                &mut candidate,
            );
            let (reduced, borrow) = nat::sub(&candidate, &N_MINUS_1_LIMBS);
            ct::conditional_select(
                Condition::<u64>::from_lsb(borrow),
                &candidate,
                &reduced,
                &mut acc,
            );
        }
    }
    let (plus_one, _) = nat::add(&acc, &[1, 0, 0, 0]);
    Bp256r1Scalar::from_limbs(plus_one)
}
