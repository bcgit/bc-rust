//! FIPS 186-5 Appendix A.4.1, "Conversion of a Bit String to an Integer mod n via Modular
//! Reduction" -- the "extra random bits" method both [`crate::keys_p256k1`]'s key generation
//! (Appendix A.2.1) and [`crate::ecdsa_p256k1`]'s randomised per-message secret (Appendix A.3.1)
//! use to turn a DRBG output wider than `n` into a value in `[1, n-1]`. Identical algorithm to
//! [`crate::extra_bits`] -- see that module's docs for the full reasoning -- with secp256k1's
//! own `n` substituted.
//!
//! # Why secp256k1 draws extra bits at all
//!
//! Not for bias. secp256k1's `n` is within `2^129` of `2^256`, so Appendix A.4.1 step 2's bound
//! (`2ρ(1-ρ)(n-1) <= ε·N`, `ε = 2^-64`) already holds at `l = 256` with a bias near `2^-127`
//! (secp256k1 is not a NIST curve, so there is no Table A.2 entry; the bound was evaluated
//! directly in Python against SEC 2 v2 §2.4.1's `n`). An earlier version of this crate drew
//! exactly 32 bytes for both key generation and the randomised per-message secret on that basis,
//! and reduced with a single conditional subtraction of `n - 1`.
//!
//! Appendix A.3.1 is stricter than that bound, though. Its step 2 returns FAILURE if `t < 64` and
//! its step 3 says: *"Obtain a bit string of N+t returned_bits from the established DRBG"*. That
//! is a requirement on the per-message secret's draw independent of how close `n` is to a power
//! of two, and 256 bits does not meet it. So `sign_randomized` now draws `N + 64 = 320` bits (40
//! bytes, [`crate::keys_p256k1::EXTRA_BITS_DRBG_OUTPUT_LEN`]) and reduces them with this module.
//! Key generation draws the same 40 bytes: Appendix A.2.1's lengths are minimums, so the wider
//! draw is permitted there too, and one reduction path per curve is simpler than two. The extra
//! bits satisfy the requirement rather than lower the bias: for an `n` this close to a power of
//! two, `2^l mod (n-1)` grows with `l` as fast as `2^l` does, so the bias stays near `2^-127` at
//! `l = 320` too (computed, not assumed).
//!
//! Verified (not checked in) against Python's arbitrary-precision `%` operator over random bit
//! strings from 8 to 328 bits, confirming both the reduction's correctness and that a single
//! conditional subtraction per bit always suffices; `extra_bits_p256k1_tests.rs` pins fixed
//! inputs against the same independent reference.

use bouncycastle_ec::nat;
use bouncycastle_ec::p256k1_scalar::{N_LIMBS, P256K1Scalar};
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 4] = [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];

/// `2^256 mod (n-1)`, i.e. `2^256 - (n-1)` (a single subtraction: `n - 1 > 2^255`) -- the
/// correction [`reduce_wide_bits_mod_n_minus_1`] adds back in when doubling the running remainder
/// carries out of the top limb. Computed in Python from SEC 2 v2 §2.4.1's `n`.
const TWO_POW_256_MOD_N_MINUS_1_LIMBS: [u64; 4] =
    [0x402da1732fc9bec0, 0x4551231950b75fc4, 0x0000000000000001, 0x0000000000000000];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the secp256k1 curve order: reduces the
/// big-endian bit string `bytes` (any length) modulo `n-1` and adds `1`, landing in `[1, n-1]`.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> P256K1Scalar {
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
    P256K1Scalar::from_limbs(plus_one)
}
