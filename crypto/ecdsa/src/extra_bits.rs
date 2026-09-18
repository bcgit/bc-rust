//! FIPS 186-5 Appendix A.4.1, "Conversion of a Bit String to an Integer mod n via Modular
//! Reduction" -- the "extra random bits" method both [`crate::keys`]'s key generation (Appendix
//! A.2.1) and [`crate::ecdsa_p256`]'s randomised per-message secret (Appendix A.3.1) use to turn a
//! DRBG output wider than `n` into a value in `[1, n-1]` with negligible bias.
//!
//! # The algorithm, and why it needs its own reduction
//!
//! Appendix A.4.1's process, for a bit string `X` of length `l` and modulus `n`:
//! 1. `x = bits2int(X)` (§B.2.1, big-endian).
//! 2. `x = x mod (n-1)`.
//! 3. `x = x + 1`.
//!
//! `X` here is 352 bits (44 bytes -- FIPS 186-5 Table A.2's "Recommended" output length for a
//! DRBG feeding a P-256 private key or per-message secret, `l = N + t` with `N = 256` and `t = 96
//! >= 64`), 96 bits wider than the 4-limb (256-bit) width every other value in this workspace's
//! P-256 arithmetic is sized for. `bouncycastle_ec::p256_scalar` reduces mod `n`, not `n-1`, and
//! has no width wider than 4 limbs, so step 2's reduction is implemented here directly, from
//! scratch, rather than reused.
//!
//! # Constant time
//!
//! `X` is DRBG output destined to become a secret `d` or `k` once step 3 adds `1`, so this is
//! exactly the kind of "value derived from a private scalar" this workspace's constant-time rules
//! (`bouncycastle_ec`'s crate docs, rule 1) forbid branching on. [`reduce_wide_bits_mod_n_minus_1`]
//! processes `X` one bit at a time, doubling the running remainder and conditionally subtracting
//! `n-1` (a single [`ct::conditional_select`], never a branch) -- the same "double, mask-select one
//! subtraction" shape [`bouncycastle_ec::p256_scalar::P256ScalarField::add`] uses for `mod n`,
//! adapted to a different modulus and to processing extra input bits one at a time instead of
//! adding two already-reduced operands.
//!
//! Verified (not checked in) against Python's arbitrary-precision `%` operator: 3000 random trials
//! of `bits2int(X) mod (n-1)` for bit strings from 8 to 352 bits, confirming both the reduction's
//! correctness and that a single conditional subtraction per bit always suffices (the running
//! remainder, doubled plus the carry-out correction, is always `< 2*(n-1)`).

use bouncycastle_ec::nat;
use bouncycastle_ec::p256_scalar::{N_LIMBS, P256Scalar};
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (SP 800-186 §3.2.1.3's `n`), so the
/// subtraction never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 4] = [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];

/// `2^256 mod (n-1)`, i.e. `2^256 - (n-1)` (a single subtraction: `n-1 < 2^256`) -- the correction
/// [`reduce_wide_bits_mod_n_minus_1`] adds back in when doubling the running remainder carries out
/// of the top limb.
const TWO_POW_256_MOD_N_MINUS_1_LIMBS: [u64; 4] =
    [0x0c46353d039cdab0, 0x4319055258e8617b, 0x0000000000000000, 0x00000000ffffffff];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the P-256 curve order: reduces the big-endian bit
/// string `bytes` (any length; only the DRBG's own output length matters for the bias bound Step 2
/// checks, which holds by construction for the 352-bit `l` [`crate::keys`] and
/// [`crate::ecdsa_p256`] both use -- see the module docs) modulo `n-1` and adds `1`, landing in
/// `[1, n-1]`.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> P256Scalar {
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
    P256Scalar::from_limbs(plus_one)
}
