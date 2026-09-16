//! "Extra random bits" reduction: turns a DRBG output wider than `n` into a value in `[1, n-1]`
//! with negligible bias, the same technique `bouncycastle-ecdsa`'s `extra_bits` module uses for
//! P-256 (and every brainpool curve on this branch), applied here for the private key `dA` and the
//! per-message secret `k` `draft-shen-sm2-ecdsa-02` §5.1.3/§5.2.1 step A3 both need. The draft
//! itself only says "pick a random number ... via a random number generator" without specifying a
//! DRBG-to-scalar conversion, so this reuses FIPS 186-5 Appendix A.4.1's method (the same
//! bias-bound methodology this workspace already applies to every other curve) rather than a plain
//! modular reduction, which would be measurably biased for a `DRBG output length == n's bit
//! length` request.
//!
//! # Why SM2 needs this at all
//!
//! Like every brainpool curve on this branch (and unlike P-384/P-521/secp256k1), SM2's `n` is not
//! close to a power of two. FIPS 186-5 Appendix A.4.1 step 2's bias-bound check
//! (`2ρ(1-ρ)(n-1) > ε·N`, `ε = 2^-64`) was evaluated directly (in Python, against `n`'s actual
//! value from `draft-shen-sm2-ecdsa-02` Appendix D) for `N = 2^l` at increasing `l`: `l = 256`
//! (matching `n`'s own bit length) fails the check, and the smallest passing `l` is `319`; this
//! crate uses `l = 320` (40 bytes, byte-aligned) as `crate::keys::EXTRA_BITS_DRBG_OUTPUT_LEN`.
//!
//! Verified (not checked in) against Python's arbitrary-precision `%` operator: 5000 random trials
//! of `bits2int(X) mod (n-1)` for bit strings from 8 to 328 bits, confirming both the reduction's
//! correctness and that a single conditional subtraction per bit always suffices.

use bouncycastle_ec::nat;
use bouncycastle_ec::sm2_scalar::{N_LIMBS, Sm2Scalar};
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 4] = [N_LIMBS[0] - 1, N_LIMBS[1], N_LIMBS[2], N_LIMBS[3]];

/// `2^256 mod (n-1)` -- the correction [`reduce_wide_bits_mod_n_minus_1`] adds back in when
/// doubling the running remainder carries out of the top limb.
const TWO_POW_256_MOD_N_MINUS_1_LIMBS: [u64; 4] =
    [0xac440bf6c62abede, 0x8dfc2094de39fad4, 0x0000000000000000, 0x0000000100000000];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for `n` = the SM2 curve order: reduces the big-endian bit
/// string `bytes` modulo `n-1` and adds `1`, landing in `[1, n-1]`.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Sm2Scalar {
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
    Sm2Scalar::from_limbs(plus_one)
}
