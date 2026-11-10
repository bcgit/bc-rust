//! FIPS 186-5 Appendix A.4.1, "Conversion of a Bit String to an Integer mod n via Modular
//! Reduction" -- the "extra random bits" method `bouncycastle-ecdsa`'s `keys_p521` key generation
//! (Appendix A.2.1) and `ecdsa_p521` randomised per-message secret (Appendix A.3.1) use to turn a
//! DRBG output wider than `n` into a value in `[1, n-1]`. Identical algorithm to
//! [`crate::hazmat::p256_extra_bits`] -- see that module's docs for the full reasoning -- with
//! P-521's own `n` substituted and, because of `n`'s width, its own reduction (see
//! [`reduce_wide_bits_mod_n_minus_1`]).
//!
//! # Why P-521 draws extra bits at all
//!
//! Not for bias: FIPS 186-5 Table A.2 gives `p521` a required and recommended DRBG output of 521
//! bits for key generation, since `n` is within `2^260` of `2^521`. But Appendix A.3.1 requires
//! `N + t` bits with `t >= 64` for the per-message secret regardless, so `bouncycastle-ecdsa`
//! draws `N + 71 = 592` bits (74 bytes, the byte-aligned width at or above `585`) for both and
//! reduces them here. `p521_extra_bits_tests.rs` pins known answers computed in Python.

use crate::hazmat::p521_scalar::{N_LIMBS, P521Scalar};
use crate::nat;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// `n - 1`, little-endian `u64` limbs. `N_LIMBS[0]` is odd (`n` is prime), so the subtraction
/// never borrows out of the low limb.
const N_MINUS_1_LIMBS: [u64; 9] = [
    N_LIMBS[0] - 1,
    N_LIMBS[1],
    N_LIMBS[2],
    N_LIMBS[3],
    N_LIMBS[4],
    N_LIMBS[5],
    N_LIMBS[6],
    N_LIMBS[7],
    N_LIMBS[8],
];

/// `2^521 mod (n-1)`, the fold constant [`reduce_wide_bits_mod_n_minus_1`] uses: `n - 1` has
/// no special form, so this is a genuine ~259-bit value, computed in Python from SP 800-186
/// §3.2.1.5's `n`.
const TWO_POW_521_MOD_N_MINUS_1_LIMBS: [u64; 9] = [
    0x449048e16ec79bf8, 0xc44a36477663b851, 0x8033feb708f65a2f, 0xae79787c40d06994,
    0x0000000000000005, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000,
];

/// FIPS 186-5 Appendix A.4.1 steps 3-5 for P-521's `n`: reduces the big-endian bit string `bytes`
/// (up to 80 bytes; the DRBG draw is 74) modulo `n-1` and adds `1`, landing in `[1, n-1]`.
///
/// P-521's `n - 1` is `2^521`-ish while the limb width is `2^576`, so neither the Solinas fold
/// the field uses nor [`crate::barrett`] (which wants a modulus filling its top limb)
/// applies as written. What does is a single fold at bit 521: split `x = hi * 2^521 + lo`, so
/// `x = hi * (2^521 mod (n-1)) + lo (mod n-1)`. With `x < 2^640`, `hi < 2^119` and the fold
/// constant is below `2^259`, so `hi * C + lo < 2^521 + 2^378 < 2 (n-1)`, and one conditional
/// subtraction finishes the reduction. Every step is branch-free in `x`: a fixed-width
/// multiplication, an addition and a masked select. Verified (not checked in) in Python against
/// arbitrary-precision `%` over 20,000 pseudorandom inputs at widths up to 80 bytes plus the
/// all-ones extremes.
pub fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> P521Scalar {
    assert!(
        bytes.len() <= 80,
        "reduce_wide_bits_mod_n_minus_1 given {} bytes, more than 80",
        bytes.len()
    );
    // Every value from the DRBG output to d is the key at some stage, so each is held in a
    // `Secret`, scrubbed when this function returns rather than left on the stack, and every
    // step writes into that `Secret` rather than returning the value through a slot a return
    // would stage it in. What this frame leaves is the returned scalar's own move.
    let mut x = Secret::<[u64; 10]>::new();
    crate::barrett::limbs_from_be_bytes_into::<10>(bytes, &mut x);

    // lo = x mod 2^521: the low 8 limbs plus the low 9 bits of limb 8.
    let mut lo = Secret::<[u64; 9]>::new();
    lo[..8].copy_from_slice(&x[..8]);
    lo[8] = x[8] & 0x1ff;
    // hi = x >> 521: bits 9..63 of limb 8 and all of limb 9, at most 119 bits.
    let mut hi = Secret::<[u64; 9]>::new();
    hi[0] = (x[8] >> 9) | (x[9] << 55);
    hi[1] = x[9] >> 9;

    let mut product = Secret::<[u64; 18]>::new();
    crate::montgomery::widening_mul_into::<9, 18>(
        &hi,
        &TWO_POW_521_MOD_N_MINUS_1_LIMBS,
        &mut product,
    );
    debug_assert!(product[9..].iter().all(|&limb| limb == 0), "hi * C must fit in 9 limbs");
    let mut sum = Secret::<[u64; 9]>::new();
    sum.copy_from_slice(&product[..9]);
    let carry = nat::add_assign(&mut sum, &lo);
    debug_assert_eq!(carry, 0, "the fold's sum must fit in 9 limbs");

    // d - 1 = sum, or sum - (n - 1) where that does not borrow, moved in under the borrow's mask.
    let mut d = Secret::<[u64; 9]>::new();
    d.copy_from_slice(&*sum);
    let borrow = nat::sub_assign(&mut d, &N_MINUS_1_LIMBS);
    let keep_sum = Condition::<u64>::from_lsb(borrow);
    for i in 0..9 {
        keep_sum.mov(sum[i], &mut d[i]);
    }

    nat::add_assign(&mut d, &[1, 0, 0, 0, 0, 0, 0, 0, 0]);
    P521Scalar::from_borrowed_limbs(&d)
}
