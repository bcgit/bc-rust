//! The `GF(2^128)` multiplication of GHASH (NIST SP 800-38D Sec 6.3) on `PMULL`/`PMULL2`.
//!
//! [`mul`] is Sec 6.3's `X • Y`. [`mul4`] is four products summed under a single reduction:
//! Sec 6.4 notes that "the GHASH function calculates `X1•H^m ⊕ X2•H^(m-1) ⊕ ... ⊕ Xm•H`", so a
//! caller holding `H`, `H^2`, `H^3` and `H^4` can fold four blocks into the running hash with
//! one call, `Y = (Y ⊕ X1)•H^4 ⊕ X2•H^3 ⊕ X3•H^2 ⊕ X4•H`.
//!
//! # Representation
//!
//! An [`Element`] is a block as `[u64; 2]`: `x[0]` is the first eight bytes of the block read
//! big-endian and `x[1]` the last eight, the form `bouncycastle_cipher`'s GHASH keeps its
//! state in. Sec 6.3's bit convention is "little endian": bit `x_0`, the coefficient of `u^0`,
//! is the leftmost bit of the first byte, so in this form it is the top bit of `x[0]`.
//!
//! `PMULL` multiplies with the opposite convention, bit 0 of a lane being the coefficient of
//! `u^0`. Reversing the sixteen bytes of a block maps one convention onto the other: the block
//! `x[0].to_be_bytes() || x[1].to_be_bytes()` reversed is `x[1].to_le_bytes() ||
//! x[0].to_le_bytes()`, which is the vector with 64-bit lanes `(x[1], x[0])`. So the conversion
//! each way is a lane swap and costs nothing (the private `load` / `store`). The product of two
//! reversed operands is the reversed product shifted right by one bit, which the reduction
//! undoes first.
//!
//! The multiply and reduce sequence is bc-fips's `gfmul()` (`native_c/arm/gcm/gcm_hash.h`) and
//! `reduce()` / `gfmul_multi_reduce()` (`native_c/arm/gcm/gcm_neon.c`), themselves the
//! shift-based reduction of Gueron and Kounavis's CLMUL white paper for the bit-reflected
//! representation. The port is checked against Sec 6.3 Algorithm 1 bit by bit and on random
//! pairs in `tests/arm64_le_ghash_tests.rs`.

use super::intrinsics::V128;

/// A block of `GF(2^128)` as two big-endian `u64`s; see the module docs.
pub type Element = [u64; 2];

/// An element in the byte-reversed order `PMULL` wants: the lane swap of the module docs.
#[target_feature(enable = "aes,neon")]
#[inline]
fn load(x: &Element) -> V128 {
    V128::from_u64x2(x[1], x[0])
}

/// The inverse of [`load`].
#[target_feature(enable = "aes,neon")]
#[inline]
fn store(v: V128) -> Element {
    [v.lane_u64::<1>(), v.lane_u64::<0>()]
}

/// Reduces a 256-bit product `high || low` of two byte-reversed operands to the byte-reversed
/// 128-bit product modulo `u^128 + u^7 + u^2 + u + 1` (the polynomial `R || 1` of Sec 6.3).
///
/// A line-for-line port of bc-fips `reduce()` (`gcm_neon.c`). Three stages:
///
/// 1. Shift the 256-bit value left by one bit, because the product of two reversed operands
///    sits one bit right of where the reversed representation needs it. Each 32-bit lane is
///    shifted on its own and the bits that cross a lane boundary are moved by `ext`:
///    `tmp6`/`tmp7` hold the top bit of each lane of `low`/`high`, `ext::<12>` slides them up
///    one lane, and the carry out of `low`'s top lane lands in `high`'s bottom lane.
/// 2. Multiply `low` by `u^7 + u^2 + u`, in the reversed representation a left shift by 31, 30
///    and 25 within each lane (the `u^128` term is the lane it crosses into), and fold the part
///    that crosses the top of the 128-bit value back onto `low`.
/// 3. The matching right shifts by 1, 2 and 7, with the carry from stage 2, complete the fold;
///    the reduced product is `high ⊕ low`.
#[target_feature(enable = "aes,neon")]
#[inline]
fn reduce(low: V128, high: V128) -> V128 {
    let zero = V128::zero();

    // Stage 1.
    let mut tmp6 = low.shr32::<31>();
    let mut tmp7 = high.shr32::<31>();
    let mut low = low.shl32::<1>();
    let mut high = high.shl32::<1>();
    let mut tmp8 = tmp6.ext::<12>(zero);
    tmp7 = zero.ext::<12>(tmp7);
    tmp6 = zero.ext::<12>(tmp6);
    low = low.orr(tmp6);
    high = high.orr(tmp7);
    high = high.orr(tmp8);

    // Stage 2.
    tmp6 = low.shl32::<31>();
    tmp7 = low.shl32::<30>();
    tmp8 = low.shl32::<25>();
    tmp6 = tmp6.eor(tmp7);
    tmp6 = tmp6.eor(tmp8);
    tmp7 = tmp6.ext::<4>(zero);
    tmp6 = zero.ext::<4>(tmp6);
    low = low.eor(tmp6);

    // Stage 3.
    let mut tmp1 = low.shr32::<1>();
    let tmp2 = low.shr32::<2>();
    let tmp3 = low.shr32::<7>();
    tmp1 = tmp1.eor(tmp2);
    tmp1 = tmp1.eor(tmp3);
    tmp1 = tmp1.eor(tmp7);
    low = low.eor(tmp1);

    high.eor(low)
}

/// The four `PMULL` products of two byte-reversed operands, combined into the low and high
/// halves of the 256-bit product: `(high, low)` with the two cross terms folded into both.
#[target_feature(enable = "aes,neon")]
#[inline]
fn mul_no_reduce(a: V128, b: V128) -> (V128, V128) {
    let zero = V128::zero();
    let high = a.pmull_hh(b);
    let low = a.pmull_ll(b);
    let cross = a.pmull_hl(b).eor(a.pmull_lh(b));
    // The cross terms straddle the halves: their low 64 bits join the top of `low`, their high
    // 64 bits the bottom of `high`.
    let low = low.eor(zero.ext::<8>(cross));
    let high = high.eor(cross.ext::<8>(zero));
    (low, high)
}

/// `X • Y` (Sec 6.3, Algorithm 1). A port of bc-fips `gfmul()`.
///
/// # Safety
///
/// Callable only through an [`Aes`](super::Aes) proof, whose existence is the precondition.
#[target_feature(enable = "aes,neon")]
pub fn mul(x: &Element, y: &Element) -> Element {
    let (low, high) = mul_no_reduce(load(x), load(y));
    store(reduce(low, high))
}

/// `x[0]•y[0] ⊕ x[1]•y[1] ⊕ x[2]•y[2] ⊕ x[3]•y[3]`, summed before the one reduction. A port of
/// bc-fips `gfmul_multi_reduce()`; the sum of unreduced products reduces to the sum of the
/// reduced ones because reduction is linear.
///
/// For GHASH pass `y = [H^4, H^3, H^2, H]` and `x[0] = Y ⊕ X1`, `x[1..] = X2, X3, X4`.
///
/// # Safety
///
/// Callable only through an [`Aes`](super::Aes) proof, whose existence is the precondition.
#[target_feature(enable = "aes,neon")]
pub fn mul4(x: &[Element; 4], y: &[Element; 4]) -> Element {
    let (mut low, mut high) = mul_no_reduce(load(&x[0]), load(&y[0]));
    for i in 1..4 {
        let (l, h) = mul_no_reduce(load(&x[i]), load(&y[i]));
        low = low.eor(l);
        high = high.eor(h);
    }
    store(reduce(low, high))
}
