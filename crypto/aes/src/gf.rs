//! Arithmetic in the finite field GF(2^8), as specified in FIPS 197 Section 4.
//!
//! Every byte of the AES state is interpreted as an element of GF(2^8); ie as the polynomial
//! (FIPS 197 Eq 4.1):
//!
//! ```text
//! b(x) = b7*x^7 + b6*x^6 + b5*x^5 + b4*x^4 + b3*x^3 + b2*x^2 + b1*x + b0
//! ```
//!
//! Addition in the field is the bitwise XOR of the two bytes (Section 4.1), so this module only
//! needs to provide multiplication.
//!
//! Multiplication (Section 4.2) is polynomial multiplication reduced modulo the fixed polynomial
//! (Eq 4.3):
//!
//! ```text
//! m(x) = x^8 + x^4 + x^3 + x + 1
//! ```
//!
//! # Why only these specific multipliers?
//!
//! The cipher never needs a general field multiplication: MIXCOLUMNS() multiplies only by
//! {02} and {03} (Eq 5.6) and INVMIXCOLUMNS() only by {09}, {0b}, {0d} and {0e} (Eq 5.13).
//! Each of those is expressed here as a short chain of [`xtimes`] calls plus XORs, exactly as
//! suggested by FIPS 197 Section 4.2 ("Multiplication by higher powers of x ... can be implemented
//! by the repeated application of xTimes()"). A general multiply routine would either need a
//! data-dependent loop or a log/antilog table, both of which leak the multiplicand through
//! timing or cache state; the fixed chains below are branch-free and table-free.
//!
//! # Constant-time behaviour
//!
//! All functions in this module are branch-free and index-free: they consist only of shifts, XORs
//! and masks over the input byte, so neither their execution time nor their memory access pattern
//! depends on the (secret) value being multiplied.

/// Multiplies `b` by {02} in GF(2^8); ie FIPS 197 Eq (4.5) xTimes(b).
///
/// The spec writes this as a conditional on the high bit of `b`:
///
/// ```text
/// xTimes(b) = {b6 b5 b4 b3 b2 b1 b0 0}                       if b7 = 0
/// xTimes(b) = {b6 b5 b4 b3 b2 b1 b0 0} XOR {0 0 0 1 1 0 1 1}  if b7 = 1
/// ```
///
/// We evaluate both arms unconditionally and select between them with a mask, so that the timing
/// and the branch-predictor state do not depend on the secret value of `b`. Do not "simplify" this
/// back into an `if`.
#[inline(always)]
pub(crate) const fn xtimes(b: u8) -> u8 {
    // `b >> 7` is exactly b7, so it is 0 or 1; `wrapping_neg()` maps 1 -> 0xFF and 0 -> 0x00.
    let b7_mask = (b >> 7).wrapping_neg();

    // `b << 1` is the polynomial multiplication by x. It discards b7, which is the degree-8 term
    // that the modular reduction has to remove.
    // {1b} == {0 0 0 1 1 0 1 1} is m(x) (Eq 4.3) with its x^8 term dropped, so XOR-ing it in is
    // the reduction "mod m(x)" -- and it must only happen when a degree-8 term was actually
    // produced, which is what the mask selects.
    (b << 1) ^ (b7_mask & 0x1b)
}

/// Multiplies `b` by {02}, one of the two MIXCOLUMNS() coefficients (FIPS 197 Eq 5.6).
///
/// This is just [`xtimes`] under the name used by Eq (5.8), for readability at the call site.
#[inline(always)]
pub(crate) const fn mul_02(b: u8) -> u8 {
    xtimes(b)
}

/// Multiplies `b` by {03}, the other MIXCOLUMNS() coefficient (FIPS 197 Eq 5.6).
///
/// {03} = {02} XOR {01} (ie x + 1), and multiplication distributes over field addition, so
/// b*{03} = xTimes(b) XOR b.
#[inline(always)]
pub(crate) const fn mul_03(b: u8) -> u8 {
    xtimes(b) ^ b
}

/// Multiplies `b` by {09}, an INVMIXCOLUMNS() coefficient (FIPS 197 Eq 5.13).
///
/// {09} = {08} XOR {01}, ie x^3 + 1, so b*{09} = xTimes^3(b) XOR b.
#[inline(always)]
pub(crate) const fn mul_09(b: u8) -> u8 {
    let x8 = xtimes(xtimes(xtimes(b)));
    x8 ^ b
}

/// Multiplies `b` by {0b}, an INVMIXCOLUMNS() coefficient (FIPS 197 Eq 5.13).
///
/// {0b} = {08} XOR {02} XOR {01}, ie x^3 + x + 1.
#[inline(always)]
pub(crate) const fn mul_0b(b: u8) -> u8 {
    let x2 = xtimes(b);
    let x8 = xtimes(xtimes(x2));
    x8 ^ x2 ^ b
}

/// Multiplies `b` by {0d}, an INVMIXCOLUMNS() coefficient (FIPS 197 Eq 5.13).
///
/// {0d} = {08} XOR {04} XOR {01}, ie x^3 + x^2 + 1.
#[inline(always)]
pub(crate) const fn mul_0d(b: u8) -> u8 {
    let x4 = xtimes(xtimes(b));
    let x8 = xtimes(x4);
    x8 ^ x4 ^ b
}

/// Multiplies `b` by {0e}, an INVMIXCOLUMNS() coefficient (FIPS 197 Eq 5.13).
///
/// {0e} = {08} XOR {04} XOR {02}, ie x^3 + x^2 + x. Note there is no XOR of `b` itself here,
/// because {0e} has no constant term.
#[inline(always)]
pub(crate) const fn mul_0e(b: u8) -> u8 {
    let x2 = xtimes(b);
    let x4 = xtimes(x2);
    let x8 = xtimes(x4);
    x8 ^ x4 ^ x2
}

/// A general GF(2^8) multiplication, used only to cross-check the fixed multipliers above and to
/// derive the S-box from its mathematical definition in the unit tests.
///
/// This is deliberately **not** available outside of tests: the loop below branches on the bits of
/// `b`, so it is not constant-time and must never be used on secret data.
#[cfg(test)]
pub(crate) fn gf_mul(a: u8, b: u8) -> u8 {
    let mut product = 0u8;
    let mut a_shifted = a;
    let mut b_remaining = b;

    // Section 4.2: multiply the polynomials, accumulating a*x^i for each set bit i of b, reducing
    // mod m(x) as we go (which the spec notes may be applied to intermediate steps).
    while b_remaining != 0 {
        if b_remaining & 1 == 1 {
            product ^= a_shifted;
        }
        a_shifted = xtimes(a_shifted);
        b_remaining >>= 1;
    }

    product
}

/// Raises `b` to the power `exponent` in GF(2^8) by repeated multiplication. Tests only.
#[cfg(test)]
pub(crate) fn gf_pow(b: u8, exponent: u32) -> u8 {
    let mut acc = 1u8;
    for _ in 0..exponent {
        acc = gf_mul(acc, b);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 197 Eq (4.6): the worked example of repeated xTimes() applied to b = {57}.
    #[test]
    fn xtimes_matches_fips197_eq_4_6() {
        assert_eq!(xtimes(0x57), 0xae); // {57} * {02}
        assert_eq!(xtimes(0xae), 0x47); // {57} * {04}
        assert_eq!(xtimes(0x47), 0x8e); // {57} * {08}
        assert_eq!(xtimes(0x8e), 0x07); // {57} * {10}
        assert_eq!(xtimes(0x07), 0x0e); // {57} * {20}
        assert_eq!(xtimes(0x0e), 0x1c); // {57} * {40}
        assert_eq!(xtimes(0x1c), 0x38); // {57} * {80}
    }

    /// FIPS 197 Eq (4.7): {57} * {13} = {57} XOR {ae} XOR {07} = {fe}.
    #[test]
    fn gf_mul_matches_fips197_eq_4_7() {
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        // Also check the decomposition the spec uses to get there: {13} = {01} + {02} + {10}.
        assert_eq!(0x57 ^ 0xae ^ 0x07, 0xfe);
    }

    /// The fixed multipliers must agree with a general field multiplication for every input byte.
    /// This is what pins the xTimes() chains in [`mul_09`] .. [`mul_0e`] to the coefficients that
    /// FIPS 197 Eq (5.6) and Eq (5.13) actually specify.
    #[test]
    fn fixed_multipliers_match_general_multiplication() {
        for b in 0..=u8::MAX {
            assert_eq!(mul_02(b), gf_mul(b, 0x02), "mul_02({b:#04x})");
            assert_eq!(mul_03(b), gf_mul(b, 0x03), "mul_03({b:#04x})");
            assert_eq!(mul_09(b), gf_mul(b, 0x09), "mul_09({b:#04x})");
            assert_eq!(mul_0b(b), gf_mul(b, 0x0b), "mul_0b({b:#04x})");
            assert_eq!(mul_0d(b), gf_mul(b, 0x0d), "mul_0d({b:#04x})");
            assert_eq!(mul_0e(b), gf_mul(b, 0x0e), "mul_0e({b:#04x})");
        }
    }

    /// FIPS 197 Eq (4.10) and (4.11): b^254 is the multiplicative inverse of every non-zero b.
    /// This is the property that the S-box is built on, so it is worth pinning independently.
    #[test]
    fn gf_pow_254_is_the_multiplicative_inverse() {
        for b in 1..=u8::MAX {
            assert_eq!(gf_mul(b, gf_pow(b, 254)), 0x01, "inverse of {b:#04x}");
        }
    }

    /// The field has no zero divisors, and {01} is the identity.
    #[test]
    fn gf_mul_basic_properties() {
        for b in 0..=u8::MAX {
            assert_eq!(gf_mul(b, 0x00), 0x00);
            assert_eq!(gf_mul(b, 0x01), b);
            // Commutativity, spot-checked across the whole range.
            assert_eq!(gf_mul(b, 0x57), gf_mul(0x57, b));
        }
    }
}
