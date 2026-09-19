//! SEC 1 v2.0 (Certicom, May 2009) §2.3.3/§2.3.4 point encoding and decoding for P-521, and the
//! public-key validation SP 800-186 (Feb 2023) Appendix D.1.1.1 requires. Identical in shape to
//! [`crate::p256_sec1`]/[`crate::p384_sec1`] -- see [`crate::p256_sec1`]'s docs for the full
//! reasoning -- with P-521's 66-byte field-element width (`ceil(521/8)`) and 9-limb type
//! substituted. `p` is `3 mod 4` here too (verified in this module's tests), so the same
//! compressed-decode square-root approach applies.
//!
//! Unlike P-256/P-384, `66 * 8 = 528` bits is 7 bits wider than `p`'s 521, so a valid encoded
//! field element's top byte always has its high 7 bits clear; [`limbs_less_than_p`] (via ordinary
//! big-integer comparison against [`P_LIMBS`]) already rejects any encoding that sets them, since
//! such a value is `>= p` (indeed `>= 2^521 > p`).

use crate::nat;
use crate::p521::{P_LIMBS, P521FieldElement};
use crate::p521_domain::B_LIMBS;
use crate::p521_point::P521JacobianPoint;

/// `(p + 1) / 4`, the exponent [`decode`]'s compressed-point square root raises `α` to.
const SQRT_EXPONENT: [u64; 9] = [
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000080,
];

/// Converts 66 big-endian bytes to little-endian `u64` limbs.
pub fn limbs_from_be_bytes(bytes: &[u8; 66]) -> [u64; 9] {
    let mut limbs = [0u64; 9];
    for i in 0..8 {
        limbs[i] = u64::from_be_bytes(bytes[(58 - i * 8)..(66 - i * 8)].try_into().unwrap());
    }
    // `bytes[0] << 8` occupies bits 8-15 and `bytes[1]` occupies bits 0-7 -- disjoint, so `|` and
    // `^` are equivalent here (an accepted mutant, not a bug: this repo's stated policy for
    // OR/XOR-over-disjoint-bits cases).
    limbs[8] = (u64::from(bytes[0]) << 8) | u64::from(bytes[1]);
    limbs
}

/// Converts little-endian `u64` limbs to 66 big-endian bytes.
pub fn be_bytes_from_limbs(limbs: &[u64; 9]) -> [u8; 66] {
    let mut out = [0u8; 66];
    for i in 0..8 {
        out[(58 - i * 8)..(66 - i * 8)].copy_from_slice(&limbs[i].to_be_bytes());
    }
    let top = limbs[8] as u16;
    out[0..2].copy_from_slice(&top.to_be_bytes());
    out
}

fn limbs_less_than_p(limbs: &[u64; 9]) -> bool {
    let (_, borrow) = nat::sub(limbs, &P_LIMBS);
    borrow == 1
}

fn either_out_of_range(x_limbs: &[u64; 9], y_limbs: &[u64; 9]) -> bool {
    !limbs_less_than_p(x_limbs) || !limbs_less_than_p(y_limbs)
}

/// `y^2 == x^3 - 3x + b`.
fn is_on_curve(x: &P521FieldElement, y: &P521FieldElement) -> bool {
    let lhs = y.mul(y);
    let x_cubed = x.mul(x).mul(x);
    let three_x = x.add(x).add(x);
    let rhs = x_cubed.sub(&three_x).add(&P521FieldElement::from_limbs(B_LIMBS));
    lhs == rhs
}

/// `base^SQRT_EXPONENT mod p`. Plain (not masked) square-and-multiply: only ever runs on public
/// data (an incoming encoded point), like [`crate::p256_sec1::pow_public`].
///
/// Flipping the `== 1` bit-test to `!= 1` here is an accepted mutant, not a bug: it computes
/// `alpha^(p - E)` instead of `alpha^E` (`E = SQRT_EXPONENT`), and since `alpha^(p-1) == 1` for any
/// `alpha != 0` (Fermat), `alpha^(p-E) == alpha / alpha^E == alpha / beta` where `beta = alpha^E`.
/// `[`decode`]`'s only use of the result is via `beta.mul(&beta) != alpha`, and `(alpha/beta)^2 ==
/// alpha` iff `beta^2 == alpha` (multiply both sides by `alpha`) -- so the mutated exponent
/// reproduces the exact same accepted `beta` when `alpha` is a residue, and the exact same
/// rejection when it isn't. Verified (not checked in) against 2000 random field elements, split
/// roughly evenly between residues and non-residues.
fn pow_public(base: &P521FieldElement, exponent_limbs: &[u64; 9]) -> P521FieldElement {
    let mut result = P521FieldElement::ONE;
    for limb_idx in (0..9).rev() {
        let limb = exponent_limbs[limb_idx];
        let bit_count = if limb_idx == 8 { 9 } else { 64 };
        for bit in (0..bit_count).rev() {
            result = result.square();
            if (limb >> bit) & 1 == 1 {
                result = result.mul(base);
            }
        }
    }
    result
}

/// SEC 1 §2.3.3 case 3: `04 || X || Y`, 133 bytes.
pub fn encode_uncompressed(x: &P521FieldElement, y: &P521FieldElement) -> [u8; 133] {
    let mut out = [0u8; 133];
    out[0] = 0x04;
    out[1..67].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out[67..133].copy_from_slice(&be_bytes_from_limbs(&y.to_limbs()));
    out
}

/// SEC 1 §2.3.3 case 2: `02 || X` or `03 || X`, 67 bytes, tag selected by `y mod 2`.
pub fn encode_compressed(x: &P521FieldElement, y: &P521FieldElement) -> [u8; 67] {
    let mut out = [0u8; 67];
    out[0] = if y.to_limbs()[0] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..67].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out
}

/// Decodes and validates a SEC 1 §2.3.4 point encoding: 67 bytes (compressed) or 133 bytes
/// (uncompressed). See [`crate::p256_sec1::decode`]'s docs for exactly which checks this performs.
pub fn decode(bytes: &[u8]) -> Option<(P521FieldElement, P521FieldElement)> {
    match bytes.len() {
        67 => {
            let y_tilde: u64 = match bytes[0] {
                0x02 => 0,
                0x03 => 1,
                _ => return None,
            };
            let x_bytes: [u8; 66] = bytes[1..67].try_into().ok()?;
            let x_limbs = limbs_from_be_bytes(&x_bytes);
            if !limbs_less_than_p(&x_limbs) {
                return None;
            }
            let x = P521FieldElement::from_limbs(x_limbs);
            let x_cubed = x.mul(&x).mul(&x);
            let three_x = x.add(&x).add(&x);
            let alpha = x_cubed.sub(&three_x).add(&P521FieldElement::from_limbs(B_LIMBS));
            let beta = pow_public(&alpha, &SQRT_EXPONENT);
            if beta.mul(&beta) != alpha {
                return None;
            }
            let beta_parity = beta.to_limbs()[0] & 1;
            let y = if beta_parity == y_tilde { beta } else { beta.negate() };
            Some((x, y))
        }
        133 => {
            if bytes[0] != 0x04 {
                return None;
            }
            let x_bytes: [u8; 66] = bytes[1..67].try_into().ok()?;
            let y_bytes: [u8; 66] = bytes[67..133].try_into().ok()?;
            let x_limbs = limbs_from_be_bytes(&x_bytes);
            let y_limbs = limbs_from_be_bytes(&y_bytes);
            if either_out_of_range(&x_limbs, &y_limbs) {
                return None;
            }
            let x = P521FieldElement::from_limbs(x_limbs);
            let y = P521FieldElement::from_limbs(y_limbs);
            if !is_on_curve(&x, &y) {
                return None;
            }
            Some((x, y))
        }
        _ => None,
    }
}

/// Decodes and validates an encoded public key (see [`decode`]) directly into a
/// [`P521JacobianPoint`].
pub fn decode_point(bytes: &[u8]) -> Option<P521JacobianPoint> {
    let (x, y) = decode(bytes)?;
    Some(P521JacobianPoint::from_affine(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_is_3_mod_4() {
        assert_eq!(P_LIMBS[0] & 0b11, 3);
    }

    #[test]
    fn limbs_less_than_p_boundary_cases() {
        assert!(limbs_less_than_p(&[0; 9]));

        let mut p_minus_1 = P_LIMBS;
        p_minus_1[0] -= 1;
        assert!(limbs_less_than_p(&p_minus_1));

        assert!(!limbs_less_than_p(&P_LIMBS));

        // every low limb of p is already saturated (0xffffffffffffffff); only the top limb (0x1ff)
        // has room to bump without overflowing the u64 itself.
        let mut p_with_bumped_limb = P_LIMBS;
        p_with_bumped_limb[8] += 1;
        assert!(!limbs_less_than_p(&p_with_bumped_limb));
    }

    #[test]
    fn either_out_of_range_requires_only_one_coordinate_to_be_out_of_range() {
        let in_range = [0u64; 9];
        let out_of_range = P_LIMBS;

        assert!(!either_out_of_range(&in_range, &in_range));
        assert!(either_out_of_range(&out_of_range, &in_range));
        assert!(either_out_of_range(&in_range, &out_of_range));
        assert!(either_out_of_range(&out_of_range, &out_of_range));
    }

    #[test]
    fn be_bytes_round_trip() {
        let limbs: [u64; 9] = [
            0x1122334455667788, 0x99aabbccddeeff00, 0x0102030405060708, 0x1020304050607080,
            0x0a0b0c0d0e0f1011, 0x1213141516171819, 0x2021222324252627, 0x2829303132333435,
            0x0000000000000123,
        ];
        assert_eq!(limbs_from_be_bytes(&be_bytes_from_limbs(&limbs)), limbs);
    }
}
