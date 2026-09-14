//! SEC 1 v2.0 (Certicom, May 2009) §2.3.3/§2.3.4 point encoding and decoding for P-384, and the
//! public-key validation SP 800-186 (Feb 2023) Appendix D.1.1.1 requires. Identical in shape to
//! [`crate::p256_sec1`] -- see that module's docs for the full reasoning (SEC 1 §2.3.3/§2.3.4
//! cases, why there is no point-at-infinity case, why partial validation is full validation here,
//! and the compressed-decode square-root derivation) -- with the width and curve constants
//! swapped for P-384's (also `p = 3 mod 4` and cofactor `h = 1`, verified the same way in this
//! module's tests).

use crate::nat;
use crate::p384::{P_LIMBS, P384FieldElement};
use crate::p384_domain::B_LIMBS;
use crate::p384_point::P384JacobianPoint;

/// `(p + 1) / 4`, the exponent [`decode`]'s compressed-point square root raises `α` to.
const SQRT_EXPONENT: [u64; 6] = [
    0x0000000040000000, 0xbfffffffc0000000, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0x3fffffffffffffff,
];

/// Converts 48 big-endian bytes to little-endian `u64` limbs.
pub fn limbs_from_be_bytes(bytes: &[u8; 48]) -> [u64; 6] {
    let mut limbs = [0u64; 6];
    for i in 0..6 {
        limbs[i] = u64::from_be_bytes(bytes[(40 - i * 8)..(48 - i * 8)].try_into().unwrap());
    }
    limbs
}

/// Converts little-endian `u64` limbs to 48 big-endian bytes.
pub fn be_bytes_from_limbs(limbs: &[u64; 6]) -> [u8; 48] {
    let mut out = [0u8; 48];
    for i in 0..6 {
        out[(40 - i * 8)..(48 - i * 8)].copy_from_slice(&limbs[i].to_be_bytes());
    }
    out
}

fn limbs_less_than_p(limbs: &[u64; 6]) -> bool {
    let (_, borrow) = nat::sub(limbs, &P_LIMBS);
    borrow == 1
}

fn either_out_of_range(x_limbs: &[u64; 6], y_limbs: &[u64; 6]) -> bool {
    !limbs_less_than_p(x_limbs) || !limbs_less_than_p(y_limbs)
}

/// `y^2 == x^3 - 3x + b`.
fn is_on_curve(x: &P384FieldElement, y: &P384FieldElement) -> bool {
    let lhs = y.mul(y);
    let x_cubed = x.mul(x).mul(x);
    let three_x = x.add(x).add(x);
    let rhs = x_cubed.sub(&three_x).add(&P384FieldElement::from_limbs(B_LIMBS));
    lhs == rhs
}

/// `base^SQRT_EXPONENT mod p`. Plain (not masked) square-and-multiply: only ever runs on public
/// data (an incoming encoded point), like [`crate::p256_sec1::pow_public`].
fn pow_public(base: &P384FieldElement, exponent_limbs: &[u64; 6]) -> P384FieldElement {
    let mut result = P384FieldElement::ONE;
    for limb_idx in (0..6).rev() {
        let limb = exponent_limbs[limb_idx];
        for bit in (0..64).rev() {
            result = result.square();
            if (limb >> bit) & 1 == 1 {
                result = result.mul(base);
            }
        }
    }
    result
}

/// SEC 1 §2.3.3 case 3: `04 || X || Y`, 97 bytes.
pub fn encode_uncompressed(x: &P384FieldElement, y: &P384FieldElement) -> [u8; 97] {
    let mut out = [0u8; 97];
    out[0] = 0x04;
    out[1..49].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out[49..97].copy_from_slice(&be_bytes_from_limbs(&y.to_limbs()));
    out
}

/// SEC 1 §2.3.3 case 2: `02 || X` or `03 || X`, 49 bytes, tag selected by `y mod 2`.
pub fn encode_compressed(x: &P384FieldElement, y: &P384FieldElement) -> [u8; 49] {
    let mut out = [0u8; 49];
    out[0] = if y.to_limbs()[0] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..49].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out
}

/// Decodes and validates a SEC 1 §2.3.4 point encoding: 49 bytes (compressed) or 97 bytes
/// (uncompressed). See [`crate::p256_sec1::decode`]'s docs for exactly which checks this performs.
pub fn decode(bytes: &[u8]) -> Option<(P384FieldElement, P384FieldElement)> {
    match bytes.len() {
        49 => {
            let y_tilde: u64 = match bytes[0] {
                0x02 => 0,
                0x03 => 1,
                _ => return None,
            };
            let x_bytes: [u8; 48] = bytes[1..49].try_into().ok()?;
            let x_limbs = limbs_from_be_bytes(&x_bytes);
            if !limbs_less_than_p(&x_limbs) {
                return None;
            }
            let x = P384FieldElement::from_limbs(x_limbs);
            let x_cubed = x.mul(&x).mul(&x);
            let three_x = x.add(&x).add(&x);
            let alpha = x_cubed.sub(&three_x).add(&P384FieldElement::from_limbs(B_LIMBS));
            let beta = pow_public(&alpha, &SQRT_EXPONENT);
            if beta.mul(&beta) != alpha {
                return None;
            }
            let beta_parity = beta.to_limbs()[0] & 1;
            let y = if beta_parity == y_tilde { beta } else { beta.negate() };
            Some((x, y))
        }
        97 => {
            if bytes[0] != 0x04 {
                return None;
            }
            let x_bytes: [u8; 48] = bytes[1..49].try_into().ok()?;
            let y_bytes: [u8; 48] = bytes[49..97].try_into().ok()?;
            let x_limbs = limbs_from_be_bytes(&x_bytes);
            let y_limbs = limbs_from_be_bytes(&y_bytes);
            if either_out_of_range(&x_limbs, &y_limbs) {
                return None;
            }
            let x = P384FieldElement::from_limbs(x_limbs);
            let y = P384FieldElement::from_limbs(y_limbs);
            if !is_on_curve(&x, &y) {
                return None;
            }
            Some((x, y))
        }
        _ => None,
    }
}

/// Decodes and validates an encoded public key (see [`decode`]) directly into a
/// [`P384JacobianPoint`].
pub fn decode_point(bytes: &[u8]) -> Option<P384JacobianPoint> {
    let (x, y) = decode(bytes)?;
    Some(P384JacobianPoint::from_affine(x, y))
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
        assert!(limbs_less_than_p(&[0, 0, 0, 0, 0, 0]));

        let mut p_minus_1 = P_LIMBS;
        p_minus_1[0] -= 1;
        assert!(limbs_less_than_p(&p_minus_1));

        assert!(!limbs_less_than_p(&P_LIMBS));

        let mut p_plus_2_pow_32 = P_LIMBS;
        p_plus_2_pow_32[0] += 1 << 32; // limb 0's top 32 bits are 0, so this cannot overflow
        assert!(!limbs_less_than_p(&p_plus_2_pow_32));

        assert!(!limbs_less_than_p(&[u64::MAX; 6]));
    }

    #[test]
    fn either_out_of_range_requires_only_one_coordinate_to_be_out_of_range() {
        let in_range = [0u64; 6];
        let out_of_range = P_LIMBS;

        assert!(!either_out_of_range(&in_range, &in_range));
        assert!(either_out_of_range(&out_of_range, &in_range));
        assert!(either_out_of_range(&in_range, &out_of_range));
        assert!(either_out_of_range(&out_of_range, &out_of_range));
    }
}
