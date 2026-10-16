//! SEC 1 v2.0 (Certicom, May 2009) §2.3.3/§2.3.4/§2.3.5/§2.3.7 point encoding, decoding, and octet-
//! string encoding for brainpoolP384r1. Identical in shape to [`crate::bp256r1_sec1`] -- see that
//! module's docs for the full reasoning (SEC 1 §2.3.3/§2.3.4 cases, why there is no
//! point-at-infinity case, why partial validation is full validation here since RFC 5639 §3.4
//! gives brainpoolP384r1 cofactor `h = 1`, and the compressed-decode square-root derivation) --
//! with the curve equation `y^2 = x^3 + Ax + B` (a general `A`, per [`crate::bp384r1_point`],
//! instead of `a = -3`) and brainpoolP384r1's own constants (also `p ≡ 3 (mod 4)`, verified the
//! same way in this module's tests; RFC 5639 §3.4 gives both `p` and `h`).
//!
//! Field elements and scalars are encoded big-endian, fixed-width (§2.3.7's plain big-endian
//! integer encoding) -- the opposite byte order from this crate's internal little-endian `u64`
//! limbs, so [`limbs_from_be_bytes`] and [`be_bytes_from_limbs`] convert at the boundary.

use crate::bp384r1::{Bp384r1FieldElement, P_LIMBS};
use crate::bp384r1_domain::{A_LIMBS, B_LIMBS};
use crate::bp384r1_point::Bp384r1JacobianPoint;
use crate::nat;

/// `(p + 1) / 4`, the exponent [`decode`]'s compressed-point square root raises `α` to.
const SQRT_EXPONENT: [u64; 6] = [
    0x61d1c004cc41fb15, 0xeb34e9ca6407469c, 0x04ac76865fedc448, 0xc54bdc427b5515ad,
    0x03d75bdf94399077, 0x232e47a0a8ce1b4a,
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

/// `true` iff either coordinate is outside `[0, p)`.
fn either_out_of_range(x_limbs: &[u64; 6], y_limbs: &[u64; 6]) -> bool {
    !limbs_less_than_p(x_limbs) || !limbs_less_than_p(y_limbs)
}

/// `y^2 == x^3 + Ax + B`.
fn is_on_curve(x: &Bp384r1FieldElement, y: &Bp384r1FieldElement) -> bool {
    let lhs = y.mul(y);
    let x_cubed = x.mul(x).mul(x);
    let ax = Bp384r1FieldElement::from_limbs(A_LIMBS).mul(x);
    let rhs = x_cubed.add(&ax).add(&Bp384r1FieldElement::from_limbs(B_LIMBS));
    lhs == rhs
}

/// `base^SQRT_EXPONENT mod p`. Plain (not masked) square-and-multiply: only ever runs on public
/// data (an incoming encoded point), like [`crate::p256_sec1::pow_public`].
fn pow_public(base: &Bp384r1FieldElement, exponent_limbs: &[u64; 6]) -> Bp384r1FieldElement {
    let mut result = Bp384r1FieldElement::ONE;
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
pub fn encode_uncompressed(x: &Bp384r1FieldElement, y: &Bp384r1FieldElement) -> [u8; 97] {
    let mut out = [0u8; 97];
    out[0] = 0x04;
    out[1..49].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out[49..97].copy_from_slice(&be_bytes_from_limbs(&y.to_limbs()));
    out
}

/// SEC 1 §2.3.3 case 2: `02 || X` or `03 || X`, 49 bytes, tag selected by `y mod 2`.
pub fn encode_compressed(x: &Bp384r1FieldElement, y: &Bp384r1FieldElement) -> [u8; 49] {
    let mut out = [0u8; 49];
    out[0] = if y.to_limbs()[0] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..49].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out
}

/// Decodes and validates a SEC 1 §2.3.4 point encoding: 49 bytes (compressed) or 97 bytes
/// (uncompressed). See [`crate::p256_sec1::decode`]'s docs for exactly which checks this performs.
pub fn decode(bytes: &[u8]) -> Option<(Bp384r1FieldElement, Bp384r1FieldElement)> {
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
            let x = Bp384r1FieldElement::from_limbs(x_limbs);
            let x_cubed = x.mul(&x).mul(&x);
            let ax = Bp384r1FieldElement::from_limbs(A_LIMBS).mul(&x);
            let alpha = x_cubed.add(&ax).add(&Bp384r1FieldElement::from_limbs(B_LIMBS));
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
            let x = Bp384r1FieldElement::from_limbs(x_limbs);
            let y = Bp384r1FieldElement::from_limbs(y_limbs);
            if !is_on_curve(&x, &y) {
                return None;
            }
            Some((x, y))
        }
        _ => None,
    }
}

/// Decodes and validates an encoded public key (see [`decode`]) directly into a
/// [`Bp384r1JacobianPoint`].
pub fn decode_point(bytes: &[u8]) -> Option<Bp384r1JacobianPoint> {
    let (x, y) = decode(bytes)?;
    Some(Bp384r1JacobianPoint::from_affine(x, y))
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

        let mut p_plus_1 = P_LIMBS;
        p_plus_1[0] += 1;
        assert!(!limbs_less_than_p(&p_plus_1));

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
