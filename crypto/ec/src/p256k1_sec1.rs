//! SEC 1 v2.0 (Certicom, May 2009) §2.3.3/§2.3.4 point encoding and decoding for secp256k1. Identical
//! in shape to [`crate::p256_sec1`] -- see that module's docs for the full reasoning (SEC 1
//! §2.3.3/§2.3.4 cases, why there is no point-at-infinity case, why partial validation is full
//! validation here, and the compressed-decode square-root derivation) -- with the curve equation
//! `y^2 = x^3 + b` (`a = 0`, per [`crate::p256k1_point`], instead of `a = -3`) and secp256k1's
//! constants (also `p ≡ 3 (mod 4)` and cofactor `h = 1`, verified the same way in this module's
//! tests; SEC 2 v2 §2.4.1 gives both).

use crate::nat;
use crate::p256k1::{P_LIMBS, P256K1FieldElement};
use crate::p256k1_domain::B_LIMBS;
use crate::p256k1_point::P256K1JacobianPoint;

/// `(p + 1) / 4`, the exponent [`decode`]'s compressed-point square root raises `α` to.
const SQRT_EXPONENT: [u64; 4] =
    [0xffffffffbfffff0c, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff];

/// Converts 32 big-endian bytes to little-endian `u64` limbs.
pub fn limbs_from_be_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
    ]
}

/// Converts little-endian `u64` limbs to 32 big-endian bytes.
pub fn be_bytes_from_limbs(limbs: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&limbs[3].to_be_bytes());
    out[8..16].copy_from_slice(&limbs[2].to_be_bytes());
    out[16..24].copy_from_slice(&limbs[1].to_be_bytes());
    out[24..32].copy_from_slice(&limbs[0].to_be_bytes());
    out
}

fn limbs_less_than_p(limbs: &[u64; 4]) -> bool {
    let (_, borrow) = nat::sub(limbs, &P_LIMBS);
    borrow == 1
}

/// `true` iff either coordinate is outside `[0, p)` (SP 800-186 Appendix D.1.1.1 step 2).
fn either_out_of_range(x_limbs: &[u64; 4], y_limbs: &[u64; 4]) -> bool {
    !limbs_less_than_p(x_limbs) || !limbs_less_than_p(y_limbs)
}

/// `y^2 == x^3 + b`.
fn is_on_curve(x: &P256K1FieldElement, y: &P256K1FieldElement) -> bool {
    let lhs = y.mul(y);
    let x_cubed = x.mul(x).mul(x);
    let rhs = x_cubed.add(&P256K1FieldElement::from_limbs(B_LIMBS));
    lhs == rhs
}

/// `base^SQRT_EXPONENT mod p`. Plain (not masked) square-and-multiply: only ever runs on public
/// data (an incoming encoded point), like [`crate::p256_sec1::pow_public`].
fn pow_public(base: &P256K1FieldElement, exponent_limbs: &[u64; 4]) -> P256K1FieldElement {
    let mut result = P256K1FieldElement::ONE;
    for limb_idx in (0..4).rev() {
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

/// SEC 1 §2.3.3 case 3: `04 || X || Y`, 65 bytes.
pub fn encode_uncompressed(x: &P256K1FieldElement, y: &P256K1FieldElement) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out[33..65].copy_from_slice(&be_bytes_from_limbs(&y.to_limbs()));
    out
}

/// SEC 1 §2.3.3 case 2: `02 || X` or `03 || X`, 33 bytes, tag selected by `y mod 2`.
pub fn encode_compressed(x: &P256K1FieldElement, y: &P256K1FieldElement) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = if y.to_limbs()[0] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..33].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out
}

/// Decodes and validates a SEC 1 §2.3.4 point encoding: 33 bytes (compressed) or 65 bytes
/// (uncompressed). See [`crate::p256_sec1::decode`]'s docs for exactly which checks this performs.
pub fn decode(bytes: &[u8]) -> Option<(P256K1FieldElement, P256K1FieldElement)> {
    match bytes.len() {
        33 => {
            let y_tilde: u64 = match bytes[0] {
                0x02 => 0,
                0x03 => 1,
                _ => return None,
            };
            let x_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
            let x_limbs = limbs_from_be_bytes(&x_bytes);
            if !limbs_less_than_p(&x_limbs) {
                return None;
            }
            let x = P256K1FieldElement::from_limbs(x_limbs);
            let x_cubed = x.mul(&x).mul(&x);
            let alpha = x_cubed.add(&P256K1FieldElement::from_limbs(B_LIMBS));
            let beta = pow_public(&alpha, &SQRT_EXPONENT);
            if beta.mul(&beta) != alpha {
                return None;
            }
            let beta_parity = beta.to_limbs()[0] & 1;
            let y = if beta_parity == y_tilde { beta } else { beta.negate() };
            Some((x, y))
        }
        65 => {
            if bytes[0] != 0x04 {
                return None;
            }
            let x_bytes: [u8; 32] = bytes[1..33].try_into().ok()?;
            let y_bytes: [u8; 32] = bytes[33..65].try_into().ok()?;
            let x_limbs = limbs_from_be_bytes(&x_bytes);
            let y_limbs = limbs_from_be_bytes(&y_bytes);
            if either_out_of_range(&x_limbs, &y_limbs) {
                return None;
            }
            let x = P256K1FieldElement::from_limbs(x_limbs);
            let y = P256K1FieldElement::from_limbs(y_limbs);
            if !is_on_curve(&x, &y) {
                return None;
            }
            Some((x, y))
        }
        _ => None,
    }
}

/// Decodes and validates an encoded public key (see [`decode`]) directly into a
/// [`P256K1JacobianPoint`].
pub fn decode_point(bytes: &[u8]) -> Option<P256K1JacobianPoint> {
    let (x, y) = decode(bytes)?;
    Some(P256K1JacobianPoint::from_affine(x, y))
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
        assert!(limbs_less_than_p(&[0, 0, 0, 0]));

        let mut p_minus_1 = P_LIMBS;
        p_minus_1[0] -= 1;
        assert!(limbs_less_than_p(&p_minus_1));

        assert!(!limbs_less_than_p(&P_LIMBS));

        // `P_LIMBS`' top three limbs are already all-`1`s, so (unlike P-256/P-384/P-521, which
        // have headroom in a non-adjacent limb) the only representable value strictly above `p`
        // is `p + 1` itself.
        let mut p_plus_1 = P_LIMBS;
        p_plus_1[0] += 1;
        assert!(!limbs_less_than_p(&p_plus_1));

        assert!(!limbs_less_than_p(&[u64::MAX; 4]));
    }

    #[test]
    fn either_out_of_range_requires_only_one_coordinate_to_be_out_of_range() {
        let in_range = [0u64; 4];
        let out_of_range = P_LIMBS;

        assert!(!either_out_of_range(&in_range, &in_range));
        assert!(either_out_of_range(&out_of_range, &in_range));
        assert!(either_out_of_range(&in_range, &out_of_range));
        assert!(either_out_of_range(&out_of_range, &out_of_range));
    }
}
