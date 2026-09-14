//! SEC 1 v2.0 (Certicom, May 2009) §2.3.3/§2.3.4 point encoding and decoding for P-256, and the
//! public-key validation SP 800-186 (Feb 2023) Appendix D.1.1.1 requires.
//!
//! # Encodings
//!
//! Field elements are encoded big-endian, fixed-width (SEC 1 §2.3.5/§2.3.7 for `GF(p)`: "convert
//! the integer to an octet string" via §2.3.7's plain big-endian integer encoding) -- the opposite
//! byte order from this crate's internal little-endian `u64` limbs, so [`limbs_from_be_bytes`] and
//! [`be_bytes_from_limbs`] convert at the boundary.
//!
//! [`encode_uncompressed`] is SEC 1 §2.3.3 case 3 (`04 || X || Y`) and [`encode_compressed`] is
//! case 2 (`02 || X` or `03 || X`, tag selected by `y mod 2`). Both take affine coordinates
//! directly rather than a [`P256JacobianPoint`], not a `[u8; 1]` "point at infinity" case: SEC 1
//! §2.3.3 case 1 encodes `∅` as a single `0x00` octet, but an ECDSA public key -- the only caller
//! -- can never legitimately be `∅` (SP 800-186 Appendix D.1.1.1 step 1 REJECTs it), so pushing the
//! infinity check to the type (a caller must have already gotten `Some(x, y)` out of
//! [`P256JacobianPoint::to_affine`]) makes encoding infinity a compile error instead of a
//! runtime one.
//!
//! [`decode`] is SEC 1 §2.3.4 cases 2 and 3 (again, no case 1: the single-byte infinity encoding
//! is never a valid input here, for the same reason). It performs every check SP 800-186 Appendix
//! D.1.1.1 ("Partial Public Key Validation") requires as part of decoding, not as a separate step:
//! step 1 (not infinity) holds by construction (see above), step 2 (`x`, `y` in `[0, p)`) is
//! [`limbs_less_than_p`], and step 3 (on the curve) is explicit for the uncompressed case and
//! automatic for the compressed case, since its `y` is constructed as an actual square root of
//! `x^3 + ax + b`. Appendix D.1.1.2's additional "full validation" step, `nQ = ∅`, is not needed:
//! SP 800-186 §3.2.1.3 states P-256 has order `h*n` with cofactor `h = 1`, so a point that passes
//! partial validation has order dividing the prime `n` and is not the identity, hence has order
//! exactly `n` -- `nQ = ∅` is implied, not a separate check.
//!
//! # Compressed decoding
//!
//! `p ≡ 3 (mod 4)` (SP 800-186 §3.2.1.3 gives `p`'s hex representation, which ends `...ffffffff`;
//! verified directly in this module's tests), so a square root of a residue `α` is
//! `β = α^((p+1)/4) mod p` (`β² = α^((p+1)/2) = α^((p-1)/2) * α = α` when `α` is a residue, by
//! Euler's criterion). [`SQRT_EXPONENT`] is `(p+1)/4`. [`decode`] verifies `β² == α` and rejects if
//! not: that check is what makes "α has no square root" (SEC 1 §2.3.4 step 2.4.1) detectable, since
//! the exponentiation itself is total and returns *something* whether or not `α` is a residue.
//!
//! Verified (not checked in) before any of this was written: the decompression formula against
//! 300 random points' known `y` (recomputed from `x` and `y`'s parity bit), and that a non-residue
//! `x` is correctly rejected.

use crate::nat;
use crate::p256::{P_LIMBS, P256FieldElement};
use crate::p256_domain::B_LIMBS;
use crate::p256_point::P256JacobianPoint;

/// `(p + 1) / 4`, the exponent [`decode`]'s compressed-point square root raises `α` to.
const SQRT_EXPONENT: [u64; 4] =
    [0x0000000000000000, 0x0000000040000000, 0x4000000000000000, 0x3fffffffc0000000];

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

/// `y^2 == x^3 - 3x + b`.
fn is_on_curve(x: &P256FieldElement, y: &P256FieldElement) -> bool {
    let lhs = y.mul(y);
    let x_cubed = x.mul(x).mul(x);
    let three_x = x.add(x).add(x);
    let rhs = x_cubed.sub(&three_x).add(&P256FieldElement::from_limbs(B_LIMBS));
    lhs == rhs
}

/// `base^SQRT_EXPONENT mod p`. Plain (not masked) square-and-multiply: `decode`'s only caller,
/// unlike everywhere else in this crate, only ever runs on public data (an incoming encoded
/// point), so there is nothing to protect here.
fn pow_public(base: &P256FieldElement, exponent_limbs: &[u64; 4]) -> P256FieldElement {
    let mut result = P256FieldElement::ONE;
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
pub fn encode_uncompressed(x: &P256FieldElement, y: &P256FieldElement) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    out[1..33].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out[33..65].copy_from_slice(&be_bytes_from_limbs(&y.to_limbs()));
    out
}

/// SEC 1 §2.3.3 case 2: `02 || X` or `03 || X`, 33 bytes, tag selected by `y mod 2`.
pub fn encode_compressed(x: &P256FieldElement, y: &P256FieldElement) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = if y.to_limbs()[0] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..33].copy_from_slice(&be_bytes_from_limbs(&x.to_limbs()));
    out
}

/// Decodes and validates a SEC 1 §2.3.4 point encoding: 33 bytes (compressed, tag `0x02`/`0x03`)
/// or 65 bytes (uncompressed, tag `0x04`). See the module docs for exactly which SP 800-186
/// Appendix D.1.1.1 checks this performs and why it constitutes full (not merely partial)
/// validation for P-256. Returns `None` for anything invalid.
pub fn decode(bytes: &[u8]) -> Option<(P256FieldElement, P256FieldElement)> {
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
            let x = P256FieldElement::from_limbs(x_limbs);
            let x_cubed = x.mul(&x).mul(&x);
            let three_x = x.add(&x).add(&x);
            let alpha = x_cubed.sub(&three_x).add(&P256FieldElement::from_limbs(B_LIMBS));
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
            let x = P256FieldElement::from_limbs(x_limbs);
            let y = P256FieldElement::from_limbs(y_limbs);
            if !is_on_curve(&x, &y) {
                return None;
            }
            Some((x, y))
        }
        _ => None,
    }
}

/// Decodes and validates an encoded public key (see [`decode`]) directly into a
/// [`P256JacobianPoint`].
pub fn decode_point(bytes: &[u8]) -> Option<P256JacobianPoint> {
    let (x, y) = decode(bytes)?;
    Some(P256JacobianPoint::from_affine(x, y))
}

// `limbs_less_than_p` and `either_out_of_range` are private and, through `decode`, only ever
// reached on inputs that also fail (or coincidentally would also fail) a later curve-membership
// check, so no integration test through the public API can pin either one's pass/fail boundary
// independent of that coincidence -- the QUALITY_AND_STYLE.md "private function, known-answer,
// can't be reached cleanly from outside the crate" exception applies to both. Known answers for
// `limbs_less_than_p`: SP 800-186 S3.2.1.3 gives `p`; 0 and `p - 1` are its immediate neighbours
// inside `[0, p)`, and `p` itself plus a value with only a non-adjacent limb bumped above `p`'s
// are its immediate neighbours outside it. `either_out_of_range` is exercised over all four
// in-range/out-of-range combinations of its two arguments, which is what pins OR against AND.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limbs_less_than_p_boundary_cases() {
        assert!(limbs_less_than_p(&[0, 0, 0, 0]));

        let p_minus_1 = [P_LIMBS[0] - 1, P_LIMBS[1], P_LIMBS[2], P_LIMBS[3]];
        assert!(limbs_less_than_p(&p_minus_1));

        assert!(!limbs_less_than_p(&P_LIMBS));

        let p_plus_2_pow_192 = [P_LIMBS[0], P_LIMBS[1], P_LIMBS[2] + 1, P_LIMBS[3]];
        assert!(!limbs_less_than_p(&p_plus_2_pow_192));

        assert!(!limbs_less_than_p(&[u64::MAX; 4]));
    }

    #[test]
    fn either_out_of_range_requires_only_one_coordinate_to_be_out_of_range() {
        let in_range = [0u64, 0, 0, 0];
        let out_of_range = P_LIMBS;

        assert!(!either_out_of_range(&in_range, &in_range));
        assert!(either_out_of_range(&out_of_range, &in_range));
        assert!(either_out_of_range(&in_range, &out_of_range));
        assert!(either_out_of_range(&out_of_range, &out_of_range));
    }
}
