//! Branch-free Jacobian-coordinate point arithmetic on the P-521 curve `y^2 = x^3 - 3x + b`.
//!
//! Identical in shape to [`crate::p256_point`]/[`crate::p384_point`] -- see
//! [`crate::p256_point`]'s docs for the full derivation and verification methodology, which
//! applies unchanged here (P-521 also has `a = -3` and cofactor `h = 1` per SP 800-186 §3.2.1.5).

use crate::p521::P521FieldElement;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// A point on the P-521 curve in Jacobian coordinates.
#[derive(Clone, Copy, Debug)]
pub struct P521JacobianPoint {
    /// `X`, the Jacobian `X` coordinate.
    pub x: P521FieldElement,
    /// `Y`, the Jacobian `Y` coordinate.
    pub y: P521FieldElement,
    /// `Z`, the Jacobian `Z` coordinate; `Z == 0` denotes the point at infinity.
    pub z: P521FieldElement,
}

impl P521JacobianPoint {
    /// The point at infinity, the identity of the curve's group.
    pub const INFINITY: Self =
        Self { x: P521FieldElement::ONE, y: P521FieldElement::ONE, z: P521FieldElement::ZERO };

    /// Builds a Jacobian point from affine coordinates (`Z = 1`). Does not check that `(x, y)` is
    /// actually on the curve -- see [`crate::p521_sec1`] for that.
    pub fn from_affine(x: P521FieldElement, y: P521FieldElement) -> Self {
        Self { x, y, z: P521FieldElement::ONE }
    }

    /// TRUE iff this is the point at infinity.
    pub fn is_infinity(&self) -> Condition<u64> {
        self.z.is_zero()
    }

    /// Converts to affine `(x, y)` coordinates, or `None` for the point at infinity. Not constant
    /// time: see [`crate::p256_point::P256JacobianPoint::to_affine`]'s docs.
    pub fn to_affine(&self) -> Option<(P521FieldElement, P521FieldElement)> {
        if self.is_infinity().to_bool() {
            return None;
        }
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.mul(&z_inv);
        let z_inv3 = z_inv2.mul(&z_inv);
        Some((self.x.mul(&z_inv2), self.y.mul(&z_inv3)))
    }

    /// `-self`: negating the `Y` coordinate.
    pub fn negate(&self) -> Self {
        Self { x: self.x, y: self.y.negate(), z: self.z }
    }

    /// `2 * self`, via the curve's `a = -3` Jacobian doubling shortcut. See
    /// [`crate::p256_point::P256JacobianPoint::double`]'s docs.
    pub fn double(&self) -> Self {
        let y1_squared = self.y.mul(&self.y);
        let t = y1_squared.mul(&y1_squared);
        let z1_squared = self.z.mul(&self.z);
        let t1 = self.x.sub(&z1_squared);
        let m = self.x.add(&z1_squared);
        let m = m.mul(&t1);
        let m = m.add(&m).add(&m);
        let s = y1_squared.mul(&self.x);
        let s = s.add(&s).add(&s).add(&s);
        let t8 = t.add(&t).add(&t).add(&t).add(&t).add(&t).add(&t).add(&t);
        let x3 = m.mul(&m).sub(&s).sub(&s);
        let y3 = s.sub(&x3);
        let y3 = y3.mul(&m).sub(&t8);
        let z3 = self.y.add(&self.y).mul(&self.z);
        Self { x: x3, y: y3, z: z3 }
    }

    /// The generic (`self != ±other`, neither infinite) Jacobian addition formula, plus the `H`
    /// and `R` intermediates [`Self::add`] uses to detect the exceptional cases. See
    /// [`crate::p256_point::P256JacobianPoint`]'s private `generic_add`'s docs.
    fn generic_add(&self, other: &Self) -> (Self, P521FieldElement, P521FieldElement) {
        let z2_sq = other.z.mul(&other.z);
        let u1 = self.x.mul(&z2_sq);
        let s1 = self.y.mul(&other.z).mul(&z2_sq);
        let z1_sq = self.z.mul(&self.z);
        let u2 = other.x.mul(&z1_sq);
        let s2 = other.y.mul(&self.z).mul(&z1_sq);

        let h = u1.sub(&u2);
        let r = s1.sub(&s2);

        let h_squared = h.mul(&h);
        let g = h_squared.mul(&h);
        let v = h_squared.mul(&u1);
        let g_neg = g.negate();
        let acc = s1.mul(&g_neg);
        let g2 = g_neg.add(&v).add(&v);
        let x3 = r.mul(&r).sub(&g2);
        let y3_temp = v.sub(&x3);
        let y3 = acc.add(&y3_temp.mul(&r));
        let z3 = h.mul(&self.z).mul(&other.z);

        (Self { x: x3, y: y3, z: z3 }, h, r)
    }

    /// `self + other`, branch-free per [`crate::p256_point::P256JacobianPoint::add`]'s docs.
    pub fn add(&self, other: &Self) -> Self {
        let self_is_infinity = self.is_infinity();
        let other_is_infinity = other.is_infinity();

        let (generic, h, r) = self.generic_add(other);
        let h_is_zero = h.is_zero();
        let r_is_zero = r.is_zero();
        let is_same_point = h_is_zero & r_is_zero;
        // Dropping the `!` here (making `is_opposite_point` collapse onto `is_same_point`) is an
        // accepted mutant, not a bug: when `h == 0`, `generic_add`'s own `z3 = h*self.z*other.z`
        // is already `0` regardless of `r`, so `generic` is already infinity-representing in the
        // true opposite-point case (`h == 0, r != 0`) even without this override selecting
        // `Self::INFINITY` explicitly.
        let is_opposite_point = h_is_zero & !r_is_zero;
        let doubled = self.double();

        let mut result = generic;
        result = select_point(is_opposite_point, &Self::INFINITY, &result);
        result = select_point(is_same_point, &doubled, &result);
        result = select_point(self_is_infinity, other, &result);
        result = select_point(other_is_infinity, self, &result);
        result
    }

    /// `self + other` for points that are **public**, branching on the exceptional cases instead
    /// of computing every candidate and masking.
    ///
    /// [`Self::add`] must evaluate the doubling candidate on every call, because on secret inputs
    /// it cannot branch on whether the doubling case applies -- that costs a full point doubling
    /// (roughly a third of the addition) on every addition, whether or not it is ever used. This
    /// version pays it only when the operands really are the same point, which for a scalar
    /// multiplier over distinct precomputed multiples is essentially never.
    ///
    /// Restricted to `pub(crate)` and used only by [`crate::p521_wnaf`], whose scalars are
    /// [`crate::p521_scalar::P521PublicScalar`] and whose points are a signer's public key and
    /// the curve's own base point: every value it branches on is already known to an attacker. Do
    /// not call this on anything derived from a private key or a per-message secret -- the
    /// constant-time [`Self::add`] exists for that, and the scalar type split is what keeps the
    /// two multipliers from being confused for one another.
    pub(crate) fn add_vartime(&self, other: &Self) -> Self {
        if self.is_infinity().to_bool() {
            return *other;
        }
        if other.is_infinity().to_bool() {
            return *self;
        }

        let (generic, h, r) = self.generic_add(other);
        if h.is_zero().to_bool() {
            // Same affine x: either the same point (double it) or its negation (sum is infinity).
            return if r.is_zero().to_bool() { self.double() } else { Self::INFINITY };
        }
        generic
    }
}

fn select_point(
    cond: Condition<u64>,
    a: &P521JacobianPoint,
    b: &P521JacobianPoint,
) -> P521JacobianPoint {
    P521JacobianPoint {
        x: P521FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.x.internal_limbs(),
            &b.x.internal_limbs(),
        )),
        y: P521FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.y.internal_limbs(),
            &b.y.internal_limbs(),
        )),
        z: P521FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.z.internal_limbs(),
            &b.z.internal_limbs(),
        )),
    }
}

fn select_limbs(cond: Condition<u64>, a: &[u64; 9], b: &[u64; 9]) -> [u64; 9] {
    let mut out = [0u64; 9];
    ct::conditional_select(cond, a, b, &mut out);
    out
}

// `add_vartime` is `pub(crate)` -- deliberately unreachable from outside the crate, since calling
// it on a secret point would undo the constant-time discipline [`P521JacobianPoint::add`] exists
// for -- so no integration test can reach it. Its whole contract is that it computes the same group
// law as `add`, differing only in *how* it gets there, so that is what is pinned here: agreement on
// every exceptional case, including the ones a scalar multiplier over distinct precomputed
// multiples essentially never reaches by chance (a point added to itself, and a point added to its
// own negation). QUALITY_AND_STYLE's private-function carve-out applies.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::p521_domain::{G_X_LIMBS, G_Y_LIMBS};

    #[test]
    fn add_vartime_agrees_with_add_on_every_case() {
        let g = P521JacobianPoint::from_affine(
            P521FieldElement::from_limbs(G_X_LIMBS),
            P521FieldElement::from_limbs(G_Y_LIMBS),
        );
        // G, 2G, -G and the identity cover all four of `add`'s exceptional cases pairwise, plus
        // the ordinary one (e.g. G + 2G).
        let points = [g, g.double(), g.negate(), P521JacobianPoint::INFINITY];
        for a in points {
            for b in points {
                assert_eq!(
                    a.add_vartime(&b).to_affine(),
                    a.add(&b).to_affine(),
                    "add_vartime disagrees with add"
                );
            }
        }
    }
}
