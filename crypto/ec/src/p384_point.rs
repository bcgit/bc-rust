//! Branch-free Jacobian-coordinate point arithmetic on the P-384 curve `y^2 = x^3 - 3x + b`.
//!
//! Identical in shape to [`crate::p256_point`] (same `a = -3` formulas, same branch-free
//! exceptional-case handling); see that module's docs for the full derivation and verification
//! methodology, which applies unchanged here (P-384 also has `a = -3` and cofactor `h = 1` per SP
//! 800-186 §3.2.1.4).

use crate::p384::P384FieldElement;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// A point on the P-384 curve in Jacobian coordinates.
#[derive(Clone, Copy, Debug)]
pub struct P384JacobianPoint {
    /// `X`, the Jacobian `X` coordinate.
    pub x: P384FieldElement,
    /// `Y`, the Jacobian `Y` coordinate.
    pub y: P384FieldElement,
    /// `Z`, the Jacobian `Z` coordinate; `Z == 0` denotes the point at infinity.
    pub z: P384FieldElement,
}

impl P384JacobianPoint {
    /// The point at infinity, the identity of the curve's group.
    pub const INFINITY: Self =
        Self { x: P384FieldElement::ONE, y: P384FieldElement::ONE, z: P384FieldElement::ZERO };

    /// Builds a Jacobian point from affine coordinates (`Z = 1`). Does not check that `(x, y)` is
    /// actually on the curve -- see [`crate::p384_sec1`] for that.
    pub fn from_affine(x: P384FieldElement, y: P384FieldElement) -> Self {
        Self { x, y, z: P384FieldElement::ONE }
    }

    /// TRUE iff this is the point at infinity.
    pub fn is_infinity(&self) -> Condition<u64> {
        self.z.is_zero()
    }

    /// Converts to affine `(x, y)` coordinates, or `None` for the point at infinity. Not constant
    /// time: see [`crate::p256_point::P256JacobianPoint::to_affine`]'s docs.
    pub fn to_affine(&self) -> Option<(P384FieldElement, P384FieldElement)> {
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
    fn generic_add(&self, other: &Self) -> (Self, P384FieldElement, P384FieldElement) {
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
        let is_opposite_point = h_is_zero & !r_is_zero;
        let doubled = self.double();

        let mut result = generic;
        result = select_point(is_opposite_point, &Self::INFINITY, &result);
        result = select_point(is_same_point, &doubled, &result);
        result = select_point(self_is_infinity, other, &result);
        result = select_point(other_is_infinity, self, &result);
        result
    }
}

fn select_point(
    cond: Condition<u64>,
    a: &P384JacobianPoint,
    b: &P384JacobianPoint,
) -> P384JacobianPoint {
    P384JacobianPoint {
        x: P384FieldElement::from_limbs(select_limbs(cond, &a.x.to_limbs(), &b.x.to_limbs())),
        y: P384FieldElement::from_limbs(select_limbs(cond, &a.y.to_limbs(), &b.y.to_limbs())),
        z: P384FieldElement::from_limbs(select_limbs(cond, &a.z.to_limbs(), &b.z.to_limbs())),
    }
}

fn select_limbs(cond: Condition<u64>, a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
    let mut out = [0u64; 6];
    ct::conditional_select(cond, a, b, &mut out);
    out
}
