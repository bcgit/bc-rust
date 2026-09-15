//! Branch-free Jacobian-coordinate point arithmetic on the secp256k1 curve `y^2 = x^3 + 7` (`a =
//! 0`, unlike every NIST curve in this crate).
//!
//! [`P256K1JacobianPoint::add`]'s exceptional-case handling (infinity, same-point, opposite-point)
//! is identical to [`crate::p256_point::P256JacobianPoint::add`] -- see that module's docs for the
//! full derivation and verification methodology, which applies unchanged here. Only
//! [`P256K1JacobianPoint::double`] differs, since it cannot use the `a = -3` shortcut: this is the
//! standard `a = 0` doubling formula ("dbl-2009-l" in the hyperelliptic.org explicit-formulas
//! database: `A = X1^2`, `B = Y1^2`, `C = B^2`, `D = 2*((X1+B)^2-A-C)`, `E = 3*A`, `F = E^2`, `X3 =
//! F-2*D`, `Y3 = E*(D-X3)-8*C`, `Z3 = 2*Y1*Z1`), verified (not checked in) against the affine
//! doubling law over many random on-curve points before being ported here.

use crate::p256k1::P256K1FieldElement;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// A point on the secp256k1 curve in Jacobian coordinates.
#[derive(Clone, Copy, Debug)]
pub struct P256K1JacobianPoint {
    /// `X`, the Jacobian `X` coordinate.
    pub x: P256K1FieldElement,
    /// `Y`, the Jacobian `Y` coordinate.
    pub y: P256K1FieldElement,
    /// `Z`, the Jacobian `Z` coordinate; `Z == 0` denotes the point at infinity.
    pub z: P256K1FieldElement,
}

impl P256K1JacobianPoint {
    /// The point at infinity, the identity of the curve's group.
    pub const INFINITY: Self = Self {
        x: P256K1FieldElement::ONE,
        y: P256K1FieldElement::ONE,
        z: P256K1FieldElement::ZERO,
    };

    /// Builds a Jacobian point from affine coordinates (`Z = 1`). Does not check that `(x, y)` is
    /// actually on the curve -- see [`crate::p256k1_sec1`] for that.
    pub fn from_affine(x: P256K1FieldElement, y: P256K1FieldElement) -> Self {
        Self { x, y, z: P256K1FieldElement::ONE }
    }

    /// TRUE iff this is the point at infinity.
    pub fn is_infinity(&self) -> Condition<u64> {
        self.z.is_zero()
    }

    /// Converts to affine `(x, y)` coordinates, or `None` for the point at infinity. Not constant
    /// time: see [`crate::p256_point::P256JacobianPoint::to_affine`]'s docs.
    pub fn to_affine(&self) -> Option<(P256K1FieldElement, P256K1FieldElement)> {
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

    /// `2 * self`, via the `a = 0` doubling formula ("dbl-2009-l") described in the module docs.
    pub fn double(&self) -> Self {
        let a = self.x.mul(&self.x); // A = X1^2
        let b = self.y.mul(&self.y); // B = Y1^2
        let c = b.mul(&b); // C = B^2
        let x1_plus_b = self.x.add(&b);
        let d = x1_plus_b.mul(&x1_plus_b).sub(&a).sub(&c);
        let d = d.add(&d); // D = 2*((X1+B)^2 - A - C)
        let e = a.add(&a).add(&a); // E = 3*A
        let f = e.mul(&e); // F = E^2
        let x3 = f.sub(&d).sub(&d); // X3 = F - 2*D
        let c8 = c.add(&c).add(&c).add(&c).add(&c).add(&c).add(&c).add(&c); // 8*C
        let y3 = e.mul(&d.sub(&x3)).sub(&c8); // Y3 = E*(D-X3) - 8*C
        let z3 = self.y.add(&self.y).mul(&self.z); // Z3 = 2*Y1*Z1
        Self { x: x3, y: y3, z: z3 }
    }

    /// The generic (`self != ±other`, neither infinite) Jacobian addition formula, plus the `H`
    /// and `R` intermediates [`Self::add`] uses to detect the exceptional cases. See
    /// [`crate::p256_point::P256JacobianPoint`]'s private `generic_add`'s docs -- this formula
    /// doesn't depend on `a` at all, so it's identical to the NIST curves' version.
    fn generic_add(&self, other: &Self) -> (Self, P256K1FieldElement, P256K1FieldElement) {
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
        // `Self::INFINITY` explicitly -- see `crate::p521_point`'s identical case for the full
        // argument.
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
    a: &P256K1JacobianPoint,
    b: &P256K1JacobianPoint,
) -> P256K1JacobianPoint {
    P256K1JacobianPoint {
        x: P256K1FieldElement::from_limbs(select_limbs(cond, &a.x.to_limbs(), &b.x.to_limbs())),
        y: P256K1FieldElement::from_limbs(select_limbs(cond, &a.y.to_limbs(), &b.y.to_limbs())),
        z: P256K1FieldElement::from_limbs(select_limbs(cond, &a.z.to_limbs(), &b.z.to_limbs())),
    }
}

fn select_limbs(cond: Condition<u64>, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    ct::conditional_select(cond, a, b, &mut out);
    out
}
