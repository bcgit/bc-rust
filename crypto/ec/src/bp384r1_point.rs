//! Branch-free Jacobian-coordinate point arithmetic on the brainpoolP384r1 curve `y^2 = x^3 + Ax +
//! B` (RFC 5639 §3.4). Unlike every NIST curve (`a = -3`) or secp256k1 (`a = 0`) in this crate,
//! brainpool's `A` is a "random" value with neither shortcut available.
//!
//! [`Bp384r1JacobianPoint::add`]'s exceptional-case handling (infinity, same-point, opposite-point)
//! is identical to [`crate::p256_point::P256JacobianPoint::add`] -- see that module's docs for the
//! full derivation and verification methodology, which applies unchanged here, since `generic_add`
//! doesn't depend on `a`. Only [`Bp384r1JacobianPoint::double`] differs: this is the general-`a`
//! doubling formula ("dbl-2007-bl" in the hyperelliptic.org explicit-formulas database): `XX =
//! X1^2`, `YY = Y1^2`, `YYYY = YY^2`, `ZZ = Z1^2`, `S = 2*((X1+YY)^2-XX-YYYY)`, `M = 3*XX +
//! a*ZZ^2`, `T = M^2 - 2*S`, `X3 = T`, `Y3 = M*(S-T) - 8*YYYY`, `Z3 = (Y1+Z1)^2 - YY - ZZ`,
//! verified (not checked in) against the affine doubling law over 500 random on-curve points,
//! using brainpoolP384r1's actual `A`, before being ported here.

use crate::bp384r1::Bp384r1FieldElement;
use crate::bp384r1_domain::A_LIMBS;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// A point on the brainpoolP384r1 curve in Jacobian coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Bp384r1JacobianPoint {
    /// `X`, the Jacobian `X` coordinate.
    pub x: Bp384r1FieldElement,
    /// `Y`, the Jacobian `Y` coordinate.
    pub y: Bp384r1FieldElement,
    /// `Z`, the Jacobian `Z` coordinate; `Z == 0` denotes the point at infinity.
    pub z: Bp384r1FieldElement,
}

impl Bp384r1JacobianPoint {
    /// The point at infinity, the identity of the curve's group.
    pub const INFINITY: Self = Self {
        x: Bp384r1FieldElement::ONE,
        y: Bp384r1FieldElement::ONE,
        z: Bp384r1FieldElement::ZERO,
    };

    /// Builds a Jacobian point from affine coordinates (`Z = 1`). Does not check that `(x, y)` is
    /// actually on the curve -- see [`crate::bp384r1_sec1`] for that.
    pub fn from_affine(x: Bp384r1FieldElement, y: Bp384r1FieldElement) -> Self {
        Self { x, y, z: Bp384r1FieldElement::ONE }
    }

    /// TRUE iff this is the point at infinity.
    pub fn is_infinity(&self) -> Condition<u64> {
        self.z.is_zero()
    }

    /// Converts to affine `(x, y)` coordinates, or `None` for the point at infinity. Not constant
    /// time: see [`crate::p256_point::P256JacobianPoint::to_affine`]'s docs.
    pub fn to_affine(&self) -> Option<(Bp384r1FieldElement, Bp384r1FieldElement)> {
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

    /// `2 * self`, via the general-`a` doubling formula ("dbl-2007-bl") described in the module
    /// docs.
    pub fn double(&self) -> Self {
        let a = Bp384r1FieldElement::from_limbs(A_LIMBS);
        let xx = self.x.mul(&self.x); // XX = X1^2
        let yy = self.y.mul(&self.y); // YY = Y1^2
        let yyyy = yy.mul(&yy); // YYYY = YY^2
        let zz = self.z.mul(&self.z); // ZZ = Z1^2
        let x1_plus_yy = self.x.add(&yy);
        let s = x1_plus_yy.mul(&x1_plus_yy).sub(&xx).sub(&yyyy);
        let s = s.add(&s); // S = 2*((X1+YY)^2 - XX - YYYY)
        let m = xx.add(&xx).add(&xx).add(&a.mul(&zz.mul(&zz))); // M = 3*XX + a*ZZ^2
        let t = m.mul(&m).sub(&s).sub(&s); // T = M^2 - 2*S
        let x3 = t;
        let yyyy8 =
            yyyy.add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy).add(&yyyy);
        let y3 = m.mul(&s.sub(&t)).sub(&yyyy8); // Y3 = M*(S-T) - 8*YYYY
        let y1_plus_z1 = self.y.add(&self.z);
        let z3 = y1_plus_z1.mul(&y1_plus_z1).sub(&yy).sub(&zz); // Z3 = (Y1+Z1)^2 - YY - ZZ
        Self { x: x3, y: y3, z: z3 }
    }

    /// The generic (`self != ±other`, neither infinite) Jacobian addition formula, plus the `H`
    /// and `R` intermediates [`Self::add`] uses to detect the exceptional cases. See
    /// [`crate::p256_point::P256JacobianPoint`]'s private `generic_add`'s docs -- this formula
    /// doesn't depend on `a` at all, so it's identical to the NIST curves' version.
    fn generic_add(&self, other: &Self) -> (Self, Bp384r1FieldElement, Bp384r1FieldElement) {
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
    a: &Bp384r1JacobianPoint,
    b: &Bp384r1JacobianPoint,
) -> Bp384r1JacobianPoint {
    Bp384r1JacobianPoint {
        x: Bp384r1FieldElement::from_limbs(select_limbs(cond, &a.x.to_limbs(), &b.x.to_limbs())),
        y: Bp384r1FieldElement::from_limbs(select_limbs(cond, &a.y.to_limbs(), &b.y.to_limbs())),
        z: Bp384r1FieldElement::from_limbs(select_limbs(cond, &a.z.to_limbs(), &b.z.to_limbs())),
    }
}

fn select_limbs(cond: Condition<u64>, a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
    let mut out = [0u64; 6];
    ct::conditional_select(cond, a, b, &mut out);
    out
}
