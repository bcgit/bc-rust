//! Branch-free Jacobian-coordinate point arithmetic on the brainpoolP512r1 curve `y^2 = x^3 + Ax +
//! B` (RFC 5639 §3.4). Unlike every NIST curve (`a = -3`) or secp256k1 (`a = 0`) in this crate,
//! brainpool's `A` is a "random" value with neither shortcut available.
//!
//! [`Bp512r1JacobianPoint::add`]'s exceptional-case handling (infinity, same-point, opposite-point)
//! is identical to [`crate::p256_point::P256JacobianPoint::add`] -- see that module's docs for the
//! full derivation and verification methodology, which applies unchanged here, since `generic_add`
//! doesn't depend on `a`. Only [`Bp512r1JacobianPoint::double`] differs: this is the general-`a`
//! doubling formula ("dbl-2007-bl" in the hyperelliptic.org explicit-formulas database): `XX =
//! X1^2`, `YY = Y1^2`, `YYYY = YY^2`, `ZZ = Z1^2`, `S = 2*((X1+YY)^2-XX-YYYY)`, `M = 3*XX +
//! a*ZZ^2`, `T = M^2 - 2*S`, `X3 = T`, `Y3 = M*(S-T) - 8*YYYY`, `Z3 = (Y1+Z1)^2 - YY - ZZ`,
//! verified (not checked in) against the affine doubling law over 500 random on-curve points,
//! using brainpoolP512r1's actual `A`, before being ported here.

use crate::bp512r1::Bp512r1FieldElement;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// The curve coefficient `A` in the field's Montgomery representation (`A * 2^512 mod p`),
/// computed in Python from RFC 5639 §3.4's `A` and pinned against
/// [`Bp512r1FieldElement::from_limbs`] by this module's tests. [`Bp512r1JacobianPoint::double`]
/// needs `A` on every call; converting the plain `A_LIMBS` into Montgomery form each time cost a
/// full field multiplication per doubling.
const A_MONTGOMERY_LIMBS: [u64; 8] = [
    0xda1f8a34ea10c446, 0x14e4957dafa7d283, 0x40b04b724675bbab, 0xcf8f01119e6e87ff,
    0xa5ec30c83f80d1c7, 0x182d0f59f41e8778, 0xb83b84fae2d0850c, 0x5ec4f187227d2a83,
];

/// A point on the brainpoolP512r1 curve in Jacobian coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Bp512r1JacobianPoint {
    /// `X`, the Jacobian `X` coordinate.
    pub x: Bp512r1FieldElement,
    /// `Y`, the Jacobian `Y` coordinate.
    pub y: Bp512r1FieldElement,
    /// `Z`, the Jacobian `Z` coordinate; `Z == 0` denotes the point at infinity.
    pub z: Bp512r1FieldElement,
}

impl Bp512r1JacobianPoint {
    /// The point at infinity, the identity of the curve's group.
    pub const INFINITY: Self = Self {
        x: Bp512r1FieldElement::ONE,
        y: Bp512r1FieldElement::ONE,
        z: Bp512r1FieldElement::ZERO,
    };

    /// Builds a Jacobian point from affine coordinates (`Z = 1`). Does not check that `(x, y)` is
    /// actually on the curve -- see [`crate::bp512r1_sec1`] for that.
    pub fn from_affine(x: Bp512r1FieldElement, y: Bp512r1FieldElement) -> Self {
        Self { x, y, z: Bp512r1FieldElement::ONE }
    }

    /// TRUE iff this is the point at infinity.
    pub fn is_infinity(&self) -> Condition<u64> {
        self.z.is_zero()
    }

    /// Converts to affine `(x, y)` coordinates, or `None` for the point at infinity. Not constant
    /// time: see [`crate::p256_point::P256JacobianPoint::to_affine`]'s docs.
    pub fn to_affine(&self) -> Option<(Bp512r1FieldElement, Bp512r1FieldElement)> {
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
        let a = Bp512r1FieldElement::from_internal_limbs(A_MONTGOMERY_LIMBS);
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
    fn generic_add(&self, other: &Self) -> (Self, Bp512r1FieldElement, Bp512r1FieldElement) {
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

    /// `self + other` for points that are **public**, branching on the exceptional cases instead
    /// of computing every candidate and masking.
    ///
    /// [`Self::add`] must evaluate the doubling candidate on every call, because on secret inputs
    /// it cannot branch on whether the doubling case applies -- that costs a full point doubling
    /// (roughly a third of the addition) on every addition, whether or not it is ever used. This
    /// version pays it only when the operands really are the same point, which for a scalar
    /// multiplier over distinct precomputed multiples is essentially never.
    ///
    /// Restricted to `pub(crate)` and used only by [`crate::bp512r1_wnaf`], whose scalars are
    /// [`crate::bp512r1_scalar::Bp512r1PublicScalar`] and whose points are a signer's public key
    /// and the curve's own base point: every value it branches on is already known to an attacker.
    /// Do not call this on anything derived from a private key or a per-message secret -- the
    /// constant-time [`Self::add`] exists for that, and the scalar type split is what keeps the two
    /// multipliers from being confused for one another.
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
    a: &Bp512r1JacobianPoint,
    b: &Bp512r1JacobianPoint,
) -> Bp512r1JacobianPoint {
    Bp512r1JacobianPoint {
        x: Bp512r1FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.x.internal_limbs(),
            &b.x.internal_limbs(),
        )),
        y: Bp512r1FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.y.internal_limbs(),
            &b.y.internal_limbs(),
        )),
        z: Bp512r1FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.z.internal_limbs(),
            &b.z.internal_limbs(),
        )),
    }
}

fn select_limbs(cond: Condition<u64>, a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let mut out = [0u64; 8];
    ct::conditional_select(cond, a, b, &mut out);
    out
}

// `add_vartime` is `pub(crate)` -- deliberately unreachable from outside the crate, since calling
// it on a secret point would undo the constant-time discipline [`Bp512r1JacobianPoint::add`] exists
// for -- so no integration test can reach it. Its whole contract is that it computes the same group
// law as `add`, differing only in *how* it gets there, so that is what is pinned here: agreement on
// every exceptional case, including the ones a scalar multiplier over distinct precomputed
// multiples essentially never reaches by chance (a point added to itself, and a point added to its
// own negation). QUALITY_AND_STYLE's private-function carve-out applies.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bp512r1_domain::A_LIMBS;

    #[test]
    fn a_montgomery_constant_is_a_in_montgomery_form() {
        assert_eq!(
            Bp512r1FieldElement::from_internal_limbs(A_MONTGOMERY_LIMBS),
            Bp512r1FieldElement::from_limbs(A_LIMBS)
        );
    }
    use crate::bp512r1_domain::{G_X_LIMBS, G_Y_LIMBS};

    #[test]
    fn add_vartime_agrees_with_add_on_every_case() {
        let g = Bp512r1JacobianPoint::from_affine(
            Bp512r1FieldElement::from_limbs(G_X_LIMBS),
            Bp512r1FieldElement::from_limbs(G_Y_LIMBS),
        );
        // G, 2G, -G and the identity cover all four of `add`'s exceptional cases pairwise, plus
        // the ordinary one (e.g. G + 2G).
        let points = [g, g.double(), g.negate(), Bp512r1JacobianPoint::INFINITY];
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
