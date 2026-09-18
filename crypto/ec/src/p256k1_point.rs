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

    /// `self + other` for an `other` given in **affine** coordinates (`Z2 = 1`), or the identity
    /// when `other_is_infinity` is TRUE (`x2`/`y2` are then ignored). The same group law and the
    /// same branch-free discipline as [`Self::add`] -- generic-add and doubling candidates computed
    /// unconditionally, the exceptional cases masked in -- but with `Z2 = 1` the generic formula
    /// simplifies: `U1 = X1`, `S1 = Y1` and `Z3 = H * Z1`, which drops five of its sixteen field
    /// multiplications. The fixed-base comb multiplier adds a table entry to its accumulator on
    /// every round, and every table entry is affine or the identity, so it is the caller this
    /// exists for; `pub(crate)` because a caller has to know its point really has `Z = 1`.
    pub(crate) fn add_affine(
        &self,
        x2: &P256K1FieldElement,
        y2: &P256K1FieldElement,
        other_is_infinity: Condition<u64>,
    ) -> Self {
        let self_is_infinity = self.is_infinity();

        // The generic mixed addition, computed unconditionally: `U1 = X1`, `S1 = Y1`.
        let z1_sq = self.z.mul(&self.z);
        let u2 = x2.mul(&z1_sq);
        let s2 = y2.mul(&self.z).mul(&z1_sq);
        let h = self.x.sub(&u2); // U1 - U2
        let r = self.y.sub(&s2); // S1 - S2
        let h_squared = h.mul(&h);
        let g = h_squared.mul(&h); // H^3
        let v = h_squared.mul(&self.x); // H^2 * U1
        let g_neg = g.negate();
        let acc = self.y.mul(&g_neg); // -S1 * H^3
        let g2 = g_neg.add(&v).add(&v); // 2V - H^3
        let x3 = r.mul(&r).sub(&g2); // R^2 + H^3 - 2V
        let y3 = acc.add(&v.sub(&x3).mul(&r)); // -S1*H^3 + (V - X3)*R
        let z3 = h.mul(&self.z); // H * Z1 * Z2 with Z2 = 1
        let generic = Self { x: x3, y: y3, z: z3 };

        let h_is_zero = h.is_zero();
        let r_is_zero = r.is_zero();
        let is_same_point = h_is_zero & r_is_zero;
        let is_opposite_point = h_is_zero & !r_is_zero;
        let doubled = self.double();
        let other = Self { x: *x2, y: *y2, z: P256K1FieldElement::ONE };

        // Same priority order as `add`: the identity cases override everything else.
        let mut result = generic;
        result = select_point(is_opposite_point, &Self::INFINITY, &result);
        result = select_point(is_same_point, &doubled, &result);
        result = select_point(self_is_infinity, &other, &result);
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
    /// Restricted to `pub(crate)` and used only by [`crate::p256k1_wnaf`], whose scalars are
    /// [`crate::p256k1_scalar::P256K1PublicScalar`] and whose points are a signer's public key and
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
    a: &P256K1JacobianPoint,
    b: &P256K1JacobianPoint,
) -> P256K1JacobianPoint {
    P256K1JacobianPoint {
        x: P256K1FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.x.internal_limbs(),
            &b.x.internal_limbs(),
        )),
        y: P256K1FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.y.internal_limbs(),
            &b.y.internal_limbs(),
        )),
        z: P256K1FieldElement::from_internal_limbs(select_limbs(
            cond,
            &a.z.internal_limbs(),
            &b.z.internal_limbs(),
        )),
    }
}

fn select_limbs(cond: Condition<u64>, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    ct::conditional_select(cond, a, b, &mut out);
    out
}

// `add_vartime` is `pub(crate)` -- deliberately unreachable from outside the crate, since calling
// it on a secret point would undo the constant-time discipline [`P256K1JacobianPoint::add`] exists
// for -- so no integration test can reach it. Its whole contract is that it computes the same group
// law as `add`, differing only in *how* it gets there, so that is what is pinned here: agreement on
// every exceptional case, including the ones a scalar multiplier over distinct precomputed
// multiples essentially never reaches by chance (a point added to itself, and a point added to its
// own negation). QUALITY_AND_STYLE's private-function carve-out applies.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256k1_domain::{G_X_LIMBS, G_Y_LIMBS};

    #[test]
    fn add_affine_agrees_with_add_on_every_case() {
        let g = P256K1JacobianPoint::from_affine(
            P256K1FieldElement::from_limbs(G_X_LIMBS),
            P256K1FieldElement::from_limbs(G_Y_LIMBS),
        );
        // A non-canonical-Z representation of G as well: `add_affine` reads `self.z`, so `self`
        // must not be assumed affine even though `other` is.
        let z = P256K1FieldElement::from_limbs(G_Y_LIMBS);
        let z2 = z.mul(&z);
        let scaled_g = P256K1JacobianPoint { x: g.x.mul(&z2), y: g.y.mul(&z2.mul(&z)), z };
        let selves = [g, g.double(), g.negate(), P256K1JacobianPoint::INFINITY, scaled_g];
        let others = [g, g.double(), g.negate()];
        for a in selves {
            for b in others {
                let (bx, by) = b.to_affine().unwrap();
                assert_eq!(
                    a.add_affine(&bx, &by, Condition::<u64>::FALSE).to_affine(),
                    a.add(&b).to_affine(),
                    "add_affine disagrees with add"
                );
            }
            // The identity flag must win regardless of the coordinates passed alongside it.
            assert_eq!(
                a.add_affine(&g.x, &g.y, Condition::<u64>::TRUE).to_affine(),
                a.to_affine(),
                "add_affine with the identity flag must return self"
            );
        }
    }

    #[test]
    fn add_vartime_agrees_with_add_on_every_case() {
        let g = P256K1JacobianPoint::from_affine(
            P256K1FieldElement::from_limbs(G_X_LIMBS),
            P256K1FieldElement::from_limbs(G_Y_LIMBS),
        );
        // G, 2G, -G and the identity cover all four of `add`'s exceptional cases pairwise, plus
        // the ordinary one (e.g. G + 2G).
        let points = [g, g.double(), g.negate(), P256K1JacobianPoint::INFINITY];
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
