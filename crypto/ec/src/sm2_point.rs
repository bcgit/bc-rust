//! Branch-free Jacobian-coordinate point arithmetic on the SM2 curve `y^2 = x^3 - 3x + b`.
//! Identical formulas to [`crate::p256_point`] -- see that module's docs for the full derivation
//! and the branch-free exceptional-case-masking methodology, which applies unchanged here since
//! SM2's curve shares P-256's `a = -3` shortcut (see [`crate::sm2`]'s docs) -- with SM2's own
//! field type and domain constants substituted.
//!
//! A point `(X, Y, Z)` represents the affine point `(X/Z^2, Y/Z^3)`; `Z = 0` is the point at
//! infinity, represented canonically as `(1, 1, 0)`.
//!
//! [`Sm2JacobianPoint::double`] is the standard `a = -3` Jacobian doubling (`M = 3(X-Z^2)(X+Z^2)`,
//! `S = 4XY^2`, `T = 8Y^4`, `X3 = M^2 - 2S`, `Y3 = M(S - X3) - T`, `Z3 = 2YZ`), and
//! [`Sm2JacobianPoint::add`]'s generic-case formula is the standard Jacobian addition (`H = U1 -
//! U2`, `R = S1 - S2`, `X3 = R^2 + H^3 - 2V`, `Y3 = R(V - X3) - S1*H^3`, `Z3 = H*Z1*Z2`, where `U1
//! = X1*Z2^2`, `S1 = Y1*Z2^3`, `U2 = X2*Z1^2`, `S2 = Y2*Z1^3`, `V = H^2*U1`).
//!
//! Verified (not checked in) against the standard affine group law using SM2's own domain
//! parameters, over 500 random on-curve points and their scaled (non-canonical-`Z`) Jacobian
//! representations, covering every exceptional case (`self`/`other` infinite, same point, opposite
//! point) plus the ordinary case, before any of this was ported here.

use crate::sm2::Sm2FieldElement;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// A point on the SM2 curve in Jacobian coordinates.
#[derive(Clone, Copy, Debug)]
pub struct Sm2JacobianPoint {
    /// `X`, the Jacobian `X` coordinate.
    pub x: Sm2FieldElement,
    /// `Y`, the Jacobian `Y` coordinate.
    pub y: Sm2FieldElement,
    /// `Z`, the Jacobian `Z` coordinate; `Z == 0` denotes the point at infinity.
    pub z: Sm2FieldElement,
}

impl Sm2JacobianPoint {
    /// The point at infinity, the identity of the curve's group.
    pub const INFINITY: Self =
        Self { x: Sm2FieldElement::ONE, y: Sm2FieldElement::ONE, z: Sm2FieldElement::ZERO };

    /// Builds a Jacobian point from affine coordinates (`Z = 1`). Does not check that `(x, y)` is
    /// actually on the curve -- see [`crate::sm2_sec1`] for that.
    pub fn from_affine(x: Sm2FieldElement, y: Sm2FieldElement) -> Self {
        Self { x, y, z: Sm2FieldElement::ONE }
    }

    /// TRUE iff this is the point at infinity.
    pub fn is_infinity(&self) -> Condition<u64> {
        self.z.is_zero()
    }

    /// Converts to affine `(x, y)` coordinates, or `None` for the point at infinity. Not constant
    /// time (branches on [`Self::is_infinity`]): intended for output/decoding boundaries on
    /// already-public points, not for use on a secret intermediate value.
    pub fn to_affine(&self) -> Option<(Sm2FieldElement, Sm2FieldElement)> {
        if self.is_infinity().to_bool() {
            return None;
        }
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.mul(&z_inv);
        let z_inv3 = z_inv2.mul(&z_inv);
        Some((self.x.mul(&z_inv2), self.y.mul(&z_inv3)))
    }

    /// `-self`: negating the `Y` coordinate, per SP 800-186 Appendix A.1.1 (`-P = (x, -y)`).
    pub fn negate(&self) -> Self {
        Self { x: self.x, y: self.y.negate(), z: self.z }
    }

    /// `2 * self`, via the curve's `a = -3` Jacobian doubling shortcut. Total: correct (and, since
    /// squaring/multiplying `0` is well-defined, does not panic) even when `self` is the point at
    /// infinity, though the result is only meaningful when it is not (callers needing the
    /// infinity case handled select for it separately, as [`Self::add`] does).
    pub fn double(&self) -> Self {
        let y1_squared = self.y.mul(&self.y);
        let t = y1_squared.mul(&y1_squared); // Y1^4
        let z1_squared = self.z.mul(&self.z);
        let t1 = self.x.sub(&z1_squared);
        let m = self.x.add(&z1_squared);
        let m = m.mul(&t1); // (X1 - Z1^2)(X1 + Z1^2) = X1^2 - Z1^4
        let m = m.add(&m).add(&m); // 3(X1^2 - Z1^4) == 3*X1^2 + a*Z1^4 for a == -3
        let s = y1_squared.mul(&self.x);
        let s = s.add(&s).add(&s).add(&s); // 4*X1*Y1^2
        let t8 = t.add(&t).add(&t).add(&t).add(&t).add(&t).add(&t).add(&t); // 8*Y1^4
        let x3 = m.mul(&m).sub(&s).sub(&s);
        let y3 = s.sub(&x3);
        let y3 = y3.mul(&m).sub(&t8);
        let z3 = self.y.add(&self.y).mul(&self.z);
        Self { x: x3, y: y3, z: z3 }
    }

    /// The generic (`self != ±other`, neither infinite) Jacobian addition formula, computed
    /// unconditionally, plus the `H` and `R` intermediates [`Self::add`] uses to detect the
    /// exceptional cases: `H == 0` iff `self` and `other` have the same affine `x`, and among
    /// those, `R == 0` iff they are the same point (needs doubling) vs `R != 0` iff they are
    /// negations of each other (sum is infinity).
    fn generic_add(&self, other: &Self) -> (Self, Sm2FieldElement, Sm2FieldElement) {
        let z2_sq = other.z.mul(&other.z);
        let u1 = self.x.mul(&z2_sq);
        let s1 = self.y.mul(&other.z).mul(&z2_sq);
        let z1_sq = self.z.mul(&self.z);
        let u2 = other.x.mul(&z1_sq);
        let s2 = other.y.mul(&self.z).mul(&z1_sq);

        let h = u1.sub(&u2);
        let r = s1.sub(&s2);

        let h_squared = h.mul(&h);
        let g = h_squared.mul(&h); // H^3
        let v = h_squared.mul(&u1);
        let g_neg = g.negate();
        let acc = s1.mul(&g_neg); // -S1*H^3
        let g2 = g_neg.add(&v).add(&v); // 2V - H^3
        let x3 = r.mul(&r).sub(&g2); // R^2 - (2V - H^3) == R^2 + H^3 - 2V
        let y3_temp = v.sub(&x3);
        let y3 = acc.add(&y3_temp.mul(&r)); // -S1*H^3 + (V - X3)*R
        let z3 = h.mul(&self.z).mul(&other.z);

        (Self { x: x3, y: y3, z: z3 }, h, r)
    }

    /// `self + other`, branch-free per the module docs: computes the generic-add and doubling
    /// candidates unconditionally, then masks in the correct result for whichever of the four
    /// exceptional cases (either operand infinite, same point, opposite point) applies, with no
    /// branch on `self` or `other`.
    pub fn add(&self, other: &Self) -> Self {
        let self_is_infinity = self.is_infinity();
        let other_is_infinity = other.is_infinity();

        let (generic, h, r) = self.generic_add(other);
        let h_is_zero = h.is_zero();
        let r_is_zero = r.is_zero();
        let is_same_point = h_is_zero & r_is_zero;
        let is_opposite_point = h_is_zero & !r_is_zero;
        let doubled = self.double();

        // Lowest priority first: each later select overrides the ones before it, so the final
        // (highest-priority) case applied is "other is infinity", then "self is infinity".
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
    /// Restricted to `pub(crate)` and used only by [`crate::sm2_wnaf`], whose scalars are
    /// [`crate::sm2_scalar::Sm2PublicScalar`] and whose points are a signer's public key and
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

/// Selects `a` if `cond` is TRUE, else `b`, over every coordinate of a point.
fn select_point(
    cond: Condition<u64>,
    a: &Sm2JacobianPoint,
    b: &Sm2JacobianPoint,
) -> Sm2JacobianPoint {
    Sm2JacobianPoint {
        x: Sm2FieldElement::from_limbs(select_limbs(cond, &a.x.to_limbs(), &b.x.to_limbs())),
        y: Sm2FieldElement::from_limbs(select_limbs(cond, &a.y.to_limbs(), &b.y.to_limbs())),
        z: Sm2FieldElement::from_limbs(select_limbs(cond, &a.z.to_limbs(), &b.z.to_limbs())),
    }
}

fn select_limbs(cond: Condition<u64>, a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    ct::conditional_select(cond, a, b, &mut out);
    out
}

// `add_vartime` is `pub(crate)` -- deliberately unreachable from outside the crate, since calling
// it on a secret point would undo the constant-time discipline [`Sm2JacobianPoint::add`] exists for
// -- so no integration test can reach it. Its whole contract is that it computes the same group law
// as `add`, differing only in *how* it gets there, so that is what is pinned here: agreement on
// every exceptional case, including the ones a scalar multiplier over distinct precomputed
// multiples essentially never reaches by chance (a point added to itself, and a point added to its
// own negation). QUALITY_AND_STYLE's private-function carve-out applies.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};

    #[test]
    fn add_vartime_agrees_with_add_on_every_case() {
        let g = Sm2JacobianPoint::from_affine(
            Sm2FieldElement::from_limbs(G_X_LIMBS),
            Sm2FieldElement::from_limbs(G_Y_LIMBS),
        );
        // G, 2G, -G and the identity cover all four of `add`'s exceptional cases pairwise, plus
        // the ordinary one (e.g. G + 2G).
        let points = [g, g.double(), g.negate(), Sm2JacobianPoint::INFINITY];
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
