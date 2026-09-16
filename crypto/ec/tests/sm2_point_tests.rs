//! Known-answer tests for [`Sm2JacobianPoint`] arithmetic.
//!
//! `G`, `2G`, `3G` were computed independently in Python via the standard affine group law
//! (`a = -3`), not from this crate, and cross-checked against `n*G == infinity`:
//!
//! ```text
//! p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
//! a = p - 3
//! # affine add/double via the standard a = -3 formulas
//! ```

use bouncycastle_ec::sm2::Sm2FieldElement;
use bouncycastle_ec::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::sm2_point::Sm2JacobianPoint;

const TWO_G_X: [u64; 4] =
    [0x495c2e1da3f2bd52, 0x9c0dfa08c08a7331, 0x0d58ef57fa73ba4d, 0x56cefd60d7c87c00];
const TWO_G_Y: [u64; 4] =
    [0x6f780d3a970a23c3, 0x6de84c182f6c8e71, 0x68535ce0f8eaf1bd, 0x31b7e7e6cc8189f6];
const THREE_G_X: [u64; 4] =
    [0xe26918f1d0509ebf, 0xa13f6bd945302244, 0xbe2daa8cdb41e24c, 0xa97f7cd4b3c993b4];
const THREE_G_Y: [u64; 4] =
    [0xaaacdd037458f6e6, 0x7c400ee5cd045292, 0xccc5cec08a72150f, 0x530b5dd88c688ef5];

fn fe(limbs: [u64; 4]) -> Sm2FieldElement {
    Sm2FieldElement::from_limbs(limbs)
}

fn g() -> Sm2JacobianPoint {
    Sm2JacobianPoint::from_affine(fe(G_X_LIMBS), fe(G_Y_LIMBS))
}

#[test]
fn known_answer_double() {
    let doubled = g().double();
    let (x, y) = doubled.to_affine().unwrap();
    assert_eq!(x, fe(TWO_G_X));
    assert_eq!(y, fe(TWO_G_Y));
}

#[test]
fn known_answer_add() {
    let sum = g().add(&g().double());
    let (x, y) = sum.to_affine().unwrap();
    assert_eq!(x, fe(THREE_G_X));
    assert_eq!(y, fe(THREE_G_Y));
}

#[test]
fn point_plus_negation_is_infinity() {
    let g = g();
    assert!(g.add(&g.negate()).is_infinity().to_bool());
}

#[test]
fn infinity_identities() {
    let g = g();
    let infinity = Sm2JacobianPoint::INFINITY;
    assert!(infinity.is_infinity().to_bool());
    assert!(infinity.to_affine().is_none());

    let (x1, y1) = g.add(&infinity).to_affine().unwrap();
    let (x2, y2) = g.to_affine().unwrap();
    assert_eq!((x1, y1), (x2, y2), "P + infinity == P");

    let (x3, y3) = infinity.add(&g).to_affine().unwrap();
    assert_eq!((x3, y3), (x2, y2), "infinity + P == P");

    assert!(infinity.add(&infinity).is_infinity().to_bool());
}

#[test]
fn scaled_z_representation_still_adds_correctly() {
    // (X, Y, Z) and (X*c^2, Y*c^3, Z*c) represent the same affine point for any nonzero c; the
    // branch-free add/double formulas must agree regardless of which representative is used.
    let c = fe([7, 0, 0, 0]);
    let c2 = c.mul(&c);
    let c3 = c2.mul(&c);
    let g = g();
    let scaled = Sm2JacobianPoint { x: g.x.mul(&c2), y: g.y.mul(&c3), z: g.z.mul(&c) };

    let canonical_double = g.double().to_affine().unwrap();
    let scaled_double = scaled.double().to_affine().unwrap();
    assert_eq!(canonical_double, scaled_double);

    let canonical_sum = g.add(&g.double()).to_affine().unwrap();
    let scaled_sum = scaled.add(&g.double()).to_affine().unwrap();
    assert_eq!(canonical_sum, scaled_sum);
}
