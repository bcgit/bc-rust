//! Known-answer tests for [`Bp384r1JacobianPoint`] arithmetic.
//!
//! `G`, `2G`, `3G` were computed independently in Python via the standard affine group law
//! (general `a`), not from this crate, and cross-checked against `n*G == infinity`:
//!
//! ```text
//! p = 0x8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53
//! a = 0x7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826
//! # affine add/double via the standard general-a formulas
//! ```

use bouncycastle_ec::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::bp384r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp384r1_point::Bp384r1JacobianPoint;

const TWO_G_X: [u64; 6] = [
    0xb427b58df9d59fca, 0x7c4ba74a09b553eb, 0xec2f80c4e0f70df8, 0x0ad520b3eb6be4d6,
    0xb95c3495d7b4fd59, 0x2282bc382a2f4dfc,
];
const TWO_G_Y: [u64; 6] = [
    0x8f1b29502b6e1d30, 0xb4b4ea69ab64fc28, 0x4d89dd051728fc3e, 0xce9bedbc170921ce,
    0x5768d14a24f37a57, 0x0edda83773ac6873,
];
const THREE_G_X: [u64; 6] = [
    0x7d7cc85b3035f11f, 0x3c11ef6596a3b889, 0x3ee1b6fcc7463bbe, 0x3df581348c6949f8,
    0x3b17452b6a27ebf5, 0x7b63205bf00ddae7,
];
const THREE_G_Y: [u64; 6] = [
    0x81d7129d48772eb3, 0x73c0edaea3b8f593, 0x7b2bd39462363e03, 0x7b2eb481ead16a5c,
    0x5521a326bc02baaf, 0x761d3a4a5f809377,
];

fn fe(limbs: [u64; 6]) -> Bp384r1FieldElement {
    Bp384r1FieldElement::from_limbs(limbs)
}

fn g() -> Bp384r1JacobianPoint {
    Bp384r1JacobianPoint::from_affine(fe(G_X_LIMBS), fe(G_Y_LIMBS))
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
    let infinity = Bp384r1JacobianPoint::INFINITY;
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
    let c = fe([7, 0, 0, 0, 0, 0]);
    let c2 = c.mul(&c);
    let c3 = c2.mul(&c);
    let g = g();
    let scaled = Bp384r1JacobianPoint { x: g.x.mul(&c2), y: g.y.mul(&c3), z: g.z.mul(&c) };

    let canonical_double = g.double().to_affine().unwrap();
    let scaled_double = scaled.double().to_affine().unwrap();
    assert_eq!(canonical_double, scaled_double);

    let canonical_sum = g.add(&g.double()).to_affine().unwrap();
    let scaled_sum = scaled.add(&g.double()).to_affine().unwrap();
    assert_eq!(canonical_sum, scaled_sum);
}
