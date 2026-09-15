//! Known-answer tests for [`P521JacobianPoint`] arithmetic. `G`, `2G`, `3G` computed independently
//! in Python via the affine group law (`a = -3`), cross-checked against `n*G == infinity`.

use bouncycastle_ec::p521::P521FieldElement;
use bouncycastle_ec::p521_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p521_point::P521JacobianPoint;

const TWO_G_X: [u64; 9] = [
    0xf43e3933ba6d783d, 0xcf2fa364d60fd967, 0xaa104a3a35c5af41, 0xb3b204da6ef55507,
    0x2c6e5505d769be97, 0x7403279b1ccc0635, 0x2fcb288148c28274, 0x3c219024277e7e68,
    0x0000000000000043,
];
const TWO_G_Y: [u64; 9] = [
    0x1be356d661f41b02, 0xeafcbe95edc0f4f7, 0x93937fa99a3248f4, 0xb3e377de9f251f6b,
    0xab21a29906c42dbb, 0xc6b5107c4da97740, 0xa7f3eceeeed3f0b5, 0xbb8cc7f86db26700,
    0x00000000000000f4,
];
const THREE_G_X: [u64; 9] = [
    0xa5919d2ede37ad7d, 0xaeb490862c32ea05, 0x1da6bd16b59fe21b, 0xad3f164a3a483205,
    0xe5ad7a112d7a8dd1, 0xb52a6e5b123d9ab9, 0xd91d6a64b5959479, 0x3d352443de29195d,
    0x00000000000001a7,
];
const THREE_G_Y: [u64; 9] = [
    0x5f588ca1ee86c0e5, 0xf105c9bc93a59042, 0x2d5aced1dec3c70c, 0x2e2dd4cf8dc575b0,
    0xd2f8ab1fa355ceec, 0xf1557fa82a9d0317, 0x979f86c6cab814f2, 0x9b03b97dfa62ddd9,
    0x000000000000013e,
];

fn fe(limbs: [u64; 9]) -> P521FieldElement {
    P521FieldElement::from_limbs(limbs)
}

fn g() -> P521JacobianPoint {
    P521JacobianPoint::from_affine(fe(G_X_LIMBS), fe(G_Y_LIMBS))
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
    let infinity = P521JacobianPoint::INFINITY;
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
    let c = fe([7, 0, 0, 0, 0, 0, 0, 0, 0]);
    let c2 = c.mul(&c);
    let c3 = c2.mul(&c);
    let g = g();
    let scaled = P521JacobianPoint { x: g.x.mul(&c2), y: g.y.mul(&c3), z: g.z.mul(&c) };

    let canonical_double = g.double().to_affine().unwrap();
    let scaled_double = scaled.double().to_affine().unwrap();
    assert_eq!(canonical_double, scaled_double);

    let canonical_sum = g.add(&g.double()).to_affine().unwrap();
    let scaled_sum = scaled.add(&g.double()).to_affine().unwrap();
    assert_eq!(canonical_sum, scaled_sum);
}
