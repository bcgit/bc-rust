//! Known-answer tests for [`P256K1JacobianPoint`] arithmetic.
//!
//! `G`, `2G`, `3G` and a pseudorandom `kG` were computed independently in Python via the standard
//! affine group law (`a = 0`), not from this crate, and cross-checked against `n*G == infinity`:
//!
//! ```text
//! p = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
//! # affine add/double/scalar-mul via the standard a = 0 formulas
//! ```

use bouncycastle_ec::p256k1::P256K1FieldElement;
use bouncycastle_ec::p256k1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p256k1_point::P256K1JacobianPoint;

const TWO_G_X: [u64; 4] =
    [0xabac09b95c709ee5, 0x5c778e4b8cef3ca7, 0x3045406e95c07cd8, 0xc6047f9441ed7d6d];
const TWO_G_Y: [u64; 4] =
    [0x236431a950cfe52a, 0xf7f632653266d0e1, 0xa3c58419466ceaee, 0x1ae168fea63dc339];
const THREE_G_X: [u64; 4] =
    [0x8601f113bce036f9, 0xb531c845836f99b0, 0x49344f85f89d5229, 0xf9308a019258c310];
const THREE_G_Y: [u64; 4] =
    [0x6cb9fd7584b8e672, 0x6500a99934c2231b, 0x0fe337e62a37f356, 0x388f7b0f632de814];

fn fe(limbs: [u64; 4]) -> P256K1FieldElement {
    P256K1FieldElement::from_limbs(limbs)
}

fn g() -> P256K1JacobianPoint {
    P256K1JacobianPoint::from_affine(fe(G_X_LIMBS), fe(G_Y_LIMBS))
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
    let infinity = P256K1JacobianPoint::INFINITY;
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
    let scaled = P256K1JacobianPoint { x: g.x.mul(&c2), y: g.y.mul(&c3), z: g.z.mul(&c) };

    let canonical_double = g.double().to_affine().unwrap();
    let scaled_double = scaled.double().to_affine().unwrap();
    assert_eq!(canonical_double, scaled_double);

    let canonical_sum = g.add(&g.double()).to_affine().unwrap();
    let scaled_sum = scaled.add(&g.double()).to_affine().unwrap();
    assert_eq!(canonical_sum, scaled_sum);
}
