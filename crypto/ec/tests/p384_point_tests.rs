//! Known-answer tests for [`P384JacobianPoint`] arithmetic.
//!
//! `G`, `2G`, `3G` and a pseudorandom `kG` were computed independently in Python via the affine
//! group law (`a = -3`), not from this crate, and cross-checked against `n*G == infinity`:
//!
//! ```text
//! p = 2**384 - 2**128 - 2**96 + 2**32 - 1
//! # affine add/double/scalar-mul via the standard a = -3 formulas
//! ```

use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p384_point::P384JacobianPoint;

const TWO_G_X: [u64; 6] = [
    0x5b96a9c75295df61, 0x4fe0e86ebe0e64f8, 0x51d207d19fb96e9e, 0x89025959a6f434d6,
    0x69260045c55b97f0, 0x08d999057ba3d2d9,
];
const TWO_G_Y: [u64; 6] = [
    0x61501e700a940e80, 0x5ffd43e94d39e22d, 0x904e505f256ab425, 0xb275d875bc6cc43e,
    0xb7bfe8dffd6dba74, 0x8e80f1fa5b1b3ced,
];
const THREE_G_X: [u64; 6] = [
    0x02d7e5c70500c831, 0xb408bbae5026580d, 0xbea4f240d3566da6, 0xcb9d3910202dcd06,
    0x64793c7e5fdc7d98, 0x077a41d4606ffa14,
];
const THREE_G_Y: [u64; 6] = [
    0xb65f28600a2f1df1, 0xc24abd6be4b5d298, 0xf7684c0edc111eac, 0x8520b41c85115aa5,
    0x7d0bbe9602a9fc99, 0xc995f7ca0b0c4283,
];

fn fe(limbs: [u64; 6]) -> P384FieldElement {
    P384FieldElement::from_limbs(limbs)
}

fn g() -> P384JacobianPoint {
    P384JacobianPoint::from_affine(fe(G_X_LIMBS), fe(G_Y_LIMBS))
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
    let infinity = P384JacobianPoint::INFINITY;
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
    let scaled = P384JacobianPoint { x: g.x.mul(&c2), y: g.y.mul(&c3), z: g.z.mul(&c) };

    let canonical_double = g.double().to_affine().unwrap();
    let scaled_double = scaled.double().to_affine().unwrap();
    assert_eq!(canonical_double, scaled_double);

    let canonical_sum = g.add(&g.double()).to_affine().unwrap();
    let scaled_sum = scaled.add(&g.double()).to_affine().unwrap();
    assert_eq!(canonical_sum, scaled_sum);
}
