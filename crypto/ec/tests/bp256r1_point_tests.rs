//! Known-answer tests for [`Bp256r1JacobianPoint`] arithmetic.
//!
//! `G`, `2G`, `3G` were computed independently in Python via the standard affine group law
//! (general `a`), not from this crate, and cross-checked against `n*G == infinity`:
//!
//! ```text
//! p = 0xA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377
//! a = 0x7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
//! # affine add/double via the standard general-a formulas
//! ```

use bouncycastle_ec::bp256r1::Bp256r1FieldElement;
use bouncycastle_ec::bp256r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp256r1_point::Bp256r1JacobianPoint;

const TWO_G_X: [u64; 4] =
    [0xd51a14c2ce13ea0e, 0x36ef044166699e37, 0xb55f8aa369593ac4, 0x743cf1b8b5cd4f2e];
const TWO_G_Y: [u64; 4] =
    [0x892ada097eeb7cd4, 0x38df059f69249406, 0x946fe0bb776529da, 0x36ed163337deba9c];
const THREE_G_X: [u64; 4] =
    [0x6b91e2ad25cae39d, 0xd2aa843d0c0fca01, 0xd6624c3ab4f6cc16, 0xa8f217b77338f1d4];
const THREE_G_Y: [u64; 4] =
    [0x7e65cc5602b74f9d, 0xfac10e4589348fb7, 0x0aa2a6850a1b40f5, 0x4b49cafc7dac26bb];

fn fe(limbs: [u64; 4]) -> Bp256r1FieldElement {
    Bp256r1FieldElement::from_limbs(limbs)
}

fn g() -> Bp256r1JacobianPoint {
    Bp256r1JacobianPoint::from_affine(fe(G_X_LIMBS), fe(G_Y_LIMBS))
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
    let infinity = Bp256r1JacobianPoint::INFINITY;
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
    let scaled = Bp256r1JacobianPoint { x: g.x.mul(&c2), y: g.y.mul(&c3), z: g.z.mul(&c) };

    let canonical_double = g.double().to_affine().unwrap();
    let scaled_double = scaled.double().to_affine().unwrap();
    assert_eq!(canonical_double, scaled_double);

    let canonical_sum = g.add(&g.double()).to_affine().unwrap();
    let scaled_sum = scaled.add(&g.double()).to_affine().unwrap();
    assert_eq!(canonical_sum, scaled_sum);
}
