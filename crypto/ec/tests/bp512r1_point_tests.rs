//! Known-answer tests for [`Bp512r1JacobianPoint`] arithmetic.
//!
//! `G`, `2G`, `3G` were computed independently in Python via the standard affine group law
//! (general `a`), not from this crate, and cross-checked against `n*G == infinity`:
//!
//! ```text
//! p = 0xAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3
//! a = 0x7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA
//! # affine add/double via the standard general-a formulas
//! ```

use bouncycastle_ec::bp512r1::Bp512r1FieldElement;
use bouncycastle_ec::bp512r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp512r1_point::Bp512r1JacobianPoint;

const TWO_G_X: [u64; 8] = [
    0x080447def02f4850, 0xf698f404089a4cc5, 0x97116e702915a4f4, 0x957877f3a8f0f725,
    0xa30d3035f4cb6581, 0xd18d8141b8a18064, 0x0a63285758f399b3, 0x9f4945f680edf980,
];
const TWO_G_Y: [u64; 8] = [
    0xe269ad21be592e71, 0x63a42e4181fd929c, 0xa5c3b602b0960cbf, 0xfdf99bb1709c700f,
    0x5a2c366b03e5d1b2, 0x149ce1238d3f1e0f, 0x49826b716292f29d, 0x6d6b4b188b699c56,
];
const THREE_G_X: [u64; 8] = [
    0x5d4abf882ccb8d94, 0xf56e34abfa9ac720, 0x4780ae53e1853d62, 0xc1f6fb975ceecade,
    0x09c09cefd830151b, 0x907c80ef3bc24593, 0x36cdd42543f20afe, 0x08dd87e12b0a4cc4,
];
const THREE_G_Y: [u64; 8] = [
    0x5cdeafba05b02c37, 0x8cce5bc75d8de649, 0xfebfcb69c0f37c5f, 0xacdab8eb772327b3,
    0xba0b382e1716d843, 0x43d903b4a6334c4b, 0x756ff0067376fa75, 0x026ef5c6e1dab71d,
];

fn fe(limbs: [u64; 8]) -> Bp512r1FieldElement {
    Bp512r1FieldElement::from_limbs(limbs)
}

fn g() -> Bp512r1JacobianPoint {
    Bp512r1JacobianPoint::from_affine(fe(G_X_LIMBS), fe(G_Y_LIMBS))
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
    let infinity = Bp512r1JacobianPoint::INFINITY;
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
    let c = fe([7, 0, 0, 0, 0, 0, 0, 0]);
    let c2 = c.mul(&c);
    let c3 = c2.mul(&c);
    let g = g();
    let scaled = Bp512r1JacobianPoint { x: g.x.mul(&c2), y: g.y.mul(&c3), z: g.z.mul(&c) };

    let canonical_double = g.double().to_affine().unwrap();
    let scaled_double = scaled.double().to_affine().unwrap();
    assert_eq!(canonical_double, scaled_double);

    let canonical_sum = g.add(&g.double()).to_affine().unwrap();
    let scaled_sum = scaled.add(&g.double()).to_affine().unwrap();
    assert_eq!(canonical_sum, scaled_sum);
}
