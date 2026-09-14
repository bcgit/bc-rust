//! Known-answer tests for [`P256JacobianPoint`] add/double against small multiples of the P-256
//! base point `G` (SP 800-186 §3.2.1.3).
//!
//! Expected coordinates were computed independently in Python from the SP 800-186 Appendix A.1.1
//! affine group law (not from recall, and not by reusing this crate's own point arithmetic):
//!
//! ```text
//! def affine_add(P1, P2):
//!     if P1 is None: return P2
//!     if P2 is None: return P1
//!     x1, y1 = P1; x2, y2 = P2
//!     if x1 == x2 and (y1 + y2) % p == 0: return None
//!     if P1 == P2:
//!         lam = (3*x1*x1 + a) * pow(2*y1, p-2, p) % p
//!     else:
//!         lam = (y2 - y1) * pow(x2 - x1, p-2, p) % p
//!     x3 = (lam*lam - x1 - x2) % p
//!     y3 = (lam*(x1 - x3) - y1) % p
//!     return (x3, y3)
//! ```
//!
//! with `P_k = k*G` computed by repeated `affine_add` (double-and-add), for small `k`.

use bouncycastle_ec::p256::P256FieldElement;
use bouncycastle_ec::p256_point::P256JacobianPoint;

const P1_X: [u64; 4] =
    [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247];
const P1_Y: [u64; 4] =
    [0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b];
const P2_X: [u64; 4] =
    [0xa60b48fc47669978, 0xc08969e277f21b35, 0x8a52380304b51ac3, 0x7cf27b188d034f7e];
const P2_Y: [u64; 4] =
    [0x9e04b79d227873d1, 0xba7dade63ce98229, 0x293d9ac69f7430db, 0x07775510db8ed040];
const P3_X: [u64; 4] =
    [0xfb41661bc6e7fd6c, 0xe6c6b721efada985, 0xc8f7ef951d4bf165, 0x5ecbe4d1a6330a44];
const P3_Y: [u64; 4] =
    [0x9a79b127a27d5032, 0xd82ab036384fb83d, 0x374b06ce1a64a2ec, 0x8734640c4998ff7e];
const P4_X: [u64; 4] =
    [0x509302446b030852, 0x031fe2db785596ef, 0xa02dde659ee62bd0, 0xe2534a3532d08fbb];
const P4_Y: [u64; 4] =
    [0x5c42c23f184ed8c6, 0x4efc96c3f30ee005, 0x19dfee5fda862d76, 0xe0f1575a4c633cc7];
const P5_X: [u64; 4] =
    [0x21554a0dc3d033ed, 0xef8c82fd1f5be524, 0xd784c85608668fdf, 0x51590b7a515140d2];
const P5_Y: [u64; 4] =
    [0xd1d0bb44fda16da4, 0x0d012f00d4d80888, 0x8ae1bf36bf8a7926, 0xe0c17da8904a727d];
const P7_X: [u64; 4] =
    [0x300628703187b2a3, 0x7ef9f8b8a80fef5b, 0x25bb30667c01fb60, 0x8e533b6fa0bf7b46];
const P7_Y: [u64; 4] =
    [0xc55e1a86c1f400b4, 0x53c73633cb041b21, 0x6d069f83a6f59000, 0x73eb1dbde0331836];
const P11_X: [u64; 4] =
    [0x433391d374bc21d1, 0x16742ed0255048bf, 0x0638379db0c21cda, 0x3ed113b7883b4c59];
const P11_Y: [u64; 4] =
    [0xe2f8eefce82a3740, 0x090d04da5e9889da, 0x24c843afa4f4c68a, 0x9099209accc4c8a2];
const P13_X: [u64; 4] =
    [0x98e15d9d46072c01, 0x792e284b65ead58a, 0x61805df2d85ee2fc, 0x177c837ae0ac495a];
const P13_Y: [u64; 4] =
    [0x9c43bbe2efc7bfd8, 0x26ee14c3a1fb4df3, 0xa24091adb40f4e72, 0x63bb58cd4ebea558];

const SUM_1_2_X: [u64; 4] = P3_X;
const SUM_1_2_Y: [u64; 4] = P3_Y;
const SUM_2_3_X: [u64; 4] = P5_X;
const SUM_2_3_Y: [u64; 4] = P5_Y;
const SUM_1_3_X: [u64; 4] = P4_X;
const SUM_1_3_Y: [u64; 4] = P4_Y;
const SUM_4_5_X: [u64; 4] =
    [0xd79e8a4b90949ee0, 0x9e0acb8c2c6df8b3, 0x878938d51d71f872, 0xea68d7b6fedf0b71];
const SUM_4_5_Y: [u64; 4] =
    [0xe85a224a4dd048fa, 0x4d714feaa4de823f, 0x87014a964a8ea0c8, 0x2a2744c972c9fce7];
const SUM_1_4_X: [u64; 4] = P5_X;
const SUM_1_4_Y: [u64; 4] = P5_Y;
const SUM_7_11_X: [u64; 4] =
    [0xd936266dbd781fda, 0x37bb4c6f9ea55c63, 0xdefc9378d1c7c874, 0x1057e0ab5780f470];
const SUM_7_11_Y: [u64; 4] =
    [0x8d83b3393c6a45a2, 0xdcc11b5c5ef4f1f7, 0x9fa9b7dfd96ee5a7, 0xf6f1645a15cbe5dc];
const SUM_2_13_X: [u64; 4] =
    [0x63668c63e59b9d5f, 0xae03af92de3a0ef1, 0xadfb378999888265, 0xf0454dc6971abae7];
const SUM_2_13_Y: [u64; 4] =
    [0x47e59cde0d034f36, 0x2a3b21ce75b5fa3f, 0x4e6594e51f9643e6, 0xb5b93ee3592e2d1f];

const DBL_1_X: [u64; 4] = P2_X;
const DBL_1_Y: [u64; 4] = P2_Y;
const DBL_2_X: [u64; 4] = P4_X;
const DBL_2_Y: [u64; 4] = P4_Y;
const DBL_3_X: [u64; 4] =
    [0xc6b0aae93c2291a9, 0x024c740debb215b4, 0x92d3242cb897dde3, 0xb01a172a76a4602c];
const DBL_3_Y: [u64; 4] =
    [0xfd7c48538fc77fe2, 0x1c00f7701c7e16bd, 0x6fec0e2dfba70379, 0xe85c10743237dad5];
const DBL_4_X: [u64; 4] =
    [0xb4dd9dc1db6fb393, 0xc1d238980fce97db, 0x4042742d3ab54cad, 0x62d9779dbee9b053];
const DBL_4_Y: [u64; 4] =
    [0xda540a6a0f09957e, 0xa2ed51f6bbe76a78, 0x4ff15d771167cee0, 0xad5accbd91e9d824];
const DBL_5_X: [u64; 4] =
    [0x4c36069404c5723f, 0x45ca6c471c48306e, 0x591214d1ea223fb5, 0xcef66d6b2a3a993e];
const DBL_5_Y: [u64; 4] =
    [0xca34bbaa44af0773, 0x590ded29fe751eee, 0x6e123cdd9d3b4c10, 0x878662a229aaae90];
const DBL_7_X: [u64; 4] =
    [0x5709277324d2920b, 0xf126acbe7a069c5e, 0x7a76647f4336df3c, 0x54e77a001c3862b9];
const DBL_7_Y: [u64; 4] =
    [0x1ba7c82f60d0b375, 0x7171ea7773509008, 0x42121f8c05a2e7c3, 0xf599f1bb29f43175];

fn fe(limbs: [u64; 4]) -> P256FieldElement {
    P256FieldElement::from_limbs(limbs)
}

fn pt(x: [u64; 4], y: [u64; 4]) -> P256JacobianPoint {
    P256JacobianPoint::from_affine(fe(x), fe(y))
}

fn assert_affine_eq(p: &P256JacobianPoint, x: [u64; 4], y: [u64; 4], msg: &str) {
    let (ax, ay) = p.to_affine().unwrap_or_else(|| panic!("{msg}: unexpectedly at infinity"));
    assert_eq!(ax, fe(x), "{msg}: x mismatch");
    assert_eq!(ay, fe(y), "{msg}: y mismatch");
}

#[test]
fn known_answer_add() {
    let cases: [(([u64; 4], [u64; 4]), ([u64; 4], [u64; 4]), ([u64; 4], [u64; 4])); 7] = [
        ((P1_X, P1_Y), (P2_X, P2_Y), (SUM_1_2_X, SUM_1_2_Y)),
        ((P2_X, P2_Y), (P3_X, P3_Y), (SUM_2_3_X, SUM_2_3_Y)),
        ((P1_X, P1_Y), (P3_X, P3_Y), (SUM_1_3_X, SUM_1_3_Y)),
        ((P4_X, P4_Y), (P5_X, P5_Y), (SUM_4_5_X, SUM_4_5_Y)),
        ((P1_X, P1_Y), (P4_X, P4_Y), (SUM_1_4_X, SUM_1_4_Y)),
        ((P7_X, P7_Y), (P11_X, P11_Y), (SUM_7_11_X, SUM_7_11_Y)),
        ((P2_X, P2_Y), (P13_X, P13_Y), (SUM_2_13_X, SUM_2_13_Y)),
    ];
    for (p1, p2, expected) in cases {
        let a = pt(p1.0, p1.1);
        let b = pt(p2.0, p2.1);
        assert_affine_eq(&a.add(&b), expected.0, expected.1, "add");
        assert_affine_eq(&b.add(&a), expected.0, expected.1, "add is commutative");
    }
}

#[test]
fn known_answer_double() {
    let cases: [(([u64; 4], [u64; 4]), ([u64; 4], [u64; 4])); 6] = [
        ((P1_X, P1_Y), (DBL_1_X, DBL_1_Y)),
        ((P2_X, P2_Y), (DBL_2_X, DBL_2_Y)),
        ((P3_X, P3_Y), (DBL_3_X, DBL_3_Y)),
        ((P4_X, P4_Y), (DBL_4_X, DBL_4_Y)),
        ((P5_X, P5_Y), (DBL_5_X, DBL_5_Y)),
        ((P7_X, P7_Y), (DBL_7_X, DBL_7_Y)),
    ];
    for (p, expected) in cases {
        let a = pt(p.0, p.1);
        assert_affine_eq(&a.double(), expected.0, expected.1, "double");
        // add() must dispatch to the same result when asked to add a point to itself.
        assert_affine_eq(&a.add(&a), expected.0, expected.1, "add(P, P) == double(P)");
    }
}

#[test]
fn point_plus_negation_is_infinity() {
    for (x, y) in [(P1_X, P1_Y), (P2_X, P2_Y), (P7_X, P7_Y), (P13_X, P13_Y)] {
        let p = pt(x, y);
        let neg = p.negate();
        assert!(p.add(&neg).to_affine().is_none(), "P + (-P) must be infinity");
        assert!(neg.add(&p).to_affine().is_none(), "-P + P must be infinity");
    }
}

#[test]
fn infinity_identities() {
    let inf = P256JacobianPoint::INFINITY;
    assert!(inf.is_infinity().to_bool());
    assert!(inf.to_affine().is_none());
    assert!(inf.add(&inf).to_affine().is_none(), "infinity + infinity == infinity");

    for (x, y) in [(P1_X, P1_Y), (P7_X, P7_Y), (P13_X, P13_Y)] {
        let p = pt(x, y);
        assert_affine_eq(&p.add(&inf), x, y, "P + infinity == P");
        assert_affine_eq(&inf.add(&p), x, y, "infinity + P == P");
    }
}

#[test]
fn scaled_z_representation_still_adds_correctly() {
    // A point need not be affine (Z == 1) to be added correctly -- P1 scaled by an arbitrary
    // nonzero Z' must still represent the same affine point through add().
    let z_scale =
        fe([0x1122334455667788, 0x99aabbccddeeff00, 0x0f0e0d0c0b0a0908, 0x0102030405060708]);
    let z2 = z_scale.mul(&z_scale);
    let z3 = z2.mul(&z_scale);
    let scaled_p1 = P256JacobianPoint { x: fe(P1_X).mul(&z2), y: fe(P1_Y).mul(&z3), z: z_scale };

    // sanity: the scaled point still maps back to the same affine coordinates
    assert_affine_eq(&scaled_p1, P1_X, P1_Y, "scaled P1 affine round-trip");

    let p2 = pt(P2_X, P2_Y);
    assert_affine_eq(&scaled_p1.add(&p2), SUM_1_2_X, SUM_1_2_Y, "scaled-Z add");
    assert_affine_eq(&scaled_p1.double(), DBL_1_X, DBL_1_Y, "scaled-Z double");
}
