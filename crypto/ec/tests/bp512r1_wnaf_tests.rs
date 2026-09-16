//! Known-answer tests for [`shamir_multiply`] (`[u]G + [v]Q`), brainpoolP512r1.
//!
//! `Q` below is `d*G` for a fixed test-only `d` (not a real key). Expected results were computed
//! independently in Python from the affine group law (general `a`), the same way as
//! `bp512r1_comb_tests.rs`, with `random.seed(808512)`.

use bouncycastle_ec::bp512r1::Bp512r1FieldElement;
use bouncycastle_ec::bp512r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp512r1_point::Bp512r1JacobianPoint;
use bouncycastle_ec::bp512r1_scalar::{Bp512r1PublicScalar, Bp512r1Scalar};
use bouncycastle_ec::bp512r1_wnaf::shamir_multiply;

const Q_X: [u64; 8] = [
    0x5816d744a9cf4eda, 0x14361f88a4d1fbcf, 0x6062798b3d4dc7f8, 0xdb6eba12aa0449c2,
    0x473c6bd692fef5a3, 0xc04b43d2d6f73a09, 0x07f88a2de934d573, 0x4d12cf5cdde21bb2,
];
const Q_Y: [u64; 8] = [
    0xb1a835f29de36a99, 0xd12a57b0461e9dcc, 0x08b9e3b064052a38, 0xe1d97bcd87b37b21,
    0xa6a5f2248c4ce531, 0x535577dcabf6f708, 0xeda6205f1acb7d00, 0x14ed25250ee66acc,
];

fn q() -> Bp512r1JacobianPoint {
    Bp512r1JacobianPoint::from_affine(
        Bp512r1FieldElement::from_limbs(Q_X),
        Bp512r1FieldElement::from_limbs(Q_Y),
    )
}

fn scalar(limbs: [u64; 8]) -> Bp512r1PublicScalar {
    Bp512r1PublicScalar::from_limbs(limbs)
}

fn assert_result_is(u: [u64; 8], v: [u64; 8], expected_x: [u64; 8], expected_y: [u64; 8]) {
    let result = shamir_multiply(&scalar(u), &scalar(v), &q());
    let (rx, ry) = result.to_affine().expect("expected a non-infinity result");
    assert_eq!(rx, Bp512r1FieldElement::from_limbs(expected_x), "x mismatch for u={u:x?} v={v:x?}");
    assert_eq!(ry, Bp512r1FieldElement::from_limbs(expected_y), "y mismatch for u={u:x?} v={v:x?}");
}

#[test]
fn known_answer_large_u_v() {
    let u: [u64; 8] = [
        0xf72c1b3dd112ad3a, 0xd9fd486b4f8f85e2, 0x34d5bb94dd8909e5, 0xc59c44fd8eccd1f7,
        0x1391126a445a5cd9, 0x88dbc08da2a4e439, 0xfb5cfa3f94b30172, 0x8d4dc198c6f7e773,
    ];
    let v: [u64; 8] = [
        0x7f06791e62c1b6d2, 0x27c9a8e864d74086, 0x7f96016b69474a61, 0xefb048bd284ce7ec,
        0x561ceeee26f27710, 0x1e626f9a88af3fef, 0xefbbc00d77c8f0ba, 0x7daae794912ace93,
    ];
    assert_result_is(
        u,
        v,
        [
            0xc65bbeb05d893442, 0x64ff7f51deda0175, 0x4c432c13e922cfdc, 0x84cba279920466bd,
            0x5152ab520b6ce4e1, 0xfcadb8d446c66aa0, 0xdfb41a87090f575d, 0x671fbd605746e874,
        ],
        [
            0xc072dfbfa132b695, 0xc517df6b74f85468, 0x7f81693763db58f3, 0x6e153d88f4bfb6cd,
            0x0ced4d6f7d1e80e1, 0xf82d8b1771d492ed, 0xa46ad57f1c9f9116, 0x47b8dd07bb0163cd,
        ],
    );
}

#[test]
fn edge_case_v_is_zero_reduces_to_u_times_g() {
    assert_result_is(
        [5, 0, 0, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 0, 0],
        [
            0x500d6f7d9d9aaa5c, 0x17bc4f43d413540b, 0xc393c273727cf25d, 0xaadc73e8d9472bb0,
            0xae0ff1c9461693d2, 0x0a4abf8dd044a3c1, 0xe3c9bc8c2bf17781, 0x8672838ed83a55b9,
        ],
        [
            0x62f8a1c2b51f7f35, 0xdb58bb174dcc0c77, 0xfa11d3cc5b06c0df, 0xa5a88c91f28d09eb,
            0xe1b69903a8863d2f, 0xea9d3a0a7a668f1e, 0x52b7a5643c936c09, 0x151d93c1de2ed9ee,
        ],
    );
}

#[test]
fn edge_case_u_is_zero_reduces_to_v_times_q() {
    assert_result_is(
        [0, 0, 0, 0, 0, 0, 0, 0],
        [5, 0, 0, 0, 0, 0, 0, 0],
        [
            0x512bcfa72f89e064, 0x9d1f8fc6c5c0273c, 0xbbd9f199434f86c4, 0x5a083de4902c9681,
            0x9322c9c7aad24529, 0x78be7c030cee42eb, 0xc19eb0bdae3e7584, 0x70e532a86012cb25,
        ],
        [
            0xd3cd888682e35709, 0x91d5589b896e9f10, 0xa7f4b26c141e68df, 0x3ef6461b33378824,
            0x29d1c225c0b68664, 0xc55d9ca3a6d1bdd9, 0x12e6f1ad0d1c63f4, 0x13ae6e16c77f51b4,
        ],
    );
}

#[test]
fn edge_case_both_zero_is_infinity() {
    let result = shamir_multiply(&scalar([0; 8]), &scalar([0; 8]), &q());
    assert!(result.to_affine().is_none());
}

/// xorshift64* PRNG, fixed seed: same rationale as the field-arithmetic property tests.
struct Xorshift64(u64);

impl Xorshift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_limbs(&mut self) -> [u64; 8] {
        [
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
        ]
    }
}

#[test]
fn cross_checked_against_the_comb_multiplier_over_many_pseudorandom_scalars() {
    // shamir_multiply(k, 0, anything) must equal comb_multiply_base_point(k): two independently
    // implemented multipliers (fixed-base comb vs. interleaved wNAF) computing the same [k]G.
    let mut rng = Xorshift64(0xE7C558A6A6E7F1DE);
    for _ in 0..500 {
        let k_limbs = rng.next_limbs();
        let via_comb = comb_multiply_base_point(&Bp512r1Scalar::from_limbs(k_limbs));
        let via_wnaf =
            shamir_multiply(&Bp512r1PublicScalar::from_limbs(k_limbs), &scalar([0; 8]), &q());
        assert_eq!(via_comb.to_affine(), via_wnaf.to_affine(), "k = {k_limbs:x?}");
    }
}
