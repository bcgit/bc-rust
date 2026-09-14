//! Known-answer tests for [`shamir_multiply`] (`[u]G + [v]Q`), P-384.
//!
//! `Q` below is `d*G` for a fixed test-only `d` (not a real key). Expected results were computed
//! independently in Python from the affine group law, the same way as `p384_comb_tests.rs`, with
//! `random.seed(808384)`.

use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_comb::comb_multiply_base_point;
use bouncycastle_ec::p384_point::P384JacobianPoint;
use bouncycastle_ec::p384_scalar::{P384PublicScalar, P384Scalar};
use bouncycastle_ec::p384_wnaf::shamir_multiply;

const Q_X: [u64; 6] = [
    0x4f6d6d13beeaa1b2, 0x3cb1efd1edd7bbff, 0xe07a2b63cdb9d941, 0xefec1918a1158b0a,
    0x354ecd94081fe303, 0xaacd2057b4583a67,
];
const Q_Y: [u64; 6] = [
    0x5e371d1feb74472f, 0x9a9227ba8e5ef0e2, 0x6db85468ef6a5e50, 0xe369fa64fc786ffb,
    0x9a4d67905a6d9075, 0x3f61f852d831009a,
];

fn q() -> P384JacobianPoint {
    P384JacobianPoint::from_affine(
        P384FieldElement::from_limbs(Q_X),
        P384FieldElement::from_limbs(Q_Y),
    )
}

fn scalar(limbs: [u64; 6]) -> P384PublicScalar {
    P384PublicScalar::from_limbs(limbs)
}

fn assert_result_is(u: [u64; 6], v: [u64; 6], expected_x: [u64; 6], expected_y: [u64; 6]) {
    let result = shamir_multiply(&scalar(u), &scalar(v), &q());
    let (rx, ry) = result.to_affine().expect("expected a non-infinity result");
    assert_eq!(rx, P384FieldElement::from_limbs(expected_x), "x mismatch for u={u:x?} v={v:x?}");
    assert_eq!(ry, P384FieldElement::from_limbs(expected_y), "y mismatch for u={u:x?} v={v:x?}");
}

#[test]
fn known_answer_large_u_v() {
    let u: [u64; 6] = [
        0x6149a1f0473fdc0a, 0xd13f8f211ee42ca3, 0x798bbf759162536a, 0xb4981a8fbcfde9fc,
        0xc8c7279f85b5b57d, 0xdf4dc003c482b49d,
    ];
    let v: [u64; 6] = [
        0xcf9d0a68d7fd9587, 0x72c8c95608f4eb96, 0x48403aad19a04ae6, 0x74cc2df91a4a3ac6,
        0xa73e462c3bc5bf0c, 0x838e541242a28502,
    ];
    assert_result_is(
        u,
        v,
        [
            0x709d13c4c9203cb0, 0x134fb91a2120df5f, 0x263d03fac7eb441c, 0xcd2bdbabfd72bf84,
            0x982474564005e793, 0x39882178259925d2,
        ],
        [
            0x2809b7a310810609, 0x8d963924b0abffb4, 0xc256c6703ce538b4, 0x0f262b8555a127b9,
            0x401c3b38d2a6ea23, 0xf6eb81915b6b13ac,
        ],
    );
}

#[test]
fn edge_case_v_is_zero_reduces_to_u_times_g() {
    assert_result_is(
        [5, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0],
        [
            0x0abcdbc3836d84bc, 0x37882f4a1ca297e6, 0x4f6661cbe56583b0, 0xf208e51dbff98fc5,
            0x573cac5ea025e467, 0x11de24a2c251c777,
        ],
        [
            0x184414abe6c1713a, 0x3177686d0ae8fb33, 0x8c986533b6901aeb, 0x284b447754d5dee8,
            0x0f5837e90a00e7c5, 0x8fa696c77440f92d,
        ],
    );
}

#[test]
fn edge_case_u_is_zero_reduces_to_v_times_q() {
    assert_result_is(
        [0, 0, 0, 0, 0, 0],
        [5, 0, 0, 0, 0, 0],
        [
            0xf931c4adf0579053, 0xdabd5bd1fbde76cb, 0x171924159a115ea8, 0x7caf68c567529296,
            0x894cecf0212acf00, 0x014bdb66a196ff9e,
        ],
        [
            0xa8d76dc9a8914d0c, 0x6cbfa095ab83f08f, 0xa47412ad0e695029, 0xb5a7b2caee0f8b05,
            0x8991406ffb6c6039, 0x14dfd74b3c35d557,
        ],
    );
}

#[test]
fn edge_case_both_zero_is_infinity() {
    let result = shamir_multiply(&scalar([0; 6]), &scalar([0; 6]), &q());
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

    fn next_limbs(&mut self) -> [u64; 6] {
        [
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
        let via_comb = comb_multiply_base_point(&P384Scalar::from_limbs(k_limbs));
        let via_wnaf =
            shamir_multiply(&P384PublicScalar::from_limbs(k_limbs), &scalar([0; 6]), &q());
        assert_eq!(via_comb.to_affine(), via_wnaf.to_affine(), "k = {k_limbs:x?}");
    }
}
