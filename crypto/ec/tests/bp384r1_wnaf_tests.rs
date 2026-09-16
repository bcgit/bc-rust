//! Known-answer tests for [`shamir_multiply`] (`[u]G + [v]Q`), brainpoolP384r1.
//!
//! `Q` below is `d*G` for a fixed test-only `d` (not a real key). Expected results were computed
//! independently in Python from the affine group law (general `a`), the same way as
//! `bp384r1_comb_tests.rs`, with `random.seed(808384)`.

use bouncycastle_ec::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::bp384r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp384r1_point::Bp384r1JacobianPoint;
use bouncycastle_ec::bp384r1_scalar::{Bp384r1PublicScalar, Bp384r1Scalar};
use bouncycastle_ec::bp384r1_wnaf::shamir_multiply;

const Q_X: [u64; 6] = [
    0x5b44524010bc5404, 0x4357db763fd6cab8, 0x1db62b723f57e3ae, 0x848f29c8305dfe90,
    0xa25d398c748f5185, 0x34664177dbe1b9a0,
];
const Q_Y: [u64; 6] = [
    0xb65bd155583f26ac, 0xeecdd7a2b2310c1d, 0x7719da95a7acae74, 0xa30d83a1c4c00d57,
    0x97617636091ba79a, 0x600741dd2ab16b2c,
];

fn q() -> Bp384r1JacobianPoint {
    Bp384r1JacobianPoint::from_affine(
        Bp384r1FieldElement::from_limbs(Q_X),
        Bp384r1FieldElement::from_limbs(Q_Y),
    )
}

fn scalar(limbs: [u64; 6]) -> Bp384r1PublicScalar {
    Bp384r1PublicScalar::from_limbs(limbs)
}

fn assert_result_is(u: [u64; 6], v: [u64; 6], expected_x: [u64; 6], expected_y: [u64; 6]) {
    let result = shamir_multiply(&scalar(u), &scalar(v), &q());
    let (rx, ry) = result.to_affine().expect("expected a non-infinity result");
    assert_eq!(rx, Bp384r1FieldElement::from_limbs(expected_x), "x mismatch for u={u:x?} v={v:x?}");
    assert_eq!(ry, Bp384r1FieldElement::from_limbs(expected_y), "y mismatch for u={u:x?} v={v:x?}");
}

#[test]
fn known_answer_large_u_v() {
    let u: [u64; 6] = [
        0xab460788b359c7e8, 0xc53f364b2831dc1d, 0x88aebe98b4707af4, 0x0cb0e573234caea1,
        0xba948bc69341a076, 0x53880bbb2c34e9eb,
    ];
    let v: [u64; 6] = [
        0xd01cc5f6019abebb, 0x1e33bc48f173dd98, 0x1778851a97225d6e, 0x1f8af7a981f2e7c1,
        0xfb3507316731ab74, 0x186bcc03ec975e9a,
    ];
    assert_result_is(
        u,
        v,
        [
            0x532067c358722c9f, 0xa9afb5f0af4af40a, 0x65ae351aeab9991e, 0xb364aad77b1c0f7e,
            0x8dceb0ad73f0e2e3, 0x1a8ca748362e8d33,
        ],
        [
            0x57eea0309aa209b7, 0xc971d41f677ad5f8, 0x237b73a259c13d6e, 0xb0c52f7bef139b37,
            0xe848cdee1beff0f9, 0x45e79622a771e8a6,
        ],
    );
}

#[test]
fn edge_case_v_is_zero_reduces_to_u_times_g() {
    assert_result_is(
        [5, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0],
        [
            0x2cebab9fd2412dfb, 0xfbc1247651c2770d, 0x0ac96ddf237f84f4, 0x465848a4b4fbb608,
            0x5100dabea7b5f59f, 0x0d3ec4dfce264772,
        ],
        [
            0x3f9b162e47634690, 0xe059c219dfbbc32b, 0x97495c4579bb950c, 0x39f00d1d90ed0c6d,
            0xebaa167fa90635f9, 0x20168ac65e9bb101,
        ],
    );
}

#[test]
fn edge_case_u_is_zero_reduces_to_v_times_q() {
    assert_result_is(
        [0, 0, 0, 0, 0, 0],
        [5, 0, 0, 0, 0, 0],
        [
            0x3f7fb20be3020eaf, 0x888e9d034b87f935, 0x3ebc83d2f22eca11, 0x666e10424c2870bf,
            0xaf17628bc72875ee, 0x892c40998e25e398,
        ],
        [
            0x67395cb642b58fda, 0x24b2a960b1355af4, 0x377593ca4162ca87, 0x9a874c7a3f4b27eb,
            0x3c16b0813a41f150, 0x671afc917054aac4,
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
        let via_comb = comb_multiply_base_point(&Bp384r1Scalar::from_limbs(k_limbs));
        let via_wnaf =
            shamir_multiply(&Bp384r1PublicScalar::from_limbs(k_limbs), &scalar([0; 6]), &q());
        assert_eq!(via_comb.to_affine(), via_wnaf.to_affine(), "k = {k_limbs:x?}");
    }
}
