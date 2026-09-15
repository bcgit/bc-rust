//! Known-answer tests for [`shamir_multiply`] (`[u]G + [v]Q`), P-521.

use bouncycastle_ec::p521::P521FieldElement;
use bouncycastle_ec::p521_comb::comb_multiply_base_point;
use bouncycastle_ec::p521_point::P521JacobianPoint;
use bouncycastle_ec::p521_scalar::{P521PublicScalar, P521Scalar};
use bouncycastle_ec::p521_wnaf::shamir_multiply;

const Q_X: [u64; 9] = [
    0xa64dc52cc15bfb04, 0xaca0b282aaa81dc2, 0xeef36ecaa8b95fe2, 0x687b823dcebc81f1,
    0xa4f6dffd0e8257f2, 0xc757f9716fb22e1e, 0x48376daf81b48bd7, 0xeac46a481ec62225,
    0x000000000000014c,
];
const Q_Y: [u64; 9] = [
    0xca6b644c91981f41, 0x815110666aafb2a8, 0xdb15842e498fede2, 0x6f032bd2342ac842,
    0xa0790c480d52a23d, 0x13753ef7ed3683e7, 0x9b60a50747dfe744, 0xb12cb10e2c79060b,
    0x0000000000000160,
];

fn q() -> P521JacobianPoint {
    P521JacobianPoint::from_affine(
        P521FieldElement::from_limbs(Q_X),
        P521FieldElement::from_limbs(Q_Y),
    )
}

fn scalar(limbs: [u64; 9]) -> P521PublicScalar {
    P521PublicScalar::from_limbs(limbs)
}

fn assert_result_is(u: [u64; 9], v: [u64; 9], expected_x: [u64; 9], expected_y: [u64; 9]) {
    let result = shamir_multiply(&scalar(u), &scalar(v), &q());
    let (rx, ry) = result.to_affine().expect("expected a non-infinity result");
    assert_eq!(rx, P521FieldElement::from_limbs(expected_x), "x mismatch for u={u:x?} v={v:x?}");
    assert_eq!(ry, P521FieldElement::from_limbs(expected_y), "y mismatch for u={u:x?} v={v:x?}");
}

#[test]
fn known_answer_large_u_v() {
    let u: [u64; 9] = [
        0x76502dbbd55de013, 0x9eecd37a3b49e19e, 0x33c315cc5803ef43, 0x062c9409f666b7bb,
        0xdaaee220685cc19c, 0x5a8b7626862337f8, 0x707a0f19c1784037, 0xa6109ce0ee8496ac,
        0x0000000000000088,
    ];
    let v: [u64; 9] = [
        0xdec5a82f3a0a30f2, 0xab186cbe22cad4c8, 0x6935acae3101699c, 0x745bcf1d6dd90512,
        0xf7548fb55be98622, 0xb47f1faf203dc251, 0x983d20175f54f0d4, 0x86b5248cbebec284,
        0x000000000000001c,
    ];
    assert_result_is(
        u,
        v,
        [
            0xe5d48e7b0f6594fa, 0x0d524f16894beedd, 0x133673b941b3de0a, 0x8d9d402465e261ff,
            0xbb5175b48d0efce6, 0xe8b9ff83af1eb56c, 0x82cb7654a02c7f2b, 0xd962dad7ed0d86ad,
            0x00000000000001b2,
        ],
        [
            0x0911be7f166dfedb, 0x078a2b1a04c37f02, 0xa18460fbe772b99f, 0x4bc7e5bbd5a938f0,
            0xb45f5980510db99d, 0x32fce6270286d0a6, 0x9b9f32c1e418a606, 0xa6197f50f7c2b1ea,
            0x0000000000000148,
        ],
    );
}

#[test]
fn edge_case_v_is_zero_reduces_to_u_times_g() {
    assert_result_is(
        [5, 0, 0, 0, 0, 0, 0, 0, 0],
        [0; 9],
        [
            0xd5ab5096ec8f3078, 0x29d7e1e6d8931738, 0x7112feaf137e79a3, 0x383c0c6d5e301423,
            0xcf03dab8f177ace4, 0x7a596efdb53f0d24, 0x3dbc3391c04eb0bf, 0x2bf3c52927a432c7,
            0x0000000000000065,
        ],
        [
            0x173cc3e8deb090cb, 0xd1f007257354f7f8, 0x311540211cf5ff79, 0xbb6897c9072cf374,
            0xedd817c9a0347087, 0x1cd8fe8e872e0051, 0x8a2b73114a811291, 0xe6ef1bdd6601d6ec,
            0x000000000000015b,
        ],
    );
}

#[test]
fn edge_case_u_is_zero_reduces_to_v_times_q() {
    assert_result_is(
        [0; 9],
        [5, 0, 0, 0, 0, 0, 0, 0, 0],
        [
            0x75ca491b7f07e70d, 0xe6dc7f1588257d2f, 0x86abc77f0ad29024, 0x6070155d58b40f74,
            0xd607266aacea7f73, 0x06dfbb1d0dc9db85, 0x798817d84830c87a, 0xc4c41c58ccb8e7c6,
            0x0000000000000017,
        ],
        [
            0xd8d09be4d547efa5, 0x47d22081c3c28c9f, 0xe54fe9c561252dcc, 0x80ca5e370551d128,
            0x8b12f279ffe7bd20, 0x71e701c2ed4aa80c, 0x05c3c429fd341f48, 0x3bbea45f73d14f84,
            0x00000000000000ab,
        ],
    );
}

#[test]
fn edge_case_both_zero_is_infinity() {
    let result = shamir_multiply(&scalar([0; 9]), &scalar([0; 9]), &q());
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

    fn next_limbs(&mut self) -> [u64; 9] {
        let mut limbs = [0u64; 9];
        for l in limbs.iter_mut() {
            *l = self.next_u64();
        }
        limbs[8] &= 0x1ff;
        limbs
    }
}

#[test]
fn cross_checked_against_the_comb_multiplier_over_many_pseudorandom_scalars() {
    // shamir_multiply(k, 0, anything) must equal comb_multiply_base_point(k): two independently
    // implemented multipliers (fixed-base comb vs. interleaved wNAF) computing the same [k]G.
    // 100, not the 500 used for P-256/P-384: P-521's per-multiply cost is higher (9-limb field
    // ops, 522-round comb/wNAF loops), and this test already shares its coverage goal with the
    // KATs and edge cases above.
    let mut rng = Xorshift64(0xA5A5A5A5A5A5A5A5);
    for _ in 0..100 {
        let k_limbs = rng.next_limbs();
        let via_comb = comb_multiply_base_point(&P521Scalar::from_limbs(k_limbs));
        let via_wnaf =
            shamir_multiply(&P521PublicScalar::from_limbs(k_limbs), &scalar([0; 9]), &q());
        assert_eq!(via_comb.to_affine(), via_wnaf.to_affine(), "k = {k_limbs:x?}");
    }
}
