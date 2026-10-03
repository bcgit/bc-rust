//! Known-answer tests for [`comb_multiply_base_point`] (`[k]G`), brainpoolP512r1.
//!
//! `k = 2, 3` reuse the values verified independently in `bp512r1_point_tests.rs`; `k` for
//! `known_answer_large_k` and `n-1` (where `[k]G = -G`) were computed the same way (Python affine
//! group law, general `a`), `random.seed(628512)` for the former.

use bouncycastle_ec::bp512r1::Bp512r1FieldElement;
use bouncycastle_ec::bp512r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp512r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp512r1_scalar::Bp512r1Scalar;

fn scalar(limbs: [u64; 8]) -> Bp512r1Scalar {
    Bp512r1Scalar::from_limbs(limbs)
}

fn assert_result_is(k_limbs: [u64; 8], x: [u64; 8], y: [u64; 8]) {
    let result = comb_multiply_base_point(&scalar(k_limbs));
    let (rx, ry) = result.to_affine().expect("[k]G must not be infinity for k in (0, n)");
    assert_eq!(rx, Bp512r1FieldElement::from_limbs(x), "x mismatch for k = {k_limbs:x?}");
    assert_eq!(ry, Bp512r1FieldElement::from_limbs(y), "y mismatch for k = {k_limbs:x?}");
}

#[test]
fn known_answer_small_k() {
    assert_result_is([1, 0, 0, 0, 0, 0, 0, 0], G_X_LIMBS, G_Y_LIMBS);
    assert_result_is(
        [2, 0, 0, 0, 0, 0, 0, 0],
        [
            0x080447def02f4850, 0xf698f404089a4cc5, 0x97116e702915a4f4, 0x957877f3a8f0f725,
            0xa30d3035f4cb6581, 0xd18d8141b8a18064, 0x0a63285758f399b3, 0x9f4945f680edf980,
        ],
        [
            0xe269ad21be592e71, 0x63a42e4181fd929c, 0xa5c3b602b0960cbf, 0xfdf99bb1709c700f,
            0x5a2c366b03e5d1b2, 0x149ce1238d3f1e0f, 0x49826b716292f29d, 0x6d6b4b188b699c56,
        ],
    );
    assert_result_is(
        [3, 0, 0, 0, 0, 0, 0, 0],
        [
            0x5d4abf882ccb8d94, 0xf56e34abfa9ac720, 0x4780ae53e1853d62, 0xc1f6fb975ceecade,
            0x09c09cefd830151b, 0x907c80ef3bc24593, 0x36cdd42543f20afe, 0x08dd87e12b0a4cc4,
        ],
        [
            0x5cdeafba05b02c37, 0x8cce5bc75d8de649, 0xfebfcb69c0f37c5f, 0xacdab8eb772327b3,
            0xba0b382e1716d843, 0x43d903b4a6334c4b, 0x756ff0067376fa75, 0x026ef5c6e1dab71d,
        ],
    );
}

#[test]
fn known_answer_large_k() {
    let k: [u64; 8] = [
        0x87853ca374a7f4e4, 0xae79c9c15dca288b, 0xe330aea7be2add07, 0x0a579fad505bf7b1,
        0x51f409ed641a5248, 0x392469d4a9acbb2d, 0x53c9bde28cb547c0, 0x7de160dffa4cc3d1,
    ];
    assert_result_is(
        k,
        [
            0x534af60225340e7d, 0xe6db088083d684b3, 0xde9649b05f5e52d7, 0x429fbc57716a8a9f,
            0xa1cb1bd40c08f996, 0xab75449a47e5e522, 0xd4211cccea3aff37, 0x0ed19b96369de5cc,
        ],
        [
            0x13405e9186c46db0, 0xe1e511ffb03ea95c, 0xb539aa547ccec7c9, 0x0c25f04aef0c65e4,
            0xd655f73c2cbd06da, 0x4b7a7fe305671709, 0x50469ea0652c8ee7, 0x9cf1116ec20e9e70,
        ],
    );
}

#[test]
fn edge_case_k_equals_n_minus_1() {
    // (n-1)*G == -G: same x as G, negated y.
    let n_minus_1: [u64; 8] = [
        0xb58796829ca90068, 0x1db1d381085ddadd, 0x418661197fac1047, 0x553e5c414ca92619,
        0xd6639cca70330870, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
    ];
    assert_result_is(
        n_minus_1,
        G_X_LIMBS,
        [
            0xafdd42471d624061, 0x56b7d3ff8492727e, 0x530355525c7c1d37, 0xca70bcb751671fe4,
            0x3662d76ee813875f, 0xd92696b38f2456f4, 0x7eea27046451d909, 0x2cff655b8586919e,
        ],
    );
}

/// `k = 0` is the one scalar for which `[k]G` is the identity: every comb digit is `0`, so every
/// round selects table entry `0` (the infinity sentinel) and the accumulator never leaves
/// `INFINITY`. Nothing in the signing path can produce it (`k` is in `[1, n-1]` by construction),
/// which is exactly why it needs pinning here rather than being left to chance.
#[test]
fn edge_case_k_equals_zero_is_infinity() {
    let result = comb_multiply_base_point(&scalar([0u64; 8]));
    assert!(result.is_infinity().to_bool());
    assert!(result.to_affine().is_none());
}
