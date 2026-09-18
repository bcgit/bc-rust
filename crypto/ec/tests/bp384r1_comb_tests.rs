//! Known-answer tests for [`comb_multiply_base_point`] (`[k]G`), brainpoolP384r1.
//!
//! `k = 2, 3` reuse the values verified independently in `bp384r1_point_tests.rs`; `k` for
//! `known_answer_large_k` and `n-1` (where `[k]G = -G`) were computed the same way (Python affine
//! group law, general `a`), `random.seed(628384)` for the former.

use bouncycastle_ec::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::bp384r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp384r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp384r1_scalar::Bp384r1Scalar;

fn scalar(limbs: [u64; 6]) -> Bp384r1Scalar {
    Bp384r1Scalar::from_limbs(limbs)
}

fn assert_result_is(k_limbs: [u64; 6], x: [u64; 6], y: [u64; 6]) {
    let result = comb_multiply_base_point(&scalar(k_limbs));
    let (rx, ry) = result.to_affine().expect("[k]G must not be infinity for k in (0, n)");
    assert_eq!(rx, Bp384r1FieldElement::from_limbs(x), "x mismatch for k = {k_limbs:x?}");
    assert_eq!(ry, Bp384r1FieldElement::from_limbs(y), "y mismatch for k = {k_limbs:x?}");
}

#[test]
fn known_answer_small_k() {
    assert_result_is([1, 0, 0, 0, 0, 0], G_X_LIMBS, G_Y_LIMBS);
    assert_result_is(
        [2, 0, 0, 0, 0, 0],
        [
            0xb427b58df9d59fca, 0x7c4ba74a09b553eb, 0xec2f80c4e0f70df8, 0x0ad520b3eb6be4d6,
            0xb95c3495d7b4fd59, 0x2282bc382a2f4dfc,
        ],
        [
            0x8f1b29502b6e1d30, 0xb4b4ea69ab64fc28, 0x4d89dd051728fc3e, 0xce9bedbc170921ce,
            0x5768d14a24f37a57, 0x0edda83773ac6873,
        ],
    );
    assert_result_is(
        [3, 0, 0, 0, 0, 0],
        [
            0x7d7cc85b3035f11f, 0x3c11ef6596a3b889, 0x3ee1b6fcc7463bbe, 0x3df581348c6949f8,
            0x3b17452b6a27ebf5, 0x7b63205bf00ddae7,
        ],
        [
            0x81d7129d48772eb3, 0x73c0edaea3b8f593, 0x7b2bd39462363e03, 0x7b2eb481ead16a5c,
            0x5521a326bc02baaf, 0x761d3a4a5f809377,
        ],
    );
}

#[test]
fn known_answer_large_k() {
    let k: [u64; 6] = [
        0xe44e54d2e3f53e11, 0xa478d04d639ee021, 0xc7175d7fc6bd2622, 0x5255ca4f4e4bb63f,
        0xd4eb1f80a5dce29a, 0x4750f0f05ef0a726,
    ];
    assert_result_is(
        k,
        [
            0x4148e10e2b92329f, 0x6015335e1dd0d619, 0x5ac90c58222c91d7, 0x70e2ac39059dcb18,
            0x0428ae9a89c8c305, 0x18d71950a766bb77,
        ],
        [
            0x10a6b41526614628, 0xff52de7651315dd8, 0x2d53719a34fe2421, 0x44cd86eca5032cbe,
            0x3c1bacd9abdfb6ed, 0x60157c879854ba88,
        ],
    );
}

#[test]
fn edge_case_k_equals_n_minus_1() {
    // (n-1)*G == -G: same x as G, negated y.
    let n_minus_1: [u64; 6] = [
        0x3b883202e9046564, 0xcf3ab6af6b7fc310, 0x1f166e6cac0425a7, 0x152f7109ed5456b3,
        0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
    ];
    assert_result_is(
        n_minus_1,
        G_X_LIMBS,
        [
            0x44c4fcd20acb993e, 0x9e8d6108188b9960, 0x3115d4c98625e7fb, 0xb27865dfee67fe4f,
            0xb2ab83efbb166c8c, 0x01fb010d823eaa83,
        ],
    );
}

/// `k = 0` is the one scalar for which `[k]G` is the identity: every comb digit is `0`, so every
/// round selects table entry `0` (the infinity sentinel) and the accumulator never leaves
/// `INFINITY`. Nothing in the signing path can produce it (`k` is in `[1, n-1]` by construction),
/// which is exactly why it needs pinning here rather than being left to chance.
#[test]
fn edge_case_k_equals_zero_is_infinity() {
    let result = comb_multiply_base_point(&scalar([0u64; 6]));
    assert!(result.is_infinity().to_bool());
    assert!(result.to_affine().is_none());
}
