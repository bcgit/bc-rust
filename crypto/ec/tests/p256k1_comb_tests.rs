//! Known-answer tests for [`comb_multiply_base_point`] (`[k]G`), secp256k1.
//!
//! `k = 2, 3` reuse the values verified independently in `p256k1_point_tests.rs`; `k` for
//! `known_answer_large_k` and `n-1` (where `[k]G = -G`) were computed the same way (Python affine
//! group law, `a = 0`), `random.seed(1246)` for the former.

use bouncycastle_ec::p256k1::P256K1FieldElement;
use bouncycastle_ec::p256k1_comb::comb_multiply_base_point;
use bouncycastle_ec::p256k1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p256k1_scalar::P256K1Scalar;

fn scalar(limbs: [u64; 4]) -> P256K1Scalar {
    P256K1Scalar::from_limbs(limbs)
}

fn assert_result_is(k_limbs: [u64; 4], x: [u64; 4], y: [u64; 4]) {
    let result = comb_multiply_base_point(&scalar(k_limbs));
    let (rx, ry) = result.to_affine().expect("[k]G must not be infinity for k in (0, n)");
    assert_eq!(rx, P256K1FieldElement::from_limbs(x), "x mismatch for k = {k_limbs:x?}");
    assert_eq!(ry, P256K1FieldElement::from_limbs(y), "y mismatch for k = {k_limbs:x?}");
}

#[test]
fn known_answer_small_k() {
    assert_result_is([1, 0, 0, 0], G_X_LIMBS, G_Y_LIMBS);
    assert_result_is(
        [2, 0, 0, 0],
        [0xabac09b95c709ee5, 0x5c778e4b8cef3ca7, 0x3045406e95c07cd8, 0xc6047f9441ed7d6d],
        [0x236431a950cfe52a, 0xf7f632653266d0e1, 0xa3c58419466ceaee, 0x1ae168fea63dc339],
    );
    assert_result_is(
        [3, 0, 0, 0],
        [0x8601f113bce036f9, 0xb531c845836f99b0, 0x49344f85f89d5229, 0xf9308a019258c310],
        [0x6cb9fd7584b8e672, 0x6500a99934c2231b, 0x0fe337e62a37f356, 0x388f7b0f632de814],
    );
}

#[test]
fn known_answer_large_k() {
    let k: [u64; 4] =
        [0x0f6492cb2a9bcd60, 0x203c90bb86fdcf60, 0x973e8813bb3b3b8f, 0x0a5b2b964ff75db2];
    assert_result_is(
        k,
        [0xa08ae34de00c7157, 0xe3005a4271afb456, 0x76db92696a558cea, 0xef077c553000618c],
        [0xcca36d4110e18f30, 0xf02ed559a3150cb0, 0xa3a0f3cf2da0aef0, 0x53a38aae0db4d23d],
    );
}

#[test]
fn edge_case_k_equals_n_minus_1() {
    // (n-1)*G == -G: same x as G, negated y.
    let n_minus_1: [u64; 4] =
        [0xbfd25e8cd0364140, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff];
    assert_result_is(
        n_minus_1,
        G_X_LIMBS,
        [0x63b82f6f04ef2777, 0x02e84bb7597aabe6, 0xa25b0403f1eef757, 0xb7c52588d95c3b9a],
    );
}
