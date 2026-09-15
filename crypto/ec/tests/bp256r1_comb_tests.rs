//! Known-answer tests for [`comb_multiply_base_point`] (`[k]G`), brainpoolP256r1.
//!
//! `k = 2, 3` reuse the values verified independently in `bp256r1_point_tests.rs`; `k` for
//! `known_answer_large_k` and `n-1` (where `[k]G = -G`) were computed the same way (Python affine
//! group law, general `a`), `random.seed(628256)` for the former.

use bouncycastle_ec::bp256r1::Bp256r1FieldElement;
use bouncycastle_ec::bp256r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp256r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp256r1_scalar::Bp256r1Scalar;

fn scalar(limbs: [u64; 4]) -> Bp256r1Scalar {
    Bp256r1Scalar::from_limbs(limbs)
}

fn assert_result_is(k_limbs: [u64; 4], x: [u64; 4], y: [u64; 4]) {
    let result = comb_multiply_base_point(&scalar(k_limbs));
    let (rx, ry) = result.to_affine().expect("[k]G must not be infinity for k in (0, n)");
    assert_eq!(rx, Bp256r1FieldElement::from_limbs(x), "x mismatch for k = {k_limbs:x?}");
    assert_eq!(ry, Bp256r1FieldElement::from_limbs(y), "y mismatch for k = {k_limbs:x?}");
}

#[test]
fn known_answer_small_k() {
    assert_result_is([1, 0, 0, 0], G_X_LIMBS, G_Y_LIMBS);
    assert_result_is(
        [2, 0, 0, 0],
        [0xd51a14c2ce13ea0e, 0x36ef044166699e37, 0xb55f8aa369593ac4, 0x743cf1b8b5cd4f2e],
        [0x892ada097eeb7cd4, 0x38df059f69249406, 0x946fe0bb776529da, 0x36ed163337deba9c],
    );
    assert_result_is(
        [3, 0, 0, 0],
        [0x6b91e2ad25cae39d, 0xd2aa843d0c0fca01, 0xd6624c3ab4f6cc16, 0xa8f217b77338f1d4],
        [0x7e65cc5602b74f9d, 0xfac10e4589348fb7, 0x0aa2a6850a1b40f5, 0x4b49cafc7dac26bb],
    );
}

#[test]
fn known_answer_large_k() {
    let k: [u64; 4] =
        [0x212709183943ca3e, 0x544272ddbf740a68, 0x6b35d760af6377e2, 0x7e72f2a30e3279c2];
    assert_result_is(
        k,
        [0xd5926c7536cd5b6f, 0x43fd851180cd5eb6, 0x53935733164d2188, 0x6bfea2ac64a53e7d],
        [0xbf7d9c2e9e6a16c7, 0x7ab99319bfc3bd9a, 0xd9ea86a322cd326b, 0xa7ccb8b1348e5931],
    );
}

#[test]
fn edge_case_k_equals_n_minus_1() {
    // (n-1)*G == -G: same x as G, negated y.
    let n_minus_1: [u64; 4] =
        [0x901e0e82974856a6, 0x8c397aa3b561a6f7, 0x3e660a909d838d71, 0xa9fb57dba1eea9bc];
    assert_result_is(
        n_minus_1,
        G_X_LIMBS,
        [0xc3f5f355f069e9e0, 0xabc4b110a73891d3, 0xa66dc47689226fa8, 0x557c5fa5de13e4be],
    );
}
