//! Known-answer tests for [`comb_multiply_base_point`] (`[k]G`), SM2.
//!
//! `k = 2, 3` reuse the values verified independently in `sm2_point_tests.rs`; `k` for
//! `known_answer_large_k` and `n-1` (where `[k]G = -G`) were computed the same way (Python affine
//! group law, `a = -3`), `random.seed(628917)` for the former.

use bouncycastle_ec::sm2::Sm2FieldElement;
use bouncycastle_ec::sm2_comb::comb_multiply_base_point;
use bouncycastle_ec::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::sm2_scalar::Sm2Scalar;

fn scalar(limbs: [u64; 4]) -> Sm2Scalar {
    Sm2Scalar::from_limbs(limbs)
}

fn assert_result_is(k_limbs: [u64; 4], x: [u64; 4], y: [u64; 4]) {
    let result = comb_multiply_base_point(&scalar(k_limbs));
    let (rx, ry) = result.to_affine().expect("[k]G must not be infinity for k in (0, n)");
    assert_eq!(rx, Sm2FieldElement::from_limbs(x), "x mismatch for k = {k_limbs:x?}");
    assert_eq!(ry, Sm2FieldElement::from_limbs(y), "y mismatch for k = {k_limbs:x?}");
}

#[test]
fn known_answer_small_k() {
    assert_result_is([1, 0, 0, 0], G_X_LIMBS, G_Y_LIMBS);
    assert_result_is(
        [2, 0, 0, 0],
        [0x495c2e1da3f2bd52, 0x9c0dfa08c08a7331, 0x0d58ef57fa73ba4d, 0x56cefd60d7c87c00],
        [0x6f780d3a970a23c3, 0x6de84c182f6c8e71, 0x68535ce0f8eaf1bd, 0x31b7e7e6cc8189f6],
    );
    assert_result_is(
        [3, 0, 0, 0],
        [0xe26918f1d0509ebf, 0xa13f6bd945302244, 0xbe2daa8cdb41e24c, 0xa97f7cd4b3c993b4],
        [0xaaacdd037458f6e6, 0x7c400ee5cd045292, 0xccc5cec08a72150f, 0x530b5dd88c688ef5],
    );
}

#[test]
fn known_answer_large_k() {
    let k: [u64; 4] =
        [0x390615907482bbf0, 0xee561b21ad65d466, 0x7ed50428cefb0fcc, 0xc876addf81b5d6d3];
    assert_result_is(
        k,
        [0x7b1a3e3203faefbd, 0x373334e5db156744, 0x1a22334ca73760b7, 0xdb74a8b512b45996],
        [0x1d5911cd8455f119, 0xf8ec3aa79e7f63b5, 0xa765d19380fe040d, 0x6107f4d9950060d7],
    );
}

#[test]
fn edge_case_k_equals_n_minus_1() {
    // (n-1)*G == -G: same x as G, negated y.
    let n_minus_1: [u64; 4] =
        [0x53bbf40939d54122, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff];
    assert_result_is(
        n_minus_1,
        G_X_LIMBS,
        [0xfd20cd1adec60f5f, 0x2f56788239d5b8c0, 0xa642311c9496deac, 0x43c8c95c0b098863],
    );
}

/// `k = 0` is the one scalar for which `[k]G` is the identity: every comb digit is `0`, so every
/// round selects table entry `0` (the infinity sentinel) and the accumulator never leaves
/// `INFINITY`. Nothing in the signing path can produce it (`k` is in `[1, n-1]` by construction),
/// which is exactly why it needs pinning here rather than being left to chance.
#[test]
fn edge_case_k_equals_zero_is_infinity() {
    let result = comb_multiply_base_point(&scalar([0u64; 4]));
    assert!(result.is_infinity().to_bool());
    assert!(result.to_affine().is_none());
}
