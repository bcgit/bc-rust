//! Known-answer tests for [`comb_multiply_base_point`] (`[k]G`), P-384.
//!
//! `k = 2, 3` reuse the values verified independently in `p384_point_tests.rs`; `k = n-1` (where
//! `[k]G = -G`) was computed the same way (Python affine group law), `random.seed` not applicable
//! since it's a fixed edge case.

use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_comb::comb_multiply_base_point;
use bouncycastle_ec::p384_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p384_scalar::P384Scalar;

fn scalar(limbs: [u64; 6]) -> P384Scalar {
    P384Scalar::from_limbs(limbs)
}

fn assert_result_is(k_limbs: [u64; 6], x: [u64; 6], y: [u64; 6]) {
    let result = comb_multiply_base_point(&scalar(k_limbs));
    let (rx, ry) = result.to_affine().expect("[k]G must not be infinity for k in (0, n)");
    assert_eq!(rx, P384FieldElement::from_limbs(x), "x mismatch for k = {k_limbs:x?}");
    assert_eq!(ry, P384FieldElement::from_limbs(y), "y mismatch for k = {k_limbs:x?}");
}

#[test]
fn known_answer_small_k() {
    assert_result_is([1, 0, 0, 0, 0, 0], G_X_LIMBS, G_Y_LIMBS);
    assert_result_is(
        [2, 0, 0, 0, 0, 0],
        [
            0x5b96a9c75295df61, 0x4fe0e86ebe0e64f8, 0x51d207d19fb96e9e, 0x89025959a6f434d6,
            0x69260045c55b97f0, 0x08d999057ba3d2d9,
        ],
        [
            0x61501e700a940e80, 0x5ffd43e94d39e22d, 0x904e505f256ab425, 0xb275d875bc6cc43e,
            0xb7bfe8dffd6dba74, 0x8e80f1fa5b1b3ced,
        ],
    );
    assert_result_is(
        [3, 0, 0, 0, 0, 0],
        [
            0x02d7e5c70500c831, 0xb408bbae5026580d, 0xbea4f240d3566da6, 0xcb9d3910202dcd06,
            0x64793c7e5fdc7d98, 0x077a41d4606ffa14,
        ],
        [
            0xb65f28600a2f1df1, 0xc24abd6be4b5d298, 0xf7684c0edc111eac, 0x8520b41c85115aa5,
            0x7d0bbe9602a9fc99, 0xc995f7ca0b0c4283,
        ],
    );
}

#[test]
fn known_answer_large_k() {
    let k: [u64; 6] = [
        0x1c80317fa3b1799e, 0xbdd640fb06671ad1, 0x3eb13b9046685257, 0x23b8c1e9392456de,
        0x1a3d1fa7bc8960a9, 0xbd9c66b3ad3c2d6d,
    ];
    assert_result_is(
        k,
        [
            0x7dd57ff886515cdc, 0x1c8525be6c64cc60, 0xefed50c6fe1a5b18, 0x251871a6fb5bccea,
            0x1c65ee00efce13bc, 0x0c10d4b4eeddcc19,
        ],
        [
            0x74f5e7f52e41abc6, 0x8d3ba3290d37622d, 0x6974925761e35ace, 0x688dd2ead26f7c83,
            0xdec652bf66370892, 0x036b7085ab9c77bd,
        ],
    );
}

#[test]
fn edge_case_k_equals_n_minus_1() {
    // (n-1)*G == -G: same x as G, negated y.
    let n_minus_1: [u64; 6] = [
        0xecec196accc52972, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff,
    ];
    assert_result_is(
        n_minus_1,
        G_X_LIMBS,
        [
            0x85bce2846f15f1a0, 0xf59f4e30e2817e62, 0x1625ceec4a0f473e, 0x070be242d765eb83,
            0xa26167406d6d23d6, 0xc9e821b569d9d390,
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
