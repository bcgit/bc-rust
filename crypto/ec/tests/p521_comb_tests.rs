//! Known-answer tests for [`comb_multiply_base_point`] (`[k]G`), P-521.

use bouncycastle_ec::p521::P521FieldElement;
use bouncycastle_ec::p521_comb::comb_multiply_base_point;
use bouncycastle_ec::p521_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p521_scalar::P521Scalar;

fn scalar(limbs: [u64; 9]) -> P521Scalar {
    P521Scalar::from_limbs(limbs)
}

fn assert_result_is(k_limbs: [u64; 9], x: [u64; 9], y: [u64; 9]) {
    let result = comb_multiply_base_point(&scalar(k_limbs));
    let (rx, ry) = result.to_affine().expect("[k]G must not be infinity for k in (0, n)");
    assert_eq!(rx, P521FieldElement::from_limbs(x), "x mismatch for k = {k_limbs:x?}");
    assert_eq!(ry, P521FieldElement::from_limbs(y), "y mismatch for k = {k_limbs:x?}");
}

#[test]
fn known_answer_small_k() {
    assert_result_is([1, 0, 0, 0, 0, 0, 0, 0, 0], G_X_LIMBS, G_Y_LIMBS);
    assert_result_is(
        [5, 0, 0, 0, 0, 0, 0, 0, 0],
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
fn known_answer_large_k() {
    let k: [u64; 9] = [
        0x567890abcdef1234, 0x567890abcdef1234, 0x567890abcdef1234, 0x567890abcdef1234,
        0x567890abcdef1234, 0x567890abcdef1234, 0x0000000000001234, 0x0000000000000000,
        0x0000000000000000,
    ];
    assert_result_is(
        k,
        [
            0x9c699e0dc9fc64bd, 0x71fd91794bcdc2a0, 0xc5931b2b3c897eca, 0x6a436b057927cd65,
            0x134afc788e3091d1, 0x184c257a06780b62, 0x89e928cbc24609e1, 0x1d7e631e94d5d55e,
            0x0000000000000090,
        ],
        [
            0x16e3badd0f622dd6, 0xc4bdc69316f08a60, 0xe3e41939aef7be70, 0x7f7b5988fddfab94,
            0xdc1bd8be391d5c9e, 0xc81a987e9e63dbda, 0x71184edd42174cd9, 0x66263adc88c73be8,
            0x000000000000017a,
        ],
    );
}

#[test]
fn edge_case_k_equals_n_minus_1() {
    // (n-1)*G == -G: same x as G, negated y.
    let n_minus_1: [u64; 9] = [
        0xbb6fb71e91386408, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0, 0x51868783bf2f966b,
        0xfffffffffffffffa, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
        0x00000000000001ff,
    ];
    assert_result_is(
        n_minus_1,
        G_X_LIMBS,
        [
            0x77416b89602e99af, 0xcac38f795d8d3dbf, 0x3aaf46fec052f89e, 0x68118d66a10bd9bf,
            0xe85042e8d8c199d3, 0x670abbb6a864bb97, 0xa375a04bd382e426, 0xc6d6958765c43ffb,
            0x00000000000000e7,
        ],
    );
}

/// `k = 0` is the one scalar for which `[k]G` is the identity: every comb digit is `0`, so every
/// round selects table entry `0` (the infinity sentinel) and the accumulator never leaves
/// `INFINITY`. Nothing in the signing path can produce it (`k` is in `[1, n-1]` by construction),
/// which is exactly why it needs pinning here rather than being left to chance.
#[test]
fn edge_case_k_equals_zero_is_infinity() {
    let result = comb_multiply_base_point(&scalar([0u64; 9]));
    assert!(result.is_infinity().to_bool());
    assert!(result.to_affine().is_none());
}
