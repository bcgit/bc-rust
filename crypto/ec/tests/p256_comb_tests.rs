//! Known-answer tests for [`comb_multiply_base_point`] (`[k]G`).
//!
//! Small-`k` vectors reuse the `k*G` values from `p256_point_tests.rs` (independently computed
//! from the SP 800-186 Appendix A.1.1 affine group law). The larger `k` vectors below were
//! generated the same way, with `random.seed(303)`, plus `k = n-1` (the edge case where `[k]G =
//! -G`, since `n*G` is the identity).

use bouncycastle_ec::p256::P256FieldElement;
use bouncycastle_ec::p256_comb::comb_multiply_base_point;
use bouncycastle_ec::p256_scalar::P256Scalar;

fn scalar(limbs: [u64; 4]) -> P256Scalar {
    P256Scalar::from_limbs(limbs)
}

fn assert_result_is(k_limbs: [u64; 4], x: [u64; 4], y: [u64; 4]) {
    let result = comb_multiply_base_point(&scalar(k_limbs));
    let (rx, ry) = result.to_affine().expect("[k]G must not be infinity for k in (0, n)");
    assert_eq!(rx, P256FieldElement::from_limbs(x), "x mismatch for k = {k_limbs:x?}");
    assert_eq!(ry, P256FieldElement::from_limbs(y), "y mismatch for k = {k_limbs:x?}");
}

#[test]
fn known_answer_small_k() {
    // k=1 (G), k=2, k=3, k=5, k=7, k=11, k=13 -- same values as p256_point_tests.rs's P1..P13.
    assert_result_is(
        [1, 0, 0, 0],
        [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247],
        [0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b],
    );
    assert_result_is(
        [2, 0, 0, 0],
        [0xa60b48fc47669978, 0xc08969e277f21b35, 0x8a52380304b51ac3, 0x7cf27b188d034f7e],
        [0x9e04b79d227873d1, 0xba7dade63ce98229, 0x293d9ac69f7430db, 0x07775510db8ed040],
    );
    assert_result_is(
        [3, 0, 0, 0],
        [0xfb41661bc6e7fd6c, 0xe6c6b721efada985, 0xc8f7ef951d4bf165, 0x5ecbe4d1a6330a44],
        [0x9a79b127a27d5032, 0xd82ab036384fb83d, 0x374b06ce1a64a2ec, 0x8734640c4998ff7e],
    );
    assert_result_is(
        [7, 0, 0, 0],
        [0x300628703187b2a3, 0x7ef9f8b8a80fef5b, 0x25bb30667c01fb60, 0x8e533b6fa0bf7b46],
        [0xc55e1a86c1f400b4, 0x53c73633cb041b21, 0x6d069f83a6f59000, 0x73eb1dbde0331836],
    );
    assert_result_is(
        [13, 0, 0, 0],
        [0x98e15d9d46072c01, 0x792e284b65ead58a, 0x61805df2d85ee2fc, 0x177c837ae0ac495a],
        [0x9c43bbe2efc7bfd8, 0x26ee14c3a1fb4df3, 0xa24091adb40f4e72, 0x63bb58cd4ebea558],
    );
}

#[test]
fn known_answer_large_k() {
    assert_result_is(
        [0x3d7c9ec7081ab44e, 0xbd8ec9a1f80385ed, 0x17857e0831e5554e, 0x90f26b82fe915329],
        [0x79ce9c83502a5578, 0xc619b85acd90b588, 0x11dae3072ce0c11b, 0xce802709673a3576],
        [0x41dd580f255b3b01, 0x7bddfdd6fa7a185a, 0x9bb6d2c693f682ff, 0x568f5771239c118b],
    );
    assert_result_is(
        [0x9f8573c9f25dc994, 0x9115361f42389a31, 0xfc83ab74842a0944, 0x285f078965f5a299],
        [0xbe5c2efa594cb48e, 0x696aaf1b094a0c0b, 0xcdc19ac4148aff9c, 0x7738f3399f918ccf],
        [0x9b7a003b13bfc146, 0xa47a04fb6f1addf8, 0x9d808272ab79b368, 0x877990fc238f16b0],
    );
    assert_result_is(
        [0x790d02ba68e2b293, 0x952cb98dca28e0ce, 0x1699fd1dd3e61f5f, 0x874ea8e941ac9159],
        [0xd76531a06fcb9e02, 0xeaa2bf9bba167f7a, 0xe8e48ec2676f3496, 0x0eaaf59c3e417ccf],
        [0x28cefc08078ab1e2, 0xcaa9f65e6dfaa4d6, 0x177bb38b4e337bc7, 0x7bf64c66ed9874b9],
    );
    assert_result_is(
        [0xc59a61378b3dda8e, 0x083d8f37af9e4e0d, 0xd253304398079d69, 0xb1e815b91f17e93f],
        [0xe16fd84feccd5f54, 0x54dd53df8b2bc858, 0x74ca22b12e5aa2e3, 0x83dbb91599c15293],
        [0xcca8553f261cb315, 0x9752d7c526d1777b, 0x356b80cb0ee111d8, 0xcae8485e5e74b3a6],
    );
}

#[test]
fn edge_case_k_equals_n_minus_1() {
    // (n-1)*G == -G: same x as G, negated y.
    assert_result_is(
        [0xf3b9cac2fc632550, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000],
        [0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247],
        [0x3449bf97c840ae0a, 0xd431cca994cea131, 0x711814b583f061e9, 0xb01cbd1c01e58065],
    );
}
