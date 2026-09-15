//! Known-answer tests for [`shamir_multiply`] (`[u]G + [v]Q`), secp256k1.
//!
//! `Q` below is `d*G` for a fixed test-only `d` (not a real key). Expected results were computed
//! independently in Python from the affine group law (`a = 0`), the same way as
//! `p256k1_comb_tests.rs`, with `random.seed(808384)`.

use bouncycastle_ec::p256k1::P256K1FieldElement;
use bouncycastle_ec::p256k1_comb::comb_multiply_base_point;
use bouncycastle_ec::p256k1_point::P256K1JacobianPoint;
use bouncycastle_ec::p256k1_scalar::{P256K1PublicScalar, P256K1Scalar};
use bouncycastle_ec::p256k1_wnaf::shamir_multiply;

const Q_X: [u64; 4] =
    [0x0ea6f07bd759d339, 0xb96d88cc46f523cb, 0x20ca70079f805400, 0x4b0096e546d82613];
const Q_Y: [u64; 4] =
    [0xa8ce78f807726fe5, 0x16a050fb2e947cd2, 0xabd80676941bde4a, 0x007c58c019edf2a3];

fn q() -> P256K1JacobianPoint {
    P256K1JacobianPoint::from_affine(
        P256K1FieldElement::from_limbs(Q_X),
        P256K1FieldElement::from_limbs(Q_Y),
    )
}

fn scalar(limbs: [u64; 4]) -> P256K1PublicScalar {
    P256K1PublicScalar::from_limbs(limbs)
}

fn assert_result_is(u: [u64; 4], v: [u64; 4], expected_x: [u64; 4], expected_y: [u64; 4]) {
    let result = shamir_multiply(&scalar(u), &scalar(v), &q());
    let (rx, ry) = result.to_affine().expect("expected a non-infinity result");
    assert_eq!(rx, P256K1FieldElement::from_limbs(expected_x), "x mismatch for u={u:x?} v={v:x?}");
    assert_eq!(ry, P256K1FieldElement::from_limbs(expected_y), "y mismatch for u={u:x?} v={v:x?}");
}

#[test]
fn known_answer_large_u_v() {
    let u: [u64; 4] =
        [0xc8c7279f85b5b57e, 0xdf4dc003c482b49d, 0xcf9d0a68d7fd9586, 0x72c8c95608f4eb96];
    let v: [u64; 4] =
        [0x48403aad19a04ae7, 0x74cc2df91a4a3ac6, 0xa73e462c3bc5bf0c, 0x838e541242a28502];
    assert_result_is(
        u,
        v,
        [0xd185e96f95c8b444, 0x4921c6651314526c, 0x38dda3e43e50e5bf, 0xe2df93a43c571e20],
        [0xb4f92d6e47a72846, 0xfb2aa735ae915e40, 0x970c60619d1cdd81, 0x21401303f02495dd],
    );
}

#[test]
fn edge_case_v_is_zero_reduces_to_u_times_g() {
    assert_result_is(
        [5, 0, 0, 0],
        [0, 0, 0, 0],
        [0xcba8d569b240efe4, 0xe88b84bddc619ab7, 0x55b4a7250a5c5128, 0x2f8bde4d1a072093],
        [0xdca87d3aa6ac62d6, 0xf788271bab0d6840, 0xd4dba9dda6c9c426, 0xd8ac222636e5e3d6],
    );
}

#[test]
fn edge_case_u_is_zero_reduces_to_v_times_q() {
    assert_result_is(
        [0, 0, 0, 0],
        [5, 0, 0, 0],
        [0xd6c3a13d8c58cf02, 0xce9fd201290122ed, 0x862cfc348c1b578d, 0x1c2dead1b2b00ca4],
        [0x5b8af69af5dcf730, 0x0464a19ce8f84a23, 0xd163788cfd503a3c, 0x0dce7d767a5e38c7],
    );
}

#[test]
fn edge_case_both_zero_is_infinity() {
    let result = shamir_multiply(&scalar([0; 4]), &scalar([0; 4]), &q());
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

    fn next_limbs(&mut self) -> [u64; 4] {
        [self.next_u64(), self.next_u64(), self.next_u64(), self.next_u64()]
    }
}

#[test]
fn cross_checked_against_the_comb_multiplier_over_many_pseudorandom_scalars() {
    // shamir_multiply(k, 0, anything) must equal comb_multiply_base_point(k): two independently
    // implemented multipliers (fixed-base comb vs. interleaved wNAF) computing the same [k]G.
    let mut rng = Xorshift64(0xE7C558A6A6E7F1DE);
    for _ in 0..500 {
        let k_limbs = rng.next_limbs();
        let via_comb = comb_multiply_base_point(&P256K1Scalar::from_limbs(k_limbs));
        let via_wnaf =
            shamir_multiply(&P256K1PublicScalar::from_limbs(k_limbs), &scalar([0; 4]), &q());
        assert_eq!(via_comb.to_affine(), via_wnaf.to_affine(), "k = {k_limbs:x?}");
    }
}
