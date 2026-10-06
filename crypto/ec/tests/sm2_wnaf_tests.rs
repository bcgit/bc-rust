//! Known-answer tests for [`shamir_multiply`] (`[u]G + [v]Q`), SM2.
//!
//! `Q` below is `d*G` for a fixed test-only `d` (not a real key). Expected results were computed
//! independently in Python from the affine group law (`a = -3`), the same way as
//! `sm2_comb_tests.rs`, with `random.seed(808917)`.

use bouncycastle_ec::sm2::Sm2FieldElement;
use bouncycastle_ec::sm2_comb::comb_multiply_base_point;
use bouncycastle_ec::sm2_point::Sm2JacobianPoint;
use bouncycastle_ec::sm2_scalar::{Sm2PublicScalar, Sm2Scalar};
use bouncycastle_ec::sm2_wnaf::shamir_multiply;

const Q_X: [u64; 4] =
    [0x30e4445e9ced5d35, 0x9403c12a2c8e5f2b, 0x066493e2dd175d35, 0x414278ad63916c59];
const Q_Y: [u64; 4] =
    [0xe1d32f6895b01fba, 0x15a5930808e4ebca, 0xe8c91327428a11ef, 0x8b8381a3b29ecdd5];

fn q() -> Sm2JacobianPoint {
    Sm2JacobianPoint::from_affine(
        Sm2FieldElement::from_limbs(Q_X),
        Sm2FieldElement::from_limbs(Q_Y),
    )
}

fn scalar(limbs: [u64; 4]) -> Sm2PublicScalar {
    Sm2PublicScalar::from_limbs(limbs)
}

fn assert_result_is(u: [u64; 4], v: [u64; 4], expected_x: [u64; 4], expected_y: [u64; 4]) {
    let result = shamir_multiply(&scalar(u), &scalar(v), &q());
    let (rx, ry) = result.to_affine().expect("expected a non-infinity result");
    assert_eq!(rx, Sm2FieldElement::from_limbs(expected_x), "x mismatch for u={u:x?} v={v:x?}");
    assert_eq!(ry, Sm2FieldElement::from_limbs(expected_y), "y mismatch for u={u:x?} v={v:x?}");
}

#[test]
fn known_answer_large_u_v() {
    let u: [u64; 4] =
        [0xb6354f7dc5327e8c, 0x7066452f6836347d, 0x6eb944867e5078ec, 0xa421b5e9b502718b];
    let v: [u64; 4] =
        [0x9e5ca34c198b2335, 0x613ec89b206a2e3e, 0x6694fd0186e14175, 0x79760b91eea092e0];
    assert_result_is(
        u,
        v,
        [0x6a7b40d34ed83d66, 0xb68575756e80961c, 0x535bf7db19e8c493, 0xeb628a48ea4cb0b2],
        [0xa30c82d2cf878375, 0x3178dbe8b7ceb98d, 0x874841d289fe9ec2, 0xd510a3dac4e0766d],
    );
}

#[test]
fn edge_case_v_is_zero_reduces_to_u_times_g() {
    assert_result_is(
        [5, 0, 0, 0],
        [0, 0, 0, 0],
        [0xa575da57cc372a9e, 0x344a417b7fce19db, 0x040e008fdd5eb77a, 0xc749061668652e26],
        [0xa6976eff5fbe6480, 0x5006206eb579ff7d, 0x4504c622b51cf38f, 0xf2df5db2d144e945],
    );
}

#[test]
fn edge_case_u_is_zero_reduces_to_v_times_q() {
    assert_result_is(
        [0, 0, 0, 0],
        [5, 0, 0, 0],
        [0x6eef35f83dd36eba, 0x5c06a43c93b48594, 0xce7cb7da9c4e7fad, 0x6c2c5adb6dff6097],
        [0xbc55a2835f29e68c, 0xfb2b16c31bc2a758, 0x47a41c4ed446f5d7, 0xe6ad613ed91ba836],
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
        let via_comb = comb_multiply_base_point(&Sm2Scalar::from_limbs(k_limbs));
        let via_wnaf =
            shamir_multiply(&Sm2PublicScalar::from_limbs(k_limbs), &scalar([0; 4]), &q());
        assert_eq!(via_comb.to_affine(), via_wnaf.to_affine(), "k = {k_limbs:x?}");
    }
}

/// Every other test in this file uses one fixed `Q = dG`. The three `Q` values here each take a
/// path that one cannot: `Q = infinity` makes every `[v]Q` digit an addition of the identity,
/// `Q = G` makes the two precomputed odd-multiple tables identical (so the interleaved
/// additions hit the same-point case of `add_vartime`), and `Q = -G` makes them negatives of
/// each other (the opposite-point case, and with `u == v` a final result of infinity). Expected
/// values come from the fixed-base comb multiplier on the combined scalar, which is pinned by
/// its own known-answer tests.
#[test]
fn edge_case_q_is_infinity_g_or_minus_g() {
    let g = Sm2JacobianPoint::from_affine(
        Sm2FieldElement::from_limbs(bouncycastle_ec::sm2_domain::G_X_LIMBS),
        Sm2FieldElement::from_limbs(bouncycastle_ec::sm2_domain::G_Y_LIMBS),
    );
    let mut u = [0u64; 4];
    u[0] = 12345;
    let mut v = [0u64; 4];
    v[0] = 6789;
    let mut u_plus_v = [0u64; 4];
    u_plus_v[0] = 19134;
    let mut u_minus_v = [0u64; 4];
    u_minus_v[0] = 5556;
    let via_comb = |k: [u64; 4]| comb_multiply_base_point(&Sm2Scalar::from_limbs(k)).to_affine();

    // [u]G + [v]infinity == [u]G
    assert_eq!(
        shamir_multiply(&scalar(u), &scalar(v), &Sm2JacobianPoint::INFINITY).to_affine(),
        via_comb(u)
    );
    // [u]G + [v]G == [u+v]G
    assert_eq!(shamir_multiply(&scalar(u), &scalar(v), &g).to_affine(), via_comb(u_plus_v));
    // [u]G + [v](-G) == [u-v]G
    assert_eq!(
        shamir_multiply(&scalar(u), &scalar(v), &g.negate()).to_affine(),
        via_comb(u_minus_v)
    );
    // [u]G + [u](-G) == infinity
    assert!(shamir_multiply(&scalar(u), &scalar(u), &g.negate()).is_infinity().to_bool());
    // [0]G + [v]G == [v]G: the G table is never consulted, only Q's
    assert_eq!(shamir_multiply(&scalar([0u64; 4]), &scalar(v), &g).to_affine(), via_comb(v));
}
