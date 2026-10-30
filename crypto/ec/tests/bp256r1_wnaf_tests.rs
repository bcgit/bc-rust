//! Known-answer tests for [`shamir_multiply`] (`[u]G + [v]Q`), brainpoolP256r1.
//!
//! `Q` below is `d*G` for a fixed test-only `d` (not a real key). Expected results were computed
//! independently in Python from the affine group law (general `a`), the same way as
//! `bp256r1_comb_tests.rs`, with `random.seed(808384)`.

use bouncycastle_ec::bp256r1::Bp256r1FieldElement;
use bouncycastle_ec::bp256r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp256r1_point::Bp256r1JacobianPoint;
use bouncycastle_ec::bp256r1_scalar::{Bp256r1PublicScalar, Bp256r1Scalar};
use bouncycastle_ec::bp256r1_wnaf::shamir_multiply;

const Q_X: [u64; 4] =
    [0xfec96d58db262cee, 0x2988091aa5352214, 0xf504fa7c525258cb, 0x168b3be33d1862b3];
const Q_Y: [u64; 4] =
    [0xec9068e7d3dc6b66, 0xe1dc7803f8f01613, 0xa4196062cbcc1858, 0x22e28e07075599e5];

fn q() -> Bp256r1JacobianPoint {
    Bp256r1JacobianPoint::from_affine(
        Bp256r1FieldElement::from_limbs(Q_X),
        Bp256r1FieldElement::from_limbs(Q_Y),
    )
}

fn scalar(limbs: [u64; 4]) -> Bp256r1PublicScalar {
    Bp256r1PublicScalar::from_limbs(limbs)
}

fn assert_result_is(u: [u64; 4], v: [u64; 4], expected_x: [u64; 4], expected_y: [u64; 4]) {
    let result = shamir_multiply(&scalar(u), &scalar(v), &q());
    let (rx, ry) = result.to_affine().expect("expected a non-infinity result");
    assert_eq!(rx, Bp256r1FieldElement::from_limbs(expected_x), "x mismatch for u={u:x?} v={v:x?}");
    assert_eq!(ry, Bp256r1FieldElement::from_limbs(expected_y), "y mismatch for u={u:x?} v={v:x?}");
}

#[test]
fn known_answer_large_u_v() {
    let u: [u64; 4] =
        [0x48403aad19a04ae7, 0x74cc2df91a4a3ac6, 0xa73e462c3bc5bf0c, 0x838e541242a28502];
    let v: [u64; 4] =
        [0xab460788b359c7e8, 0xc53f364b2831dc1d, 0x88aebe98b4707af4, 0x0cb0e573234caea1];
    assert_result_is(
        u,
        v,
        [0xbb838ffd0371790a, 0x4a6d6d80383ef9b4, 0x977db6b0671f717f, 0x690f712b194fca7f],
        [0x75521b078d47c966, 0x70d10ec465a9c3b6, 0x28640fe13c1fa2d3, 0x43df13a6d54004c1],
    );
}

#[test]
fn edge_case_v_is_zero_reduces_to_u_times_g() {
    assert_result_is(
        [5, 0, 0, 0],
        [0, 0, 0, 0],
        [0x32f95f7c85fe101d, 0x7cf41589c0d8c3fb, 0xa5f863e8b69fc147, 0x855433a3a4c8e334],
        [0xef9e224a5fd8814c, 0x097082129591c88b, 0xd7e172e40350d911, 0xa50c95efc2ad06c4],
    );
}

#[test]
fn edge_case_u_is_zero_reduces_to_v_times_q() {
    assert_result_is(
        [0, 0, 0, 0],
        [5, 0, 0, 0],
        [0xfbac247234e00fb4, 0x14454623c3fd1cfe, 0x687d606b92c96503, 0x453d28b5a120a7c9],
        [0x7c759dd686bb3b84, 0x06fcf1dccf3875c7, 0xe2180f511dff15d7, 0x2e0931f528334076],
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
        let via_comb = comb_multiply_base_point(&Bp256r1Scalar::from_limbs(k_limbs));
        let via_wnaf =
            shamir_multiply(&Bp256r1PublicScalar::from_limbs(k_limbs), &scalar([0; 4]), &q());
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
    let g = Bp256r1JacobianPoint::from_affine(
        Bp256r1FieldElement::from_limbs(bouncycastle_ec::bp256r1_domain::G_X_LIMBS),
        Bp256r1FieldElement::from_limbs(bouncycastle_ec::bp256r1_domain::G_Y_LIMBS),
    );
    let mut u = [0u64; 4];
    u[0] = 12345;
    let mut v = [0u64; 4];
    v[0] = 6789;
    let mut u_plus_v = [0u64; 4];
    u_plus_v[0] = 19134;
    let mut u_minus_v = [0u64; 4];
    u_minus_v[0] = 5556;
    let via_comb =
        |k: [u64; 4]| comb_multiply_base_point(&Bp256r1Scalar::from_limbs(k)).to_affine();

    // [u]G + [v]infinity == [u]G
    assert_eq!(
        shamir_multiply(&scalar(u), &scalar(v), &Bp256r1JacobianPoint::INFINITY).to_affine(),
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
