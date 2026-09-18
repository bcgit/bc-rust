//! Known-answer tests for [`shamir_multiply`] (`[u]G + [v]Q`).
//!
//! `Q` below is `d*G` for a fixed test-only `d` (not a real key). Expected results were computed
//! independently in Python from the SP 800-186 Appendix A.1.1 affine group law, the same way as
//! `p256_comb_tests.rs`, with `random.seed(808)`.

use bouncycastle_ec::p256::P256FieldElement;
use bouncycastle_ec::p256_comb::comb_multiply_base_point;
use bouncycastle_ec::p256_point::P256JacobianPoint;
use bouncycastle_ec::p256_scalar::{P256PublicScalar, P256Scalar};
use bouncycastle_ec::p256_wnaf::shamir_multiply;

const Q_X: [u64; 4] =
    [0xb8ead9e9b37489ae, 0xb2bd6640d485e210, 0x65021b418d419835, 0x8db3ea9c500e21de];
const Q_Y: [u64; 4] =
    [0xdfda9d4b2257b9f5, 0xaa237e07ab5789f0, 0x66dc9154eb749075, 0x1a8b7e4595d73287];

fn q() -> P256JacobianPoint {
    P256JacobianPoint::from_affine(
        P256FieldElement::from_limbs(Q_X),
        P256FieldElement::from_limbs(Q_Y),
    )
}

fn scalar(limbs: [u64; 4]) -> P256PublicScalar {
    P256PublicScalar::from_limbs(limbs)
}

fn assert_result_is(u: [u64; 4], v: [u64; 4], expected_x: [u64; 4], expected_y: [u64; 4]) {
    let result = shamir_multiply(&scalar(u), &scalar(v), &q());
    let (rx, ry) = result.to_affine().expect("expected a non-infinity result");
    assert_eq!(rx, P256FieldElement::from_limbs(expected_x), "x mismatch for u={u:x?} v={v:x?}");
    assert_eq!(ry, P256FieldElement::from_limbs(expected_y), "y mismatch for u={u:x?} v={v:x?}");
}

#[test]
fn known_answer_small_u_v() {
    assert_result_is(
        [12345, 0, 0, 0],
        [6789, 0, 0, 0],
        [0x891ec66a07d3dd0b, 0xd34e6b109a97879d, 0xd3e6c8c8eb8db51a, 0x3d5afe5709f19122],
        [0x84ed8e7ab7daaaf3, 0x94af16193179d563, 0x7e455089f00cecea, 0x2948dbc14abcc92a],
    );
    assert_result_is(
        [1, 0, 0, 0],
        [1, 0, 0, 0],
        [0x7993b285982367e5, 0x1380b2a785d18e95, 0x73b3a283cdd79a9b, 0xf351345def9ede77],
        [0x4ca5032233e7894e, 0x620febfc3aba9618, 0xdab82d8b820e5b60, 0x4f718d4f426025f4],
    );
}

#[test]
fn known_answer_large_u_v() {
    assert_result_is(
        [0xc2c21a69f006dcc2, 0xe0c8cc433ca149bd, 0x6346ab1c59d237b2, 0xc71fe0537ca93045],
        [0xd30b99fb3eb640b9, 0xa0f42e6188c6f196, 0x2ed48753c852873b, 0x44a1f0a402f4eea6],
        [0x0b74e63145c21821, 0x78079cd518bbff20, 0x0d370eced42e7464, 0x23b0e4ecaea7f530],
        [0x56b583922e2e277e, 0x35cf03e7b50a1629, 0x48c996a406feac77, 0x27d677f7140d39eb],
    );
    assert_result_is(
        [0xb3741c87117f9b32, 0x5a3b774dc31e0a4f, 0x9468f6370a9c3f95, 0x9838c9b21b004bea],
        [0xec09a621f2563f9e, 0x853761ae35c74b86, 0xede6b87945b9a46d, 0xa01d685690b61514],
        [0x5c2ae8035fedbd6b, 0x783ec0ae4f9b4185, 0xd94028e563cb656f, 0xdf974dc081216a1b],
        [0x94f029efe09a9a39, 0xd9f5e6e81615ddd6, 0x8fe9ac9c96b26409, 0xe90324b8f810ba2e],
    );
}

#[test]
fn edge_case_v_is_zero_reduces_to_u_times_g() {
    // u=5, v=0 must equal 5*G, i.e. p256_comb_tests's known 5*G value (P5 there).
    assert_result_is(
        [5, 0, 0, 0],
        [0, 0, 0, 0],
        [0x21554a0dc3d033ed, 0xef8c82fd1f5be524, 0xd784c85608668fdf, 0x51590b7a515140d2],
        [0xd1d0bb44fda16da4, 0x0d012f00d4d80888, 0x8ae1bf36bf8a7926, 0xe0c17da8904a727d],
    );
}

#[test]
fn edge_case_u_is_zero_reduces_to_v_times_q() {
    assert_result_is(
        [0, 0, 0, 0],
        [5, 0, 0, 0],
        [0x2f5f2aad64286296, 0x1d6281be4abe14c0, 0x88b12452a34a8a4a, 0x100da2f784e9e086],
        [0xf287dc33778a55c1, 0x0b35c3de7f7cadbc, 0x347663651c0a8ae8, 0x2941b7ace017645b],
    );
}

#[test]
fn edge_case_both_zero_is_infinity() {
    let result = shamir_multiply(&scalar([0, 0, 0, 0]), &scalar([0, 0, 0, 0]), &q());
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
    let mut rng = Xorshift64(0xD1B54A32D192ED03);
    for _ in 0..500 {
        let k_limbs = rng.next_limbs();
        let via_comb = comb_multiply_base_point(&P256Scalar::from_limbs(k_limbs));
        let via_wnaf =
            shamir_multiply(&P256PublicScalar::from_limbs(k_limbs), &scalar([0, 0, 0, 0]), &q());
        assert_eq!(via_comb.to_affine(), via_wnaf.to_affine(), "k = {k_limbs:x?}");
    }
}

#[test]
fn edge_case_u_v_equal_n_minus_1() {
    let n_minus_1: [u64; 4] =
        [0xf3b9cac2fc632550, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000];
    assert_result_is(
        n_minus_1,
        n_minus_1,
        [0x7993b285982367e5, 0x1380b2a785d18e95, 0x73b3a283cdd79a9b, 0xf351345def9ede77],
        [0xb35afcddcc1876b1, 0x9df01404c54569e7, 0x2547d2747df1a49f, 0xb08e72afbd9fda0c],
    );
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
    let g = P256JacobianPoint::from_affine(
        P256FieldElement::from_limbs(bouncycastle_ec::p256_domain::G_X_LIMBS),
        P256FieldElement::from_limbs(bouncycastle_ec::p256_domain::G_Y_LIMBS),
    );
    let mut u = [0u64; 4];
    u[0] = 12345;
    let mut v = [0u64; 4];
    v[0] = 6789;
    let mut u_plus_v = [0u64; 4];
    u_plus_v[0] = 19134;
    let mut u_minus_v = [0u64; 4];
    u_minus_v[0] = 5556;
    let via_comb = |k: [u64; 4]| comb_multiply_base_point(&P256Scalar::from_limbs(k)).to_affine();

    // [u]G + [v]infinity == [u]G
    assert_eq!(
        shamir_multiply(&scalar(u), &scalar(v), &P256JacobianPoint::INFINITY).to_affine(),
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
