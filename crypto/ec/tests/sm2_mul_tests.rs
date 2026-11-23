//! Behavioural tests for [`multiply_point`] (`[k]Q`, constant time in `k`): cross-checked against
//! the fixed-base comb for `Q = G`, against the variable-time wNAF multiplier for a random `Q`,
//! and against `[a k mod n]G` for `Q = [a]G` (three multipliers of independent design computing
//! the same point), plus the edge cases a windowed multiplier can get wrong: `k = 0`, `k = 1`,
//! `k = n-1`, `k = n`, windows of all ones and runs of zero windows, `Q` the identity, `Q` negated,
//! `Q` given in a non-canonical-`Z` Jacobian representation, and (debug builds only) `Q` off the
//! curve. [`Sm2JacobianPoint::affine_of_nonidentity`] is tested here on the multiplier's output.
//!
//! The known answers were computed in Python with plain integer arithmetic and the affine group
//! law (`a = p - 3`, double-and-add), not from this crate, using `p`, `b`, `G` and `n` as
//! `sm2.rs`, `sm2_domain.rs` and `sm2_scalar.rs` give them, after checking that `G` is on the
//! curve and `[n]G` is the identity:
//!
//! ```text
//! lift(x, even): y = (x^3 - 3x + b)^((p+1)/4) mod p, rejected unless y^2 == x^3 - 3x + b,
//!                negated if its parity is not the one asked for
//! SMALL_Q = lift(0, even)       # 0 is the smallest x with a point on the curve
//! LARGE_Q = lift(p - 2, odd)    # p - 2 is the largest; p - 1 has none
//! K_EVERY_WINDOW = 0x0123456789abcdef repeated four times (below n)
//! K_G, K_SMALL_Q, K_LARGE_Q = [K_EVERY_WINDOW]G, [K_EVERY_WINDOW]SMALL_Q, [K_EVERY_WINDOW]LARGE_Q
//! ```
//!
//! Both points were checked to be on the curve and to have order `n`.

use bouncycastle_ec::hazmat::sm2::Sm2FieldElement;
use bouncycastle_ec::hazmat::sm2_comb::comb_multiply_base_point;
use bouncycastle_ec::hazmat::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::hazmat::sm2_mul::multiply_point;
use bouncycastle_ec::hazmat::sm2_point::Sm2JacobianPoint;
use bouncycastle_ec::hazmat::sm2_scalar::{N_LIMBS, Sm2PublicScalar, Sm2Scalar, Sm2ScalarField};
use bouncycastle_ec::hazmat::sm2_wnaf::shamir_multiply;
use bouncycastle_utils::nat;

const LIMBS: usize = 4;

const SMALL_Q_X: [u64; 4] = [0; 4];
const SMALL_Q_Y: [u64; 4] =
    [0x6e232e00f5cdc154, 0x7fae6d1a9c9330e7, 0x07e88a83d6cf5a16, 0xfd4511e81736a60f];
const LARGE_Q_X: [u64; 4] =
    [0xfffffffffffffffd, 0xffffffff00000000, 0xffffffffffffffff, 0xfffffffeffffffff];
const LARGE_Q_Y: [u64; 4] =
    [0x03870800065279a3, 0x2aa98b5ffa95982f, 0x218f405f792355bf, 0x9f7a091433a81e3f];
/// A scalar whose 64 windows hold every window value, `0` to `15`, four times each.
const K_EVERY_WINDOW: [u64; 4] =
    [0x0123456789abcdef, 0x0123456789abcdef, 0x0123456789abcdef, 0x0123456789abcdef];
const K_G_X: [u64; 4] =
    [0x2086ab4c5962b89b, 0x957eae15aeb852e7, 0x38d71d721bd072d8, 0x344081b80805540a];
const K_G_Y: [u64; 4] =
    [0xf2efb3b58830e0f3, 0x63cff46dc04c7e68, 0x30f341a5a25886c0, 0x5bb8628b9d9c4edd];
const K_SMALL_Q_X: [u64; 4] =
    [0xacfd5e9f1ca94fe4, 0xe2064c2908e7dc4a, 0x29036a6ac85abca8, 0x45277367f7b91ca0];
const K_SMALL_Q_Y: [u64; 4] =
    [0xcc10e3dee4a578df, 0x24affb32da096e60, 0x11a283430b150d59, 0x30e3bc5cf97bc3d0];
const K_LARGE_Q_X: [u64; 4] =
    [0xed3908788b953a6e, 0xa2b0a14fcd53ff9a, 0xa166988036571ce1, 0x36e9a4b0f11007b3];
const K_LARGE_Q_Y: [u64; 4] =
    [0xeb04ecd62770c9e0, 0xe3f5da2ad091ce0e, 0xb406012225fdd3cd, 0x57e8ba9375a605ea];

fn point(x: [u64; 4], y: [u64; 4]) -> Sm2JacobianPoint {
    Sm2JacobianPoint::from_affine(Sm2FieldElement::from_limbs(x), Sm2FieldElement::from_limbs(y))
}

fn affine_limbs(p: &Sm2JacobianPoint) -> Option<([u64; 4], [u64; 4])> {
    p.to_affine().map(|(x, y)| (x.to_limbs(), y.to_limbs()))
}

fn g() -> Sm2JacobianPoint {
    Sm2JacobianPoint::from_affine(
        Sm2FieldElement::from_limbs(G_X_LIMBS),
        Sm2FieldElement::from_limbs(G_Y_LIMBS),
    )
}

/// `(G.x, G.y + 1)`, which is not on the curve.
#[cfg(debug_assertions)]
fn off_curve() -> Sm2JacobianPoint {
    Sm2JacobianPoint::from_affine(
        Sm2FieldElement::from_limbs(G_X_LIMBS),
        Sm2FieldElement::from_limbs(G_Y_LIMBS).add(&Sm2FieldElement::ONE),
    )
}

fn zero() -> [u64; LIMBS] {
    [0; LIMBS]
}

fn small(v: u64) -> [u64; LIMBS] {
    let mut limbs = zero();
    limbs[0] = v;
    limbs
}

fn one() -> [u64; LIMBS] {
    small(1)
}

fn n_minus_1() -> [u64; LIMBS] {
    let (limbs, borrow) = nat::sub(&N_LIMBS, &one());
    assert_eq!(borrow, 0);
    limbs
}

/// A pseudorandom value reduced into `[0, n)`, so it is a valid scalar for every multiplier.
fn reduced(limbs: [u64; LIMBS]) -> [u64; LIMBS] {
    Sm2ScalarField::from_limbs(limbs).to_limbs()
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

    fn next_limbs(&mut self) -> [u64; LIMBS] {
        let mut limbs = zero();
        for limb in limbs.iter_mut() {
            *limb = self.next_u64();
        }
        limbs
    }
}

#[test]
fn k_times_g_agrees_with_the_comb_multiplier() {
    let mut rng = Xorshift64(0x9E3779B97F4A7C15);
    let mut cases = vec![one(), small(2), small(3), small(15), small(16), small(17)];
    cases.push(n_minus_1());
    let mut n_minus_2 = n_minus_1();
    n_minus_2[0] -= 1;
    cases.push(n_minus_2);
    for _ in 0..50 {
        cases.push(reduced(rng.next_limbs()));
    }
    for k in cases {
        let via_mul = multiply_point(&Sm2Scalar::from_limbs(k), &g());
        let via_comb = comb_multiply_base_point(&Sm2Scalar::from_limbs(k));
        assert_eq!(via_mul.to_affine(), via_comb.to_affine(), "k = {k:x?}");
    }
}

#[test]
fn k_times_q_agrees_with_the_wnaf_multiplier_and_with_the_scalar_field() {
    let mut rng = Xorshift64(0xC2B2AE3D27D4EB4F);
    for _ in 0..50 {
        let a = reduced(rng.next_limbs());
        let k = reduced(rng.next_limbs());
        let q = comb_multiply_base_point(&Sm2Scalar::from_limbs(a));

        let via_mul = multiply_point(&Sm2Scalar::from_limbs(k), &q);

        // [0]G + [k]Q by the variable-time multiplier.
        let via_wnaf = shamir_multiply(
            &Sm2PublicScalar::from_limbs(zero()),
            &Sm2PublicScalar::from_limbs(k),
            &q,
        );
        assert_eq!(via_mul.to_affine(), via_wnaf.to_affine(), "wnaf: a = {a:x?}, k = {k:x?}");

        // [a k mod n]G by the fixed-base multiplier.
        let ak = Sm2ScalarField::from_limbs(a).mul(&Sm2ScalarField::from_limbs(k)).to_limbs();
        let via_comb = comb_multiply_base_point(&Sm2Scalar::from_limbs(ak));
        assert_eq!(via_mul.to_affine(), via_comb.to_affine(), "comb: a = {a:x?}, k = {k:x?}");
    }
}

#[test]
fn edge_case_k_equals_zero_is_infinity() {
    let q = g().double();
    assert!(multiply_point(&Sm2Scalar::from_limbs(zero()), &q).is_infinity().to_bool());
}

#[test]
fn edge_case_k_equals_one_is_q() {
    let q = g().double();
    assert_eq!(multiply_point(&Sm2Scalar::from_limbs(one()), &q).to_affine(), q.to_affine());
}

#[test]
fn edge_case_k_equals_n_minus_1_is_minus_q() {
    let q = g().double().add(&g());
    let result = multiply_point(&Sm2Scalar::from_limbs(n_minus_1()), &q);
    assert_eq!(result.to_affine(), q.negate().to_affine());
}

#[test]
fn edge_case_k_equals_n_reduces_to_zero() {
    // `Sm2Scalar::from_limbs` reduces, so `n` is `0` and `n + 1` is `1`.
    let q = g().double();
    assert!(multiply_point(&Sm2Scalar::from_limbs(N_LIMBS), &q).is_infinity().to_bool());
    let (n_plus_1, carry) = nat::add(&N_LIMBS, &one());
    assert_eq!(carry, 0);
    assert_eq!(multiply_point(&Sm2Scalar::from_limbs(n_plus_1), &q).to_affine(), q.to_affine());
}

/// Scalars made of runs of zero windows and of all-ones windows, at both ends and across the limb
/// boundaries, against both other multipliers.
#[test]
fn runs_of_zero_and_all_ones_windows_agree_with_the_other_multipliers() {
    let cases: [[u64; LIMBS]; 9] = [
        [0, 0, 0, 1 << 63],                      // the top bit alone
        [0, 0, 0, 1 << 60],                      // top window 1, sixty-three zero windows
        [0xf, 0, 0, 0],                          // bottom window all ones
        [0x10, 0, 0, 0],                         // the second window from the bottom alone
        [u64::MAX, u64::MAX, 0, 0],              // 32 all-ones windows under 32 zero windows
        [0, 0, u64::MAX, 0x7fff_ffff_ffff_ffff], // the reverse, below n
        [0xf000_0000_0000_000f, 0xf, 0xf000_0000_0000_0000, 0],
        [0x1111_1111_1111_1111; LIMBS], // every window 1
        [
            0xeeee_eeee_eeee_eeee, 0xeeee_eeee_eeee_eeee, 0xeeee_eeee_eeee_eeee,
            0xeeee_eeee_eeee_eeee,
        ],
    ];
    let q = point(LARGE_Q_X, LARGE_Q_Y);
    for k in cases {
        assert_eq!(reduced(k), k, "the case is below n");
        let via_mul = multiply_point(&Sm2Scalar::from_limbs(k), &q);
        let via_wnaf = shamir_multiply(
            &Sm2PublicScalar::from_limbs(zero()),
            &Sm2PublicScalar::from_limbs(k),
            &q,
        );
        assert_eq!(via_mul.to_affine(), via_wnaf.to_affine(), "wnaf: k = {k:x?}");

        let via_mul_g = multiply_point(&Sm2Scalar::from_limbs(k), &g());
        let via_comb = comb_multiply_base_point(&Sm2Scalar::from_limbs(k));
        assert_eq!(via_mul_g.to_affine(), via_comb.to_affine(), "comb: k = {k:x?}");
    }
}

#[test]
fn known_answers_for_every_window_value() {
    let k = || Sm2Scalar::from_limbs(K_EVERY_WINDOW);
    assert_eq!(affine_limbs(&multiply_point(&k(), &g())), Some((K_G_X, K_G_Y)));
    assert_eq!(
        affine_limbs(&multiply_point(&k(), &point(SMALL_Q_X, SMALL_Q_Y))),
        Some((K_SMALL_Q_X, K_SMALL_Q_Y))
    );
    assert_eq!(
        affine_limbs(&multiply_point(&k(), &point(LARGE_Q_X, LARGE_Q_Y))),
        Some((K_LARGE_Q_X, K_LARGE_Q_Y))
    );
}

#[test]
fn affine_of_nonidentity_agrees_with_to_affine_and_with_the_known_answer() {
    let kq = multiply_point(&Sm2Scalar::from_limbs(K_EVERY_WINDOW), &point(SMALL_Q_X, SMALL_Q_Y));
    // The multiplier's output is not in affine form, so the conversion has work to do.
    assert_ne!(kq.z, Sm2FieldElement::ONE);
    let (x, y) = kq.affine_of_nonidentity();
    assert_eq!((x.to_limbs(), y.to_limbs()), (K_SMALL_Q_X, K_SMALL_Q_Y));
    assert_eq!(Some((x, y)), kq.to_affine());

    // A point already affine is returned as it is, and the identity as (0, 0).
    let (gx, gy) = g().affine_of_nonidentity();
    assert_eq!((gx.to_limbs(), gy.to_limbs()), (G_X_LIMBS, G_Y_LIMBS));
    let (ix, iy) = Sm2JacobianPoint::INFINITY.affine_of_nonidentity();
    assert_eq!((ix, iy), (Sm2FieldElement::ZERO, Sm2FieldElement::ZERO));
}

#[test]
fn edge_case_q_is_infinity() {
    let k = reduced(Xorshift64(0x2545F4914F6CDD1D).next_limbs());
    assert!(
        multiply_point(&Sm2Scalar::from_limbs(k), &Sm2JacobianPoint::INFINITY)
            .is_infinity()
            .to_bool()
    );
}

#[test]
fn negating_q_negates_the_result() {
    let k = reduced(Xorshift64(0x1234_5678_9ABC_DEF1).next_limbs());
    let q = g().double();
    let kq = multiply_point(&Sm2Scalar::from_limbs(k), &q);
    let k_neg_q = multiply_point(&Sm2Scalar::from_limbs(k), &q.negate());
    assert_eq!(k_neg_q.to_affine(), kq.negate().to_affine());
}

#[test]
fn q_in_a_non_canonical_z_representation_gives_the_same_result() {
    // (X, Y, Z) and (λ²X, λ³Y, λZ) are the same affine point; the multiplier must treat them alike.
    let k = reduced(Xorshift64(0xDEADBEEFCAFEF00D).next_limbs());
    let q = g().double();
    let lambda = Sm2FieldElement::from_limbs(small(7));
    let lambda2 = lambda.mul(&lambda);
    let lambda3 = lambda2.mul(&lambda);
    let scaled =
        Sm2JacobianPoint { x: q.x.mul(&lambda2), y: q.y.mul(&lambda3), z: q.z.mul(&lambda) };
    assert_eq!(scaled.to_affine(), q.to_affine(), "the scaled point is the same point");
    assert_eq!(
        multiply_point(&Sm2Scalar::from_limbs(k), &scaled).to_affine(),
        multiply_point(&Sm2Scalar::from_limbs(k), &q).to_affine()
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "Q is not on the curve")]
fn q_off_the_curve_is_rejected_in_debug_builds() {
    let _ = multiply_point(&Sm2Scalar::from_limbs(one()), &off_curve());
}
