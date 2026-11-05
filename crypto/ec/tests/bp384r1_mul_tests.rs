//! Behavioural tests for [`multiply_point`] (`[k]Q`, constant time in `k`): cross-checked against
//! the fixed-base comb for `Q = G`, against the variable-time wNAF multiplier for a random `Q`,
//! and against `[a k mod n]G` for `Q = [a]G` (three multipliers of independent design computing
//! the same point), plus the edge cases a windowed multiplier can get wrong: `k = 0`, `k = 1`,
//! `k = n-1`, a window of all ones, `Q` the identity, `Q` negated, `Q` given in a
//! non-canonical-`Z` Jacobian representation, and (debug builds only) `Q` off the curve.

use bouncycastle_ec::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::bp384r1_comb::comb_multiply_base_point;
use bouncycastle_ec::bp384r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp384r1_mul::multiply_point;
use bouncycastle_ec::bp384r1_point::Bp384r1JacobianPoint;
use bouncycastle_ec::bp384r1_scalar::{
    Bp384r1PublicScalar, Bp384r1Scalar, Bp384r1ScalarField, N_LIMBS,
};
use bouncycastle_ec::bp384r1_wnaf::shamir_multiply;
use bouncycastle_ec::nat;

const LIMBS: usize = 6;

fn g() -> Bp384r1JacobianPoint {
    Bp384r1JacobianPoint::from_affine(
        Bp384r1FieldElement::from_limbs(G_X_LIMBS),
        Bp384r1FieldElement::from_limbs(G_Y_LIMBS),
    )
}

/// `(G.x, G.y + 1)`, which is not on the curve.
fn off_curve() -> Bp384r1JacobianPoint {
    Bp384r1JacobianPoint::from_affine(
        Bp384r1FieldElement::from_limbs(G_X_LIMBS),
        Bp384r1FieldElement::from_limbs(G_Y_LIMBS).add(&Bp384r1FieldElement::ONE),
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
    Bp384r1ScalarField::from_limbs(limbs).to_limbs()
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
        let via_mul = multiply_point(&Bp384r1Scalar::from_limbs(k), &g());
        let via_comb = comb_multiply_base_point(&Bp384r1Scalar::from_limbs(k));
        assert_eq!(via_mul.to_affine(), via_comb.to_affine(), "k = {k:x?}");
    }
}

#[test]
fn k_times_q_agrees_with_the_wnaf_multiplier_and_with_the_scalar_field() {
    let mut rng = Xorshift64(0xC2B2AE3D27D4EB4F);
    for _ in 0..50 {
        let a = reduced(rng.next_limbs());
        let k = reduced(rng.next_limbs());
        let q = comb_multiply_base_point(&Bp384r1Scalar::from_limbs(a));

        let via_mul = multiply_point(&Bp384r1Scalar::from_limbs(k), &q);

        // [0]G + [k]Q by the variable-time multiplier.
        let via_wnaf = shamir_multiply(
            &Bp384r1PublicScalar::from_limbs(zero()),
            &Bp384r1PublicScalar::from_limbs(k),
            &q,
        );
        assert_eq!(via_mul.to_affine(), via_wnaf.to_affine(), "wnaf: a = {a:x?}, k = {k:x?}");

        // [a k mod n]G by the fixed-base multiplier.
        let ak =
            Bp384r1ScalarField::from_limbs(a).mul(&Bp384r1ScalarField::from_limbs(k)).to_limbs();
        let via_comb = comb_multiply_base_point(&Bp384r1Scalar::from_limbs(ak));
        assert_eq!(via_mul.to_affine(), via_comb.to_affine(), "comb: a = {a:x?}, k = {k:x?}");
    }
}

#[test]
fn edge_case_k_equals_zero_is_infinity() {
    let q = g().double();
    assert!(multiply_point(&Bp384r1Scalar::from_limbs(zero()), &q).is_infinity().to_bool());
}

#[test]
fn edge_case_k_equals_one_is_q() {
    let q = g().double();
    assert_eq!(multiply_point(&Bp384r1Scalar::from_limbs(one()), &q).to_affine(), q.to_affine());
}

#[test]
fn edge_case_k_equals_n_minus_1_is_minus_q() {
    let q = g().double().add(&g());
    let result = multiply_point(&Bp384r1Scalar::from_limbs(n_minus_1()), &q);
    assert_eq!(result.to_affine(), q.negate().to_affine());
}

#[test]
fn edge_case_q_is_infinity() {
    let k = reduced(Xorshift64(0x2545F4914F6CDD1D).next_limbs());
    assert!(
        multiply_point(&Bp384r1Scalar::from_limbs(k), &Bp384r1JacobianPoint::INFINITY)
            .is_infinity()
            .to_bool()
    );
}

#[test]
fn negating_q_negates_the_result() {
    let k = reduced(Xorshift64(0x1234_5678_9ABC_DEF1).next_limbs());
    let q = g().double();
    let kq = multiply_point(&Bp384r1Scalar::from_limbs(k), &q);
    let k_neg_q = multiply_point(&Bp384r1Scalar::from_limbs(k), &q.negate());
    assert_eq!(k_neg_q.to_affine(), kq.negate().to_affine());
}

#[test]
fn q_in_a_non_canonical_z_representation_gives_the_same_result() {
    // (X, Y, Z) and (λ²X, λ³Y, λZ) are the same affine point; the multiplier must treat them alike.
    let k = reduced(Xorshift64(0xDEADBEEFCAFEF00D).next_limbs());
    let q = g().double();
    let lambda = Bp384r1FieldElement::from_limbs(small(7));
    let lambda2 = lambda.mul(&lambda);
    let lambda3 = lambda2.mul(&lambda);
    let scaled =
        Bp384r1JacobianPoint { x: q.x.mul(&lambda2), y: q.y.mul(&lambda3), z: q.z.mul(&lambda) };
    assert_eq!(scaled.to_affine(), q.to_affine(), "the scaled point is the same point");
    assert_eq!(
        multiply_point(&Bp384r1Scalar::from_limbs(k), &scaled).to_affine(),
        multiply_point(&Bp384r1Scalar::from_limbs(k), &q).to_affine()
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "Q is not on the curve")]
fn q_off_the_curve_is_rejected_in_debug_builds() {
    let _ = multiply_point(&Bp384r1Scalar::from_limbs(one()), &off_curve());
}
