//! Benchmarks for P-384's scalar side: the scalar field (arithmetic mod the curve order `n`,
//! used for `k^-1` and `s = k^-1(e + rd)` in signing) and the two scalar multipliers built on it --
//! [`comb_multiply_base_point`], the constant-time fixed-base `[k]G` that dominates key generation
//! and signing, and [`shamir_multiply`], the variable-time `[u]G + [v]Q` that dominates
//! verification. These are the crate's most expensive routines; the field and point benches next to
//! this file measure only their building blocks.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_comb::comb_multiply_base_point;
use bouncycastle_ec::p384_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p384_point::P384JacobianPoint;
use bouncycastle_ec::p384_scalar::{P384PublicScalar, P384Scalar, P384ScalarField};
use bouncycastle_ec::p384_wnaf::shamir_multiply;

const A_LIMBS: [u64; 6] = [
    0x9f8573c9f25dc994, 0x9115361f42389a31, 0xfc83ab74842a0944, 0x285f078965f5a299,
    0x3d7c9ec7081ab44e, 0xbd8ec9a1f80385ed,
];
const B_LIMBS: [u64; 6] = [
    0x790d02ba68e2b293, 0x952cb98dca28e0ce, 0x1699fd1dd3e61f5f, 0x174ea8e941ac9159,
    0xc59a61378b3dda8e, 0x083d8f37af9e4e0d,
];

fn bench_p384_scalar(c: &mut Criterion) {
    let x = P384ScalarField::from_limbs(A_LIMBS);
    let y = P384ScalarField::from_limbs(B_LIMBS);

    let mut group = c.benchmark_group("p384_scalar");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(x).add(black_box(&y))))
    });
    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(black_box(x).mul(black_box(&y))))
    });
    group.bench_function("invert", |bencher| bencher.iter(|| black_box(black_box(x).invert())));
    group.finish();
}

fn bench_p384_scalar_mul(c: &mut Criterion) {
    let k = P384Scalar::from_limbs(A_LIMBS);
    let u = P384PublicScalar::from_limbs(A_LIMBS);
    let v = P384PublicScalar::from_limbs(B_LIMBS);
    // A stand-in for a signer's public key: any point on the curve will do for timing, and `[2]G`
    // is reachable without a scalar multiplication of its own.
    let g = P384JacobianPoint::from_affine(
        P384FieldElement::from_limbs(G_X_LIMBS),
        P384FieldElement::from_limbs(G_Y_LIMBS),
    );
    let q = g.double();

    let mut group = c.benchmark_group("p384_scalar_mul");
    // Constant-time fixed-base [k]G (signing, key generation).
    group.bench_function("comb_base_point", |bencher| {
        bencher.iter(|| black_box(comb_multiply_base_point(black_box(&k))))
    });
    // Variable-time [u]G + [v]Q via Shamir's trick (verification).
    group.bench_function("shamir", |bencher| {
        bencher.iter(|| shamir_multiply(black_box(&u), black_box(&v), black_box(&q)))
    });
    group.finish();
}

criterion_group!(benches, bench_p384_scalar, bench_p384_scalar_mul);
criterion_main!(benches);
