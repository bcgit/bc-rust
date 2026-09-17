//! Benchmarks for P-521's scalar side: the scalar field (arithmetic mod the curve order `n`,
//! used for `k^-1` and `s = k^-1(e + rd)` in signing) and the two scalar multipliers built on it --
//! [`comb_multiply_base_point`], the constant-time fixed-base `[k]G` that dominates key generation
//! and signing, and [`shamir_multiply`], the variable-time `[u]G + [v]Q` that dominates
//! verification. These are the crate's most expensive routines; the field and point benches next to
//! this file measure only their building blocks.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::p521::P521FieldElement;
use bouncycastle_ec::p521_comb::comb_multiply_base_point;
use bouncycastle_ec::p521_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p521_point::P521JacobianPoint;
use bouncycastle_ec::p521_scalar::{P521PublicScalar, P521Scalar, P521ScalarField};
use bouncycastle_ec::p521_wnaf::shamir_multiply;

const A_LIMBS: [u64; 9] = [
    0x9f8573c9f25dc994, 0x9115361f42389a31, 0xfc83ab74842a0944, 0x285f078965f5a299,
    0x3d7c9ec7081ab44e, 0xbd8ec9a1f80385ed, 0x17857e0831e5554e, 0x10f26b82fe915329,
    0x0000000000000101,
];
const B_LIMBS: [u64; 9] = [
    0x790d02ba68e2b293, 0x952cb98dca28e0ce, 0x1699fd1dd3e61f5f, 0x174ea8e941ac9159,
    0xc59a61378b3dda8e, 0x083d8f37af9e4e0d, 0xd253304398079d69, 0x11e815b91f17e93f,
    0x00000000000000b7,
];

fn bench_p521_scalar(c: &mut Criterion) {
    let x = P521ScalarField::from_limbs(A_LIMBS);
    let y = P521ScalarField::from_limbs(B_LIMBS);

    let mut group = c.benchmark_group("p521_scalar");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(x).add(black_box(&y))))
    });
    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(black_box(x).mul(black_box(&y))))
    });
    group.bench_function("invert", |bencher| bencher.iter(|| black_box(black_box(x).invert())));
    group.finish();
}

fn bench_p521_scalar_mul(c: &mut Criterion) {
    let k = P521Scalar::from_limbs(A_LIMBS);
    let u = P521PublicScalar::from_limbs(A_LIMBS);
    let v = P521PublicScalar::from_limbs(B_LIMBS);
    // A stand-in for a signer's public key: any point on the curve will do for timing, and `[2]G`
    // is reachable without a scalar multiplication of its own.
    let g = P521JacobianPoint::from_affine(
        P521FieldElement::from_limbs(G_X_LIMBS),
        P521FieldElement::from_limbs(G_Y_LIMBS),
    );
    let q = g.double();

    let mut group = c.benchmark_group("p521_scalar_mul");
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

criterion_group!(benches, bench_p521_scalar, bench_p521_scalar_mul);
criterion_main!(benches);
