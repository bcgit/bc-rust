use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::p256::P256FieldElement;
use bouncycastle_ec::p256_mul::multiply_point;
use bouncycastle_ec::p256_point::P256JacobianPoint;
use bouncycastle_ec::p256_scalar::P256Scalar;

fn bench_p256_point(c: &mut Criterion) {
    // G, the P-256 base point (SP 800-186 §3.2.1.3).
    let g = P256JacobianPoint::from_affine(
        P256FieldElement::from_limbs([
            0xf4a13945d898c296, 0x77037d812deb33a0, 0xf8bce6e563a440f2, 0x6b17d1f2e12c4247,
        ]),
        P256FieldElement::from_limbs([
            0xcbb6406837bf51f5, 0x2bce33576b315ece, 0x8ee7eb4a7c0f9e16, 0x4fe342e2fe1a7f9b,
        ]),
    );
    let two_g = g.double();

    let mut group = c.benchmark_group("p256_point");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(&g).add(black_box(&two_g))))
    });
    group.bench_function("double", |bencher| bencher.iter(|| black_box(black_box(&g).double())));
    group.bench_function("to_affine", |bencher| {
        bencher.iter(|| black_box(black_box(&two_g).to_affine()))
    });
    // A full-width scalar: the multiplier's cost does not depend on its value.
    let mut k_limbs = [0u64; 4];
    for (i, limb) in k_limbs.iter_mut().enumerate() {
        *limb = 0x9E37_79B9_7F4A_7C15 ^ (i as u64);
    }
    let k = P256Scalar::from_limbs(k_limbs);
    group.bench_function("multiply_point", |bencher| {
        bencher.iter(|| black_box(multiply_point(black_box(&k), black_box(&two_g))))
    });
    group.finish();
}

criterion_group!(benches, bench_p256_point);
criterion_main!(benches);
