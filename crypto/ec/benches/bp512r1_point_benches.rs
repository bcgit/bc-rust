use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::hazmat::bp512r1::Bp512r1FieldElement;
use bouncycastle_ec::hazmat::bp512r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::hazmat::bp512r1_mul::multiply_point;
use bouncycastle_ec::hazmat::bp512r1_point::Bp512r1JacobianPoint;
use bouncycastle_ec::hazmat::bp512r1_scalar::Bp512r1Scalar;

fn bench_bp512r1_point(c: &mut Criterion) {
    let g = Bp512r1JacobianPoint::from_affine(
        Bp512r1FieldElement::from_limbs(G_X_LIMBS),
        Bp512r1FieldElement::from_limbs(G_Y_LIMBS),
    );
    let two_g = g.double();

    let mut group = c.benchmark_group("bp512r1_point");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(&g).add(black_box(&two_g))))
    });
    group.bench_function("double", |bencher| bencher.iter(|| black_box(black_box(&g).double())));
    group.bench_function("to_affine", |bencher| {
        bencher.iter(|| black_box(black_box(&two_g).to_affine()))
    });
    // A full-width scalar: the multiplier's cost does not depend on its value.
    let mut k_limbs = [0u64; 8];
    for (i, limb) in k_limbs.iter_mut().enumerate() {
        *limb = 0x9E37_79B9_7F4A_7C15 ^ (i as u64);
    }
    let k = Bp512r1Scalar::from_limbs(k_limbs);
    group.bench_function("multiply_point", |bencher| {
        bencher.iter(|| black_box(multiply_point(black_box(&k), black_box(&two_g))))
    });
    group.finish();
}

criterion_group!(benches, bench_bp512r1_point);
criterion_main!(benches);
