use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::hazmat::sm2::Sm2FieldElement;
use bouncycastle_ec::hazmat::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::hazmat::sm2_mul::multiply_point;
use bouncycastle_ec::hazmat::sm2_point::Sm2JacobianPoint;
use bouncycastle_ec::hazmat::sm2_scalar::Sm2Scalar;

fn bench_sm2_point(c: &mut Criterion) {
    let g = Sm2JacobianPoint::from_affine(
        Sm2FieldElement::from_limbs(G_X_LIMBS),
        Sm2FieldElement::from_limbs(G_Y_LIMBS),
    );
    let two_g = g.double();

    let mut group = c.benchmark_group("sm2_point");
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
    let k = Sm2Scalar::from_limbs(k_limbs);
    group.bench_function("multiply_point", |bencher| {
        bencher.iter(|| black_box(multiply_point(black_box(&k), black_box(&two_g))))
    });
    group.finish();
}

criterion_group!(benches, bench_sm2_point);
criterion_main!(benches);
