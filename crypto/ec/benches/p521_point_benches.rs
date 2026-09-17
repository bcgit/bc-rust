use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::p521::P521FieldElement;
use bouncycastle_ec::p521_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p521_point::P521JacobianPoint;

fn bench_p521_point(c: &mut Criterion) {
    let g = P521JacobianPoint::from_affine(
        P521FieldElement::from_limbs(G_X_LIMBS),
        P521FieldElement::from_limbs(G_Y_LIMBS),
    );
    let two_g = g.double();

    let mut group = c.benchmark_group("p521_point");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(&g).add(black_box(&two_g))))
    });
    group.bench_function("double", |bencher| bencher.iter(|| black_box(black_box(&g).double())));
    group.bench_function("to_affine", |bencher| {
        bencher.iter(|| black_box(black_box(&two_g).to_affine()))
    });
    group.finish();
}

criterion_group!(benches, bench_p521_point);
criterion_main!(benches);
