use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::p384::P384FieldElement;
use bouncycastle_ec::p384_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::p384_point::P384JacobianPoint;

fn bench_p384_point(c: &mut Criterion) {
    let g = P384JacobianPoint::from_affine(
        P384FieldElement::from_limbs(G_X_LIMBS),
        P384FieldElement::from_limbs(G_Y_LIMBS),
    );
    let two_g = g.double();

    let mut group = c.benchmark_group("p384_point");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(&g).add(black_box(&two_g))))
    });
    group.bench_function("double", |bencher| bencher.iter(|| black_box(black_box(&g).double())));
    group.bench_function("to_affine", |bencher| {
        bencher.iter(|| black_box(black_box(&two_g).to_affine()))
    });
    group.finish();
}

criterion_group!(benches, bench_p384_point);
criterion_main!(benches);
