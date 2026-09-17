use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::bp384r1::Bp384r1FieldElement;
use bouncycastle_ec::bp384r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::bp384r1_point::Bp384r1JacobianPoint;

fn bench_bp384r1_point(c: &mut Criterion) {
    let g = Bp384r1JacobianPoint::from_affine(
        Bp384r1FieldElement::from_limbs(G_X_LIMBS),
        Bp384r1FieldElement::from_limbs(G_Y_LIMBS),
    );
    let two_g = g.double();

    let mut group = c.benchmark_group("bp384r1_point");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(&g).add(black_box(&two_g))))
    });
    group.bench_function("double", |bencher| bencher.iter(|| black_box(black_box(&g).double())));
    group.bench_function("to_affine", |bencher| {
        bencher.iter(|| black_box(black_box(&two_g).to_affine()))
    });
    group.finish();
}

criterion_group!(benches, bench_bp384r1_point);
criterion_main!(benches);
