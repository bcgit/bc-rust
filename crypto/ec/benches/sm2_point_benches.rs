use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::sm2::Sm2FieldElement;
use bouncycastle_ec::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
use bouncycastle_ec::sm2_point::Sm2JacobianPoint;

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
    group.finish();
}

criterion_group!(benches, bench_sm2_point);
criterion_main!(benches);
