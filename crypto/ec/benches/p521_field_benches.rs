use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::p521::P521FieldElement;
use bouncycastle_ec::p521_domain::{G_X_LIMBS, G_Y_LIMBS};

fn bench_p521_field(c: &mut Criterion) {
    let a = P521FieldElement::from_limbs(G_X_LIMBS);
    let b = P521FieldElement::from_limbs(G_Y_LIMBS);

    let mut group = c.benchmark_group("p521_field");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(a).add(black_box(&b))))
    });
    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(black_box(a).mul(black_box(&b))))
    });
    group.bench_function("square", |bencher| bencher.iter(|| black_box(black_box(a).square())));
    group.bench_function("invert", |bencher| bencher.iter(|| black_box(black_box(a).invert())));
    group.finish();
}

criterion_group!(benches, bench_p521_field);
criterion_main!(benches);
