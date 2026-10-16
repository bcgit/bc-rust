use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::bp512r1::Bp512r1FieldElement;
use bouncycastle_ec::bp512r1_domain::{G_X_LIMBS, G_Y_LIMBS};

fn bench_bp512r1_field(c: &mut Criterion) {
    let a = Bp512r1FieldElement::from_limbs(G_X_LIMBS);
    let b = Bp512r1FieldElement::from_limbs(G_Y_LIMBS);

    let mut group = c.benchmark_group("bp512r1_field");
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

criterion_group!(benches, bench_bp512r1_field);
criterion_main!(benches);
