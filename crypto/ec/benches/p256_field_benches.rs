use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::p256::P256FieldElement;

fn bench_p256_field(c: &mut Criterion) {
    let a = P256FieldElement::from_limbs([
        0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x0444444444444444,
    ]);
    let b = P256FieldElement::from_limbs([
        0x5555555555555555, 0x6666666666666666, 0x7777777777777777, 0x0888888888888888,
    ]);

    let mut group = c.benchmark_group("p256_field");
    group.bench_function("add", |bencher| {
        bencher.iter(|| black_box(black_box(a).add(black_box(&b))))
    });
    group.bench_function("mul", |bencher| {
        bencher.iter(|| black_box(black_box(a).mul(black_box(&b))))
    });
    group.bench_function("invert", |bencher| bencher.iter(|| black_box(black_box(a).invert())));
    group.finish();
}

criterion_group!(benches, bench_p256_field);
criterion_main!(benches);
