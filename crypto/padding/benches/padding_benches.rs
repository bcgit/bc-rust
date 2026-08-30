use bouncycastle_core::traits::Padding;
use bouncycastle_padding::PKCS7;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_pkcs7(c: &mut Criterion) {
    let mut group = c.benchmark_group("padding::PKCS7");
    group.bench_function("pad/16", |b| {
        let mut block = [0u8; 16];
        b.iter(|| {
            <PKCS7 as Padding<16>>::pad(black_box(&mut block), black_box(5)).unwrap();
            black_box(&block);
        })
    });
    group.bench_function("unpad/16", |b| {
        let mut block = [0u8; 16];
        <PKCS7 as Padding<16>>::pad(&mut block, 5).unwrap();
        b.iter(|| {
            let n = <PKCS7 as Padding<16>>::unpad(black_box(&block)).unwrap();
            black_box(n);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_pkcs7);
criterion_main!(benches);
