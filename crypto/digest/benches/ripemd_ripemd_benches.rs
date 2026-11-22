use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{Hash, RNG};
use bouncycastle_digest::ripemd::*;
use bouncycastle_rng as rng;

fn bench_hash<H: Hash + Default>(c: &mut Criterion, group_name: &str) {
    let mut data = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    let mut digest = vec![0; H::default().output_len()];

    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut md = H::default();
            for _ in 0..16 {
                md.do_update(black_box(&data));
            }
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_ripemd128(c: &mut Criterion) {
    bench_hash::<RIPEMD128>(c, "ripemd::ripemd128");
}

fn bench_ripemd160(c: &mut Criterion) {
    bench_hash::<RIPEMD160>(c, "ripemd::ripemd160");
}

fn bench_ripemd256(c: &mut Criterion) {
    bench_hash::<RIPEMD256>(c, "ripemd::ripemd256");
}

fn bench_ripemd320(c: &mut Criterion) {
    bench_hash::<RIPEMD320>(c, "ripemd::ripemd320");
}

criterion_group!(benches, bench_ripemd128, bench_ripemd160, bench_ripemd256, bench_ripemd320);
criterion_main!(benches);
