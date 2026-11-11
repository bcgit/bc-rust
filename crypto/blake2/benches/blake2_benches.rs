//! Criterion benches for BLAKE2b-512 and BLAKE2s-256: 16 KiB of input per iteration.
//!
//! The keyed (MAC) types share the hash engine and differ only by one extra key block, so they are
//! not benchmarked separately (QUALITY_AND_STYLE.md "Performance Benchmarks").

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_blake2::{BLAKE2b_512, BLAKE2s_256};
use bouncycastle_core::traits::{Hash, RNG};
use bouncycastle_rng as rng;

fn bench_blake2b_512(c: &mut Criterion) {
    let mut data = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    let mut digest = vec![0; BLAKE2b_512::new().output_len()];

    let mut group = c.benchmark_group("blake2b-512");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut md = BLAKE2b_512::new();
            for _ in 0..16 {
                md.do_update(black_box(&data));
            }
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_blake2s_256(c: &mut Criterion) {
    let mut data = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    let mut digest = vec![0; BLAKE2s_256::new().output_len()];

    let mut group = c.benchmark_group("blake2s-256");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut md = BLAKE2s_256::new();
            for _ in 0..16 {
                md.do_update(black_box(&data));
            }
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_blake2b_512, bench_blake2s_256);
criterion_main!(benches);
