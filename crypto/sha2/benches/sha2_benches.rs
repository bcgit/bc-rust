use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{Hash, RNG};
use bouncycastle_rng as rng;
use bouncycastle_sha2::*;

fn bench_sha256(c: &mut Criterion) {
    let mut data = vec![0_u8; 1024 * 1024];
    let mut rng = rng::DefaultRNG::default();
    for chunk in data.chunks_mut(1024) {
        rng.next_bytes_out(chunk).unwrap();
    }

    let mut digest = vec![0; SHA256::new().output_len()];

    let mut group = c.benchmark_group("sha2::sha256");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB/one-shot", |b| {
        b.iter(|| {
            let mut md = SHA256::new();
            md.do_update(black_box(&data[..16 * 1024]));
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.bench_function("16KiB/1KiB-chunks", |b| {
        b.iter(|| {
            let mut md = SHA256::new();
            for chunk in data[..16 * 1024].chunks(1024) {
                md.do_update(black_box(chunk));
            }
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();

    let mut group = c.benchmark_group("sha2::sha256");
    group.throughput(Throughput::Bytes(1024 * 1024));
    group.bench_function("1MiB/one-shot", |b| {
        b.iter(|| {
            let mut md = SHA256::new();
            md.do_update(black_box(&data));
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let mut data = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    let mut digest = vec![0; SHA512::new().output_len()];

    let mut group = c.benchmark_group("sha2::sha512");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut md = SHA512::new();
            for _ in 0..16 {
                md.do_update(black_box(&data));
            }
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_sha256, bench_sha512);
criterion_main!(benches);
