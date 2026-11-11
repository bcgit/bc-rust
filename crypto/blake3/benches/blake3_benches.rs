//! Criterion benches for BLAKE3.
//!
//! Two cost profiles are measured: absorbing input (the chunk/tree hash) and squeezing extended
//! output (repeated root compressions, s. 2.6). The keyed_hash and derive_key modes are not benched
//! separately: they run the same compression function over the same tree, differing only in the
//! key words and a flag (s. 2.3). derive_key adds one hash of the context string at construction.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_blake3::BLAKE3;
use bouncycastle_core::traits::{Hash, RNG, XOF, XOFSqueezer};
use bouncycastle_rng as rng;

fn bench_blake3(c: &mut Criterion) {
    let mut data = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    let mut digest = vec![0; BLAKE3::new().output_len()];

    let mut group = c.benchmark_group("blake3");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut md = BLAKE3::new();
            for _ in 0..16 {
                md.do_update(black_box(&data));
            }
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_blake3_squeeze(c: &mut Criterion) {
    let mut output = vec![0_u8; 1024];

    let mut group = c.benchmark_group("blake3-squeeze");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut md = BLAKE3::new();
            md.do_update(black_box(b"abc"));
            let mut squeezer = md.into_squeezer();
            for _ in 0..16 {
                squeezer.do_output_out(&mut output);
                black_box(&output);
            }
        })
    });
    group.finish();
}

criterion_group!(benches, bench_blake3, bench_blake3_squeeze);
criterion_main!(benches);
