use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{Hash, RNG};
use bouncycastle_rng as rng;
use bouncycastle_sha2::*;

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

fn bench_sha256(c: &mut Criterion) {
    bench_hash::<SHA256>(c, "sha2::sha256");
}

fn bench_sha512(c: &mut Criterion) {
    bench_hash::<SHA512>(c, "sha2::sha512");
}

fn bench_sha512_224(c: &mut Criterion) {
    bench_hash::<SHA512_224>(c, "sha2::sha512_224");
}

fn bench_sha512_256(c: &mut Criterion) {
    bench_hash::<SHA512_256>(c, "sha2::sha512_256");
}

criterion_group!(benches, bench_sha256, bench_sha512, bench_sha512_224, bench_sha512_256);
criterion_main!(benches);
