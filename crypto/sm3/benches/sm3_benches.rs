use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{Hash, RNG};
use bouncycastle_rng as rng;
use bouncycastle_sm3::SM3;

fn bench_sm3(c: &mut Criterion) {
    let mut data = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();

    let mut digest = vec![0; SM3::new().output_len()];

    let mut group = c.benchmark_group("sm3");
    group.throughput(Throughput::Bytes(16 * 1024));
    group.bench_function("16KiB", |b| {
        b.iter(|| {
            let mut md = SM3::new();
            for _ in 0..16 {
                md.do_update(black_box(&data));
            }
            _ = md.do_final_out(&mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_sm3);
criterion_main!(benches);
