use bouncycastle_rng as rng;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{MAC, RNG};
use bouncycastle_poly1305::hazmat::key_from_bytes;

const DATA_LEN: usize = 16 * 1024;

fn random_data(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();
    data
}

fn bench_poly1305(c: &mut Criterion) {
    // A fixed key is fine for timing; a real one-time key must never be reused.
    let key = [0x42u8; 32];
    let data = random_data(DATA_LEN);
    let mut tag = [0u8; 16];

    let mut group = c.benchmark_group("poly1305::Poly1305");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function(format!("{DATA_LEN} bytes -- ::mac_out()"), |b| {
        // A key is consumed by its one message, so each iteration is given its own.
        b.iter_batched(
            || key_from_bytes(&key).into_generator(),
            |mac| {
                mac.mac_out(black_box(&data), &mut tag).unwrap();
                black_box(&tag);
            },
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group!(benches, bench_poly1305);
criterion_main!(benches);
