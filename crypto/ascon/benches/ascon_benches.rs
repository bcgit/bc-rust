use bouncycastle_rng as rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ascon::ascon_aead128::AsconAead128;
use bouncycastle_ascon::ascon_cxof128::AsconCXof128;
use bouncycastle_ascon::ascon_hash256::AsconHash256;
use bouncycastle_ascon::ascon_xof128::AsconXof128;
use bouncycastle_core::traits::{Hash, RNG, XOF};

const DATA_LEN: usize = 16 * 1024;

fn random_data(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();
    data
}

fn bench_aead128_encrypt(c: &mut Criterion) {
    let key = [0x42u8; 16];
    let nonce = [0x24u8; 16];
    let data = random_data(DATA_LEN);
    let mut out = vec![0u8; DATA_LEN + 16];

    let mut group = c.benchmark_group("ascon::AsconAead128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));
    group.bench_function(format!("{DATA_LEN} bytes -- ::encrypt()"), |b| {
        b.iter(|| {
            AsconAead128::encrypt(&key, &nonce, None, black_box(&data), &mut out);
            black_box(&out);
        })
    });
    group.finish();
}

fn bench_hash256(c: &mut Criterion) {
    let data = random_data(DATA_LEN);
    let mut digest = [0u8; 32];

    let mut group = c.benchmark_group("ascon::AsconHash256");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));
    group.bench_function(format!("{DATA_LEN} bytes -- ::hash_out()"), |b| {
        b.iter(|| {
            AsconHash256::new().hash_out(black_box(&data), &mut digest);
            black_box(&digest);
        })
    });
    group.finish();
}

fn bench_xof128(c: &mut Criterion) {
    let data = random_data(DATA_LEN);
    let mut out = [0u8; 64];

    let mut group = c.benchmark_group("ascon::AsconXof128");
    group.throughput(Throughput::Bytes((DATA_LEN + out.len()) as u64));
    group.bench_function(
        format!("input: {DATA_LEN} bytes, output: 64 bytes -- ::hash_xof_out()"),
        |b| {
            b.iter(|| {
                AsconXof128::new().hash_xof_out(black_box(&data), &mut out);
                black_box(&out);
            })
        },
    );
    group.finish();
}

fn bench_cxof128(c: &mut Criterion) {
    let data = random_data(DATA_LEN);
    let customization = b"bench-customization";
    let mut out = [0u8; 64];

    let mut group = c.benchmark_group("ascon::AsconCXof128");
    group.throughput(Throughput::Bytes((DATA_LEN + out.len()) as u64));
    group.bench_function(
        format!("input: {DATA_LEN} bytes, output: 64 bytes -- ::hash_xof_out()"),
        |b| {
            b.iter(|| {
                AsconCXof128::with_customization(customization)
                    .hash_xof_out(black_box(&data), &mut out);
                black_box(&out);
            })
        },
    );
    group.finish();
}

criterion_group!(benches, bench_aead128_encrypt, bench_hash256, bench_xof128, bench_cxof128);
criterion_main!(benches);
