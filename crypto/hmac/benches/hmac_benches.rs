use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use bouncycastle_rng as rng;
use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyMaterial512, KeyType};
use bouncycastle_core_interface::traits::{MAC, RNG};
use bouncycastle_hmac::{HMAC_SHA256, HMAC_SHA512};

fn bench_hmac_sha256(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let hmac_key = KeyMaterial256::from_bytes_as_type(&data_block[..32], KeyType::MACKey).unwrap();
    let mut out = [0u8; 32];

    let mut group = c.benchmark_group("hmac::HMAC_SHA256::mac_out() -- 16x1024 one-shot");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- ::hashes()", big_data.len() as u64), |b| {
        b.iter(|| {
            HMAC_SHA256::new(&hmac_key).unwrap().mac_out(black_box(&big_data), &mut out).unwrap();
            black_box(&out);
        })
    });
    group.finish();
}

fn bench_hmac_sha512(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let hmac_key = KeyMaterial512::from_bytes_as_type(&data_block[..64], KeyType::MACKey).unwrap();
    let mut out = [0u8; 64];

    let mut group = c.benchmark_group("hmac::HMAC_SHA512::mac_out() -- 16x1024 one-shot");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- ::hashes()", big_data.len() as u64), |b| {
        b.iter(|| {
            HMAC_SHA512::new(&hmac_key).unwrap().mac_out(black_box(&big_data), &mut out).unwrap();
            black_box(&out);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_hmac_sha256, bench_hmac_sha512);
criterion_main!(benches);