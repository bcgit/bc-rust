use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::RNG;
use bouncycastle_hmac::HmacKey;
use bouncycastle_rng as rng;
use bouncycastle_sm3::SM3;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_hmac_sm3(c: &mut Criterion) {
    let mut data_block = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let hmac_key = KeyMaterial256::from_bytes_as_type(&data_block[..32], KeyType::MACKey).unwrap();
    let key = HmacKey::<SM3>::from_key_material(&hmac_key).unwrap();
    let mut out = [0u8; 32];

    let mut group = c.benchmark_group("hmac::HmacKey<SM3>::mac_out() -- 16x1024 one-shot");
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- key.mac_out()", big_data.len() as u64), |b| {
        b.iter(|| {
            key.mac_out(black_box(&big_data), &mut out).unwrap();
            black_box(&out);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_hmac_sm3);
criterion_main!(benches);
