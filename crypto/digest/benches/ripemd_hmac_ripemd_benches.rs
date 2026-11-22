use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::RNG;
use bouncycastle_digest::ripemd::RIPEMD160;
use bouncycastle_hmac::{HMACParams, HmacKey};
use bouncycastle_rng as rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_hmac<const N: usize, H: HMACParams<MACKey = KeyMaterial<N>>>(
    c: &mut Criterion,
    group_name: &str,
) {
    let mut data_block = [0_u8; 1024];
    rng::DefaultRNG::default().next_bytes_out(&mut data_block).unwrap();

    let mut big_data: Vec<u8> = vec![];
    for _ in 0..16 {
        big_data.extend_from_slice(&data_block);
    }

    let hmac_key = KeyMaterial256::from_bytes_as_type(&data_block[..N], KeyType::MACKey).unwrap();
    let key = HmacKey::<H>::from_key_material(&hmac_key).unwrap();
    let mut out = [0u8; N];

    let mut group = c.benchmark_group(group_name);
    group.throughput(Throughput::Bytes(big_data.len() as u64));
    group.bench_function(format!("{} bytes -- key.mac_out()", big_data.len() as u64), |b| {
        b.iter(|| {
            key.mac_out(black_box(&big_data), &mut out);
            black_box(&out);
        })
    });
    group.finish();
}

fn bench_hmac_ripemd160(c: &mut Criterion) {
    bench_hmac::<20, RIPEMD160>(c, "hmac::HmacKey<RIPEMD160>::mac_out() -- 16x1024 one-shot");
}

criterion_group!(benches, bench_hmac_ripemd160);
criterion_main!(benches);
