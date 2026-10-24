use bouncycastle_rng as rng;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ascon::AsconAEAD128Key;
use bouncycastle_ascon::AsconCXof128;
use bouncycastle_ascon::AsconHash256;
use bouncycastle_ascon::AsconXof128;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{Hash, RNG, XOF};

const DATA_LEN: usize = 16 * 1024;

fn random_data(len: usize) -> Vec<u8> {
    let mut data = vec![0u8; len];
    rng::DefaultRNG::default().next_bytes_out(&mut data).unwrap();
    data
}

fn bench_aead128_encrypt(c: &mut Criterion) {
    let material =
        KeyMaterial::<16>::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
    let key = AsconAEAD128Key::from_key_material(&material).unwrap();
    let nonce = [0x24u8; 16];
    let data = random_data(DATA_LEN);
    let mut out = vec![0u8; DATA_LEN + 16];

    let mut group = c.benchmark_group("ascon::Ascon_AEAD128");
    group.throughput(Throughput::Bytes(DATA_LEN as u64));

    group.bench_function(format!("{DATA_LEN} bytes -- encrypt_with_aad_nonce_out"), |b| {
        b.iter(|| {
            key.encrypt_with_aad_nonce_out(&nonce, &[], black_box(&data), &mut out).unwrap();
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
        format!("input: {DATA_LEN} bytes, output: 64 bytes -- ::xof_out()"),
        |b| {
            b.iter(|| {
                AsconXof128::new().xof_out(black_box(&data), &mut out);
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
        format!("input: {DATA_LEN} bytes, output: 64 bytes -- ::xof_out()"),
        |b| {
            b.iter(|| {
                AsconCXof128::with_customization(customization)
                    .unwrap()
                    .xof_out(black_box(&data), &mut out);

                black_box(&out);
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_aead128_encrypt, bench_hash256, bench_xof128, bench_cxof128);
criterion_main!(benches);
