use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_pbkdf2::{PBKDF2_HMAC_SHA3_256, PBKDF2_HMAC_SHA256, PBKDF2_HMAC_SHA512};
use core::num::NonZeroU32;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_pbkdf2(c: &mut Criterion) {
    let password =
        KeyMaterial::<64>::from_bytes_as_type(b"correct horse battery staple", KeyType::Unknown)
            .unwrap();
    let salt = [0x5Au8; 16];

    let mut group = c.benchmark_group("pbkdf2");
    group.sample_size(10);
    for iterations in [1_000u32, 100_000] {
        let count = NonZeroU32::new(iterations).unwrap();
        group.bench_function(format!("hmac-sha256, {iterations} iterations, 32 bytes"), |b| {
            let mut out = KeyMaterial::<32>::new();
            b.iter(|| {
                PBKDF2_HMAC_SHA256::derive_out(black_box(&password), &salt, count, 32, &mut out)
                    .unwrap()
            })
        });
        group.bench_function(format!("hmac-sha512, {iterations} iterations, 64 bytes"), |b| {
            let mut out = KeyMaterial::<64>::new();
            b.iter(|| {
                PBKDF2_HMAC_SHA512::derive_out(black_box(&password), &salt, count, 64, &mut out)
                    .unwrap()
            })
        });
        group.bench_function(format!("hmac-sha3-256, {iterations} iterations, 32 bytes"), |b| {
            let mut out = KeyMaterial::<32>::new();
            b.iter(|| {
                PBKDF2_HMAC_SHA3_256::derive_out(black_box(&password), &salt, count, 32, &mut out)
                    .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_pbkdf2);
criterion_main!(benches);
