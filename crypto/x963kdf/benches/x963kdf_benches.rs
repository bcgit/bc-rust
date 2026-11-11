use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_x963kdf::{X963KDF_SHA256, X963KDF_SHA512};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_x963kdf(c: &mut Criterion) {
    let z = KeyMaterial::<32>::from_bytes_as_type(&[0x5A; 32], KeyType::SharedSecret).unwrap();
    let info = b"x963kdf bench";

    let mut group = c.benchmark_group("x963kdf");
    group.bench_function("sha256 32 bytes", |b| {
        let mut out = KeyMaterial::<32>::new();
        b.iter(|| X963KDF_SHA256::derive_out(black_box(&z), black_box(info), 32, &mut out).unwrap())
    });
    group.bench_function("sha256 1024 bytes", |b| {
        let mut out = KeyMaterial::<1024>::new();
        b.iter(|| {
            X963KDF_SHA256::derive_out(black_box(&z), black_box(info), 1024, &mut out).unwrap()
        })
    });
    group.bench_function("sha512 64 bytes", |b| {
        let mut out = KeyMaterial::<64>::new();
        b.iter(|| X963KDF_SHA512::derive_out(black_box(&z), black_box(info), 64, &mut out).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_x963kdf);
criterion_main!(benches);
