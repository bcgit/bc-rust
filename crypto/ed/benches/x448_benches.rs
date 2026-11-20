use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_ed::x448::{SCALAR_LEN, X448PrivateKey, X448PublicKey, keygen_from_seed};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// The number of distinct keys each benchmark iterates over, so that the CPU does not cache one
/// input or learn its branches.
const NUM_ELEMS: usize = 32;

/// `NUM_ELEMS` distinct 56-byte seeds, taken from `DUMMY_SEED`.
fn seeds() -> Vec<KeyMaterial<SCALAR_LEN>> {
    (0..NUM_ELEMS)
        .map(|i| {
            // DUMMY_SEED repeats every 256 bytes, so windows 8 bytes apart repeat every 32;
            // mixing in the index keeps the seeds distinct whatever NUM_ELEMS is.
            let mut bytes: [u8; SCALAR_LEN] = DUMMY_SEED[8 * i..][..SCALAR_LEN].try_into().unwrap();
            bytes[1] ^= i as u8;
            KeyMaterial::<SCALAR_LEN>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap()
        })
        .collect()
}

/// A key pair for each of [`seeds`].
fn key_pairs() -> Vec<(X448PublicKey, X448PrivateKey)> {
    seeds().iter().map(|seed| keygen_from_seed(seed).unwrap()).collect()
}

fn bench_x448_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyGen");

    // Set up the seeds outside of the timing loop.
    let seeds = seeds();

    group.throughput(criterion::Throughput::Elements(seeds.len() as u64));

    group.bench_function("X448", |b| {
        b.iter(|| {
            for seed in seeds.iter() {
                _ = black_box(keygen_from_seed(seed));
            }
        })
    });

    group.finish();
}

fn bench_x448_key_agreement(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyAgreement");

    let keys = key_pairs();

    group.throughput(criterion::Throughput::Elements(keys.len() as u64));

    // Each private key agrees with the next key pair's public key.
    group.bench_function("X448", |b| {
        b.iter(|| {
            for i in 0..keys.len() {
                let pk = &keys[(i + 1) % keys.len()].0;
                _ = black_box(keys[i].1.agree(pk, ()));
            }
        })
    });

    group.finish();
}

criterion_group!(benches, bench_x448_keygen, bench_x448_key_agreement);
criterion_main!(benches);
