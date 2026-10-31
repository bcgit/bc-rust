use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core::traits::{KEMDecapsulator, KEMEncapsulator, KeyAgreement};
use bouncycastle_core_test_framework::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_ed::x25519::{X25519, X25519PrivateKey, X25519PublicKey};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

/// The number of distinct keys each benchmark iterates over, so that the CPU does not cache one
/// input or learn its branches.
const NUM_ELEMS: usize = 32;

/// `NUM_ELEMS` distinct 32-byte seeds, taken from `DUMMY_SEED`.
fn seeds() -> Vec<KeyMaterial256> {
    DUMMY_SEED
        .chunks(32)
        .take(NUM_ELEMS)
        .enumerate()
        .map(|(i, chunk)| {
            // The chunks of DUMMY_SEED repeat every 8; mixing in the index keeps all NUM_ELEMS
            // seeds distinct.
            let mut bytes: [u8; 32] = chunk.try_into().unwrap();
            bytes[0] ^= i as u8;
            KeyMaterial256::from_bytes_as_type(&bytes, KeyType::Seed).unwrap()
        })
        .collect()
}

/// A key pair for each of [`seeds`].
fn key_pairs() -> Vec<(X25519PublicKey, X25519PrivateKey)> {
    seeds().iter().map(|seed| X25519::keygen_from_seed(seed).unwrap()).collect()
}

fn bench_x25519_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyGen");

    // Set up the seeds outside of the timing loop.
    let seeds = seeds();

    group.throughput(criterion::Throughput::Elements(seeds.len() as u64));

    group.bench_function("X25519", |b| {
        b.iter(|| {
            for seed in seeds.iter() {
                _ = black_box(X25519::keygen_from_seed(seed));
            }
        })
    });

    group.finish();
}

fn bench_x25519_key_agreement(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyAgreement");

    let keys = key_pairs();

    group.throughput(criterion::Throughput::Elements(keys.len() as u64));

    // Each private key agrees with the next key pair's public key.
    group.bench_function("X25519", |b| {
        b.iter(|| {
            for i in 0..keys.len() {
                let pk = &keys[(i + 1) % keys.len()].0;
                _ = black_box(X25519::key_agreement(pk, &keys[i].1));
            }
        })
    });

    group.finish();
}

fn bench_x25519_encaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encaps");

    let keys = key_pairs();

    // A fixed-output RNG per encapsulation, so that we're not measuring the time of the DRBG.
    let mut ephemeral_seeds = [[0u8; 32]; NUM_ELEMS];
    for (i, seed) in ephemeral_seeds.iter_mut().enumerate() {
        seed.fill(i as u8 + 1);
    }

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("DHKEM(X25519, HKDF-SHA256)", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                let mut rng = FixedSeedRNG::new(ephemeral_seeds[i]);
                _ = black_box(X25519::encaps_rng(&keys[i].0, &mut rng));
            }
        })
    });

    group.finish();
}

fn bench_x25519_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decaps");

    let keys = key_pairs();

    // Set up the ciphertexts outside of the timing loop.
    let cts: Vec<[u8; 32]> = keys.iter().map(|(pk, _sk)| X25519::encaps(pk).unwrap().1).collect();

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("DHKEM(X25519, HKDF-SHA256)", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                _ = black_box(X25519::decaps(&keys[i].1, &cts[i]));
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_x25519_keygen,
    bench_x25519_key_agreement,
    bench_x25519_encaps,
    bench_x25519_decaps,
);
criterion_main!(benches);
