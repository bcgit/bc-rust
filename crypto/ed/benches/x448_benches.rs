use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_ed::x448::{
    POINT_LEN, SCALAR_LEN, X448PrivateKey, X448PublicKey, keygen_from_seed,
};
use bouncycastle_rng::FixedSeedRNG;
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

fn bench_x448_encaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("Encaps");

    let keys = key_pairs();

    // A fixed-output RNG per encapsulation, so that we're not measuring the time of the DRBG.
    let mut ephemeral_seeds = [[0u8; SCALAR_LEN]; NUM_ELEMS];
    for (i, seed) in ephemeral_seeds.iter_mut().enumerate() {
        seed.fill(i as u8 + 1);
    }

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("DHKEM(X448, HKDF-SHA512)", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                let mut rng = FixedSeedRNG::new(ephemeral_seeds[i]);
                _ = black_box(keys[i].0.encaps(&mut rng, ()));
            }
        })
    });

    group.finish();
}

fn bench_x448_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decaps");

    let keys = key_pairs();

    // Set up the ciphertexts outside of the timing loop.
    let mut rng = FixedSeedRNG::new(&DUMMY_SEED[..SCALAR_LEN]);
    let cts: Vec<[u8; POINT_LEN]> =
        keys.iter().map(|(pk, _sk)| pk.encaps(&mut rng, ()).unwrap().1).collect();

    group.throughput(criterion::Throughput::Elements(NUM_ELEMS as u64));

    group.bench_function("DHKEM(X448, HKDF-SHA512)", |b| {
        b.iter(|| {
            for i in 0..NUM_ELEMS {
                _ = black_box(keys[i].1.decaps(&cts[i], ()));
            }
        })
    });

    group.finish();
}

criterion_group!(
    benches, bench_x448_keygen, bench_x448_key_agreement, bench_x448_encaps, bench_x448_decaps,
);
criterion_main!(benches);
