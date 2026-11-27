use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotVerifyingKey, VerifyingKey,
};
use bouncycastle_core::traits::{PrivateKey, PublicKey, SignatureSigner, SignatureVerifier};
use bouncycastle_ec::ed::ed25519::{Ed25519PrivateKey, Ed25519PublicKey, keygen};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// A short message, where the curve arithmetic is the whole cost, and a longer one, where
/// Ed25519's two passes over the message and Ed25519ph's one begin to show.
const MSG_LENS: [usize; 2] = [64, 16 * 1024];

/// The 32 octets a key generation draws, from an RNG that only copies them out, so that no
/// DRBG is measured.
const SEED: [u8; 32] = [0x2A; 32];

fn bench_ed25519_keys(c: &mut Criterion) {
    let (pk, sk) = keygen(&mut FixedSeedRNG::new(SEED)).unwrap();
    let sk_bytes = sk.encode();
    let pk_bytes = pk.encode();

    let mut group = c.benchmark_group("ed25519_keys");
    group.bench_function("keygen", |b| {
        b.iter(|| black_box(keygen(&mut FixedSeedRNG::new(black_box(SEED))).unwrap()))
    });
    // Key expansion: SHA-512 and a fixed-base multiplication.
    group.bench_function("sk_from_bytes", |b| {
        b.iter(|| black_box(Ed25519PrivateKey::from_bytes(black_box(&sk_bytes)).unwrap()))
    });
    // Full validation: decompression and the subgroup check.
    group.bench_function("pk_from_bytes", |b| {
        b.iter(|| black_box(Ed25519PublicKey::from_bytes(black_box(&pk_bytes)).unwrap()))
    });
    group.bench_function("pk_from_sk", |b| b.iter(|| black_box(black_box(&sk).pk().unwrap())));
    group.finish();
}

/// Ed25519 through the one-shots, its only form.
fn bench_ed25519(c: &mut Criterion) {
    let (pk, sk) = keygen(&mut FixedSeedRNG::new(SEED)).unwrap();

    let mut group = c.benchmark_group("ed25519");
    for len in MSG_LENS {
        let msg = vec![0xA5u8; len];
        let sig = sk.sign_deterministic(&msg, None).unwrap();

        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("sign", len), &msg, |b, msg| {
            b.iter(|| black_box(black_box(&sk).sign_deterministic(black_box(msg), None).unwrap()))
        });
        group.bench_with_input(BenchmarkId::new("verify", len), &msg, |b, msg| {
            b.iter(|| black_box(&pk).verify(black_box(msg), None, black_box(&sig)).unwrap())
        });
    }
    group.finish();
}

/// Ed25519ph through the workers; its one-shots run the same workers.
fn bench_ed25519ph(c: &mut Criterion) {
    let (pk, sk) = keygen(&mut FixedSeedRNG::new(SEED)).unwrap();

    let mut group = c.benchmark_group("ed25519ph");
    for len in MSG_LENS {
        let msg = vec![0xA5u8; len];
        let mut signer = sk.as_prehash().create_signer_deterministic(None).unwrap();
        signer.do_update(&msg);
        let sig = signer.do_final().unwrap();

        group.throughput(Throughput::Bytes(len as u64));
        group.bench_with_input(BenchmarkId::new("sign", len), &msg, |b, msg| {
            b.iter(|| {
                let mut signer =
                    black_box(&sk).as_prehash().create_signer_deterministic(None).unwrap();
                signer.do_update(black_box(msg));
                black_box(signer.do_final().unwrap())
            })
        });
        group.bench_with_input(BenchmarkId::new("verify", len), &msg, |b, msg| {
            b.iter(|| {
                let mut verifier = black_box(&pk).as_prehash().create_verifier(None).unwrap();
                verifier.do_update(black_box(msg));
                verifier.do_verify_final(black_box(&sig)).unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_ed25519_keys, bench_ed25519, bench_ed25519ph);
criterion_main!(benches);
