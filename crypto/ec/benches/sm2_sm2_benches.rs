use bouncycastle_core::signature_key::{OneShotSigningKey, OneShotVerifyingKey};
use bouncycastle_rng::DefaultRNG;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ec::sm2::encryption;
use bouncycastle_ec::sm2::keys::keygen;

const MSG: &[u8] = b"a representative message for benchmarking SM2";
const ID: &[u8] = b"benchmark-identity@example.com";

fn bench_sm2(c: &mut Criterion) {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let sig = sk.sign(&mut DefaultRNG::default(), MSG, Some(ID)).unwrap();

    let mut group = c.benchmark_group("sm2");
    group.bench_function("keygen", |bencher| {
        bencher.iter(|| black_box(keygen(&mut DefaultRNG::default()).unwrap()))
    });
    group.bench_function("sign", |bencher| {
        bencher.iter(|| {
            black_box(
                black_box(&sk)
                    .sign(&mut DefaultRNG::default(), black_box(MSG), Some(black_box(ID)))
                    .unwrap(),
            )
        })
    });
    group.bench_function("verify", |bencher| {
        bencher.iter(|| {
            black_box(&pk).verify(black_box(MSG), Some(black_box(ID)), black_box(&sig)).unwrap()
        })
    });
    group.finish();
}

/// Encryption and decryption of messages of 32 bytes (a key) and 1024, detached and in place;
/// the contiguous forms are the same computation and a copy.
fn bench_sm2_encryption(c: &mut Criterion) {
    let (pk, sk) = encryption::keygen(&mut DefaultRNG::default()).unwrap();
    let mut rng = DefaultRNG::default();

    let mut group = c.benchmark_group("sm2_encryption");
    group.bench_function("keygen", |bencher| {
        bencher.iter(|| black_box(encryption::keygen(&mut rng).unwrap()))
    });
    for len in [32usize, 1024] {
        let msg = vec![0x4d; len];
        let mut ciphertext = msg.clone();
        let (c1, c3) = pk.encrypt_detached_inplace(&mut rng, &mut ciphertext).unwrap();

        group.throughput(criterion::Throughput::Bytes(len as u64));
        group.bench_function(format!("encrypt/{len}"), |bencher| {
            let mut buf = msg.clone();
            bencher.iter(|| {
                buf.copy_from_slice(&msg);
                black_box(black_box(&pk).encrypt_detached_inplace(&mut rng, &mut buf).unwrap())
            })
        });
        group.bench_function(format!("decrypt/{len}"), |bencher| {
            let mut buf = ciphertext.clone();
            bencher.iter(|| {
                buf.copy_from_slice(&ciphertext);
                black_box(&sk)
                    .decrypt_detached_inplace(black_box(&c1), black_box(&c3), &mut buf)
                    .unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sm2, bench_sm2_encryption);
criterion_main!(benches);
