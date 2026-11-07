use bouncycastle_core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
use bouncycastle_rng::DefaultRNG;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_ecdsa::keys_p384::keygen;

const MSG: &[u8] = b"a representative message for benchmarking ECDSA P-384";

fn bench_ecdsa_p384(c: &mut Criterion) {
    let (pk, sk) = keygen(&mut DefaultRNG::default()).unwrap();
    let sig = sk.sign(&mut DefaultRNG::default(), MSG, None).unwrap();

    let mut group = c.benchmark_group("ecdsa_p384");
    group.bench_function("keygen", |bencher| {
        bencher.iter(|| black_box(keygen(&mut DefaultRNG::default()).unwrap()))
    });
    group.bench_function("sign", |bencher| {
        bencher.iter(|| {
            black_box(
                black_box(&sk).sign(&mut DefaultRNG::default(), black_box(MSG), None).unwrap(),
            )
        })
    });
    group.bench_function("sign_rng", |bencher| {
        bencher.iter(|| {
            black_box(
                black_box(&sk).sign(&mut DefaultRNG::default(), black_box(MSG), None).unwrap(),
            )
        })
    });
    group.bench_function("sign_deterministic", |bencher| {
        bencher.iter(|| black_box(black_box(&sk).sign_deterministic(black_box(MSG), None).unwrap()))
    });
    group.bench_function("verify", |bencher| {
        bencher.iter(|| black_box(&pk).verify(black_box(MSG), None, black_box(&sig)).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_ecdsa_p384);
criterion_main!(benches);
