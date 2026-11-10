use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
use bouncycastle_rng::DefaultRNG;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_sm2::keys::keygen;

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

criterion_group!(benches, bench_sm2);
criterion_main!(benches);
