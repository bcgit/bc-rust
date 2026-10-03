use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_sm2::keys::keygen;
use bouncycastle_sm2::sm2::SM2;

const MSG: &[u8] = b"a representative message for benchmarking SM2";
const ID: &[u8] = b"benchmark-identity@example.com";

fn bench_sm2(c: &mut Criterion) {
    let (pk, sk) = keygen().unwrap();
    let sig = SM2::sign(&sk, MSG, Some(ID)).unwrap();

    let mut group = c.benchmark_group("sm2");
    group.bench_function("keygen", |bencher| bencher.iter(|| black_box(keygen().unwrap())));
    group.bench_function("sign", |bencher| {
        bencher.iter(|| {
            black_box(SM2::sign(black_box(&sk), black_box(MSG), Some(black_box(ID))).unwrap())
        })
    });
    group.bench_function("verify", |bencher| {
        bencher.iter(|| {
            SM2::verify(black_box(&pk), black_box(MSG), Some(black_box(ID)), black_box(&sig))
                .unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_sm2);
criterion_main!(benches);
