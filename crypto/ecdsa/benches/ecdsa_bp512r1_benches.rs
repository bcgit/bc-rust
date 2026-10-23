use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_ecdsa::ecdsa_bp512r1::ECDSABp512r1;
use bouncycastle_ecdsa::keys_bp512r1::keygen;
use bouncycastle_rng::DefaultRNG;

const MSG: &[u8] = b"a representative message for benchmarking ECDSA brainpoolP512r1";

fn bench_ecdsa_bp512r1(c: &mut Criterion) {
    let (pk, sk) = keygen().unwrap();
    let sig = ECDSABp512r1::sign(&sk, MSG, None).unwrap();

    let mut group = c.benchmark_group("ecdsa_bp512r1");
    group.bench_function("keygen", |bencher| bencher.iter(|| black_box(keygen().unwrap())));
    group.bench_function("sign", |bencher| {
        bencher
            .iter(|| black_box(ECDSABp512r1::sign(black_box(&sk), black_box(MSG), None).unwrap()))
    });
    group.bench_function("sign_randomized", |bencher| {
        bencher.iter(|| {
            black_box(
                ECDSABp512r1::sign_randomized(
                    black_box(&sk),
                    black_box(MSG),
                    &mut DefaultRNG::default(),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("verify", |bencher| {
        bencher.iter(|| {
            ECDSABp512r1::verify(black_box(&pk), black_box(MSG), None, black_box(&sig)).unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_ecdsa_bp512r1);
criterion_main!(benches);
