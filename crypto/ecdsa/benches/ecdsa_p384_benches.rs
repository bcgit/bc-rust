use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_ecdsa::ecdsa_p384::ECDSAP384;
use bouncycastle_ecdsa::keys_p384::keygen;
use bouncycastle_rng::DefaultRNG;

const MSG: &[u8] = b"a representative message for benchmarking ECDSA P-384";

fn bench_ecdsa_p384(c: &mut Criterion) {
    let (pk, sk) = keygen().unwrap();
    let sig = ECDSAP384::sign(&sk, MSG, None).unwrap();

    let mut group = c.benchmark_group("ecdsa_p384");
    group.bench_function("keygen", |bencher| bencher.iter(|| black_box(keygen().unwrap())));
    group.bench_function("sign", |bencher| {
        bencher.iter(|| black_box(ECDSAP384::sign(black_box(&sk), black_box(MSG), None).unwrap()))
    });
    group.bench_function("sign_randomized", |bencher| {
        bencher.iter(|| {
            black_box(
                ECDSAP384::sign_randomized(
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
            ECDSAP384::verify(black_box(&pk), black_box(MSG), None, black_box(&sig)).unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_ecdsa_p384);
criterion_main!(benches);
