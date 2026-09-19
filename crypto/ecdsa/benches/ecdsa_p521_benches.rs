use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_ecdsa::ecdsa_p521::ECDSAP521;
use bouncycastle_ecdsa::keys_p521::keygen;
use bouncycastle_rng::DefaultRNG;

const MSG: &[u8] = b"a representative message for benchmarking ECDSA P-521";

fn bench_ecdsa_p521(c: &mut Criterion) {
    let (pk, sk) = keygen().unwrap();
    let sig = ECDSAP521::sign(&sk, MSG, None).unwrap();

    let mut group = c.benchmark_group("ecdsa_p521");
    group.bench_function("keygen", |bencher| bencher.iter(|| black_box(keygen().unwrap())));
    group.bench_function("sign", |bencher| {
        bencher.iter(|| black_box(ECDSAP521::sign(black_box(&sk), black_box(MSG), None).unwrap()))
    });
    group.bench_function("sign_randomized", |bencher| {
        bencher.iter(|| {
            black_box(
                ECDSAP521::sign_randomized(
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
            ECDSAP521::verify(black_box(&pk), black_box(MSG), None, black_box(&sig)).unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_ecdsa_p521);
criterion_main!(benches);
