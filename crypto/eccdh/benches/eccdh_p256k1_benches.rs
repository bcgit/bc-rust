use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_eccdh::keys_p256k1::keygen;
use bouncycastle_rng::DefaultRNG;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_eccdh_p256k1(c: &mut Criterion) {
    let (_pk_a, sk_a) = keygen(&mut DefaultRNG::default()).unwrap();
    let (pk_b, _sk_b) = keygen(&mut DefaultRNG::default()).unwrap();

    let mut group = c.benchmark_group("eccdh_p256k1");
    group.bench_function("keygen", |bencher| {
        bencher.iter(|| black_box(keygen(&mut DefaultRNG::default()).unwrap()))
    });
    // The one-shot and the worker share the core, so one `agree` bench covers both.
    group.bench_function("agree", |bencher| {
        bencher.iter(|| black_box(black_box(&sk_a).agree(black_box(&pk_b), ()).unwrap()))
    });
    group.finish();
}

criterion_group!(benches, bench_eccdh_p256k1);
criterion_main!(benches);
