use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_ec::curve::Curve;
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_eccdh::keys::keygen;
use bouncycastle_rng::DefaultRNG;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_curve<C, const SS_LEN: usize>(c: &mut Criterion, group: &str)
where
    C: Curve<FeBytes = [u8; SS_LEN]>,
{
    let (_pk_a, sk_a) = keygen::<C>(&mut DefaultRNG::default()).unwrap();
    let (pk_b, _sk_b) = keygen::<C>(&mut DefaultRNG::default()).unwrap();

    let mut group = c.benchmark_group(group);
    group.bench_function("keygen", |bencher| {
        bencher.iter(|| black_box(keygen::<C>(&mut DefaultRNG::default()).unwrap()))
    });
    // The one-shot and the worker share the core, so one `agree` bench covers both.
    group.bench_function("agree", |bencher| {
        bencher.iter(|| black_box(black_box(&sk_a).agree(black_box(&pk_b), ()).unwrap()))
    });
    group.finish();
}

fn bench_eccdh(c: &mut Criterion) {
    bench_curve::<P256, 32>(c, "eccdh_p256");
    bench_curve::<P384, 48>(c, "eccdh_p384");
    bench_curve::<P521, 66>(c, "eccdh_p521");
    bench_curve::<Secp256K1, 32>(c, "eccdh_secp256k1");
    bench_curve::<Bp256r1, 32>(c, "eccdh_bp256r1");
    bench_curve::<Bp384r1, 48>(c, "eccdh_bp384r1");
    bench_curve::<Bp512r1, 64>(c, "eccdh_bp512r1");
}

criterion_group!(benches, bench_eccdh);
criterion_main!(benches);
