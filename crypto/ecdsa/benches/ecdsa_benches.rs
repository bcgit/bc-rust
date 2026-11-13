use bouncycastle_core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
use bouncycastle_ec::curve::Curve;
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_ecdsa::ecdsa::EcdsaHash;
use bouncycastle_ecdsa::keys::keygen;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

const MSG: &[u8] = b"a representative message for benchmarking ECDSA";

/// Key generation, the random and the deterministic signer, and verification for one curve
/// and hash. The one-shots and the workers share the core, so one bench of each covers both.
fn bench_curve<C, H, const SIG_LEN: usize>(c: &mut Criterion, group: &str)
where
    C: Curve<Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    let (pk, sk) = keygen::<C, H>(&mut DefaultRNG::default()).unwrap();
    let sig = sk.sign(&mut DefaultRNG::default(), MSG, None).unwrap();

    let mut group = c.benchmark_group(group);
    group.bench_function("keygen", |bencher| {
        bencher.iter(|| black_box(keygen::<C, H>(&mut DefaultRNG::default()).unwrap()))
    });
    group.bench_function("sign", |bencher| {
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

fn bench_ecdsa(c: &mut Criterion) {
    bench_curve::<P256, SHA256, 64>(c, "ecdsa_p256_sha256");
    bench_curve::<P384, SHA384, 96>(c, "ecdsa_p384_sha384");
    bench_curve::<P521, SHA512, 132>(c, "ecdsa_p521_sha512");
    bench_curve::<Secp256K1, SHA256, 64>(c, "ecdsa_secp256k1_sha256");
    bench_curve::<Bp256r1, SHA256, 64>(c, "ecdsa_bp256r1_sha256");
    bench_curve::<Bp384r1, SHA384, 96>(c, "ecdsa_bp384r1_sha384");
    bench_curve::<Bp512r1, SHA512, 128>(c, "ecdsa_bp512r1_sha512");
}

criterion_group!(benches, bench_ecdsa);
criterion_main!(benches);
