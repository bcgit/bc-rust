//! Criterion benches for RSA-2048: one `bench_function` per (scheme, hash) pairing this size
//! wires up, since each has a different performance profile (SHA-256/384/512 hash different
//! amounts of data per block; PSS additionally draws a fresh salt and runs MGF1/SHAKE). The
//! genuine key is the same one `tests/rsa_2048_pkcs1_v1_5_tests.rs` recovers from Wycheproof's
//! `rsa_pkcs1_2048_sig_gen_test.json` (see that file for the full, sourced provenance).

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsa_2048::{
    Rsa2048PrivateKey, Rsa2048PublicKey, pkcs1_v1_5_sign_sha256, pkcs1_v1_5_sign_sha384,
    pkcs1_v1_5_sign_sha512, pkcs1_v1_5_verify_sha256, pkcs1_v1_5_verify_sha384,
    pkcs1_v1_5_verify_sha512, pss_shake128_sign, pss_shake128_verify, pss_sign_sha256,
    pss_sign_sha384, pss_sign_sha512, pss_verify_sha256, pss_verify_sha384, pss_verify_sha512,
};

const MSG: &[u8] = b"a representative message for benchmarking RSA-2048";

fn genuine_key() -> Rsa2048PrivateKey {
    let p: [u64; 16] = [
        0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
        0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
        0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
        0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
    ];
    let q: [u64; 16] = [
        0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
        0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
        0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
        0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
    ];
    let d_p: [u64; 16] = [
        0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
        0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
        0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
        0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
    ];
    let d_q: [u64; 16] = [
        0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
        0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
        0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
        0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
    ];
    let q_inv: [u64; 16] = [
        0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
        0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
        0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
        0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
    ];
    Rsa2048PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
        .expect("genuine RSA-2048 CRT components must be accepted")
}

fn bench_rsa_2048(c: &mut Criterion) {
    let sk = genuine_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();

    let sig_pkcs1_256 = pkcs1_v1_5_sign_sha256(&sk, MSG).unwrap();
    let sig_pkcs1_384 = pkcs1_v1_5_sign_sha384(&sk, MSG).unwrap();
    let sig_pkcs1_512 = pkcs1_v1_5_sign_sha512(&sk, MSG).unwrap();
    let sig_pss_256 = pss_sign_sha256(&sk, MSG, &mut rng).unwrap();
    let sig_pss_384 = pss_sign_sha384(&sk, MSG, &mut rng).unwrap();
    let sig_pss_512 = pss_sign_sha512(&sk, MSG, &mut rng).unwrap();
    let sig_pss_shake128 = pss_shake128_sign(&sk, MSG, &mut rng).unwrap();

    let mut group = c.benchmark_group("rsa_2048");

    group.bench_function("pkcs1v15_sign_sha256", |b| {
        b.iter(|| black_box(pkcs1_v1_5_sign_sha256(black_box(&sk), black_box(MSG)).unwrap()))
    });
    group.bench_function("pkcs1v15_verify_sha256", |b| {
        b.iter(|| {
            pkcs1_v1_5_verify_sha256(black_box(&pk), black_box(MSG), black_box(&sig_pkcs1_256))
                .unwrap()
        })
    });
    group.bench_function("pkcs1v15_sign_sha384", |b| {
        b.iter(|| black_box(pkcs1_v1_5_sign_sha384(black_box(&sk), black_box(MSG)).unwrap()))
    });
    group.bench_function("pkcs1v15_verify_sha384", |b| {
        b.iter(|| {
            pkcs1_v1_5_verify_sha384(black_box(&pk), black_box(MSG), black_box(&sig_pkcs1_384))
                .unwrap()
        })
    });
    group.bench_function("pkcs1v15_sign_sha512", |b| {
        b.iter(|| black_box(pkcs1_v1_5_sign_sha512(black_box(&sk), black_box(MSG)).unwrap()))
    });
    group.bench_function("pkcs1v15_verify_sha512", |b| {
        b.iter(|| {
            pkcs1_v1_5_verify_sha512(black_box(&pk), black_box(MSG), black_box(&sig_pkcs1_512))
                .unwrap()
        })
    });
    group.bench_function("pss_sign_sha256", |b| {
        b.iter(|| {
            black_box(
                pss_sign_sha256(black_box(&sk), black_box(MSG), &mut DefaultRNG::default())
                    .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_sha256", |b| {
        b.iter(|| {
            pss_verify_sha256(black_box(&pk), black_box(MSG), black_box(&sig_pss_256)).unwrap()
        })
    });
    group.bench_function("pss_sign_sha384", |b| {
        b.iter(|| {
            black_box(
                pss_sign_sha384(black_box(&sk), black_box(MSG), &mut DefaultRNG::default())
                    .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_sha384", |b| {
        b.iter(|| {
            pss_verify_sha384(black_box(&pk), black_box(MSG), black_box(&sig_pss_384)).unwrap()
        })
    });
    group.bench_function("pss_sign_sha512", |b| {
        b.iter(|| {
            black_box(
                pss_sign_sha512(black_box(&sk), black_box(MSG), &mut DefaultRNG::default())
                    .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_sha512", |b| {
        b.iter(|| {
            pss_verify_sha512(black_box(&pk), black_box(MSG), black_box(&sig_pss_512)).unwrap()
        })
    });
    group.bench_function("pss_sign_shake128", |b| {
        b.iter(|| {
            black_box(
                pss_shake128_sign(black_box(&sk), black_box(MSG), &mut DefaultRNG::default())
                    .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_shake128", |b| {
        b.iter(|| {
            pss_shake128_verify(black_box(&pk), black_box(MSG), black_box(&sig_pss_shake128))
                .unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_rsa_2048);
criterion_main!(benches);
