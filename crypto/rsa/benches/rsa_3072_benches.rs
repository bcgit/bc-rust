//! Criterion benches for RSA-3072. See `rsa_2048_benches.rs`'s docs for the rationale; the genuine
//! key is the same one `tests/rsa_3072_tests.rs` recovers from Wycheproof's
//! `rsa_pkcs1_3072_sig_gen_test.json`.

use bouncycastle_core::traits::{SignatureVerifier, Signer};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsa_3072::keygen;
use bouncycastle_rsa::rsa_3072::{
    RSA3072PrivateKey, RSA3072PublicKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PKCS1_v1_5_SHA384,
    RSASSA_PKCS1_v1_5_SHA512, RSASSA_PSS_SHA256, RSASSA_PSS_SHA384, RSASSA_PSS_SHA512,
    RSASSA_PSS_SHAKE128,
};

const MSG: &[u8] = b"a representative message for benchmarking RSA-3072";

fn genuine_key() -> RSA3072PrivateKey {
    let p: [u64; 24] = [
        0xb26d973345bc4c5f, 0x23251a1d29962ca9, 0x554fc3f23d6c9046, 0x89ffe73b1401e9b8,
        0xe0b448b454670aca, 0xa73ea5c2413d1da2, 0xe9539bc7a8d3b351, 0x357984fc116af9cb,
        0xa93e40aac908e4e3, 0xae586c1e7f5c52cd, 0x80deaeaab651c7a9, 0xe261a4f7f4505580,
        0xc5a703b2fc28bfcf, 0x14521a6893f3f3c5, 0x0f08d649107f449a, 0xd96ceabb7ee83ce5,
        0x1b2e8a9b2bb69525, 0x383ead851fac07ad, 0x939deb88dff68550, 0xce9fa16a1cc92120,
        0x43604a7f2be2860f, 0xba55f20a964c4e63, 0x0ed9ac8a812545da, 0xf5eca16e0e83696b,
    ];
    let q: [u64; 24] = [
        0x7981610848c55cdd, 0x8bce03c5d339b975, 0xb8227d7b5d76ce8b, 0x6edee1e9d17781db,
        0x1c127ac3c4d0bd59, 0xb8b28f38951d7bee, 0x496086fa1300249a, 0x790e5c34729a8efb,
        0x9bdb81968f4a6d7c, 0x6018fd4ed9a3545f, 0x6ccb168d5b510dbe, 0xe1d845c6553c0a54,
        0x73ec1d97f669e298, 0x8b898025ef470e43, 0x160deb327e8ace01, 0x640191099b355611,
        0xe0ec501ccc94b2b0, 0x4f98c9ee4fdae41b, 0x0082a3bc42af1a14, 0x510a623c2b47a522,
        0x32057f9da6dbefc4, 0x95ad92b6f295d610, 0x19ddbfcfa2d96704, 0xcf25446f59cf5129,
    ];
    let d_p: [u64; 24] = [
        0xeeb10a8531c470ed, 0xbcd9be04cdc9d65c, 0xb684b458e4ab3854, 0x6a2dafd0d3b23a21,
        0xc812cbd3dccc8b35, 0x3e67363a947405c6, 0xa3ce9c7d391bdbb2, 0xf8bd10156b4bd580,
        0x3c1ce3ae99eb37da, 0xcfa5f4771567cc23, 0x35e0be9a437021c1, 0x8a527b7b967be52e,
        0xc649435b483585d6, 0x1dc154ddadf6bc20, 0x69105ecfc1144838, 0x3dad9bdd05d4f6d4,
        0xf95601b3d122be79, 0x92f1eed27a0ada46, 0x152e93f904cfe6e6, 0x5a6e6d9c19e8bdb3,
        0x6c0437d3cb7c843f, 0x370e84e9f5f0f931, 0x514c6940c20eb67b, 0x6357a59679d26801,
    ];
    let d_q: [u64; 24] = [
        0x1a4dbeba87772d29, 0xe51861bbb4e73e73, 0x9e86b2483e9bf22c, 0xc9ebcf4d7c2d6c9f,
        0xbe8fe9def6b7a62c, 0x4e8805a755ac2904, 0x734f44f3e4e88d18, 0x7626602fc90ae694,
        0xde97c88d40fa1ac4, 0x4eeaf1aafe2e1ba5, 0x25cd66f5205b038b, 0x8fa6bb6ae73b182d,
        0x0c85ab03068cbfee, 0x96f0ae48529b490f, 0xbb4cc906ba283d18, 0x4bf60c135a264919,
        0x4c2cf95ce74fe42c, 0xf4a5e8eed2a70c7a, 0x14ecee22e846a7d3, 0xd2a4139a39cec9df,
        0x4ba0e0801d31cbf5, 0x088a7986f6c2b8c0, 0x8bdc0f566f876191, 0x0004dadabfc15b1a,
    ];
    let q_inv: [u64; 24] = [
        0x45b268741fca195c, 0x94eacf955ae5dacd, 0x3ad1a334fd85aa87, 0xe8b01c83f2aec93e,
        0xd05fdc78929fa0cf, 0x0745ab95edda215b, 0xe5c81a2189f11467, 0xeded3f90e0ba4a97,
        0xfbf69baed9510be5, 0x6bee976c25dbaff8, 0x6ad65e9fe6c28038, 0xef6613dd6bf885c1,
        0x594990da705ebdf7, 0x8ee8b716f19429fb, 0x2662db8c85318de4, 0x22481fc74a7a3d62,
        0xfe6c3600d9b8e9a9, 0x744fac4daabf5488, 0xfbee6ec24b75fbf0, 0x8be552c8be44f139,
        0xfb0da96bd423759d, 0xb3443d93e7e8ca62, 0x36fe01b950885ecd, 0x214a1f73130e48b3,
    ];
    RSA3072PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
        .expect("genuine RSA-3072 CRT components must be accepted")
}

fn bench_rsa_3072(c: &mut Criterion) {
    let sk = genuine_key();
    let pk = RSA3072PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();

    let sig_pkcs1_256 = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, MSG, None).unwrap();
    let sig_pkcs1_384 = RSASSA_PKCS1_v1_5_SHA384::sign(&sk, MSG, None).unwrap();
    let sig_pkcs1_512 = RSASSA_PKCS1_v1_5_SHA512::sign(&sk, MSG, None).unwrap();
    let sig_pss_256 = RSASSA_PSS_SHA256::sign_randomized(&sk, MSG, &mut rng).unwrap();
    let sig_pss_384 = RSASSA_PSS_SHA384::sign_randomized(&sk, MSG, &mut rng).unwrap();
    let sig_pss_512 = RSASSA_PSS_SHA512::sign_randomized(&sk, MSG, &mut rng).unwrap();
    let sig_pss_shake128 = RSASSA_PSS_SHAKE128::sign_randomized(&sk, MSG, &mut rng).unwrap();

    let mut group = c.benchmark_group("rsa_3072");

    group.bench_function("pkcs1v15_sign_sha256", |b| {
        b.iter(|| {
            black_box(RSASSA_PKCS1_v1_5_SHA256::sign(black_box(&sk), black_box(MSG), None).unwrap())
        })
    });
    group.bench_function("pkcs1v15_verify_sha256", |b| {
        b.iter(|| {
            RSASSA_PKCS1_v1_5_SHA256::verify(
                black_box(&pk),
                black_box(MSG),
                None,
                black_box(&sig_pkcs1_256),
            )
            .unwrap()
        })
    });
    group.bench_function("pkcs1v15_sign_sha384", |b| {
        b.iter(|| {
            black_box(RSASSA_PKCS1_v1_5_SHA384::sign(black_box(&sk), black_box(MSG), None).unwrap())
        })
    });
    group.bench_function("pkcs1v15_verify_sha384", |b| {
        b.iter(|| {
            RSASSA_PKCS1_v1_5_SHA384::verify(
                black_box(&pk),
                black_box(MSG),
                None,
                black_box(&sig_pkcs1_384),
            )
            .unwrap()
        })
    });
    group.bench_function("pkcs1v15_sign_sha512", |b| {
        b.iter(|| {
            black_box(RSASSA_PKCS1_v1_5_SHA512::sign(black_box(&sk), black_box(MSG), None).unwrap())
        })
    });
    group.bench_function("pkcs1v15_verify_sha512", |b| {
        b.iter(|| {
            RSASSA_PKCS1_v1_5_SHA512::verify(
                black_box(&pk),
                black_box(MSG),
                None,
                black_box(&sig_pkcs1_512),
            )
            .unwrap()
        })
    });
    group.bench_function("pss_sign_sha256", |b| {
        b.iter(|| {
            black_box(
                RSASSA_PSS_SHA256::sign_randomized(
                    black_box(&sk),
                    black_box(MSG),
                    &mut DefaultRNG::default(),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_sha256", |b| {
        b.iter(|| {
            RSASSA_PSS_SHA256::verify(black_box(&pk), black_box(MSG), None, black_box(&sig_pss_256))
                .unwrap()
        })
    });
    group.bench_function("pss_sign_sha384", |b| {
        b.iter(|| {
            black_box(
                RSASSA_PSS_SHA384::sign_randomized(
                    black_box(&sk),
                    black_box(MSG),
                    &mut DefaultRNG::default(),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_sha384", |b| {
        b.iter(|| {
            RSASSA_PSS_SHA384::verify(black_box(&pk), black_box(MSG), None, black_box(&sig_pss_384))
                .unwrap()
        })
    });
    group.bench_function("pss_sign_sha512", |b| {
        b.iter(|| {
            black_box(
                RSASSA_PSS_SHA512::sign_randomized(
                    black_box(&sk),
                    black_box(MSG),
                    &mut DefaultRNG::default(),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_sha512", |b| {
        b.iter(|| {
            RSASSA_PSS_SHA512::verify(black_box(&pk), black_box(MSG), None, black_box(&sig_pss_512))
                .unwrap()
        })
    });
    group.bench_function("pss_sign_shake128", |b| {
        b.iter(|| {
            black_box(
                RSASSA_PSS_SHAKE128::sign_randomized(
                    black_box(&sk),
                    black_box(MSG),
                    &mut DefaultRNG::default(),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_shake128", |b| {
        b.iter(|| {
            RSASSA_PSS_SHAKE128::verify(
                black_box(&pk),
                black_box(MSG),
                None,
                black_box(&sig_pss_shake128),
            )
            .unwrap()
        })
    });

    group.finish();

    // FIPS 186-5 A.1.3 key generation: rejection sampling, so the run-to-run spread is large;
    // ten samples is enough to see the order of magnitude without a multi-minute bench.
    let mut keygen_group = c.benchmark_group("rsa_3072_keygen");
    keygen_group.sample_size(10);
    keygen_group.bench_function("keygen", |b| b.iter(|| black_box(keygen().unwrap())));
    keygen_group.finish();
}

criterion_group!(benches, bench_rsa_3072);
criterion_main!(benches);
