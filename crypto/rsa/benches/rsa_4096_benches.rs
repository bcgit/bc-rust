//! Criterion benches for RSA-4096. See `rsa_2048_benches.rs`'s docs for the rationale; the genuine
//! key is the same one `tests/rsa_4096_tests.rs` recovers from Wycheproof's
//! `rsa_pkcs1_4096_sig_gen_test.json`. `shake256` (not `shake128`) is the SHAKE choice wired up at
//! this modulus size (RFC 8702 SS5).

use bouncycastle_core::traits::{SignatureVerifier, Signer};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsa_4096::{
    RSASSA_PKCS1_v1_5_SHA256, RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512,
    RSASSA_PSS_SHA256, RSASSA_PSS_SHA384, RSASSA_PSS_SHA512, RSASSA_PSS_SHAKE256,
    Rsa4096PrivateKey, Rsa4096PublicKey,
};

const MSG: &[u8] = b"a representative message for benchmarking RSA-4096";

fn genuine_key() -> Rsa4096PrivateKey {
    let p: [u64; 32] = [
        0x5141acd4afd4771f, 0x5857742b7e4032dc, 0xb7a9b97fe5371396, 0x4b1783c5bc91a6dc,
        0xaf5d0c912d97b728, 0xeb265a7f28b88976, 0x5e993302aa72f11d, 0xc007ad09d76ae22a,
        0x44cbb87b8bec8fd3, 0xf152f15c73b95ac5, 0x8dbdad655fbbad20, 0x59855d0de1c794ac,
        0x4c6060926d878a20, 0xf38860474e44993d, 0x177a91caeef98b13, 0xd1676123544d3def,
        0xc1673063d8487390, 0xfedd55ba2e233a6d, 0x016a5735b883c639, 0xbd813f9fb752805b,
        0x923a7b775b5ffaff, 0xb174e55ca6a12c21, 0x0373077895a6934a, 0x6b725388f54ffea3,
        0x953c09104e1fd2d3, 0x9114f39017871528, 0x33918eb72b786b3c, 0xf43b8626af13d14a,
        0x886a0904eb486140, 0x0037409b81f3a5b3, 0x19e44e26140d2ede, 0xc3c677495c2bd566,
    ];
    let q: [u64; 32] = [
        0xee0745546a6a1c73, 0x8b1050436d882425, 0xdc2e7872ce6fb2b7, 0xf98671ee4899050b,
        0x796a5dd847400804, 0x9ba1f51132355792, 0xc39066a9fc27985b, 0x81f4bca5d15e0962,
        0x6a46cf6dbb6d2ad9, 0xdf3d085ae7693b7e, 0xf58e3c750b6d978a, 0xb52b9000d3a7aab1,
        0xdbb07e23bce1960c, 0x4e291b5c8ddaa6a7, 0x0544a7a7cb3f0792, 0xc695e324fbb11beb,
        0xbded418507f2f175, 0x49fe5f47737ff436, 0xeb37f85b7554d7ad, 0x724d042aef25cea2,
        0xeadbd11dcd2fec7b, 0xb50812705b379f5d, 0xfc50fa98fb67b746, 0x16f2bdf5964b26c7,
        0xcc1c817507859246, 0x6810c2136ad81b16, 0xd7bc78d637e17e0e, 0x6882825347455782,
        0xcdb615d921f5e705, 0x0a982efbe6658e6b, 0x59e96686f7b8752f, 0xc357cf685f9b8d4e,
    ];
    let d_p: [u64; 32] = [
        0x3cd8e91fee6bcdd3, 0x074fdc015ab1c45f, 0x34135987a2288907, 0xf6961d44dfb7505c,
        0x251be32315a85b75, 0xe8982e8493a2ae78, 0xc268493861002977, 0x140fb5806735814e,
        0x35d426d719b12c41, 0xa5f194dbbf374226, 0xa0a6c5314c1a2375, 0x66899d59c04b60c4,
        0x5158d7867dbfec94, 0xec1dde997c00125e, 0x62e5a19b2a71decf, 0x310291892c37e8a2,
        0x223e06c9521f4a45, 0xe4f08e1d5543ed74, 0xcf4dc8de58b9e9ad, 0x9167ad4f122b3263,
        0xf110dbac286712f6, 0x2db237d0f39cda5f, 0xa54b67367c857476, 0x138b37b7b1ed2219,
        0x950d9f4e82aab9bc, 0x90943e671e928e23, 0x44791809c9fcf19f, 0xc70396da054ba478,
        0x77248f6fe00e31bd, 0xf3731b1415d5f2ee, 0xf5242aa6657760cd, 0xa6bbb5460638d2b2,
    ];
    let d_q: [u64; 32] = [
        0xfa935bd36284ea6b, 0x9c255a57d6b3ac0f, 0x35b350881ec52e99, 0xf48d35dd11598957,
        0x61fee5d3763b8cfb, 0xf86f5d1936a161ae, 0x3a8b852507264ae2, 0xe558f90950a572a2,
        0x205aeb15029c95a6, 0x0fa8cf020e960c3b, 0x6a793c66abfb0963, 0xa9c7d7b391d0cbee,
        0x6310f31421e85c6b, 0xc0de89d2edb32796, 0x1cf37af6eab4ed97, 0x1533eacf819c878e,
        0xc700fc7e2a482abe, 0x4d1c62a63d917682, 0x89141558095c3228, 0x029bb05df0b8f121,
        0xa239e00b24ba9b5b, 0x74c3c55d5051f35f, 0x2f45200123860c7d, 0x4fabf224d27abaf1,
        0x0acb80fbf7ed2d86, 0x87db455a8bee03ce, 0x980bbbd1afa8fac6, 0x9d9ee6515ded4930,
        0x4c62a05dae0f744b, 0x69ff90e2839348c9, 0xda141e6d351e42da, 0x178cd58f72bf5118,
    ];
    let q_inv: [u64; 32] = [
        0x5792505b857d3e8d, 0x8a13922b1240c0d2, 0xb5fcb8bf3df1f936, 0x74483606c2cd7ed8,
        0xd40f33bbfd9be093, 0xb5f40ed6632989f5, 0x7f2cc0cd8c8a0661, 0x87630c6b25dddeb5,
        0x7032a5af6ef7c20f, 0x90331600142e6cb9, 0x67b92645b68c6d8f, 0xb63517c7c39843cf,
        0xd50712bf8fc35882, 0x3c421e2447b1a989, 0x7a251afa7aaa6908, 0x43b4de11f99b2654,
        0x1e02735920ef48a3, 0x218fc24da34ce8f0, 0x280446e49b3b9b15, 0x8d96f07411c882bf,
        0x66e283f5d5fb0e6e, 0x0844efd28d853446, 0x5eb4def8dba57b99, 0x474111f92d19f3ab,
        0x748d7b5d94cacd4d, 0xcf634f3a07cea4b7, 0x8dbcca51f4da4379, 0x80774236a54ec9dc,
        0x6a1ef00ee582d3d1, 0xdecfb14ca1e80c8e, 0xc78af5f6c807cc99, 0x484ad86e79415ea3,
    ];
    Rsa4096PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
        .expect("genuine RSA-4096 CRT components must be accepted")
}

fn bench_rsa_4096(c: &mut Criterion) {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();

    let sig_pkcs1_256 = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, MSG, None).unwrap();
    let sig_pkcs1_384 = RSASSA_PKCS1_v1_5_SHA384::sign(&sk, MSG, None).unwrap();
    let sig_pkcs1_512 = RSASSA_PKCS1_v1_5_SHA512::sign(&sk, MSG, None).unwrap();
    let sig_pss_256 = RSASSA_PSS_SHA256::sign_randomized(&sk, MSG, &mut rng).unwrap();
    let sig_pss_384 = RSASSA_PSS_SHA384::sign_randomized(&sk, MSG, &mut rng).unwrap();
    let sig_pss_512 = RSASSA_PSS_SHA512::sign_randomized(&sk, MSG, &mut rng).unwrap();
    let sig_pss_shake256 = RSASSA_PSS_SHAKE256::sign_randomized(&sk, MSG, &mut rng).unwrap();

    let mut group = c.benchmark_group("rsa_4096");

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
    group.bench_function("pss_sign_shake256", |b| {
        b.iter(|| {
            black_box(
                RSASSA_PSS_SHAKE256::sign_randomized(
                    black_box(&sk),
                    black_box(MSG),
                    &mut DefaultRNG::default(),
                )
                .unwrap(),
            )
        })
    });
    group.bench_function("pss_verify_shake256", |b| {
        b.iter(|| {
            RSASSA_PSS_SHAKE256::verify(
                black_box(&pk),
                black_box(MSG),
                None,
                black_box(&sig_pss_shake256),
            )
            .unwrap()
        })
    });

    group.finish();
}

criterion_group!(benches, bench_rsa_4096);
criterion_main!(benches);
