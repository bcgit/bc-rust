//! Criterion benches for RSA-1536: verification only (see `bouncycastle_rsa::rsa_1536`'s docs --
//! this crate has no RSA-1536 private key type at all). Public keys and signatures are Wycheproof
//! `rsa_pkcs1_1536_sig_gen_test.json`'s own genuine `(n, e)` and real `(msg, sig)` pairs, the same
//! provenance `tests/rsa_1536_tests.rs` uses.

use bouncycastle_core::traits::SignatureVerifier;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rsa::rsa_1536::{
    RSASSA_PKCS1_v1_5_SHA256, RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512, Rsa1536PublicKey,
};

fn bench_rsa_1536(c: &mut Criterion) {
    let n_sha256: [u64; 24] = [
        0xe58590d069a2a271, 0xb2909211b75f8182, 0x052fd6f0a20f6cde, 0x06d4eb560a8fddff,
        0x703a83c6cbfd949d, 0x553f827a27719c2c, 0x395bdb0865f22ac0, 0x12bdb15dde506945,
        0x16db14f2e1c9b8d3, 0x51702cfaa46fcaf7, 0xe62269e04112c194, 0x7728dcea18bc1193,
        0xab906e57364cac81, 0x852f673d3288544a, 0x9547f55a3d7b1d08, 0x8e6d3a99c058b1c8,
        0x5e2c811a56b5d946, 0x6c9fc8200b205487, 0x7b401487a9c85917, 0x41744b5872ccebc8,
        0x86eb04d51f21ac52, 0xe029a743f0649ae5, 0x6cf4930cf2615140, 0xeb477c90d46bd189,
    ];
    let pk_sha256 = Rsa1536PublicKey::new(&n_sha256, 0x10001).unwrap();
    let msg = hex_decode("0000000000000000000000000000000000000000").unwrap();
    let sig_sha256: [u8; 192] = hex_decode(
        "8d2611d4c79f6b2087ae8bc76610905c361b9fe0a6629388197b4293f9e14ecbeb377206e4c1db35cdc0ab163dc5c51e8a7370a059e9ee8014d18ef0937f7936879d7825c792180a4f10a0d46e0a954f093d703b82bd076dcec0b8a66fc3be9bdf79ce4550c453015dc1c7397ec1bfceed040a4d777915546b9cbcf1eeb13eb71ac49c235e69cb07c315d529442f4863d61b7d5caa5ce07820edf649a9342211a26f8280dab9c5dd11af0752168326f8e8d5e834ddba3bce063f011eccc8f46d",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let n_sha384: [u64; 24] = [
        0x0c8a0645adb04d7f, 0x4913d26ff2dd0383, 0xe5567ac4c3edf882, 0x965f5b7b146663f4,
        0x6802e12716431e25, 0x8d39e0d5c93fe29a, 0xb940509dbf238383, 0x84fb9ca6ac2ffd03,
        0x67b11769af1178d2, 0x98fa3b27d4de0a32, 0xec385a5db04f4731, 0x065c58db8b8166aa,
        0x2ed95a2a8cfd33da, 0x821cb5e40dc781e7, 0x3cb9b09f241b0700, 0x30b30fe5ea0d2408,
        0xd7841125d38dd9f4, 0xb0ed9964c7b125da, 0x06d573f19163ae2a, 0xa7716c797d15afe5,
        0xcf19e47fadf98cfd, 0xdc9306f2f3646bbc, 0x9c3c1865cf6beaf5, 0xd1060fe7c6d185f0,
    ];
    let pk_sha384 = Rsa1536PublicKey::new(&n_sha384, 0x10001).unwrap();
    let sig_sha384: [u8; 192] = hex_decode(
        "58c4c42da5eee1b757b31e3362a95d75180c0fee472c431527ff5500fe0b5c1d59968d79e6e41650f013a6b3e37c5a1d79233b818ef76c4ed469a09607becdc58987e6a548610de14ff06899ef284778dd5329a27b85072e8ffd46b63a5e8f7602ddb9fc5a07224c49818fc8057581ea36da033f2b936f0761186c7fd82b474e87d47aa1b7ec610642d3bcb16c59bb70ac68b1f081a9c9248f069474d6ed9b29c669fc40a979cdfc2053e1a3c0cf40efa29c01785323995f1d8f3850c32bdf92",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let n_sha512: [u64; 24] = [
        0xb4095eb4bf90b6e9, 0x4b57f8d656600e5f, 0x176e311fe8dbcac2, 0x115b2ec41eb9acc4,
        0xdb3ecfc281f8da29, 0xc93bc5bf6c2504fb, 0x0e7896e87fb399e6, 0x69ae5f32937a207e,
        0x230ddd8c067dae90, 0xed1e42ebfbe70645, 0xa16f8e2300ef7c35, 0x70b29f55dd21d2cb,
        0x7e3413f9891e2f8a, 0xa7e0de9008f3a9a6, 0x4df9f5c38e950175, 0xc8e722c8dedc065a,
        0xfe887a4a1fae6ca8, 0xa96a2bedc3e72738, 0xe2ad09578c749863, 0xffb63f097ed7b5c5,
        0xcea5ba02d99f0807, 0x1cb9a9b7b769d6df, 0xfd4c711aef054e29, 0xd1f33c4d0c3b127c,
    ];
    let pk_sha512 = Rsa1536PublicKey::new(&n_sha512, 0x10001).unwrap();
    let sig_sha512: [u8; 192] = hex_decode(
        "5259fe9566e1bd81952a805384b1657374f33550ee0895b57b7a0869a831270d3b3b2db8e295a4eb98d8eb036183b3d228ad22b8e493c7eb0f9ab00eeab2e086f10f8018a8daaff4858ae745a4d70881a166963c64403216422e18974aa456d8229ef2e43002e0390166630c7fabd14efaa974a9521a72a69e0b446971db077ce80f6dd95cf797b6ed276873bbf6b1ba6a79df8c917c2a3fbbc0e5347b0bb99eec6ad0b6bdb7bc9d3e0a7f6b7b623f2aa9dba1e940676ec5629d39778286f261",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let mut group = c.benchmark_group("rsa_1536");
    group.bench_function("pkcs1v15_verify_sha256", |b| {
        b.iter(|| {
            RSASSA_PKCS1_v1_5_SHA256::verify(
                black_box(&pk_sha256),
                black_box(&msg),
                None,
                black_box(&sig_sha256),
            )
            .unwrap()
        })
    });
    group.bench_function("pkcs1v15_verify_sha384", |b| {
        b.iter(|| {
            RSASSA_PKCS1_v1_5_SHA384::verify(
                black_box(&pk_sha384),
                black_box(&msg),
                None,
                black_box(&sig_sha384),
            )
            .unwrap()
        })
    });
    group.bench_function("pkcs1v15_verify_sha512", |b| {
        b.iter(|| {
            RSASSA_PKCS1_v1_5_SHA512::verify(
                black_box(&pk_sha512),
                black_box(&msg),
                None,
                black_box(&sig_sha512),
            )
            .unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_rsa_1536);
criterion_main!(benches);
