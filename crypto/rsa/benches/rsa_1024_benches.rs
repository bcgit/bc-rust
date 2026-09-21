//! Criterion benches for RSA-1024: verification only (see `bouncycastle_rsa::rsa_1024`'s docs --
//! this crate has no RSA-1024 private key type at all). The public key and signature are Wycheproof
//! `rsa_pkcs1_1024_sig_gen_test.json`'s own genuine `(n, e)` and one real `(msg, sig)` pair, the
//! same provenance `tests/rsa_1024_tests.rs` uses.

use bouncycastle_core::traits::SignatureVerifier;
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rsa::rsa_1024::{
    RSA1024PublicKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PKCS1_v1_5_SHA384,
};

fn bench_rsa_1024(c: &mut Criterion) {
    let n_sha256: [u64; 16] = [
        0xd00343468eaacfbf, 0xb7c7044cc202dcca, 0x9686f30f478db649, 0x5179b54951fff6aa,
        0xbabb14f550d5d0dd, 0x5405db7c5c8f4cf6, 0x9816e2eda41fd7b9, 0xb31b6abd805bace9,
        0xb909dd0f4c6014f2, 0x9c8a5810b6d05990, 0x40760d1f23fe9250, 0x90adb011a919575a,
        0x45e48572113cab28, 0xcb9ca9ec12000fc8, 0x91b4fcaf62a14595, 0xac9048a7a4f560af,
    ];
    let pk_sha256 = RSA1024PublicKey::new(&n_sha256, 0x10001).unwrap();
    let msg_sha256 = hex_decode("0000000000000000000000000000000000000000").unwrap();
    let sig_sha256: [u8; 128] = hex_decode(
        "41339884a9b3940e8488d666bb158063c6a2a2717cae7f564834a876fcbf7098ecf3acbfabf37d38a8e6127b1e313744f1f896e165efdaea0b2e7673867842b9e94db0868ed9a92bcdcb370a4e20ff275c82595e4400a8b9e9f12482f014846b48216f321266ae6ae6338dbcdc41b711e483e6e3e728772e7f9f5ef95c30196b",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let n_sha384: [u64; 16] = [
        0x5cfd178f3f07ed01, 0x7c94e28878397cb4, 0x57dbd3d6d0f5b77f, 0x89f8ec36d7f5cae7,
        0x73d399b04ad55c0a, 0x33b063490cf7b670, 0x51996b97d5b25da9, 0x0af3f4b5efec3586,
        0xe60ee26a7b7cfccb, 0xaf86df2283c8e327, 0x7dea6692a1713516, 0xe94e94385dffc5e2,
        0x8cf0173a0a309a1e, 0x3ea5161e5450d16a, 0xba51135f78844d9a, 0xa1d3912e65d994e0,
    ];
    let pk_sha384 = RSA1024PublicKey::new(&n_sha384, 0x10001).unwrap();
    let msg_sha384 = hex_decode("0000000000000000000000000000000000000000").unwrap();
    let sig_sha384: [u8; 128] = hex_decode(
        "74b9a7b9548a281c5a258520c879e0e64d8a28812a7b6461c6e418e0502b61008a8e535a5b55fb64529a6a6df2f60ef33c1844b27f81532be2bc2992d0eb5e524112da90bf40adefcf206469639ff3895a9826674ee1acbdd623842ab0a9a36d48da13ba17c4ee069254da2ea418d5a8f135e2a414c0654a266d538621917545",
    )
    .unwrap()
    .try_into()
    .unwrap();

    let mut group = c.benchmark_group("rsa_1024");
    group.bench_function("pkcs1v15_verify_sha256", |b| {
        b.iter(|| {
            RSASSA_PKCS1_v1_5_SHA256::verify(
                black_box(&pk_sha256),
                black_box(&msg_sha256),
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
                black_box(&msg_sha384),
                None,
                black_box(&sig_sha384),
            )
            .unwrap()
        })
    });
    group.finish();
}

criterion_group!(benches, bench_rsa_1024);
criterion_main!(benches);
