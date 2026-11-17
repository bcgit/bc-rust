//! HPKE's own work: the key schedule per KDF, the context's seal and open per AEAD, and the
//! export. The setups include their KEM operation, here DHKEM(X25519, HKDF-SHA256); the KEMs
//! are benchmarked on their own in the crates of their groups.

use bouncycastle_aes::{AES128Key, AES256Key};
use bouncycastle_chacha20_poly1305_aead::ChaCha20Poly1305Key;
use bouncycastle_cipher::modes::GCM;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_ed::x25519::keygen;
use bouncycastle_hpke::{
    HpkeAuthRecipient, HpkeAuthSender, HpkeCipher, HpkeContext, HpkeKdf, HpkeParams, HpkeRecipient,
    HpkeSender, NT,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const MESSAGE_LEN: usize = 1024;

fn bench_setup<H: HpkeKdf>(c: &mut Criterion, kdf: &str) {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = keygen(&mut rng).unwrap();
    let params = HpkeParams::<H, AES128Key<GCM>>::new(b"bench");
    let (enc, _) = pk.setup_sender(&mut rng, params).unwrap();

    let mut group = c.benchmark_group("Setup");
    group.bench_function(format!("X25519/{kdf}/AES-128-GCM/sender"), |b| {
        b.iter(|| black_box(pk.setup_sender(&mut rng, params).is_ok()))
    });
    group.bench_function(format!("X25519/{kdf}/AES-128-GCM/recipient"), |b| {
        b.iter(|| black_box(sk.setup_recipient(&enc, params).is_ok()))
    });
    // The authenticated setups run a second DH.
    let (pk_s, sk_s) = keygen(&mut rng).unwrap();
    let (enc, _) = pk.setup_auth_sender(&mut rng, &sk_s, params).unwrap();
    group.bench_function(format!("X25519/{kdf}/AES-128-GCM/auth sender"), |b| {
        b.iter(|| black_box(pk.setup_auth_sender(&mut rng, &sk_s, params).is_ok()))
    });
    group.bench_function(format!("X25519/{kdf}/AES-128-GCM/auth recipient"), |b| {
        b.iter(|| black_box(sk.setup_auth_recipient(&enc, &pk_s, params).is_ok()))
    });
    group.finish();
}

fn bench_messages<A: HpkeCipher>(c: &mut Criterion, aead: &str) {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = keygen(&mut rng).unwrap();
    let params = HpkeParams::<SHA256, A>::new(b"bench");
    let pt = [0x5Au8; MESSAGE_LEN];
    let mut ct = [0u8; MESSAGE_LEN + NT];
    let mut out = [0u8; MESSAGE_LEN + NT];

    let mut group = c.benchmark_group("Message");
    group.throughput(Throughput::Bytes(MESSAGE_LEN as u64));
    let (_, mut sender) = pk.setup_sender(&mut rng, params).unwrap();
    group.bench_function(format!("{aead}/seal"), |b| {
        b.iter(|| black_box(sender.seal_out(b"aad", &pt, &mut ct)))
    });
    // The recipient opens each message once, in step with the sender, which is what a context
    // is for: the same ciphertext does not open twice.
    let (enc, mut sender) = pk.setup_sender(&mut rng, params).unwrap();
    let mut recipient = sk.setup_recipient(&enc, params).unwrap();
    group.bench_function(format!("{aead}/seal+open"), |b| {
        b.iter(|| {
            sender.seal_out(b"aad", &pt, &mut ct).unwrap();
            black_box(recipient.open_out(b"aad", &ct, &mut out))
        })
    });
    group.finish();
}

fn bench_export(c: &mut Criterion) {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, _) = keygen(&mut rng).unwrap();
    let (_, sender): (_, HpkeContext<_, SHA256, AES128Key<GCM>>) =
        pk.setup_sender(&mut rng, HpkeParams::new(b"bench")).unwrap();
    let mut out = KeyMaterial::<32>::new();

    let mut group = c.benchmark_group("Export");
    group.bench_function("HKDF-SHA256/32 bytes", |b| {
        b.iter(|| black_box(sender.export_out(b"exporter context", &mut out)))
    });
    group.finish();
}

fn benches(c: &mut Criterion) {
    bench_setup::<SHA256>(c, "HKDF-SHA256");
    bench_setup::<SHA384>(c, "HKDF-SHA384");
    bench_setup::<SHA512>(c, "HKDF-SHA512");
    bench_messages::<AES128Key<GCM>>(c, "AES-128-GCM");
    bench_messages::<AES256Key<GCM>>(c, "AES-256-GCM");
    bench_messages::<ChaCha20Poly1305Key>(c, "ChaCha20Poly1305");
    bench_export(c);
}

criterion_group!(hpke_benches, benches);
criterion_main!(hpke_benches);
