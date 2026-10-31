//! AES-256-GCM over 16 KiB packets: the per-packet cost of building the `AES256Key<GCM>` from raw
//! key material for every packet, which validates and expands the key and derives GCM's hash
//! subkey each time, against building it once and handing the stored state to each packet's
//! encryptor.
//!
//! Both arms stream one packet through the same `Gcm` type -- `create_encryptor` /
//! `create_decryptor`, one `do_encrypt_out` / `do_decrypt_out` over the whole packet, final -- so
//! the only difference between them is where `from_key_material` is paid. The nonce comes from a
//! fixed test RNG so that the RNG is not part of the comparison, except in the `OS DRBG per
//! packet` arms, which instantiate a fresh `HashDRBG_SHA512` from the OS for every packet: what a
//! per-packet default RNG would add. The `init` group isolates the construction cost with no data
//! at all.
//!
//! The cipher works in place, so each measurement runs on a fresh output buffer made in
//! criterion's untimed setup (`iter_batched_ref`); the copy is not part of the timing.

use bouncycastle_aes::{AES_GCM_256, AES256Key};
use bouncycastle_cipher::modes::GCM;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_rng::HashDRBG_SHA512;
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

/// One TLS-record-sized packet.
const PACKET_LEN: usize = 16 * 1024;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

type Enc<'k> = AES_GCM_256<'k, Encrypting>;
type Dec<'k> = AES_GCM_256<'k, Decrypting>;
type Key = AES256Key<GCM>;

fn material() -> KeyMaterial<32> {
    let bytes: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<32>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn rng() -> FixedSeedRNG<NONCE_LEN> {
    FixedSeedRNG::<NONCE_LEN>::new([0x24u8; NONCE_LEN])
}

/// Encrypt one packet and finish: the shape of both encrypt arms once the encryptor exists.
fn encrypt_packet(
    mut enc: Enc,
    packet: &[u8; PACKET_LEN],
    out: &mut [u8; PACKET_LEN],
) -> [u8; TAG_LEN] {
    enc.do_encrypt_out(packet, out).unwrap();
    let (_, tag) = enc.do_encrypt_final_detached_out(&mut [0u8; TAG_LEN]).unwrap();
    tag
}

/// Decrypt one packet and check its tag: the shape of both decrypt arms once the decryptor exists.
fn decrypt_packet(
    mut dec: Dec,
    ct: &[u8; PACKET_LEN],
    tag: &[u8; TAG_LEN],
    out: &mut [u8; PACKET_LEN],
) -> usize {
    let n = dec.do_decrypt_out(ct, out).unwrap();
    let mut last = [0u8; TAG_LEN];
    n + dec.do_decrypt_final_detached_out(tag, &mut last).unwrap()
}

fn bench_encrypt_packets(c: &mut Criterion) {
    let km = material();
    let key = Key::from_key_material(&km).expect("a valid key");
    let packet = [0xA5u8; PACKET_LEN];
    let mut rng = rng();

    let mut group = c.benchmark_group("gcm::AES_256 16KiB packet encrypt");
    group.throughput(Throughput::Bytes(PACKET_LEN as u64));

    group.bench_function("AES256Key<GCM>: from_key_material per packet (expand per packet)", |b| {
        b.iter_batched_ref(
            || [0u8; PACKET_LEN],
            |out| {
                let per_packet = Key::from_key_material(black_box(&km)).unwrap();
                let (enc, nonce) = per_packet.create_encryptor(&mut rng).unwrap();
                black_box((nonce, encrypt_packet(enc, black_box(&packet), out)))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("AES256Key<GCM>: create_encryptor (stored schedule and H)", |b| {
        b.iter_batched_ref(
            || [0u8; PACKET_LEN],
            |out| {
                let (enc, nonce) = black_box(&key).create_encryptor(&mut rng).unwrap();
                black_box((nonce, encrypt_packet(enc, black_box(&packet), out)))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function(
        "AES256Key<GCM>: from_key_material per packet (OS DRBG per packet, expand per packet)",
        |b| {
            b.iter_batched_ref(
                || [0u8; PACKET_LEN],
                |out| {
                    let mut os_rng = HashDRBG_SHA512::new_from_os();
                    let per_packet = Key::from_key_material(black_box(&km)).unwrap();
                    let (enc, nonce) = per_packet.create_encryptor(&mut os_rng).unwrap();
                    black_box((nonce, encrypt_packet(enc, black_box(&packet), out)))
                },
                BatchSize::LargeInput,
            )
        },
    );
    group.bench_function("AES256Key<GCM>: create_encryptor (OS DRBG per packet)", |b| {
        b.iter_batched_ref(
            || [0u8; PACKET_LEN],
            |out| {
                let mut os_rng = HashDRBG_SHA512::new_from_os();
                let (enc, nonce) = black_box(&key).create_encryptor(&mut os_rng).unwrap();
                black_box((nonce, encrypt_packet(enc, black_box(&packet), out)))
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

fn bench_decrypt_packets(c: &mut Criterion) {
    let km = material();
    let key = Key::from_key_material(&km).expect("a valid key");
    let packet = [0xA5u8; PACKET_LEN];

    // One valid packet to decrypt, made outside the timing.
    let mut ct = [0u8; PACKET_LEN];
    let (enc, nonce) = key.create_encryptor(&mut rng()).unwrap();
    let tag = encrypt_packet(enc, &packet, &mut ct);

    let mut group = c.benchmark_group("gcm::AES_256 16KiB packet decrypt");
    group.throughput(Throughput::Bytes(PACKET_LEN as u64));

    group.bench_function("AES256Key<GCM>: from_key_material per packet (expand per packet)", |b| {
        b.iter_batched_ref(
            || [0u8; PACKET_LEN],
            |out| {
                let per_packet = Key::from_key_material(black_box(&km)).unwrap();
                let dec = per_packet.create_decryptor(&nonce);
                black_box(decrypt_packet(dec, black_box(&ct), &tag, out))
            },
            BatchSize::LargeInput,
        )
    });
    group.bench_function("AES256Key<GCM>: create_decryptor (stored schedule and H)", |b| {
        b.iter_batched_ref(
            || [0u8; PACKET_LEN],
            |out| {
                let dec = black_box(&key).create_decryptor(&nonce);
                black_box(decrypt_packet(dec, black_box(&ct), &tag, out))
            },
            BatchSize::LargeInput,
        )
    });

    group.finish();
}

/// Construction alone, no data: what each packet pays before its first byte.
fn bench_init(c: &mut Criterion) {
    let km = material();
    let key = Key::from_key_material(&km).expect("a valid key");
    let nonce = [0x24u8; NONCE_LEN];
    let mut rng = rng();

    let mut group = c.benchmark_group("gcm::AES_256 init");

    group.bench_function("AES256Key<GCM>::from_key_material (once per key)", |b| {
        b.iter(|| black_box(Key::from_key_material(black_box(&km)).unwrap()))
    });
    group.bench_function(
        "AES256Key<GCM>: from_key_material + create_encryptor (per packet)",
        |b| {
            b.iter(|| {
                let per_packet = Key::from_key_material(black_box(&km)).unwrap();
                let (enc, nonce) = per_packet.create_encryptor(&mut rng).unwrap();
                // The worker borrows the key, so what a per-packet key costs is what it takes
                // to make the worker and finish it.
                black_box((nonce, enc.do_encrypt_final().unwrap()))
            })
        },
    );
    group.bench_function("AES256Key<GCM>: create_encryptor", |b| {
        b.iter(|| black_box(black_box(&key).create_encryptor(&mut rng).unwrap()))
    });
    group.bench_function(
        "AES256Key<GCM>: from_key_material + create_decryptor (per packet)",
        |b| {
            b.iter(|| {
                let per_packet = Key::from_key_material(black_box(&km)).unwrap();
                let dec = per_packet.create_decryptor(&nonce);
                black_box(dec.do_decrypt_final().is_ok())
            })
        },
    );
    group.bench_function("AES256Key<GCM>: create_decryptor", |b| {
        b.iter(|| black_box(black_box(&key).create_decryptor(&nonce)))
    });
    group.bench_function(
        "AES256Key<GCM>: from_key_material + create_encryptor (OS DRBG per call)",
        |b| {
            b.iter(|| {
                let mut os_rng = HashDRBG_SHA512::new_from_os();
                let per_packet = Key::from_key_material(black_box(&km)).unwrap();
                let (enc, nonce) = per_packet.create_encryptor(&mut os_rng).unwrap();
                black_box((nonce, enc.do_encrypt_final().unwrap()))
            })
        },
    );
    group.bench_function("AES256Key<GCM>: create_encryptor (OS DRBG per call)", |b| {
        b.iter(|| {
            let mut os_rng = HashDRBG_SHA512::new_from_os();
            black_box(black_box(&key).create_encryptor(&mut os_rng).unwrap())
        })
    });

    group.finish();
}

criterion_group!(benches, bench_encrypt_packets, bench_decrypt_packets, bench_init);
criterion_main!(benches);
