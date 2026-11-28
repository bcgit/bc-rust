//! Seeking in CTR, against NIST SP 800-38A Appendix F.5.1 / F.5.2 (CTR-AES128).
//!
//! F.5's initial counter block is `f0f1...fcfdfeff`, which a key's workers, starting at counter
//! field 0, reach only by seeking: under a 12-byte nonce `f0..fb` the counter field is
//! `fcfdfeff`, under a 14-byte nonce `f0..fd` it is `feff`. Under a 15-byte nonce the one-byte
//! counter `ff` is the last value, so the vector's second block, `...ff00`, is past the end.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    SeekableStreamCipher, StreamCipherDecryptor, StreamCipherEncryptor,
};
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkSeekableStreamCipher;
use bouncycastle_symmetric::aes::AES128Key;
use bouncycastle_symmetric::modes::CTR;

const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const INIT_COUNTER: &str = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);
const CIPHERTEXT: &str = concat!(
    "874d6191b620e3261bef6864990db6ce",
    "9806f66b7970fdff8617187bb9fffdff",
    "5ae4df3edbd5d35e5b4f09020db03eab",
    "1e031dda2fbe03d1792170a0f3009cee",
);

fn key<const NONCE_LEN: usize>() -> AES128Key<CTR<NONCE_LEN>> {
    let bytes: [u8; 16] = hex::decode(KEY).unwrap().try_into().unwrap();
    let material =
        KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
    AES128Key::from_key_material(&material).unwrap()
}

/// F.5's initial counter block split at `NONCE_LEN`: the nonce, and the counter field's value.
fn split<const NONCE_LEN: usize>() -> ([u8; NONCE_LEN], u64) {
    let t1 = hex::decode(INIT_COUNTER).unwrap();
    let nonce = t1[..NONCE_LEN].try_into().unwrap();
    let counter = t1[NONCE_LEN..].iter().fold(0u64, |c, &b| (c << 8) | u64::from(b));
    (nonce, counter)
}

/// F.5.1 and F.5.2 from the start of the first block and from every offset into the four blocks,
/// each on a fresh worker, then backwards over the blocks on one worker.
fn check<const NONCE_LEN: usize>() {
    let key = key::<NONCE_LEN>();
    let (nonce, counter) = split::<NONCE_LEN>();
    let base = counter * 16;
    let pt = hex::decode(PLAINTEXT).unwrap();
    let ct = hex::decode(CIPHERTEXT).unwrap();

    for off in 0..=pt.len() {
        let mut enc = key.create_encryptor_nonce(&nonce);
        enc.seek_to(base + off as u64).unwrap();
        let mut data = pt[off..].to_vec();
        enc.do_encrypt_inplace(&mut data).unwrap();
        assert_eq!(data, ct[off..], "F.5.1 from byte {off}, nonce length {NONCE_LEN}");
        assert_eq!(enc.position(), base + pt.len() as u64);

        let mut dec = key.create_decryptor(&nonce);
        dec.seek_to(base + off as u64).unwrap();
        dec.do_decrypt_inplace(&mut data).unwrap();
        assert_eq!(data, pt[off..], "F.5.2 from byte {off}, nonce length {NONCE_LEN}");
    }

    let mut enc = key.create_encryptor_nonce(&nonce);
    let mut data = pt.clone();
    for (j, block) in data.chunks_mut(16).enumerate().rev() {
        enc.seek_to(base + 16 * j as u64).unwrap();
        enc.do_encrypt_inplace(block).unwrap();
    }
    assert_eq!(data, ct, "F.5.1 block by block, last first, nonce length {NONCE_LEN}");
}

#[test]
fn f5_is_reached_by_seeking_under_a_four_byte_counter() {
    check::<12>();
}

#[test]
fn f5_is_reached_by_seeking_under_a_two_byte_counter() {
    check::<14>();
}

/// Under a one-byte counter F.5's first block is the last one: it encrypts, and the next byte,
/// whose counter block would wrap to `...00`, is refused, as is a seek one byte past the end.
#[test]
fn a_one_byte_counter_ends_after_f5_first_block() {
    let key = key::<15>();
    let (nonce, counter) = split::<15>();
    assert_eq!(counter, 0xff);
    let pt = hex::decode(PLAINTEXT).unwrap();
    let ct = hex::decode(CIPHERTEXT).unwrap();

    let mut enc = key.create_encryptor_nonce(&nonce);
    enc.seek_to(0xff * 16).unwrap();
    let mut block = pt[..16].to_vec();
    enc.do_encrypt_inplace(&mut block).unwrap();
    assert_eq!(block, ct[..16]);
    assert_eq!(enc.position(), 256 * 16);
    assert!(matches!(
        enc.do_encrypt_inplace(&mut [0u8; 1]),
        Err(SymmetricCipherError::DataLimitExceeded)
    ));
    assert!(matches!(enc.seek_to(256 * 16 + 1), Err(SymmetricCipherError::DataLimitExceeded)));
    assert_eq!(enc.position(), 256 * 16, "a refused seek leaves the worker where it was");
    enc.seek_to(256 * 16).unwrap();
}

/// The seek suite at each counter width, whose end is `16 * 2^(8 * counter bytes)`.
#[test]
fn every_counter_width_passes_the_seek_framework() {
    let framework = TestFrameworkSeekableStreamCipher::new();
    framework.test_key::<16, 12, _>(&key::<12>(), 16 << 32);
    framework.test_key::<16, 13, _>(&key::<13>(), 16 << 24);
    framework.test_key::<16, 14, _>(&key::<14>(), 16 << 16);
    framework.test_key::<16, 15, _>(&key::<15>(), 16 << 8);
}
