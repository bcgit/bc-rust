//! Multi-block known-answer tests for CTR, generated with OpenSSL.
//!
//! # Why these exist alongside the ACVP suite
//!
//! `acvp_ctr_tests.rs` runs 1853 official NIST vectors, but **every one of them is a single
//! block**, so all of them use counter 0 and none exercises the increment. A counter that never
//! advanced -- or advanced the wrong way, or wrote its bytes little-endian -- would pass the entire
//! ACVP set. (That is not hypothetical: a deliberately little-endian counter was checked against
//! the ACVP suite while these tests were written, and it passed.)
//!
//! `ctr_tests.rs` covers the increment against the raw permutation, which is sound because that
//! permutation is itself ACVP-validated, but it is our own code on both sides of the comparison.
//! These vectors close that gap with an **independent implementation**: the ciphertexts below were
//! produced by OpenSSL 3.0.13, following the same convention the SM3 and HMAC suites use for
//! openssl-sourced values. They span five counter blocks, so they pin the increment end to end,
//! and their last block is partial, so they also pin Sec 6.5's `MSB_u(On)` handling.
//!
//! # How they were generated
//!
//! ```text
//! openssl enc -aes-128-ctr -K <key> -iv 000102030405060708090a0b00000000 -in plaintext.bin
//! ```
//!
//! OpenSSL takes the whole 16-byte initial counter block as its `-iv`. Ours is a 12-byte nonce with
//! the counter starting at zero, so the two line up exactly when the IV's low four bytes are zero,
//! which is why the IV above ends in `00000000`. See the [`Ctr`] module docs.

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{ElectronicCodeBook, StreamCipherDecryptor, StreamCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Ctr, Decrypting, Encrypting};

const BLOCK_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// The nonce: the leading 12 bytes of the OpenSSL IV `000102030405060708090a0b00000000`.
const NONCE: &str = "000102030405060708090a0b";

/// The four SP 800-38A Appendix F plaintext blocks followed by five more bytes, so the message is
/// 69 bytes: five counter blocks, the last of them partial.
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
    "0011223344",
);

/// The three keys used throughout SP 800-38A Appendix F.
const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// `openssl enc -aes-128-ctr`, OpenSSL 3.0.13.
const CT_128: &str = concat!(
    "ffd8816338abebca17491bc67fe6751c",
    "093833c279e946d49804c6b03df09f9d",
    "6b0727101b346a530523d59fb883e678",
    "fda525b39296cfc5a821d4dcda5a6227",
    "06efd63405",
);
/// `openssl enc -aes-192-ctr`, OpenSSL 3.0.13.
const CT_192: &str = concat!(
    "c85f24d60a6fd4593209730ecd1ed507",
    "deae5f770708a1e162d04d42fe3dd6e6",
    "acf360f5c5f25e53a09396547d8b7f9b",
    "9d12dc684df141cd0b5462450a8d1900",
    "4a271f6e8e",
);
/// `openssl enc -aes-256-ctr`, OpenSSL 3.0.13.
const CT_256: &str = concat!(
    "b66c7ac8885c5ff473855203b36048ff",
    "5e7e0746b6e3ad4c2b84aaf440b1b987",
    "38a9ad1527187f6f435b83b09734cb04",
    "b3e3a2a77d2a02c4759cbd9b8fc822b3",
    "1223c7e590",
);

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn key_material<const N: usize>(hex_str: &str) -> KeyMaterial<N> {
    let raw = unhex(hex_str);
    assert_eq!(raw.len(), N, "key length");
    KeyMaterial::<N>::from_bytes_as_type(&raw, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

/// Chunk sizes that cut across the block and the four-block batch, so the vectors are reproduced
/// through every path rather than only the batched one.
const CHUNKINGS: [usize; 6] = [1, 5, 16, 17, 33, 69];

fn check<P, const KEY_LEN: usize>(name: &str, key_hex: &str, expected_hex: &str)
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let key = key_material::<KEY_LEN>(key_hex);
    let nonce: [u8; NONCE_LEN] = unhex(NONCE).try_into().expect("a 12-byte nonce");
    let plaintext = unhex(PLAINTEXT);
    let expected = unhex(expected_hex);
    assert_eq!(plaintext.len(), 69, "the message should be five counter blocks, the last partial");
    assert_eq!(expected.len(), plaintext.len(), "CTR does not change the length");

    // Encryption, in one call and in every chunking.
    for chunk in [plaintext.len()].into_iter().chain(CHUNKINGS) {
        let (mut enc, got) =
            Ctr::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN>::do_encrypt_init_rng(
                &key,
                &mut FixedSeedRNG::<NONCE_LEN>::new(nonce),
            )
            .expect("encrypt init");
        assert_eq!(got, nonce, "{name}: the pinned RNG should reproduce the nonce");

        let mut data = plaintext.clone();
        for piece in data.chunks_mut(chunk) {
            enc.do_encrypt(piece).expect("encryption");
        }
        assert_eq!(data, expected, "{name}: encrypting in {chunk}-byte calls");
    }

    // Decryption, likewise.
    for chunk in [expected.len()].into_iter().chain(CHUNKINGS) {
        let mut dec =
            Ctr::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN>::do_decrypt_init(&key, &nonce)
                .expect("decrypt init");
        let mut data = expected.clone();
        for piece in data.chunks_mut(chunk) {
            dec.do_decrypt(piece).expect("decryption");
        }
        assert_eq!(data, plaintext, "{name}: decrypting in {chunk}-byte calls");
    }

    // ...and the one-shot.
    let mut data = expected.clone();
    Ctr::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN>::decrypt(&key, &nonce, &mut data)
        .expect("one-shot decryption");
    assert_eq!(data, plaintext, "{name}: one-shot");
}

#[test]
fn aes128_ctr_matches_openssl() {
    check::<AES_128, 16>("AES-128", KEY_128, CT_128);
}

#[test]
fn aes192_ctr_matches_openssl() {
    check::<AES_192, 24>("AES-192", KEY_192, CT_192);
}

#[test]
fn aes256_ctr_matches_openssl() {
    check::<AES_256, 32>("AES-256", KEY_256, CT_256);
}

/// The vectors must actually depend on the counter advancing: the second block of ciphertext must
/// differ from what a mode that reused counter 0 would produce.
///
/// Without this, a vector could in principle be satisfied by a stuck counter if the plaintext
/// happened to cooperate. Here the first two plaintext blocks differ, so `C1 XOR C2` would equal
/// `P1 XOR P2` if the keystream were the same for both -- and it must not.
#[test]
fn the_vectors_depend_on_the_counter_advancing() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = unhex(CT_128);

    let ks_xor: Vec<u8> = ciphertext[..BLOCK_LEN]
        .iter()
        .zip(ciphertext[BLOCK_LEN..2 * BLOCK_LEN].iter())
        .zip(plaintext[..BLOCK_LEN].iter().zip(plaintext[BLOCK_LEN..2 * BLOCK_LEN].iter()))
        .map(|((c1, c2), (p1, p2))| c1 ^ c2 ^ p1 ^ p2)
        .collect();

    assert_ne!(
        ks_xor,
        vec![0u8; BLOCK_LEN],
        "O1 and O2 must differ, i.e. the counter must have advanced between them"
    );
}
