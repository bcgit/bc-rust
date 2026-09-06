//! Tests for the padded AES-ECB aliases.
//!
//! As with the CBC aliases, these are only type aliases, so what is worth testing is that both
//! parameters select: the direction picks the encryptor or the decryptor, and the padding scheme
//! reaches the behaviour. ECB's own properties are tested in `bouncycastle-modes`; what is specific
//! here is that its `INIT_DATA_LEN` is 0, so the projection must carry a different value than CBC's
//! and the aliases must still resolve correctly.

use bouncycastle_aes_lowmemory::{AES_ECB_128, AES_ECB_192, AES_ECB_256, Aes128};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_modes::{Decrypting, Ecb, Encrypting};
use bouncycastle_padding::{NoPadding, PKCS7, PaddedDecryptor, PaddedEncryptor};

fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// The aliases must resolve to exactly the adapters they claim to, with `INIT_DATA_LEN = 0`.
#[test]
fn the_aliases_name_the_expected_types() {
    use core::mem::size_of;

    assert_eq!(
        size_of::<AES_ECB_128<Encrypting, PKCS7>>(),
        size_of::<PaddedEncryptor<Ecb<Aes128, Encrypting, 16, 16>, PKCS7, 16, 0, 16>>()
    );
    assert_eq!(
        size_of::<AES_ECB_128<Decrypting, PKCS7>>(),
        size_of::<PaddedDecryptor<Ecb<Aes128, Decrypting, 16, 16>, PKCS7, 16, 0, 16>>()
    );
}

/// ECB has no IV, so the init data is an empty array and the ciphertext is exactly the padded
/// plaintext with nothing prepended. That is the difference from the CBC aliases, and it comes from
/// the `INIT_DATA_LEN = 0` the projection is given.
#[test]
fn there_is_no_iv() {
    let (no_iv, ciphertext) =
        AES_ECB_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), b"hello").expect("encryption");
    assert_eq!(no_iv, [0u8; 0], "ECB has no IV, so the init data is empty");
    assert_eq!(ciphertext.len(), 16, "five bytes padded to one block, nothing prepended");

    let recovered =
        AES_ECB_128::<Decrypting, PKCS7>::decrypt(&key::<16>(), &no_iv, &ciphertext).unwrap();
    assert_eq!(recovered, b"hello");
}

/// Every key length round-trips through its alias, at lengths that need padding and lengths that do
/// not.
#[test]
fn every_key_length_round_trips() {
    fn check<const N: usize, Enc, Dec>(name: &str)
    where
        Enc: SymmetricCipherEncryptor<N, 0, 16>,
        Dec: SymmetricCipherDecryptor<N, 0, 16>,
    {
        for len in [0usize, 1, 15, 16, 17, 64] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
            let (no_iv, ciphertext) = Enc::encrypt(&key::<N>(), &plaintext).expect("encryption");
            assert_eq!(no_iv, [0u8; 0], "{name}: no IV");
            assert_eq!(
                ciphertext.len(),
                (len / 16 + 1) * 16,
                "{name}, len {len}: PKCS7 pads up to the next whole block"
            );

            let recovered = Dec::decrypt(&key::<N>(), &no_iv, &ciphertext).expect("decryption");
            assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, AES_ECB_128<Encrypting, PKCS7>, AES_ECB_128<Decrypting, PKCS7>>("AES-128");
    check::<24, AES_ECB_192<Encrypting, PKCS7>, AES_ECB_192<Decrypting, PKCS7>>("AES-192");
    check::<32, AES_ECB_256<Encrypting, PKCS7>, AES_ECB_256<Decrypting, PKCS7>>("AES-256");
}

/// The padding parameter must select the scheme here too.
#[test]
fn the_padding_parameter_selects_the_scheme() {
    let aligned = [0x5Au8; 16];
    let (_, pkcs7) =
        AES_ECB_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), &aligned).expect("PKCS7");
    let (_, nopad) =
        AES_ECB_128::<Encrypting, NoPadding>::encrypt(&key::<16>(), &aligned).expect("NoPadding");
    assert_eq!(pkcs7.len(), 32, "PKCS7 adds a whole block to aligned data");
    assert_eq!(nopad.len(), 16, "NoPadding adds nothing");

    assert!(
        AES_ECB_128::<Encrypting, NoPadding>::encrypt(&key::<16>(), b"hello").is_err(),
        "NoPadding must refuse a partial block"
    );
}

/// Padding does not fix ECB: identical plaintext blocks still give identical ciphertext blocks, and
/// the same message under the same key always gives the same ciphertext. The aliases carry the
/// warning; this is the test that it is warranted.
#[test]
fn padding_does_not_hide_the_codebook_property() {
    // Two identical blocks give two identical ciphertext blocks.
    let (_, ciphertext) =
        AES_ECB_128::<Encrypting, NoPadding>::encrypt(&key::<16>(), &[0x5Au8; 32]).unwrap();
    assert_eq!(ciphertext[..16], ciphertext[16..], "ECB is a codebook, padded or not");

    // ...and encryption is deterministic, there being no IV to vary.
    let (_, a) = AES_ECB_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), b"hello").unwrap();
    let (_, b) = AES_ECB_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), b"hello").unwrap();
    assert_eq!(a, b, "the same message encrypts the same way every time");
}
