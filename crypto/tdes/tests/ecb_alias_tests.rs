//! Tests for the padded TDES-ECB alias.
//!
//! As with the CBC alias, this is only a type alias, so what is worth testing is that both
//! parameters select: the direction picks the encryptor or the decryptor, and the padding scheme
//! reaches the behaviour. ECB's own properties are tested in `bouncycastle-modes`; what is specific
//! here is the 8-byte block, and that `INIT_DATA_LEN` is 0 so the projection carries a different
//! value than CBC's.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{SimpleCipherDecryptor, SimpleCipherEncryptor};
use bouncycastle_modes::{Decrypting, Ecb, Encrypting};
use bouncycastle_padding::{NoPadding, PKCS7, PaddedDecryptor, PaddedEncryptor};
use bouncycastle_tdes::{BLOCK_LEN, KEY_LEN, TDES, TDES_ECB};

fn key() -> KeyMaterial<KEY_LEN> {
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid key")
}

/// The alias must resolve to exactly the adapters it claims to, with `INIT_DATA_LEN = 0`.
#[test]
fn the_alias_names_the_expected_types() {
    use core::mem::size_of;

    assert_eq!(
        size_of::<TDES_ECB<Encrypting, PKCS7>>(),
        size_of::<
            PaddedEncryptor<
                Ecb<TDES, Encrypting, KEY_LEN, BLOCK_LEN>,
                PKCS7,
                KEY_LEN,
                0,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<TDES_ECB<Decrypting, PKCS7>>(),
        size_of::<
            PaddedDecryptor<
                Ecb<TDES, Decrypting, KEY_LEN, BLOCK_LEN>,
                PKCS7,
                KEY_LEN,
                0,
                BLOCK_LEN,
            >,
        >()
    );
}

/// ECB has no IV, so the init data is an empty array and the ciphertext is exactly the padded
/// plaintext with nothing prepended.
#[test]
fn there_is_no_iv() {
    let (no_iv, ciphertext) =
        TDES_ECB::<Encrypting, PKCS7>::encrypt(&key(), b"hello").expect("encryption");
    assert_eq!(no_iv, [0u8; 0], "ECB has no IV, so the init data is empty");
    assert_eq!(ciphertext.len(), 8, "five bytes padded to one block, nothing prepended");

    let recovered = TDES_ECB::<Decrypting, PKCS7>::decrypt(&key(), &no_iv, &ciphertext).unwrap();
    assert_eq!(recovered, b"hello");
}

/// Round trips at lengths that need padding and lengths that do not, around the 8-byte block.
#[test]
fn round_trips_at_every_alignment() {
    for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 64] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
        let (no_iv, ciphertext) =
            TDES_ECB::<Encrypting, PKCS7>::encrypt(&key(), &plaintext).expect("encryption");
        assert_eq!(no_iv, [0u8; 0]);
        assert_eq!(
            ciphertext.len(),
            (len / 8 + 1) * 8,
            "len {len}: PKCS7 pads up to the next whole block"
        );

        let recovered = TDES_ECB::<Decrypting, PKCS7>::decrypt(&key(), &no_iv, &ciphertext)
            .expect("decryption");
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// The padding parameter must select the scheme here too.
#[test]
fn the_padding_parameter_selects_the_scheme() {
    let aligned = [0x5Au8; 8];
    let (_, pkcs7) = TDES_ECB::<Encrypting, PKCS7>::encrypt(&key(), &aligned).expect("PKCS7");
    let (_, nopad) =
        TDES_ECB::<Encrypting, NoPadding>::encrypt(&key(), &aligned).expect("NoPadding");
    assert_eq!(pkcs7.len(), 16, "PKCS7 adds a whole block to aligned data");
    assert_eq!(nopad.len(), 8, "NoPadding adds nothing");

    assert!(
        TDES_ECB::<Encrypting, NoPadding>::encrypt(&key(), b"hello").is_err(),
        "NoPadding must refuse a partial block"
    );
}

/// Padding does not fix ECB: identical plaintext blocks still give identical ciphertext blocks, and
/// the same message under the same key always gives the same ciphertext.
#[test]
fn padding_does_not_hide_the_codebook_property() {
    let (_, ciphertext) =
        TDES_ECB::<Encrypting, NoPadding>::encrypt(&key(), &[0x5Au8; 16]).unwrap();
    assert_eq!(ciphertext[..8], ciphertext[8..], "ECB is a codebook, padded or not");

    let (_, a) = TDES_ECB::<Encrypting, PKCS7>::encrypt(&key(), b"hello").unwrap();
    let (_, b) = TDES_ECB::<Encrypting, PKCS7>::encrypt(&key(), b"hello").unwrap();
    assert_eq!(a, b, "the same message encrypts the same way every time");
}
