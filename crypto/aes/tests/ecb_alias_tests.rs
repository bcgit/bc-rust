//! Tests for the padded AES-ECB aliases.
//!
//! As with the CBC aliases, these are only type aliases, so what is worth testing is that both
//! parameters select: the direction picks the encryptor or the decryptor, and the padding scheme
//! reaches the behaviour. ECB's own properties are tested in `bouncycastle_cipher::modes`; what is specific
//! here is that its `INIT_DATA_LEN` is 0, so the projection must carry a different value than CBC's
//! and the aliases must still resolve correctly.

use bouncycastle_aes::hazmat::AES128Internal;
use bouncycastle_aes::hazmat::{AES_ECB_128, AES_ECB_192, AES_ECB_256};
use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::hazmat::{ECB, Ecb};
use bouncycastle_cipher::padding::{
    NoPadding, PKCS7, PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_rng::HashDRBG_SHA512;

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn key_for<M: Mode<AES128Internal>>() -> AES128Key<M> {
    AES128Key::from_key_material(&material::<16>()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// The aliases must resolve to exactly the adapters they claim to, with `INIT_DATA_LEN = 0`, and
/// be what the keys hand out.
#[test]
fn the_aliases_name_the_expected_types() {
    use core::mem::size_of;

    assert_eq!(
        size_of::<AES_ECB_128<'_, Encrypting, PKCS7>>(),
        size_of::<PaddedBlockCipherEncryptor<Ecb<'_, AES128Internal, Encrypting, 16>, PKCS7, 0, 16>>(
        )
    );
    assert_eq!(
        size_of::<AES_ECB_128<'_, Decrypting, PKCS7>>(),
        size_of::<PaddedBlockCipherDecryptor<Ecb<'_, AES128Internal, Decrypting, 16>, PKCS7, 0, 16>>(
        )
    );

    let key = key_for::<ECB<PKCS7>>();
    let (enc, no_iv) = key.create_encryptor(&mut rng()).unwrap();
    let _: AES_ECB_128<'_, Encrypting, PKCS7> = enc;
    let _: AES_ECB_128<'_, Decrypting, PKCS7> = key.create_decryptor(&no_iv);
}

/// ECB has no IV, so the init data is an empty array and the ciphertext is exactly the padded
/// plaintext with nothing prepended. That is the difference from the CBC aliases, and it comes from
/// the `INIT_DATA_LEN = 0` the projection is given.
#[test]
fn there_is_no_iv() {
    let key = key_for::<ECB<PKCS7>>();
    let (no_iv, ciphertext) = key.encrypt(&mut rng(), b"hello").expect("encryption");
    assert_eq!(no_iv, [0u8; 0], "ECB has no IV, so the init data is empty");
    assert_eq!(ciphertext.len(), 16, "five bytes padded to one block, nothing prepended");

    let recovered = key.decrypt(&no_iv, &ciphertext).unwrap();
    assert_eq!(recovered, b"hello");
}

/// Every key length round-trips through its alias, at lengths that need padding and lengths that do
/// not.
#[test]
fn every_key_length_round_trips() {
    fn check<const N: usize, K>(name: &str)
    where
        K: FromKeyMaterial<N> + SymmetricEncryptionKey<N, 0, 16> + SymmetricDecryptionKey<N, 0, 16>,
    {
        let key = K::from_key_material(&material::<N>()).expect("a valid key");
        for len in [0usize, 1, 15, 16, 17, 64] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
            let (no_iv, ciphertext) = key.encrypt(&mut rng(), &plaintext).expect("encryption");
            assert_eq!(no_iv, [0u8; 0], "{name}: no IV");
            assert_eq!(
                ciphertext.len(),
                (len / 16 + 1) * 16,
                "{name}, len {len}: PKCS7 pads up to the next whole block"
            );

            let recovered = key.decrypt(&no_iv, &ciphertext).expect("decryption");
            assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, AES128Key<ECB<PKCS7>>>("AES-128");
    check::<24, AES192Key<ECB<PKCS7>>>("AES-192");
    check::<32, AES256Key<ECB<PKCS7>>>("AES-256");

    // The other two aliases are the same projection at the other key lengths.
    let _: AES_ECB_192<'_, Encrypting, PKCS7> =
        AES192Key::<ECB<PKCS7>>::from_key_material(&material::<24>())
            .unwrap()
            .create_encryptor(&mut rng())
            .unwrap()
            .0;
    let _: AES_ECB_256<'_, Encrypting, PKCS7> =
        AES256Key::<ECB<PKCS7>>::from_key_material(&material::<32>())
            .unwrap()
            .create_encryptor(&mut rng())
            .unwrap()
            .0;
}

/// The padding parameter must select the scheme here too.
#[test]
fn the_padding_parameter_selects_the_scheme() {
    let aligned = [0x5Au8; 16];
    let (_, pkcs7) = key_for::<ECB<PKCS7>>().encrypt(&mut rng(), &aligned).expect("PKCS7");
    let (_, nopad) = key_for::<ECB<NoPadding>>().encrypt(&mut rng(), &aligned).expect("NoPadding");
    assert_eq!(pkcs7.len(), 32, "PKCS7 adds a whole block to aligned data");
    assert_eq!(nopad.len(), 16, "NoPadding adds nothing");

    assert!(
        key_for::<ECB<NoPadding>>().encrypt(&mut rng(), b"hello").is_err(),
        "NoPadding must refuse a partial block"
    );
}

/// Padding does not fix ECB: identical plaintext blocks still give identical ciphertext blocks, and
/// the same message under the same key always gives the same ciphertext. The aliases carry the
/// warning; this is the test that it is warranted.
#[test]
fn padding_does_not_hide_the_codebook_property() {
    // Two identical blocks give two identical ciphertext blocks.
    let (_, ciphertext) = key_for::<ECB<NoPadding>>().encrypt(&mut rng(), &[0x5Au8; 32]).unwrap();
    assert_eq!(ciphertext[..16], ciphertext[16..], "ECB is a codebook, padded or not");

    // ...and encryption is deterministic, there being no IV to vary.
    let key = key_for::<ECB<PKCS7>>();
    let (_, a) = key.encrypt(&mut rng(), b"hello").unwrap();
    let (_, b) = key.encrypt(&mut rng(), b"hello").unwrap();
    assert_eq!(a, b, "the same message encrypts the same way every time");
}
