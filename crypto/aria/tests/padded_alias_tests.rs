//! The padded CBC mode through the three ARIA keys.
//!
//! The aliases are only type aliases, so what is worth testing is that both parameters actually
//! select: the direction picks the encryptor or the decryptor, and the padding scheme changes the
//! behaviour rather than being decorative. The mode and the padding layer are tested in
//! `bouncycastle-cipher`; this checks the wiring between them and the key that hands the aliases
//! out. Which type each alias resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_aria::{ARIA128Key, ARIA192Key, ARIA256Key, BLOCK_LEN};
use bouncycastle_cipher::modes::CBC;
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_rng::HashDRBG_SHA512;

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// Round trips at lengths that need padding and lengths that do not, at every key length.
fn round_trips<const KEY_LEN: usize, K>(name: &str, key: &K)
where
    K: SymmetricEncryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>
        + SymmetricDecryptionKey<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 127, 128] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
        let (iv, ciphertext) = key.encrypt(&mut rng(), &plaintext).expect("encryption");
        assert_eq!(iv.len(), BLOCK_LEN);
        assert_eq!(
            ciphertext.len(),
            (len / BLOCK_LEN + 1) * BLOCK_LEN,
            "{name}, len {len}: PKCS7 pads up to the next whole block"
        );
        let recovered = key.decrypt(&iv, &ciphertext).expect("decryption");
        assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
    }
}

#[test]
fn every_key_length_round_trips() {
    round_trips::<16, _>(
        "ARIA-128",
        &ARIA128Key::<CBC<PKCS7>>::from_key_material(&material()).unwrap(),
    );
    round_trips::<24, _>(
        "ARIA-192",
        &ARIA192Key::<CBC<PKCS7>>::from_key_material(&material()).unwrap(),
    );
    round_trips::<32, _>(
        "ARIA-256",
        &ARIA256Key::<CBC<PKCS7>>::from_key_material(&material()).unwrap(),
    );
}

/// The padding parameter must actually select the scheme, not merely be carried around.
#[test]
fn the_padding_parameter_selects_the_scheme() {
    let pkcs7_key = ARIA128Key::<CBC<PKCS7>>::from_key_material(&material()).unwrap();
    let nopad_key = ARIA128Key::<CBC<NoPadding>>::from_key_material(&material()).unwrap();

    // A whole block: both schemes accept it, and they disagree about the length.
    let aligned = [0x5Au8; BLOCK_LEN];
    let (_, pkcs7) = pkcs7_key.encrypt(&mut rng(), &aligned).expect("PKCS7 accepts it");
    let (_, nopad) = nopad_key.encrypt(&mut rng(), &aligned).expect("NoPadding accepts it");
    assert_eq!(pkcs7.len(), 32, "PKCS7 adds a whole block of padding to aligned data");
    assert_eq!(nopad.len(), 16, "NoPadding adds nothing");

    // Five bytes: PKCS7 pads it, NoPadding refuses rather than silently padding.
    assert!(pkcs7_key.encrypt(&mut rng(), b"hello").is_ok(), "PKCS7 pads a partial block");
    assert!(nopad_key.encrypt(&mut rng(), b"hello").is_err(), "NoPadding must refuse it");
}

/// A ciphertext made under one scheme must not decrypt cleanly under the other.
#[test]
fn the_two_schemes_are_not_interchangeable() {
    let pkcs7_key = ARIA128Key::<CBC<PKCS7>>::from_key_material(&material()).unwrap();
    let nopad_key = ARIA128Key::<CBC<NoPadding>>::from_key_material(&material()).unwrap();
    let aligned = [0x5Au8; BLOCK_LEN];
    let (iv, pkcs7) = pkcs7_key.encrypt(&mut rng(), &aligned).expect("encryption");

    // NoPadding hands back the padding block as if it were data: the silent mismatch the type
    // parameter is there to prevent.
    let as_nopad = nopad_key.decrypt(&iv, &pkcs7).expect("NoPadding cannot tell");
    assert_ne!(as_nopad, aligned);
    assert_eq!(as_nopad.len(), 32, "it keeps the padding block as data");

    assert_eq!(pkcs7_key.decrypt(&iv, &pkcs7).expect("decryption"), aligned);
}

/// The IV is drawn per encryption, so the same plaintext gives different ciphertext.
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let key = ARIA128Key::<CBC<PKCS7>>::from_key_material(&material()).unwrap();
    let mut rng = rng();
    let plaintext = [0x77u8; 32];
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (iv, ct) = key.encrypt(&mut rng, &plaintext).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions");
        assert_eq!(key.decrypt(&iv, &ct).unwrap(), plaintext);
    }
}
