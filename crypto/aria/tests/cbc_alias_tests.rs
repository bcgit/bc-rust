//! Tests for the padded CBC aliases.
//!
//! The aliases are only type aliases, so what is worth testing is that they name the right types
//! and that both parameters actually select: the direction picks the encryptor or the decryptor,
//! and the padding scheme changes behaviour rather than being decorative. The cipher and the
//! padding layer are tested in their own right elsewhere; this checks the wiring between them.

use bouncycastle_aria::{ARIA_128, ARIA_CBC_128, ARIA_CBC_192, ARIA_CBC_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
use bouncycastle_padding::{NoPadding, PKCS7, PaddedDecryptor, PaddedEncryptor};

fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// The alias must resolve to exactly the adapter it claims to, at both directions.
#[test]
fn the_aliases_name_the_expected_types() {
    use core::mem::size_of;

    assert_eq!(
        size_of::<ARIA_CBC_128<Encrypting, PKCS7>>(),
        size_of::<PaddedEncryptor<Cbc<ARIA_128, Encrypting, 16, 16>, PKCS7, 16, 16, 16>>()
    );
    assert_eq!(
        size_of::<ARIA_CBC_128<Decrypting, PKCS7>>(),
        size_of::<PaddedDecryptor<Cbc<ARIA_128, Decrypting, 16, 16>, PKCS7, 16, 16, 16>>()
    );
}

/// Every key length round-trips through its alias, at lengths that need padding and lengths that
/// do not.
#[test]
fn every_key_length_round_trips() {
    fn check<const N: usize, Enc, Dec>(name: &str)
    where
        Enc: SymmetricCipherEncryptor<N, 16, 16>,
        Dec: SymmetricCipherDecryptor<N, 16, 16>,
    {
        for len in [0usize, 1, 15, 16, 17, 64] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
            let (iv, ciphertext) = Enc::encrypt(&key::<N>(), &plaintext).expect("encryption");
            assert_eq!(
                ciphertext.len(),
                (len / 16 + 1) * 16,
                "{name}, len {len}: PKCS7 pads up to the next whole block"
            );
            let recovered = Dec::decrypt(&key::<N>(), &iv, &ciphertext).expect("decryption");
            assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, ARIA_CBC_128<Encrypting, PKCS7>, ARIA_CBC_128<Decrypting, PKCS7>>("ARIA_CBC_128");
    check::<24, ARIA_CBC_192<Encrypting, PKCS7>, ARIA_CBC_192<Decrypting, PKCS7>>("ARIA_CBC_192");
    check::<32, ARIA_CBC_256<Encrypting, PKCS7>, ARIA_CBC_256<Decrypting, PKCS7>>("ARIA_CBC_256");
}

/// The padding parameter must select the scheme, not merely be carried around.
#[test]
fn the_padding_parameter_selects_the_scheme() {
    let aligned = [0x5Au8; 16];
    let (_, pkcs7) =
        ARIA_CBC_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), &aligned).expect("PKCS7");
    let (_, nopad) =
        ARIA_CBC_128::<Encrypting, NoPadding>::encrypt(&key::<16>(), &aligned).expect("NoPadding");
    assert_eq!(pkcs7.len(), 32, "PKCS7 adds a whole block to aligned data");
    assert_eq!(nopad.len(), 16, "NoPadding adds nothing");

    assert!(
        ARIA_CBC_128::<Encrypting, NoPadding>::encrypt(&key::<16>(), b"hello").is_err(),
        "NoPadding must refuse a message that is not a whole number of blocks"
    );
}

/// A fresh IV per encryption, so the same plaintext gives different ciphertext.
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let plaintext = [0x77u8; 32];
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (iv, ct) =
            ARIA_CBC_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), &plaintext).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions");
        let back = ARIA_CBC_128::<Decrypting, PKCS7>::decrypt(&key::<16>(), &iv, &ct).unwrap();
        assert_eq!(back, plaintext);
    }
}
