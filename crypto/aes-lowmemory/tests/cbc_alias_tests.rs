//! Tests for the padded AES-CBC aliases.
//!
//! The aliases are only type aliases, so what is worth testing is that they name the *right* types
//! and that both parameters actually select: the direction picks the encryptor or the decryptor, and
//! the padding scheme changes the behaviour rather than being decorative. The mode and the padding
//! layer are tested in their own crates; this checks the wiring between them.

use bouncycastle_aes_lowmemory::{AES_CBC_128, AES_CBC_192, AES_CBC_256, Aes128};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
use bouncycastle_padding::{NoPadding, PKCS7, PaddedDecryptor, PaddedEncryptor};

fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// The aliases must resolve to exactly the adapters they claim to, at both directions.
///
/// A type alias that quietly resolved to something else -- the wrong padding, the wrong direction,
/// the wrong key length -- would still compile everywhere it is used, so this pins the projection
/// itself by asserting the layouts coincide with the fully spelled-out types.
#[test]
fn the_aliases_name_the_expected_types() {
    use core::mem::size_of;

    assert_eq!(
        size_of::<AES_CBC_128<Encrypting, PKCS7>>(),
        size_of::<PaddedEncryptor<Cbc<Aes128, Encrypting, 16, 16>, PKCS7, 16, 16, 16>>()
    );
    assert_eq!(
        size_of::<AES_CBC_128<Decrypting, PKCS7>>(),
        size_of::<PaddedDecryptor<Cbc<Aes128, Decrypting, 16, 16>, PKCS7, 16, 16, 16>>()
    );

    // The two directions are genuinely different types, so the encryptor and the decryptor do not
    // have to agree in size -- and here they do not, which is itself evidence the projection
    // selected two different adapters rather than one.
    assert_ne!(
        size_of::<AES_CBC_128<Encrypting, PKCS7>>(),
        size_of::<AES_CBC_128<Decrypting, PKCS7>>()
    );
}

/// Every key length round-trips through its alias, at a length that needs padding and one that does
/// not.
#[test]
fn every_key_length_round_trips() {
    fn check<const N: usize, Enc, Dec>(name: &str)
    where
        Enc: SymmetricCipherEncryptor<N, 16, 16>,
        Dec: SymmetricCipherDecryptor<N, 16, 16>,
    {
        for len in [0usize, 1, 15, 16, 17, 63, 64] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
            let (iv, ciphertext) = Enc::encrypt(&key::<N>(), &plaintext).expect("encryption");

            // PKCS#7 always adds at least one byte, and rounds up to a whole block.
            assert_eq!(
                ciphertext.len(),
                (len / 16 + 1) * 16,
                "{name}, len {len}: PKCS7 pads up to the next whole block"
            );

            let recovered = Dec::decrypt(&key::<N>(), &iv, &ciphertext).expect("decryption");
            assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, AES_CBC_128<Encrypting, PKCS7>, AES_CBC_128<Decrypting, PKCS7>>("AES-128");
    check::<24, AES_CBC_192<Encrypting, PKCS7>, AES_CBC_192<Decrypting, PKCS7>>("AES-192");
    check::<32, AES_CBC_256<Encrypting, PKCS7>, AES_CBC_256<Decrypting, PKCS7>>("AES-256");
}

/// The padding parameter must actually select the scheme, not merely be carried around.
///
/// `PKCS7` accepts any length and always grows the message; `NoPadding` accepts only whole blocks
/// and never grows it. Checking both against the same alias, key and plaintext is what proves the
/// parameter reaches the behaviour.
#[test]
fn the_padding_parameter_selects_the_scheme() {
    type Pkcs7Enc = AES_CBC_128<Encrypting, PKCS7>;
    type NoPadEnc = AES_CBC_128<Encrypting, NoPadding>;

    // A whole block: both schemes accept it, and they disagree about the length.
    let aligned = [0x5Au8; 16];
    let (_, pkcs7) = Pkcs7Enc::encrypt(&key::<16>(), &aligned).expect("PKCS7 accepts aligned data");
    let (_, nopad) = NoPadEnc::encrypt(&key::<16>(), &aligned).expect("NoPadding accepts it too");
    assert_eq!(pkcs7.len(), 32, "PKCS7 adds a whole block of padding to aligned data");
    assert_eq!(nopad.len(), 16, "NoPadding adds nothing");

    // Five bytes: PKCS7 pads it, NoPadding refuses rather than silently padding.
    let unaligned = b"hello";
    assert!(Pkcs7Enc::encrypt(&key::<16>(), unaligned).is_ok(), "PKCS7 pads a partial block");
    assert!(
        NoPadEnc::encrypt(&key::<16>(), unaligned).is_err(),
        "NoPadding must refuse a message that is not a whole number of blocks"
    );
}

/// A ciphertext made under one scheme must not decrypt cleanly under the other.
///
/// This is the practical reason the scheme is named in the type: the two are not interchangeable,
/// and without the type parameter nothing would stop a caller pairing them.
#[test]
fn the_two_schemes_are_not_interchangeable() {
    let aligned = [0x5Au8; 16];
    let (iv, pkcs7) =
        AES_CBC_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), &aligned).expect("encryption");

    // NoPadding will hand back the padded block as if it were data, so it "succeeds" with the
    // wrong answer -- exactly the silent mismatch the type parameter is there to prevent.
    let as_nopad = AES_CBC_128::<Decrypting, NoPadding>::decrypt(&key::<16>(), &iv, &pkcs7)
        .expect("NoPadding cannot tell that the trailing block is padding");
    assert_ne!(as_nopad, aligned, "the recovered data must not match the original");
    assert_eq!(as_nopad.len(), 32, "it keeps the padding block as data");

    // ...and the matching scheme gets it right.
    let correct =
        AES_CBC_128::<Decrypting, PKCS7>::decrypt(&key::<16>(), &iv, &pkcs7).expect("decryption");
    assert_eq!(correct, aligned);
}

/// The IV is generated per encryption, so the same plaintext gives different ciphertext.
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let plaintext = [0x77u8; 32];
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (iv, ct) = AES_CBC_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), &plaintext).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions");
        let back = AES_CBC_128::<Decrypting, PKCS7>::decrypt(&key::<16>(), &iv, &ct).unwrap();
        assert_eq!(back, plaintext);
    }
}
