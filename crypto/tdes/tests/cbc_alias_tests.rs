//! Tests for the padded TDES-CBC alias.
//!
//! The alias is only a type alias, so what is worth testing is that it names the *right* types and
//! that both parameters actually select: the direction picks the encryptor or the decryptor, and
//! the padding scheme changes the behaviour rather than being decorative. The mode and the padding
//! layer are tested in their own crates; this checks the wiring between them at the 8-byte block.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{SimpleCipherDecryptor, SimpleCipherEncryptor};
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
use bouncycastle_padding::{NoPadding, PKCS7, PaddedDecryptor, PaddedEncryptor};
use bouncycastle_tdes::{BLOCK_LEN, KEY_LEN, TDES, TDES_CBC};

fn key() -> KeyMaterial<KEY_LEN> {
    let bytes: [u8; KEY_LEN] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<KEY_LEN>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid key")
}

/// The alias must resolve to exactly the adapters it claims to, at both directions.
#[test]
fn the_alias_names_the_expected_types() {
    use core::mem::size_of;

    assert_eq!(
        size_of::<TDES_CBC<Encrypting, PKCS7>>(),
        size_of::<
            PaddedEncryptor<
                Cbc<TDES, Encrypting, KEY_LEN, BLOCK_LEN>,
                PKCS7,
                KEY_LEN,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );
    assert_eq!(
        size_of::<TDES_CBC<Decrypting, PKCS7>>(),
        size_of::<
            PaddedDecryptor<
                Cbc<TDES, Decrypting, KEY_LEN, BLOCK_LEN>,
                PKCS7,
                KEY_LEN,
                BLOCK_LEN,
                BLOCK_LEN,
            >,
        >()
    );

    // The two directions are genuinely different types, so the encryptor and the decryptor do not
    // have to agree in size -- and here they do not, which is itself evidence the projection
    // selected two different adapters rather than one.
    assert_ne!(size_of::<TDES_CBC<Encrypting, PKCS7>>(), size_of::<TDES_CBC<Decrypting, PKCS7>>());
}

/// Round trips at lengths that need padding and lengths that do not, and the IV is one 8-byte block.
#[test]
fn round_trips_at_every_alignment() {
    for len in [0usize, 1, 7, 8, 9, 15, 16, 17, 63, 64] {
        let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
        let (iv, ciphertext) =
            TDES_CBC::<Encrypting, PKCS7>::encrypt(&key(), &plaintext).expect("encryption");
        assert_eq!(iv.len(), BLOCK_LEN);
        assert_eq!(
            ciphertext.len(),
            (len / 8 + 1) * 8,
            "len {len}: PKCS7 pads up to the next whole block"
        );

        let recovered =
            TDES_CBC::<Decrypting, PKCS7>::decrypt(&key(), &iv, &ciphertext).expect("decryption");
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// The padding parameter must actually select the scheme, not merely be carried around.
#[test]
fn the_padding_parameter_selects_the_scheme() {
    type Pkcs7Enc = TDES_CBC<Encrypting, PKCS7>;
    type NoPadEnc = TDES_CBC<Encrypting, NoPadding>;

    let aligned = [0x5Au8; 8];
    let (_, pkcs7) = Pkcs7Enc::encrypt(&key(), &aligned).expect("PKCS7 accepts aligned data");
    let (_, nopad) = NoPadEnc::encrypt(&key(), &aligned).expect("NoPadding accepts it too");
    assert_eq!(pkcs7.len(), 16, "PKCS7 adds a whole block of padding to aligned data");
    assert_eq!(nopad.len(), 8, "NoPadding adds nothing");

    let unaligned = b"hello";
    assert!(Pkcs7Enc::encrypt(&key(), unaligned).is_ok(), "PKCS7 pads a partial block");
    assert!(NoPadEnc::encrypt(&key(), unaligned).is_err(), "NoPadding must refuse a partial block");
}

/// A ciphertext made under one scheme must not decrypt cleanly under the other.
#[test]
fn the_two_schemes_are_not_interchangeable() {
    let aligned = [0x5Au8; 8];
    let (iv, pkcs7) = TDES_CBC::<Encrypting, PKCS7>::encrypt(&key(), &aligned).expect("encryption");

    let as_nopad = TDES_CBC::<Decrypting, NoPadding>::decrypt(&key(), &iv, &pkcs7)
        .expect("NoPadding cannot tell that the trailing block is padding");
    assert_ne!(as_nopad, aligned);
    assert_eq!(as_nopad.len(), 16, "it keeps the padding block as data");

    let correct = TDES_CBC::<Decrypting, PKCS7>::decrypt(&key(), &iv, &pkcs7).expect("decryption");
    assert_eq!(correct, aligned);
}

/// The IV is generated per encryption, so the same plaintext gives different ciphertext.
#[test]
fn each_encryption_gets_a_fresh_iv() {
    let plaintext = [0x77u8; 16];
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (iv, ct) = TDES_CBC::<Encrypting, PKCS7>::encrypt(&key(), &plaintext).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions");
        let back = TDES_CBC::<Decrypting, PKCS7>::decrypt(&key(), &iv, &ct).unwrap();
        assert_eq!(back, plaintext);
    }
}
