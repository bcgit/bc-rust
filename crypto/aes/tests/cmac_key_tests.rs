//! `AES*Key<CMAC>`: the key object holding the subkeys, and the workers it hands out producing
//! exactly what the mode's own route produces over a `CmacKeyState` built from the same bytes.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_aes::{AES_CMAC_128, AES_CMAC_192, AES_CMAC_256, AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::{CMAC, CmacKeyState};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{ElectronicCodeBook, MacMode, Mode};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::MAC;
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;

fn mac_key<const N: usize>(fill: u8) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[fill; N], KeyType::MACKey).expect("a MAC key")
}

/// The same bytes as [`mac_key`] tagged as the permutation itself takes them, for the bare key
/// state the key object is compared against.
fn cipher_key<const N: usize>(fill: u8) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[fill; N], KeyType::SymmetricCipherKey)
        .expect("a cipher key")
}

const MSG: &[u8] = b"The quick brown fox jumps over the lazy dog";

/// NIST CSRC AES_CMAC.pdf Example #3 (Mlen = 20), AES-128: the key object reproduces a published
/// answer, so the retagged copy it hands the permutation is the right key.
#[test]
fn the_key_object_gives_the_csrc_answer() {
    let material = KeyMaterial::<16>::from_bytes_as_type(
        &hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap(),
        KeyType::MACKey,
    )
    .unwrap();
    let msg = hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a57").unwrap();
    let key = AES128Key::<CMAC>::from_key_material(&material).unwrap();
    assert_eq!(key.mac(&msg), hex::decode("7d85449ea6ea19c823a7bf78837dfade").unwrap());
}

#[test]
fn the_key_and_the_bare_key_state_agree_at_every_key_length() {
    let state_16 = <CMAC as Mode<AES128Internal>>::key_state(
        AES128Internal::new(&cipher_key::<16>(0x0b)).unwrap(),
    );
    let state_24 = <CMAC as Mode<AES192Internal>>::key_state(
        AES192Internal::new(&cipher_key::<24>(0x0c)).unwrap(),
    );
    let state_32 = <CMAC as Mode<AES256Internal>>::key_state(
        AES256Internal::new(&cipher_key::<32>(0x0d)).unwrap(),
    );
    for len in [0usize, 1, 15, 16, 17, 43] {
        let msg = &MSG[..len];
        assert_eq!(
            AES128Key::<CMAC>::from_key_material(&mac_key::<16>(0x0b)).unwrap().mac(msg),
            <CMAC as MacMode<AES128Internal>>::mac_init(&state_16).mac(msg)
        );
        assert_eq!(
            AES192Key::<CMAC>::from_key_material(&mac_key::<24>(0x0c)).unwrap().mac(msg),
            <CMAC as MacMode<AES192Internal>>::mac_init(&state_24).mac(msg)
        );
        assert_eq!(
            AES256Key::<CMAC>::from_key_material(&mac_key::<32>(0x0d)).unwrap().mac(msg),
            <CMAC as MacMode<AES256Internal>>::mac_init(&state_32).mac(msg)
        );
    }
}

#[test]
fn several_workers_from_one_key_are_independent_and_the_key_is_unchanged() {
    let key = AES128Key::<CMAC>::from_key_material(&mac_key::<16>(0x0b)).unwrap();
    let before = key.mac(MSG);

    let mut a = key.create_generator();
    let mut b = key.create_generator();
    a.do_update(b"message one");
    b.do_update(b"message two");
    let mut tag_b = [0u8; 16];
    let nb = b.do_final_out(&mut tag_b).unwrap(); // finished in the other order
    let mut tag_a = [0u8; 16];
    let na = a.do_final_out(&mut tag_a).unwrap();
    assert_eq!((na, nb), (16, 16));
    assert_ne!(tag_a, tag_b);
    assert_eq!(tag_a[..], key.mac(b"message one")[..]);
    assert_eq!(tag_b[..], key.mac(b"message two")[..]);

    let mut v = key.create_verifier();
    v.do_update(MSG);
    assert!(v.do_verify_final(&before));
    assert!(key.verify(MSG, &before));
    assert!(!key.verify(b"not the message", &before));
    assert_eq!(key.mac(MSG), before);
}

#[test]
fn a_cipher_key_is_refused_at_construction() {
    let cipher_key =
        KeyMaterial::<16>::from_bytes_as_type(&[0x0b; 16], KeyType::SymmetricCipherKey).unwrap();
    match AES128Key::<CMAC>::from_key_material(&cipher_key) {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        other => panic!("expected InvalidKeyType, got {:?}", other.err()),
    }
    // And a MAC key is refused by a cipher mode, the other way round.
    match AES128Key::<bouncycastle_cipher::modes::GCM>::from_key_material(&mac_key::<16>(0x0b)) {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        other => panic!("expected InvalidKeyType, got {:?}", other.err()),
    }
}

#[test]
fn a_key_below_its_own_strength_is_refused_at_construction() {
    let mut weak = mac_key::<32>(0x0d);
    weak.set_security_strength(SecurityStrength::_128bit).unwrap();
    match AES256Key::<CMAC>::from_key_material(&weak) {
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => {}
        other => panic!("expected SecurityStrength, got {:?}", other.err()),
    }
}

#[test]
fn generate_draws_a_mac_key() {
    let mut rng = FixedSeedRNG::<32>::new([0x24u8; 32]);
    let key = AES256Key::<CMAC>::generate(&mut rng).unwrap();
    let tag = key.mac(MSG);
    assert!(key.verify(MSG, &tag));
    assert_eq!(AES128Key::<CMAC>::KEY_TYPE, KeyType::MACKey);
}

/// The sizes the docs quote.
#[test]
fn sizes() {
    use core::mem::size_of;
    assert_eq!(
        size_of::<AES128Key<CMAC>>(),
        size_of::<CmacKeyState<bouncycastle_aes::hazmat::AES128Internal, 16>>()
    );
    assert_eq!(
        [size_of::<AES128Key<CMAC>>(), size_of::<AES192Key<CMAC>>(), size_of::<AES256Key<CMAC>>()],
        [208, 240, 272]
    );
    assert_eq!(
        [size_of::<AES_CMAC_128>(), size_of::<AES_CMAC_192>(), size_of::<AES_CMAC_256>()],
        [48, 48, 48]
    );
}

/// Equality follows the material through the CMAC state, subkeys included: the same bytes
/// compare equal, as does a clone, and different bytes do not.
#[test]
fn cmac_keys_compare_equal_exactly_when_their_material_does() {
    let key = AES128Key::<CMAC>::from_key_material(&mac_key::<16>(0x2b)).unwrap();
    assert!(key == key.clone());
    assert!(key == AES128Key::<CMAC>::from_key_material(&mac_key::<16>(0x2b)).unwrap());
    assert!(key != AES128Key::<CMAC>::from_key_material(&mac_key::<16>(0x2c)).unwrap());
}
