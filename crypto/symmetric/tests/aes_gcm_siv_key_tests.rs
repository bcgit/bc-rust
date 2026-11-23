//! The AES-GCM-SIV keys through the shared suites of `bouncycastle-cipher-test-framework`: the
//! construction policy, and the in-place AEAD contract that is the key's only role, at the two
//! key lengths RFC 8452 defines. What is GCM-SIV's own is in `gcm_siv_tests.rs`, and the known
//! answers are in the vector suites beside this file.

use bouncycastle_cipher_test_framework::material::{material, rng};
use bouncycastle_cipher_test_framework::mode_keys;
use bouncycastle_core::symmetric_key::{
    AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey, FromKeyMaterial,
};
use bouncycastle_symmetric::aes::hazmat::{AES128Internal, AES256Internal};
use bouncycastle_symmetric::aes::{
    AES_GCM_SIV_128, AES_GCM_SIV_256, AES128Key, AES256Key, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN,
};
use bouncycastle_symmetric::modes::{GCM, GCM_SIV};

#[test]
fn gcm_siv_keys_enforce_the_material_policy() {
    mode_keys::gcm_siv_construction::<AES128Internal, 16>();
    mode_keys::gcm_siv_construction::<AES256Internal, 32>();
}

#[test]
fn gcm_siv_keys_pass_the_in_place_aead_framework() {
    mode_keys::gcm_siv_in_place::<AES128Internal, 16>();
    mode_keys::gcm_siv_in_place::<AES256Internal, 32>();
}

/// The aliases are the mode-bound keys, and the lengths the crate re-exports are the mode's.
#[test]
fn the_aliases_name_the_mode_bound_keys() {
    let _: AES128Key<GCM_SIV> = AES_GCM_SIV_128::from_key_material(&material::<16>()).unwrap();
    let _: AES256Key<GCM_SIV> = AES_GCM_SIV_256::from_key_material(&material::<32>()).unwrap();
    assert_eq!((GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN), (12, 16));
}

/// Seals through `enc` and opens through `dec`, each a trait object.
fn round_trip_through_trait_objects(
    enc: &dyn AeadInPlaceEncryptionKey<32, 12, 16>,
    dec: &dyn AeadInPlaceDecryptionKey<32, 12, 16>,
) {
    let message = *b"a message held in its own buffer";
    let mut buf = message;
    let (nonce, tag) = enc.encrypt_detached_inplace(&mut rng(), b"aad", &mut buf).unwrap();
    assert_ne!(buf, message);
    let mut again = message;
    assert_eq!(enc.encrypt_detached_inplace_nonce(&nonce, b"aad", &mut again).unwrap(), tag);
    assert_eq!(again, buf);
    dec.decrypt_detached_inplace(&nonce, b"aad", &mut buf, &tag).unwrap();
    assert_eq!(buf, message);
}

/// The in-place roles are dyn-compatible: code that holds a key as a trait object needs no type
/// parameter for the mode, whether the key can also stream (GCM) or not (GCM-SIV).
#[test]
fn the_in_place_roles_are_held_as_trait_objects() {
    let siv = AES256Key::<GCM_SIV>::from_key_material(&material::<32>()).unwrap();
    round_trip_through_trait_objects(&siv, &siv);
    let gcm = AES256Key::<GCM>::from_key_material(&material::<32>()).unwrap();
    round_trip_through_trait_objects(&gcm, &gcm);
}
