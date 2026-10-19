//! Different AES modes are different algorithms, and material bound to one of them is refused by
//! the others' keys: material bound to `AES_CBC_128` builds an `AES128Key<CBC<..>>` but not an
//! `AES128Key<GCM>` or `<CTR>`, and a suspended CBC state does not resume under it either.
//! Unbound material is still accepted by all, since binding is opt-in. The per-key contract is
//! checked for every key type by `TestFrameworkFromKeyMaterial`; this pins the cross-mode case
//! on the real types.

use bouncycastle_aes::{AES_CBC_128, AES_GCM_128, AES128Key};
use bouncycastle_cipher::Encrypting;
use bouncycastle_cipher::modes::{CBC, CTR, GCM};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_core::errors::{KeyMaterialError, SuspendableError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{Algorithm, SuspendableKeyed};
use bouncycastle_rng::HashDRBG_SHA512;

type CbcEnc = AES_CBC_128<Encrypting, PKCS7>;
type GcmEnc = AES_GCM_128<Encrypting>;

fn material() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap()
}

fn bound(alg_name: &'static str) -> KeyMaterial<16> {
    let mut key = material();
    key.set_algorithm(Some(alg_name)).unwrap();
    key
}

fn assert_refused<T>(result: Result<T, SymmetricCipherError>) {
    assert!(matches!(
        result,
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
}

#[test]
fn material_bound_to_cbc_is_refused_by_gcm() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let cbc_material = bound(CbcEnc::ALG_NAME);
    assert_eq!(cbc_material.algorithm(), Some("AES_CBC_128"));

    // CBC takes it.
    let cbc_key = AES128Key::<CBC<PKCS7>>::from_key_material(&cbc_material).unwrap();
    let mut ct = [0u8; 32];
    let (written, iv) = cbc_key.encrypt_out(&mut rng, b"sixteen byte msg", &mut ct).unwrap();
    let mut pt = [0u8; 32];
    let n = cbc_key.decrypt_out(&iv, &ct[..written], &mut pt).unwrap();
    assert_eq!(&pt[..n], b"sixteen byte msg");

    // GCM, and every other mode, does not: the one gate is the key's constructor.
    assert_refused(AES128Key::<GCM>::from_key_material(&cbc_material));
    assert_refused(AES128Key::<CTR>::from_key_material(&cbc_material));

    // And the other way round.
    assert_refused(AES128Key::<CBC<PKCS7>>::from_key_material(&bound(GcmEnc::ALG_NAME)));
}

#[test]
fn unbound_material_is_accepted_by_both() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let material = material();
    assert_eq!(material.algorithm(), None);
    AES128Key::<CBC<PKCS7>>::from_key_material(&material)
        .unwrap()
        .create_encryptor(&mut rng)
        .unwrap();
    AES128Key::<GCM>::from_key_material(&material).unwrap().create_encryptor(&mut rng).unwrap();
}

#[test]
fn a_suspended_state_does_not_resume_under_another_algorithms_key() {
    let cbc_material = bound(CbcEnc::ALG_NAME);
    let cbc_key = AES128Key::<CBC<PKCS7>>::from_key_material(&cbc_material).unwrap();
    let (enc, _iv) = cbc_key.create_encryptor(&mut HashDRBG_SHA512::new_from_os()).unwrap();
    let state: [u8; CbcEnc::SUSPENDED_STATE_LEN] = enc.suspend();

    CbcEnc::from_suspended(state, &cbc_material).unwrap();
    assert_eq!(
        CbcEnc::from_suspended(state, &bound(GcmEnc::ALG_NAME)).err(),
        Some(SuspendableError::InvalidData)
    );
}
