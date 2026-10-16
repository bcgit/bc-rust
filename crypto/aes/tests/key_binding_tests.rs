//! Different AES modes are different algorithms, and a key bound to one of them is refused by the
//! others: a key bound to `AES_CBC_128` cannot be used for `AES_GCM_128`, through the streaming
//! init, the one-shots, or resuming a suspended state. An unbound key is still accepted by both,
//! since binding is opt-in. The per-trait contract is checked for every cipher by the shared test
//! framework; this pins the cross-mode case on the real aliases.

use bouncycastle_aes::{AES_CBC_128, AES_CTR_128, AES_GCM_128};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SuspendableError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    Algorithm, SuspendableKeyed, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

type CbcEnc = AES_CBC_128<Encrypting, PKCS7>;
type CbcDec = AES_CBC_128<Decrypting, PKCS7>;
type GcmEnc = AES_GCM_128<Encrypting>;
type GcmDec = AES_GCM_128<Decrypting>;
type CtrEnc = AES_CTR_128<Encrypting>;

fn key() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap()
}

fn bound(alg_name: &'static str) -> KeyMaterial<16> {
    let mut key = key();
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
fn a_cbc_key_is_refused_by_gcm() {
    let cbc_key = bound(CbcEnc::ALG_NAME);
    assert_eq!(cbc_key.algorithm(), Some("AES_CBC_128"));

    // CBC takes it.
    let mut ct = [0u8; 32];
    let (iv, written) = CbcEnc::encrypt_out(&cbc_key, b"sixteen byte msg", &mut ct).unwrap();
    let mut pt = [0u8; 32];
    let n = CbcDec::decrypt_out(&cbc_key, &iv, &ct[..written], &mut pt).unwrap();
    assert_eq!(&pt[..n], b"sixteen byte msg");

    // GCM, and every other mode, does not: streaming init, one-shot, either direction.
    assert_refused(GcmEnc::do_encrypt_init(&cbc_key));
    assert_refused(GcmDec::do_decrypt_init(&cbc_key, &[0u8; 12]));
    assert_refused(GcmEnc::encrypt_out(&cbc_key, b"msg", &mut [0u8; 3 + 16]));
    assert_refused(CtrEnc::do_encrypt_init(&cbc_key));

    // And the other way round.
    assert_refused(CbcEnc::do_encrypt_init(&bound(GcmEnc::ALG_NAME)));
}

#[test]
fn an_unbound_key_is_accepted_by_both() {
    let key = key();
    assert_eq!(key.algorithm(), None);
    CbcEnc::do_encrypt_init(&key).unwrap();
    GcmEnc::do_encrypt_init(&key).unwrap();
}

#[test]
fn a_suspended_state_does_not_resume_under_another_algorithms_key() {
    let cbc_key = bound(CbcEnc::ALG_NAME);
    let (enc, _iv) = CbcEnc::do_encrypt_init(&cbc_key).unwrap();
    let state: [u8; CbcEnc::SUSPENDED_STATE_LEN] = enc.clone().suspend();

    CbcEnc::from_suspended(state, &cbc_key).unwrap();
    assert_eq!(
        CbcEnc::from_suspended(state, &bound(GcmEnc::ALG_NAME)).err(),
        Some(SuspendableError::InvalidData)
    );
}
