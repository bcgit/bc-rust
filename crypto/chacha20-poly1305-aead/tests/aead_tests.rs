use bouncycastle_chacha20_poly1305_aead::{
    ChaCha20Poly1305Decryptor as Dec, ChaCha20Poly1305Encryptor as Enc,
};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::aead::TestFrameworkAEADCipher;

#[test]
fn core_aead_and_symmetric_contracts() {
    TestFrameworkAEADCipher::new().test_encryptor_decryptor::<32, 12, 16, 16, Enc, Dec>();
}

#[test]
fn failed_update_can_be_retried_without_ending_aad() {
    let key = KeyMaterial::<32>::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap();
    let nonce = [9; 12];
    let msg = [0x42; 65];
    let mut enc = Enc::new_with_nonce(&key, &nonce).unwrap();
    let mut short = [0xa5; 64];
    assert_eq!(
        enc.do_encrypt_out(&msg, &mut short),
        Err(SymmetricCipherError::OutputBufferTooSmall(65))
    );
    assert_eq!(short, [0xa5; 64]);
    enc.do_update_aad(b"aad").unwrap();
    let mut ct = [0u8; 65];
    enc.do_encrypt_out(&msg, &mut ct).unwrap();
    let (tag, _) = enc.do_final().unwrap();
    let mut dec = Dec::do_decrypt_init(&key, &nonce).unwrap();
    let mut short = [0xa5; 48];
    assert_eq!(
        dec.do_decrypt_out(&ct, &mut short),
        Err(SymmetricCipherError::OutputBufferTooSmall(49))
    );
    assert_eq!(short, [0xa5; 48]);
    dec.do_update_aad(b"aad").unwrap();
    let mut pt = [0u8; 65];
    let n = dec.do_decrypt_out(&ct, &mut pt).unwrap();
    let (last, m) = dec.do_final_detached(&tag).unwrap();
    pt[n..n + m].copy_from_slice(&last[..m]);
    assert_eq!(pt, msg);
}

#[test]
fn key_capacity_does_not_replace_key_length() {
    for len in 0..32 {
        let mut key =
            KeyMaterial::<32>::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap();
        key.set_key_len(len).unwrap();
        assert!(matches!(
            Enc::new_with_nonce(&key, &[0; 12]),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
        assert!(matches!(
            Dec::do_decrypt_init(&key, &[0; 12]),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
    }
}
