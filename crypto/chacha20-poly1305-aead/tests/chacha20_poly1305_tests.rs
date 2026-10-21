use bouncycastle_chacha20_poly1305_aead::{
    ChaCha20_Poly1305, ChaCha20Poly1305Key, MAX_MESSAGE_LEN,
};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::aead::{
    TestFrameworkAEADCipher, TestFrameworkAEADTaggedLayout,
};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_rng::HashDRBG_SHA512;

type Enc<'k> = ChaCha20_Poly1305<'k, Encrypting>;
type Dec<'k> = ChaCha20_Poly1305<'k, Decrypting>;

fn material() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&[7; 32], KeyType::SymmetricCipherKey).unwrap()
}

fn key() -> ChaCha20Poly1305Key {
    ChaCha20Poly1305Key::from_key_material(&material()).unwrap()
}

#[test]
fn core_aead_and_symmetric_contracts() {
    let key = key();
    TestFrameworkAEADCipher::new()
        .test_key::<32, 12, 16, 16, _>(&key, &mut HashDRBG_SHA512::new_from_os());
    TestFrameworkAEADTaggedLayout::new().test_key::<32, 12, 16, 16, _>(&key);
}

/// The key's construction suite: the type, binding and strength policy of `from_key_material`.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<32, ChaCha20Poly1305Key>(Enc::ALG_NAME, SecurityStrength::_256bit);
}

/// RFC 8439 Sec 2.8: "P_MAX (maximum size of the plaintext) is 274,877,906,880 bytes".
#[test]
fn max_message_len_is_the_rfc_p_max() {
    assert_eq!(MAX_MESSAGE_LEN, 274_877_906_880);
}

#[test]
fn failed_update_can_be_retried_without_ending_aad() {
    let key = key();
    let nonce = [9; 12];
    let msg = [0x42; 65];
    let mut enc = key.create_encryptor_nonce(&nonce);
    let mut short = [0xa5; 64];
    assert_eq!(
        enc.do_encrypt_out(&msg, &mut short),
        Err(SymmetricCipherError::OutputBufferTooSmall(65))
    );
    assert_eq!(short, [0; 64], "a refused call zeroizes its output buffer");
    enc.do_update_aad(b"aad").unwrap();
    let mut ct = [0u8; 65];
    enc.do_encrypt_out(&msg, &mut ct).unwrap();
    let (tag, _) = enc.do_encrypt_final().unwrap();
    let mut dec = key.create_decryptor(&nonce);
    let mut short = [0xa5; 48];
    assert_eq!(
        dec.do_decrypt_out(&ct, &mut short),
        Err(SymmetricCipherError::OutputBufferTooSmall(49))
    );
    assert_eq!(short, [0; 48], "a refused call zeroizes its output buffer");
    dec.do_update_aad(b"aad").unwrap();
    let mut pt = [0u8; 65];
    let n = dec.do_decrypt_out(&ct, &mut pt).unwrap();
    let (last, m) = dec.do_decrypt_final_detached(&tag).unwrap();
    pt[n..n + m].copy_from_slice(&last[..m]);
    assert_eq!(pt, msg);
}

#[test]
fn key_capacity_does_not_replace_key_length() {
    for len in 0..32 {
        let mut short = material();
        short.set_key_len(len).unwrap();
        assert!(matches!(
            ChaCha20Poly1305Key::from_key_material(&short),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
    }
}

/// The figures in the crate docs' Memory Usage table.
#[cfg(target_pointer_width = "64")]
#[test]
fn sizes_match_the_documented_memory_table() {
    use core::mem::size_of;
    assert_eq!(size_of::<ChaCha20Poly1305Key>(), 32);
    assert_eq!(size_of::<Enc<'static>>(), 344);
    assert_eq!(size_of::<Dec<'static>>(), 344);
}
