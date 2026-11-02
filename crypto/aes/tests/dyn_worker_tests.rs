//! A worker lent out as a trait object for the streaming part of a job (issue #173): the owner
//! keeps the concrete encryptor, hands `&mut dyn ...` to code that only needs to feed it, and
//! finishes it itself. No allocation, no `Box`, and the one-shot decrypts what came out.

use bouncycastle_aes::{AES_CBC_128, AES_GCM_128};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;

const MSG: &[u8] = b"the quick brown fox jumps over the lazy dog, twice over, for two blocks";

fn key_material() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
        .expect("a 16-byte symmetric cipher key")
}

/// Feeds `plaintext` in 7-byte pieces through the trait object and returns the ciphertext so far.
fn stream_through(enc: &mut dyn SymmetricCipherEncryptor<16, 16, 16>, plaintext: &[u8]) -> Vec<u8> {
    assert_eq!(enc.alg_name(), "AES_CBC_128");
    assert_eq!(enc.max_security_strength(), SecurityStrength::_128bit);
    let mut out = Vec::new();
    for piece in plaintext.chunks(7) {
        let mut buf = vec![0u8; enc.do_encrypt_out_len(piece.len())];
        let n = enc.do_encrypt_out(piece, &mut buf).expect("CBC never fails mid-stream");
        out.extend_from_slice(&buf[..n]);
    }
    out
}

#[test]
fn cbc_streams_through_a_trait_object() {
    let key = key_material();
    let mut rng = FixedSeedRNG::<16>::new([7u8; 16]);
    let (mut enc, iv) =
        AES_CBC_128::<Encrypting, PKCS7>::do_encrypt_init_rng(&key, &mut rng).unwrap();

    let mut ct = stream_through(&mut enc, MSG);
    // The final is the concrete value's: `do_encrypt_final` takes `self`.
    let (last, n) = enc.do_encrypt_final().unwrap();
    ct.extend_from_slice(&last[..n]);

    assert_eq!(AES_CBC_128::<Decrypting, PKCS7>::decrypt(&key, &iv, &ct).unwrap(), MSG);
}

/// The AAD and the plaintext go through the trait object; the tag comes from the concrete final.
fn aad_and_stream_through(
    enc: &mut dyn AEADCipherEncryptor<16, 12, 16, 16>,
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    assert_eq!(enc.alg_name(), "AES_GCM_128");
    assert_eq!(enc.max_security_strength(), SecurityStrength::_128bit);
    enc.do_update_aad(aad).expect("AAD before any plaintext");
    let mut out = Vec::new();
    for piece in plaintext.chunks(7) {
        let mut buf = vec![0u8; enc.do_encrypt_out_len(piece.len())];
        let n = enc.do_encrypt_out(piece, &mut buf).expect("GCM never fails mid-stream");
        out.extend_from_slice(&buf[..n]);
    }
    out
}

#[test]
fn gcm_streams_through_a_trait_object() {
    let key = key_material();
    let mut rng = FixedSeedRNG::<12>::new([9u8; 12]);
    let (mut enc, nonce) = AES_GCM_128::<Encrypting>::do_encrypt_init_rng(&key, &mut rng).unwrap();

    let mut ct = aad_and_stream_through(&mut enc, b"header", MSG);
    let (last, n) = enc.do_encrypt_final().unwrap();
    ct.extend_from_slice(&last[..n]);

    assert_eq!(
        AES_GCM_128::<Decrypting>::decrypt_with_aad(&key, &nonce, b"header", &ct).unwrap(),
        MSG
    );
    assert!(
        AES_GCM_128::<Decrypting>::decrypt_with_aad(&key, &nonce, b"other", &ct).is_err(),
        "the AAD was bound"
    );
}
