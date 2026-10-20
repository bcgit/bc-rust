//! ChaCha20 and ChaCha20-Poly1305 are different algorithms over the same 32-byte key, and a key
//! bound to one is refused by the other: through the streaming inits, the supplied-nonce
//! constructor, the one-shots, and resuming a suspended state. An unbound key is still accepted by
//! both, since binding is opt-in. The shared framework checks each cipher against a name no cipher
//! has; this pins the case between the AEAD and the keystream it is built on.

use bouncycastle_chacha20::ChaCha20;
use bouncycastle_chacha20::hazmat::ChaCha20KeyStream;
use bouncycastle_chacha20_poly1305_aead::ChaCha20_Poly1305;
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, SuspendableKeyed,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

type Enc = ChaCha20_Poly1305<Encrypting>;
type Dec = ChaCha20_Poly1305<Decrypting>;
type StreamEnc = ChaCha20<Encrypting>;
type StreamDec = ChaCha20<Decrypting>;

const NONCE: [u8; 12] = [3; 12];

fn key() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap()
}

fn bound(alg_name: &'static str) -> KeyMaterial<32> {
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

/// The names a caller binds a key to; both directions of each cipher share one.
#[test]
fn the_two_algorithms_have_distinct_names() {
    assert_eq!(Enc::ALG_NAME, "ChaCha20-Poly1305");
    assert_eq!(Dec::ALG_NAME, Enc::ALG_NAME);
    assert_eq!(StreamEnc::ALG_NAME, "ChaCha20");
    assert_eq!(StreamDec::ALG_NAME, StreamEnc::ALG_NAME);
}

#[test]
fn an_aead_key_is_refused_by_chacha20() {
    let aead_key = bound(Enc::ALG_NAME);

    // The AEAD takes it, in both directions.
    let mut sealed = [0u8; 5 + 16];
    let written =
        Enc::encrypt_with_aad_nonce_out(&aead_key, &NONCE, b"aad", b"hello", &mut sealed).unwrap();
    let mut opened = [0u8; 5];
    let n = Dec::decrypt_with_aad_out(&aead_key, &NONCE, b"aad", &sealed[..written], &mut opened)
        .unwrap();
    assert_eq!(&opened[..n], b"hello");
    Enc::do_encrypt_init(&aead_key).unwrap();

    // ChaCha20 does not: block 0 of its keystream under this key and nonce is the AEAD's one-time
    // Poly1305 key.
    assert_refused(StreamEnc::do_encrypt_init(&aead_key));
    assert_refused(StreamDec::do_decrypt_init(&aead_key, &NONCE));
    assert_refused(ChaCha20KeyStream::new(&aead_key, &NONCE));
}

#[test]
fn a_chacha20_key_is_refused_by_every_aead_constructor() {
    let stream_key = bound(StreamEnc::ALG_NAME);
    StreamEnc::do_encrypt_init(&stream_key).unwrap();

    assert_refused(Enc::do_encrypt_init(&stream_key));
    assert_refused(Enc::do_encrypt_init_nonce(&stream_key, &NONCE));
    assert_refused(Dec::do_decrypt_init(&stream_key, &NONCE));
    assert_refused(Enc::encrypt_detached_nonce_out(&stream_key, &NONCE, b"", b"msg", &mut [0; 3]));
    let mut plaintext = [0xa5; 3];
    assert_refused(Dec::decrypt_detached_out(
        &stream_key, &NONCE, b"", &[0; 3], &[0; 16], &mut plaintext,
    ));
    assert_eq!(plaintext, [0; 3]);
}

#[test]
fn an_unbound_key_is_accepted_by_both() {
    let key = key();
    assert_eq!(key.algorithm(), None);
    Enc::do_encrypt_init_nonce(&key, &NONCE).unwrap();
    Dec::do_decrypt_init(&key, &NONCE).unwrap();
    StreamEnc::do_encrypt_init(&key).unwrap();
    StreamDec::do_decrypt_init(&key, &NONCE).unwrap();
}

#[test]
fn a_chacha20_state_does_not_resume_under_an_aead_key() {
    let stream_key = bound(StreamEnc::ALG_NAME);
    let (enc, _nonce) = StreamEnc::do_encrypt_init(&stream_key).unwrap();
    let state: [u8; StreamEnc::SUSPENDED_STATE_LEN] = enc.suspend();

    StreamEnc::from_suspended(state, &stream_key).unwrap();
    assert_eq!(
        StreamEnc::from_suspended(state, &bound(Enc::ALG_NAME)).err(),
        Some(SuspendableError::InvalidData)
    );
}
