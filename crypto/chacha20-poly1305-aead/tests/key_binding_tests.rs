//! ChaCha20 and ChaCha20-Poly1305 are different algorithms over the same 32-byte key, and material
//! bound to one is refused by the other's key object, which is the only way to either cipher and
//! so covers every constructor and one-shot. An unbound key is still accepted by both, since
//! binding is opt-in. The construction suite checks each key against a name no cipher has; this
//! pins the case between the AEAD and the keystream it is built on.

use bouncycastle_chacha20::{ChaCha20, ChaCha20Key};
use bouncycastle_chacha20_poly1305_aead::{ChaCha20_Poly1305, ChaCha20Poly1305Key};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::Algorithm;

type Enc<'k> = ChaCha20_Poly1305<'k, Encrypting>;
type Dec<'k> = ChaCha20_Poly1305<'k, Decrypting>;
type StreamEnc<'k> = ChaCha20<'k, Encrypting>;
type StreamDec<'k> = ChaCha20<'k, Decrypting>;

const NONCE: [u8; 12] = [3; 12];

fn material() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap()
}

fn bound(alg_name: &'static str) -> KeyMaterial<32> {
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
    let aead_material = bound(Enc::ALG_NAME);

    // The AEAD takes it, in both directions.
    let key = ChaCha20Poly1305Key::from_key_material(&aead_material).unwrap();
    let mut sealed = [0u8; 5 + 16];
    let written = key.encrypt_with_aad_nonce_out(&NONCE, b"aad", b"hello", &mut sealed).unwrap();
    let mut opened = [0u8; 5];
    let n = key.decrypt_with_aad_out(&NONCE, b"aad", &sealed[..written], &mut opened).unwrap();
    assert_eq!(&opened[..n], b"hello");

    // ChaCha20 does not: block 0 of its keystream under this key and nonce is the AEAD's one-time
    // Poly1305 key.
    assert_refused(ChaCha20Key::from_key_material(&aead_material));
}

#[test]
fn a_chacha20_key_is_refused_by_the_aead() {
    let stream_material = bound(StreamEnc::ALG_NAME);
    ChaCha20Key::from_key_material(&stream_material).unwrap();
    assert_refused(ChaCha20Poly1305Key::from_key_material(&stream_material));
}

#[test]
fn an_unbound_key_is_accepted_by_both() {
    let material = material();
    assert_eq!(material.algorithm(), None);
    let aead = ChaCha20Poly1305Key::from_key_material(&material).unwrap();
    aead.create_encryptor_nonce(&NONCE);
    aead.create_decryptor(&NONCE);
    ChaCha20Key::from_key_material(&material).unwrap();
}
