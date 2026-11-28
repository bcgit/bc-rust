//! `bouncycastle_symmetric::prelude` alone brings the methods of the calls below into scope: an AEAD, a
//! block mode, a stream cipher, a MAC and a key wrap are called below with no other trait
//! imported.

use bouncycastle_core::key_material::{KeyMaterial128, KeyMaterial256, KeyType};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_symmetric::aes::{AES128Key, AES256Key};
use bouncycastle_symmetric::chacha20::ChaCha20Key;
use bouncycastle_symmetric::modes::{CBC, CMAC, GCM, KW};
use bouncycastle_symmetric::padding::PKCS7;
use bouncycastle_symmetric::prelude::*;

fn material(key_type: KeyType) -> KeyMaterial128 {
    KeyMaterial128::from_bytes_as_type(&[0x42; 16], key_type).unwrap()
}

#[test]
fn aead() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let key = AES128Key::<GCM>::from_key_material(&material(KeyType::SymmetricCipherKey)).unwrap();

    // One-shots on the key.
    let mut ct = [0u8; 5 + 16];
    let (nonce, n) = key.encrypt_with_aad_out(&mut rng, b"aad", b"hello", &mut ct).unwrap();
    let mut pt = [0u8; 5 + 16];
    let m = key.decrypt_with_aad_out(&nonce, b"aad", &ct[..n], &mut pt).unwrap();
    assert_eq!(&pt[..m], b"hello");

    // The streaming workers.
    let mut enc = key.create_encryptor_nonce(&nonce);
    enc.do_update_aad(b"aad").unwrap();
    let mut streamed = [0u8; 5 + 16];
    let w = enc.do_encrypt_out(b"hello", &mut streamed).unwrap();
    let (tag, tag_len) = enc.do_encrypt_final().unwrap();
    streamed[w..w + tag_len].copy_from_slice(&tag[..tag_len]);
    assert_eq!(streamed, ct);

    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(b"aad").unwrap();
    let mut out = [0u8; 5 + 16];
    let r = dec.do_decrypt_out(&ct, &mut out).unwrap();
    let mut last = [0u8; 16];
    let l = dec.do_decrypt_final_out(&mut last).unwrap();
    out[r..r + l].copy_from_slice(&last[..l]);
    assert_eq!(&out[..r + l], b"hello");
}

#[test]
fn block_mode() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let key =
        AES128Key::<CBC<PKCS7>>::from_key_material(&material(KeyType::SymmetricCipherKey)).unwrap();
    let mut ct = [0u8; 32];
    let (iv, n) = key.encrypt_out(&mut rng, b"hello", &mut ct).unwrap();
    let mut pt = [0u8; 32];
    let m = key.decrypt_out(&iv, &ct[..n], &mut pt).unwrap();
    assert_eq!(&pt[..m], b"hello");
}

#[test]
fn stream_cipher() {
    let material =
        KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
    let key = ChaCha20Key::from_key_material(&material).unwrap();
    let mut message = *b"message";
    let (nonce, _) =
        key.encrypt_inplace(&mut HashDRBG_SHA512::new_from_os(), &mut message).unwrap();

    let mut dec = key.create_decryptor(&nonce);
    dec.seek_to(0).unwrap();
    dec.do_decrypt_inplace(&mut message).unwrap();
    assert_eq!(&message, b"message");
    assert_eq!(dec.position(), 7);
}

#[test]
fn mac() {
    let key = AES128Key::<CMAC>::from_key_material(&material(KeyType::MACKey)).unwrap();
    let mut generator = key.create_generator();
    generator.do_update(b"message");
    let mut tag = [0u8; 16];
    generator.do_final_out(&mut tag);
    assert_eq!(key.mac(b"message"), tag);
    assert!(key.verify(b"message", &tag).is_ok());
}

#[test]
fn key_wrap() {
    let kek = AES256Key::<KW>::from_key_material(
        &KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap(),
    )
    .unwrap();
    let key = [0x07u8; 16];
    let mut wrapped = [0u8; 24];
    assert_eq!(kek.wrap_out_len(16), 24);
    let n = kek.wrap_out(&key, &mut wrapped).unwrap();
    let mut unwrapped = [0u8; 24];
    let m = kek.unwrap_out(&wrapped[..n], &mut unwrapped).unwrap();
    assert_eq!(&unwrapped[..m], &key);
}
