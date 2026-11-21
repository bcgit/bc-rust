//! A worker lent out as a trait object for the streaming part of a job (issue #173): the owner
//! keeps the concrete encryptor, hands `&mut dyn ...` to code that only needs to feed it, and
//! finishes it itself. No allocation, no `Box`, and the key decrypts what came out.
//!
//! And a worker stored as `Box<dyn ...>` by code that does not name the cipher: it is fed through
//! the box and finished through the `_boxed` twin of its final, which consumes the box.

use bouncycastle_aes::AES128Key;
use bouncycastle_cipher::modes::{CBC, GCM};
use bouncycastle_cipher::padding::PKCS7;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey,
    SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};

const MSG: &[u8] = b"the quick brown fox jumps over the lazy dog, twice over, for two blocks";

fn key_material() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
        .expect("a 16-byte symmetric cipher key")
}

/// Feeds `plaintext` in 7-byte pieces through the trait object and returns the ciphertext so far.
fn stream_through(enc: &mut dyn SymmetricCipherEncryptor<16, 16>, plaintext: &[u8]) -> Vec<u8> {
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
    let key = AES128Key::<CBC<PKCS7>>::from_key_material(&key_material()).unwrap();
    let mut rng = FixedSeedRNG::new([7u8; 16]);
    let (mut enc, iv) = key.create_encryptor(&mut rng).unwrap();

    let mut ct = stream_through(&mut enc, MSG);
    // The final is the concrete value's: `do_encrypt_final` takes `self`.
    let (last, n) = enc.do_encrypt_final().unwrap();
    ct.extend_from_slice(&last[..n]);

    assert_eq!(key.decrypt(&iv, &ct).unwrap(), MSG);
}

/// The AAD and the plaintext go through the trait object; the tag comes from the concrete final.
fn aad_and_stream_through(
    enc: &mut dyn AEADCipherEncryptor<12, 16, 16>,
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
    let key = AES128Key::<GCM>::from_key_material(&key_material()).unwrap();
    let mut rng = FixedSeedRNG::new([9u8; 12]);
    let (mut enc, nonce) = key.create_encryptor(&mut rng).unwrap();

    let mut ct = aad_and_stream_through(&mut enc, b"header", MSG);
    let (last, n) = enc.do_encrypt_final().unwrap();
    ct.extend_from_slice(&last[..n]);

    assert_eq!(key.decrypt_with_aad(&nonce, b"header", &ct).unwrap(), MSG);
    assert!(key.decrypt_with_aad(&nonce, b"other", &ct).is_err(), "the AAD was bound");
}

/// A holder that keeps "the worker for this stream" across calls without being generic over the
/// cipher. `finish` takes the box out, so a second finish has nothing to call.
struct Session<'k> {
    enc: Option<Box<dyn SymmetricCipherEncryptor<16, 16> + 'k>>,
    dec: Option<Box<dyn SymmetricCipherDecryptor<16, 16> + 'k>>,
}

impl Session<'_> {
    fn encrypt(&mut self, piece: &[u8], out: &mut Vec<u8>) {
        let enc = self.enc.as_mut().expect("not finished");
        let mut buf = vec![0u8; enc.do_encrypt_out_len(piece.len())];
        let n = enc.do_encrypt_out(piece, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
    }
    fn finish_encrypt(&mut self, out: &mut Vec<u8>) {
        let (last, n) = self.enc.take().expect("not finished").do_encrypt_final_boxed().unwrap();
        out.extend_from_slice(&last[..n]);
    }
    fn decrypt(&mut self, piece: &[u8], out: &mut Vec<u8>) {
        let dec = self.dec.as_mut().expect("not finished");
        let mut buf = vec![0u8; dec.do_decrypt_out_len(piece.len())];
        let n = dec.do_decrypt_out(piece, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
    }
    fn finish_decrypt(&mut self, out: &mut Vec<u8>) -> Result<(), SymmetricCipherError> {
        let (last, n) = self.dec.take().expect("not finished").do_decrypt_final_boxed()?;
        out.extend_from_slice(&last[..n]);
        Ok(())
    }
}

#[test]
fn cbc_stored_as_a_box_finishes_through_the_boxed_final() {
    let key = AES128Key::<CBC<PKCS7>>::from_key_material(&key_material()).unwrap();
    let (enc, iv) = key.create_encryptor(&mut FixedSeedRNG::new([7u8; 16])).unwrap();
    let mut session =
        Session { enc: Some(Box::new(enc)), dec: Some(Box::new(key.create_decryptor(&iv))) };

    let mut ct = Vec::new();
    MSG.chunks(7).for_each(|piece| session.encrypt(piece, &mut ct));
    session.finish_encrypt(&mut ct);
    assert!(session.enc.is_none(), "the final consumed the box");
    // The same bytes as the concrete worker's, so the padded last block was not lost.
    let (_, expected) = key.encrypt(&mut FixedSeedRNG::new([7u8; 16]), MSG).unwrap();
    assert_eq!(ct, expected);

    let mut pt = Vec::new();
    ct.chunks(5).for_each(|piece| session.decrypt(piece, &mut pt));
    session.finish_decrypt(&mut pt).unwrap();
    assert_eq!(pt, MSG);

    // A damaged last block is refused through the box as it is on the concrete value.
    let mut session = Session { enc: None, dec: Some(Box::new(key.create_decryptor(&iv))) };
    *ct.last_mut().unwrap() ^= 0x80;
    let mut pt = Vec::new();
    session.decrypt(&ct, &mut pt);
    assert!(session.finish_decrypt(&mut pt).is_err());
}

#[test]
fn gcm_stored_as_a_box_finishes_through_the_boxed_finals() {
    let key = AES128Key::<GCM>::from_key_material(&key_material()).unwrap();

    // Tag inline, through the base trait's twin: the tag is the final's output.
    let (enc, nonce) = key.create_encryptor(&mut FixedSeedRNG::new([9u8; 12])).unwrap();
    let mut enc: Box<dyn AEADCipherEncryptor<12, 16, 16> + '_> = Box::new(enc);
    let mut ct = aad_and_stream_through(enc.as_mut(), b"header", MSG);
    let (last, n) = enc.do_encrypt_final_boxed().unwrap();
    ct.extend_from_slice(&last[..n]);
    assert_eq!(key.decrypt_with_aad(&nonce, b"header", &ct).unwrap(), MSG);

    // Tag detached, through the AEAD twin.
    let (enc, nonce) = key.create_encryptor(&mut FixedSeedRNG::new([9u8; 12])).unwrap();
    let mut enc: Box<dyn AEADCipherEncryptor<12, 16, 16> + '_> = Box::new(enc);
    let mut ct = aad_and_stream_through(enc.as_mut(), b"header", MSG);
    let mut last = [0u8; 16];
    let (n, tag) = enc.do_encrypt_final_detached_out_boxed(&mut last).unwrap();
    ct.extend_from_slice(&last[..n]);
    assert_eq!(key.decrypt_detached(&nonce, b"header", &ct, &tag).unwrap(), MSG);

    // The decryptor, boxed: the right tag releases the held-back bytes, a wrong one is refused.
    let boxed_decryptor = |aad: &[u8]| {
        let mut dec: Box<dyn AEADCipherDecryptor<12, 16, 16> + '_> =
            Box::new(key.create_decryptor(&nonce));
        dec.do_update_aad(aad).unwrap();
        let mut pt = vec![0u8; dec.do_decrypt_out_len(ct.len())];
        let n = dec.do_decrypt_out(&ct, &mut pt).unwrap();
        pt.truncate(n);
        (dec, pt)
    };
    let (dec, mut pt) = boxed_decryptor(b"header");
    let mut last = [0u8; 16];
    let n = dec.do_decrypt_final_detached_out_boxed(&tag, &mut last).unwrap();
    pt.extend_from_slice(&last[..n]);
    assert_eq!(pt, MSG);
    let (dec, _) = boxed_decryptor(b"other");
    assert!(matches!(
        dec.do_decrypt_final_detached_out_boxed(&tag, &mut last),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
}
