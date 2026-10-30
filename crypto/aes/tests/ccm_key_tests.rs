//! The mode-bound CCM key: the declared-length role traits, whose constructors take the AAD and payload
//! lengths, their one-shots at any length, and agreement with the generic-trait pair.
//!
//! Only the worker traits are in scope here, since the pair's cipher-trait methods share their
//! names.

use bouncycastle_aes::hazmat::AES128Internal;
use bouncycastle_aes::{AES128Key, AES192Key};
use bouncycastle_cipher::modes::CCM;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{AeadDeclaredEncryptMode, ElectronicCodeBook};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, FromKeyMaterial,
};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn rng() -> FixedSeedRNG<12> {
    FixedSeedRNG::<12>::new([0x24u8; 12])
}

const AAD: &[u8] = b"header, sent in the clear";
const LENS: [usize; 9] = [0, 1, 15, 16, 63, 64, 65, 200, 1000];

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

/// The mode's in-place `_nonce` one-shot over the bare permutation (the hazmat mode-trait
/// route), the reference for every form below.
fn reference(km: &KeyMaterial<16>, nonce: &[u8; 12], msg: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let perm = AES128Internal::new(km).unwrap();
    let mut ct = msg.to_vec();
    let tag = CCM::<12, 16>::encrypt_detached_in_place_nonce(&perm, nonce, AAD, &mut ct).unwrap();
    (ct, tag)
}

/// Every form on the key -- in place, `_out`, allocating, drawing and supplied-nonce, and the
/// streams -- takes any length and agrees with the pair byte for byte.
#[test]
fn every_form_takes_any_length_and_agrees_with_the_pair() {
    let km = material::<16>();
    let key = AES128Key::<CCM<12, 16>>::from_key_material(&km).unwrap();

    for len in LENS {
        let msg = message(len);
        let (nonce, ct, tag) = key.encrypt_detached(&mut rng(), AAD, &msg).unwrap();
        assert_eq!(reference(&km, &nonce, &msg), (ct.clone(), tag), "len {len}");

        let mut buf = msg.clone();
        assert_eq!(key.encrypt_detached_in_place_nonce(&nonce, AAD, &mut buf).unwrap(), tag);
        assert_eq!(buf, ct, "len {len}: in place");
        key.decrypt_detached_in_place(&nonce, AAD, &mut buf, &tag).unwrap();
        assert_eq!(buf, msg, "len {len}: in place round trip");

        let inline = key.encrypt_with_aad_nonce(&nonce, AAD, &msg).unwrap();
        assert_eq!((&inline[..len], &inline[len..]), (&ct[..], &tag[..]), "len {len}: inline");
        assert_eq!(key.decrypt_with_aad(&nonce, AAD, &inline).unwrap(), msg);
        assert_eq!(key.decrypt_detached(&nonce, AAD, &ct, &tag).unwrap(), msg);

        // The streams, chunked, agree too: the lengths were declared, so nothing is held back.
        let mut enc = key.create_encryptor_nonce(&nonce, AAD.len(), len).unwrap();
        enc.do_update_aad(&AAD[..5]).unwrap();
        enc.do_update_aad(&AAD[5..]).unwrap();
        let mut streamed = vec![0u8; len];
        let mut written = 0;
        for piece in msg.chunks(7) {
            assert_eq!(enc.do_encrypt_out_len(piece.len()), piece.len());
            written += enc.do_encrypt_out(piece, &mut streamed[written..]).unwrap();
        }
        let mut last = [0u8; 16];
        let (n, streamed_tag) = enc.do_encrypt_final_detached_out(&mut last).unwrap();
        assert_eq!((n, streamed, streamed_tag), (0, ct.clone(), tag), "len {len}: streamed");

        let mut dec = key.create_decryptor(&nonce, AAD.len(), len).unwrap();
        dec.do_update_aad(AAD).unwrap();
        let mut opened = vec![0u8; len];
        let mut written = 0;
        for piece in inline.chunks(5) {
            written += dec.do_decrypt_out(piece, &mut opened[written..]).unwrap();
        }
        assert_eq!(written, len, "len {len}: the payload is released, the tag held");
        assert_eq!(dec.do_decrypt_final().unwrap().1, 0);
        assert_eq!(opened, msg, "len {len}: streamed round trip");
    }
}

/// The streams hold to the declared lengths: more AAD or payload than declared is refused, a
/// final before the payload is complete is refused, and the inline final needs a whole tag.
#[test]
fn the_streams_hold_to_the_declared_lengths() {
    let key = AES128Key::<CCM<12, 16>>::from_key_material(&material::<16>()).unwrap();
    let nonce = [0x24u8; 12];

    let mut enc = key.create_encryptor_nonce(&nonce, 4, 8).unwrap();
    assert!(matches!(enc.do_update_aad(&[0u8; 5]), Err(SymmetricCipherError::StateError(_))));
    enc.do_update_aad(&[0u8; 4]).unwrap();
    let mut out = [0u8; 9];
    assert!(matches!(
        enc.do_encrypt_out(&[0u8; 9], &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    enc.do_encrypt_out(&[0u8; 4], &mut out).unwrap();
    assert!(matches!(enc.do_encrypt_final(), Err(SymmetricCipherError::StateError(_))));

    let mut dec = key.create_decryptor(&nonce, 0, 8).unwrap();
    let mut out = [0u8; 8];
    assert!(matches!(
        dec.do_decrypt_out(&[0u8; 8 + 16 + 1], &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    dec.do_decrypt_out(&[0u8; 8 + 15], &mut out).unwrap();
    assert!(matches!(dec.do_decrypt_final(), Err(SymmetricCipherError::DecryptionFailed)));
    let mut dec = key.create_decryptor(&nonce, 0, 8).unwrap();
    dec.do_decrypt_out(&[0u8; 8 + 1], &mut out).unwrap();
    let mut last = [0u8; 16];
    assert!(matches!(
        dec.do_decrypt_final_detached_out(&[0u8; 16], &mut last),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
}

/// A.1's payload limit is refused at construction, and an inline ciphertext too short for a tag
/// is malformed before anything is built.
#[test]
fn lengths_the_mode_cannot_encode_are_refused_up_front() {
    let key = AES128Key::<CCM<13, 8>>::from_key_material(&material::<16>()).unwrap();
    let nonce = [0x24u8; 13];
    assert!(key.create_encryptor_nonce(&nonce, 0, 65535).is_ok());
    assert!(matches!(
        key.create_encryptor_nonce(&nonce, 0, 65536),
        Err(SymmetricCipherError::GenericError(_))
    ));
    let mut out = [0u8; 8];
    assert!(matches!(
        key.decrypt_with_aad_out(&nonce, &[], &[0u8; 7], &mut out),
        Err(SymmetricCipherError::DecryptionFailed)
    ));
}

/// A failed tag check leaves zeros in the caller's buffer, since the plaintext was written there
/// before the tag could be checked.
#[test]
fn a_bad_tag_or_aad_zeroizes_the_buffer() {
    let key = AES192Key::<CCM<12, 16>>::from_key_material(&material::<24>()).unwrap();
    let msg = message(200);
    let mut buf = msg.clone();
    let (nonce, mut tag) = key.encrypt_detached_in_place(&mut rng(), AAD, &mut buf).unwrap();
    let ct = buf.clone();
    assert!(matches!(
        key.decrypt_detached_in_place(&nonce, b"other aad", &mut buf, &tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert!(buf.iter().all(|&b| b == 0));
    tag[0] ^= 1;
    let mut buf = ct;
    assert!(matches!(
        key.decrypt_detached_in_place(&nonce, AAD, &mut buf, &tag),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert!(buf.iter().all(|&b| b == 0));
}

/// A nonce below the 12-byte floor for drawn nonces is reachable through the supplied-nonce
/// forms at any A.1 length, while the drawing forms are never instantiated for it.
#[test]
fn a_short_nonce_is_reachable_through_the_supplied_nonce_forms() {
    let km = material::<16>();
    let key = AES128Key::<CCM<8, 8>>::from_key_material(&km).unwrap();
    let nonce = [0xA5u8; 8];
    let msg = message(100);
    let mut buf = msg.clone();
    let tag = key.encrypt_detached_in_place_nonce(&nonce, AAD, &mut buf).unwrap();
    let (ct, tag_p) = {
        let perm = AES128Internal::new(&km).unwrap();
        let mut ct = msg.clone();
        let t = CCM::<8, 8>::encrypt_detached_in_place_nonce(&perm, &nonce, AAD, &mut ct).unwrap();
        (ct, t)
    };
    assert_eq!((ct, tag_p), (buf.clone(), tag));
    key.decrypt_detached_in_place(&nonce, AAD, &mut buf, &tag).unwrap();
    assert_eq!(buf, msg);
}

/// The workers are the mode's `Ccm` state over a borrowed schedule, 96 B at every key length,
/// with the decryptor adding the tag it holds back and that tag's length; the aes docs quote
/// these.
#[test]
fn worker_sizes_match_the_documented_memory_table() {
    use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
    use bouncycastle_cipher::modes::{CcmDecryptor, CcmEncryptor};
    use core::mem::size_of;
    assert_eq!(size_of::<CcmEncryptor<'_, AES128Internal, 12, 16>>(), 96);
    assert_eq!(size_of::<CcmEncryptor<'_, AES192Internal, 12, 16>>(), 96);
    assert_eq!(size_of::<CcmEncryptor<'_, AES256Internal, 12, 16>>(), 96);
    assert_eq!(size_of::<CcmDecryptor<'_, AES128Internal, 12, 16>>(), 120);
    assert_eq!(size_of::<CcmDecryptor<'_, AES192Internal, 12, 16>>(), 120);
    assert_eq!(size_of::<CcmDecryptor<'_, AES256Internal, 12, 16>>(), 120);
}

/// A refused `do_encrypt_out` / `do_decrypt_out` leaves nothing of the input in the caller's
/// buffer, and zeroes the buffer first as every `_out` method must: payload offered while declared
/// AAD is still owed, and payload past the declared length, on both sides.
#[test]
fn a_refused_update_leaves_no_payload_in_the_output_buffer() {
    use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};

    let key = AES128Key::<CCM<12, 16>>::from_key_material(&material::<16>()).unwrap();
    let nonce = [0x11u8; 12];
    let payload = [0x5Au8; 16];

    // AAD still owed: the four bytes declared have not been supplied.
    let mut enc = key.create_encryptor_nonce(&nonce, 4, 16).unwrap();
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        enc.do_encrypt_out(&payload, &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0u8; 32], "a refused encrypt must leave only zeros behind");

    // Past the declared payload length.
    let mut enc = key.create_encryptor_nonce(&nonce, 0, 8).unwrap();
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        enc.do_encrypt_out(&payload, &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0u8; 32], "an over-length encrypt must leave only zeros behind");

    // The decryptor, with AAD still owed: the sixteen bytes are within the declared payload, so
    // they are not held back as a tag, and must not be copied either.
    let mut dec = key.create_decryptor(&nonce, 4, 16).unwrap();
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        dec.do_decrypt_out(&payload, &mut out),
        Err(SymmetricCipherError::StateError(_))
    ));
    assert_eq!(out, [0u8; 32], "a refused decrypt must leave only zeros behind");
}
