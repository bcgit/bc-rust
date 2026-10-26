//! The CBC and ECB aliases with their padding parameter.
//!
//! The aliases are only type aliases, so what is worth testing is that both parameters actually
//! select: the direction picks the encryptor or the decryptor, and the padding scheme changes the
//! behaviour rather than being decorative. The mode and the padding layer are tested in their own
//! crates; this checks the wiring between them, through the keys that hand the aliases out. Which
//! type each alias resolves to is pinned in `alg_name_tests.rs`.

use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::CBC;
use bouncycastle_cipher::modes::hazmat::ecb::ECB;
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};
use bouncycastle_rng::HashDRBG_SHA512;

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn key_for<const N: usize, K: FromKeyMaterial<N>>() -> K {
    K::from_key_material(&material::<N>()).expect("a valid key")
}

fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

#[test]
fn every_key_length_round_trips() {
    fn check<const N: usize, const IV_LEN: usize, K>(name: &str)
    where
        K: FromKeyMaterial<N>
            + SymmetricEncryptionKey<N, IV_LEN, 16>
            + SymmetricDecryptionKey<N, IV_LEN, 16>,
    {
        let key = key_for::<N, K>();
        for len in [0usize, 1, 15, 16, 17, 63, 64] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
            let (iv, ciphertext) = key.encrypt(&mut rng(), &plaintext).expect("encryption");

            // PKCS#7 always adds at least one byte, and rounds up to a whole block.
            assert_eq!(
                ciphertext.len(),
                (len / 16 + 1) * 16,
                "{name}, len {len}: PKCS7 pads up to the next whole block"
            );

            let recovered = key.decrypt(&iv, &ciphertext).expect("decryption");
            assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, 16, AES128Key<CBC<PKCS7>>>("CBC-128");
    check::<24, 16, AES192Key<CBC<PKCS7>>>("CBC-192");
    check::<32, 16, AES256Key<CBC<PKCS7>>>("CBC-256");
    check::<16, 0, AES128Key<ECB<PKCS7>>>("ECB-128");
    check::<24, 0, AES192Key<ECB<PKCS7>>>("ECB-192");
    check::<32, 0, AES256Key<ECB<PKCS7>>>("ECB-256");
}

#[test]
fn the_padding_parameter_selects_the_scheme() {
    fn check<const IV_LEN: usize, Pkcs7Key, NoPadKey>(name: &str)
    where
        Pkcs7Key: FromKeyMaterial<16> + SymmetricEncryptionKey<16, IV_LEN, 16>,
        NoPadKey: FromKeyMaterial<16> + SymmetricEncryptionKey<16, IV_LEN, 16>,
    {
        let pkcs7_key = key_for::<16, Pkcs7Key>();
        let nopad_key = key_for::<16, NoPadKey>();

        // A whole block: both schemes accept it, and they disagree about the length.
        let aligned = [0x5Au8; 16];
        let (_, pkcs7) = pkcs7_key.encrypt(&mut rng(), &aligned).expect("PKCS7 accepts it");
        let (_, nopad) = nopad_key.encrypt(&mut rng(), &aligned).expect("NoPadding accepts it");
        assert_eq!(pkcs7.len(), 32, "{name}: PKCS7 adds a whole block of padding to aligned data");
        assert_eq!(nopad.len(), 16, "{name}: NoPadding adds nothing");

        // Five bytes: PKCS7 pads it, NoPadding refuses rather than silently padding.
        let unaligned = b"hello";
        assert!(pkcs7_key.encrypt(&mut rng(), unaligned).is_ok(), "{name}: PKCS7 pads it");
        assert!(
            nopad_key.encrypt(&mut rng(), unaligned).is_err(),
            "{name}: NoPadding must refuse a message that is not a whole number of blocks"
        );
    }

    check::<16, AES128Key<CBC<PKCS7>>, AES128Key<CBC<NoPadding>>>("CBC");
    check::<0, AES128Key<ECB<PKCS7>>, AES128Key<ECB<NoPadding>>>("ECB");
}

#[test]
fn the_two_schemes_are_not_interchangeable() {
    let aligned = [0x5Au8; 16];
    let (iv, pkcs7) =
        key_for::<16, AES128Key<CBC<PKCS7>>>().encrypt(&mut rng(), &aligned).expect("encryption");

    // NoPadding will hand back the padded block as if it were data, so it "succeeds" with the
    // wrong answer -- exactly the silent mismatch the type parameter is there to prevent.
    let as_nopad = key_for::<16, AES128Key<CBC<NoPadding>>>()
        .decrypt(&iv, &pkcs7)
        .expect("NoPadding cannot tell that the trailing block is padding");
    assert_ne!(as_nopad, aligned, "the recovered data must not match the original");
    assert_eq!(as_nopad.len(), 32, "it keeps the padding block as data");

    // ...and the matching scheme gets it right.
    let correct = key_for::<16, AES128Key<CBC<PKCS7>>>().decrypt(&iv, &pkcs7).expect("decryption");
    assert_eq!(correct, aligned);
}

#[test]
fn each_cbc_encryption_gets_a_fresh_iv() {
    let key = key_for::<16, AES128Key<CBC<PKCS7>>>();
    let mut rng = rng();
    let plaintext = [0x77u8; 32];
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (iv, ct) = key.encrypt(&mut rng, &plaintext).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions");
        let back = key.decrypt(&iv, &ct).unwrap();
        assert_eq!(back, plaintext);
    }
}

#[test]
fn ecb_has_no_iv() {
    let key = key_for::<16, AES128Key<ECB<PKCS7>>>();
    let (no_iv, ciphertext) = key.encrypt(&mut rng(), b"hello").expect("encryption");
    assert_eq!(no_iv, [0u8; 0], "ECB has no IV, so the init data is empty");
    assert_eq!(ciphertext.len(), 16, "five bytes padded to one block, nothing prepended");

    let recovered = key.decrypt(&no_iv, &ciphertext).unwrap();
    assert_eq!(recovered, b"hello");
}

#[test]
fn padding_does_not_hide_the_ecb_codebook_property() {
    // Two identical blocks give two identical ciphertext blocks.
    let (_, ciphertext) =
        key_for::<16, AES128Key<ECB<NoPadding>>>().encrypt(&mut rng(), &[0x5Au8; 32]).unwrap();
    assert_eq!(ciphertext[..16], ciphertext[16..], "ECB is a codebook, padded or not");

    // ...and encryption is deterministic, there being no IV to vary.
    let key = key_for::<16, AES128Key<ECB<PKCS7>>>();
    let (_, a) = key.encrypt(&mut rng(), b"hello").unwrap();
    let (_, b) = key.encrypt(&mut rng(), b"hello").unwrap();
    assert_eq!(a, b, "the same message encrypts the same way every time");
}

#[test]
fn the_allocating_streaming_wrappers_match_the_out_versions() {
    let key = key_for::<16, AES128Key<CBC<PKCS7>>>();

    let plaintext: Vec<u8> = (0u8..40).collect();
    // Piece lengths 5, 11, 1, 20, 0, 3: CBC releases a block only once it is full, so these
    // release 0, 16, 0, 16, 0, 0 bytes, leaving 8 buffered for `do_encrypt_final` to pad.
    let pieces = [0..5, 5..16, 16..17, 17..37, 37..37, 37..40];
    let expected_released = [0, 16, 0, 16, 0, 0];

    let (mut enc, iv) = key.create_encryptor(&mut rng()).unwrap();
    let mut ciphertext = Vec::new();
    for (range, expected) in pieces.into_iter().zip(expected_released) {
        let piece = &plaintext[range];
        let mut via_out = vec![0u8; enc.do_encrypt_out_len(piece.len())];
        let n = enc.clone().do_encrypt_out(piece, &mut via_out).unwrap();
        assert_eq!(n, via_out.len());

        let released = enc.do_encrypt(piece).unwrap();
        assert_eq!(released.len(), expected, "piece of {} bytes", piece.len());
        assert_eq!(released, via_out, "do_encrypt must match do_encrypt_out");
        ciphertext.extend_from_slice(&released);
    }
    let (last, last_len) = enc.do_encrypt_final().unwrap();
    ciphertext.extend_from_slice(&last[..last_len]);
    assert_eq!(ciphertext.len(), 48);
    assert_eq!(key.decrypt(&iv, &ciphertext).unwrap(), plaintext);

    // Decrypt the same ciphertext through `do_decrypt` in uneven pieces: the decryptor holds back
    // the block that might carry the padding, so some pieces release nothing.
    let mut dec = key.create_decryptor(&iv);
    let mut recovered = Vec::new();
    let mut saw_empty = false;
    for range in [0..16, 16..17, 17..48] {
        let piece = &ciphertext[range];
        let mut via_out = vec![0u8; dec.do_decrypt_out_len(piece.len())];
        let n = dec.clone().do_decrypt_out(piece, &mut via_out).unwrap();
        assert_eq!(n, via_out.len());

        let released = dec.do_decrypt(piece).unwrap();
        assert_eq!(released, via_out, "do_decrypt must match do_decrypt_out");
        saw_empty |= released.is_empty();
        recovered.extend_from_slice(&released);
    }
    assert!(saw_empty, "the piece lengths must exercise the held-back case");
    let (last, data_len) = dec.do_decrypt_final().unwrap();
    recovered.extend_from_slice(&last[..data_len]);
    assert_eq!(recovered, plaintext);
}
