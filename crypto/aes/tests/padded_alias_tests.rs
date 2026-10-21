//! Tests for the padded AES-CBC and AES-ECB aliases.
//!
//! The aliases are only type aliases, so what is worth testing is that both parameters actually
//! select: the direction picks the encryptor or the decryptor, and the padding scheme changes the
//! behaviour rather than being decorative. The mode and the padding layer are tested in their own
//! crates; this checks the wiring between them. Which type each alias resolves to is pinned in
//! `alias_tests.rs`.

use bouncycastle_aes::hazmat::{AES_ECB_128, AES_ECB_192, AES_ECB_256};
use bouncycastle_aes::{AES_CBC_128, AES_CBC_192, AES_CBC_256};
use bouncycastle_cipher::padding::{NoPadding, PKCS7};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{SymmetricCipherDecryptor, SymmetricCipherEncryptor};

fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// Every key length round-trips through its alias, at lengths that need padding and lengths that
/// do not.
#[test]
fn every_key_length_round_trips() {
    fn check<const N: usize, const IV_LEN: usize, Enc, Dec>(name: &str)
    where
        Enc: SymmetricCipherEncryptor<N, IV_LEN, 16>,
        Dec: SymmetricCipherDecryptor<N, IV_LEN, 16>,
    {
        for len in [0usize, 1, 15, 16, 17, 63, 64] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 11 + 3) as u8).collect();
            let (iv, ciphertext) = Enc::encrypt(&key::<N>(), &plaintext).expect("encryption");

            // PKCS#7 always adds at least one byte, and rounds up to a whole block.
            assert_eq!(
                ciphertext.len(),
                (len / 16 + 1) * 16,
                "{name}, len {len}: PKCS7 pads up to the next whole block"
            );

            let recovered = Dec::decrypt(&key::<N>(), &iv, &ciphertext).expect("decryption");
            assert_eq!(recovered, plaintext, "{name}, len {len}: round trip");
        }
    }

    check::<16, 16, AES_CBC_128<Encrypting, PKCS7>, AES_CBC_128<Decrypting, PKCS7>>("CBC-128");
    check::<24, 16, AES_CBC_192<Encrypting, PKCS7>, AES_CBC_192<Decrypting, PKCS7>>("CBC-192");
    check::<32, 16, AES_CBC_256<Encrypting, PKCS7>, AES_CBC_256<Decrypting, PKCS7>>("CBC-256");
    check::<16, 0, AES_ECB_128<Encrypting, PKCS7>, AES_ECB_128<Decrypting, PKCS7>>("ECB-128");
    check::<24, 0, AES_ECB_192<Encrypting, PKCS7>, AES_ECB_192<Decrypting, PKCS7>>("ECB-192");
    check::<32, 0, AES_ECB_256<Encrypting, PKCS7>, AES_ECB_256<Decrypting, PKCS7>>("ECB-256");
}

/// The padding parameter must actually select the scheme, not merely be carried around.
///
/// `PKCS7` accepts any length and always grows the message; `NoPadding` accepts only whole blocks
/// and never grows it. Checking both against the same alias, key and plaintext is what proves the
/// parameter reaches the behaviour.
#[test]
fn the_padding_parameter_selects_the_scheme() {
    fn check<const IV_LEN: usize, Pkcs7Enc, NoPadEnc>(name: &str)
    where
        Pkcs7Enc: SymmetricCipherEncryptor<16, IV_LEN, 16>,
        NoPadEnc: SymmetricCipherEncryptor<16, IV_LEN, 16>,
    {
        // A whole block: both schemes accept it, and they disagree about the length.
        let aligned = [0x5Au8; 16];
        let (_, pkcs7) = Pkcs7Enc::encrypt(&key::<16>(), &aligned).expect("PKCS7 accepts it");
        let (_, nopad) = NoPadEnc::encrypt(&key::<16>(), &aligned).expect("NoPadding accepts it");
        assert_eq!(pkcs7.len(), 32, "{name}: PKCS7 adds a whole block of padding to aligned data");
        assert_eq!(nopad.len(), 16, "{name}: NoPadding adds nothing");

        // Five bytes: PKCS7 pads it, NoPadding refuses rather than silently padding.
        let unaligned = b"hello";
        assert!(Pkcs7Enc::encrypt(&key::<16>(), unaligned).is_ok(), "{name}: PKCS7 pads it");
        assert!(
            NoPadEnc::encrypt(&key::<16>(), unaligned).is_err(),
            "{name}: NoPadding must refuse a message that is not a whole number of blocks"
        );
    }

    check::<16, AES_CBC_128<Encrypting, PKCS7>, AES_CBC_128<Encrypting, NoPadding>>("CBC");
    check::<0, AES_ECB_128<Encrypting, PKCS7>, AES_ECB_128<Encrypting, NoPadding>>("ECB");
}

/// A ciphertext made under one scheme must not decrypt cleanly under the other.
///
/// This is the practical reason the scheme is named in the type: the two are not interchangeable,
/// and without the type parameter nothing would stop a caller pairing them.
#[test]
fn the_two_schemes_are_not_interchangeable() {
    let aligned = [0x5Au8; 16];
    let (iv, pkcs7) =
        AES_CBC_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), &aligned).expect("encryption");

    // NoPadding will hand back the padded block as if it were data, so it "succeeds" with the
    // wrong answer -- exactly the silent mismatch the type parameter is there to prevent.
    let as_nopad = AES_CBC_128::<Decrypting, NoPadding>::decrypt(&key::<16>(), &iv, &pkcs7)
        .expect("NoPadding cannot tell that the trailing block is padding");
    assert_ne!(as_nopad, aligned, "the recovered data must not match the original");
    assert_eq!(as_nopad.len(), 32, "it keeps the padding block as data");

    // ...and the matching scheme gets it right.
    let correct =
        AES_CBC_128::<Decrypting, PKCS7>::decrypt(&key::<16>(), &iv, &pkcs7).expect("decryption");
    assert_eq!(correct, aligned);
}

/// The IV is generated per encryption, so the same plaintext gives different ciphertext.
#[test]
fn each_cbc_encryption_gets_a_fresh_iv() {
    let plaintext = [0x77u8; 32];
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let (iv, ct) = AES_CBC_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), &plaintext).unwrap();
        assert!(seen.insert(iv), "IV repeated across encryptions");
        let back = AES_CBC_128::<Decrypting, PKCS7>::decrypt(&key::<16>(), &iv, &ct).unwrap();
        assert_eq!(back, plaintext);
    }
}

/// ECB has no IV, so the init data is an empty array and the ciphertext is exactly the padded
/// plaintext with nothing prepended. That is the difference from the CBC aliases, and it comes from
/// the `INIT_DATA_LEN = 0` the projection is given.
#[test]
fn ecb_has_no_iv() {
    let (no_iv, ciphertext) =
        AES_ECB_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), b"hello").expect("encryption");
    assert_eq!(no_iv, [0u8; 0], "ECB has no IV, so the init data is empty");
    assert_eq!(ciphertext.len(), 16, "five bytes padded to one block, nothing prepended");

    let recovered =
        AES_ECB_128::<Decrypting, PKCS7>::decrypt(&key::<16>(), &no_iv, &ciphertext).unwrap();
    assert_eq!(recovered, b"hello");
}

/// Padding does not fix ECB: identical plaintext blocks still give identical ciphertext blocks, and
/// the same message under the same key always gives the same ciphertext. The aliases carry the
/// warning; this is the test that it is warranted.
#[test]
fn padding_does_not_hide_the_ecb_codebook_property() {
    // Two identical blocks give two identical ciphertext blocks.
    let (_, ciphertext) =
        AES_ECB_128::<Encrypting, NoPadding>::encrypt(&key::<16>(), &[0x5Au8; 32]).unwrap();
    assert_eq!(ciphertext[..16], ciphertext[16..], "ECB is a codebook, padded or not");

    // ...and encryption is deterministic, there being no IV to vary.
    let (_, a) = AES_ECB_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), b"hello").unwrap();
    let (_, b) = AES_ECB_128::<Encrypting, PKCS7>::encrypt(&key::<16>(), b"hello").unwrap();
    assert_eq!(a, b, "the same message encrypts the same way every time");
}

/// The allocating streaming wrappers `do_encrypt` / `do_decrypt` return exactly what their `_out`
/// counterparts write -- `do_*_out_len` bytes, including none when a piece is wholly buffered or
/// held back -- and a message streamed through them round-trips.
#[test]
fn the_allocating_streaming_wrappers_match_the_out_versions() {
    type Enc = AES_CBC_128<Encrypting, PKCS7>;
    type Dec = AES_CBC_128<Decrypting, PKCS7>;

    let plaintext: Vec<u8> = (0u8..40).collect();
    // Piece lengths 5, 11, 1, 20, 0, 3: CBC releases a block only once it is full, so these
    // release 0, 16, 0, 16, 0, 0 bytes, leaving 8 buffered for `do_encrypt_final` to pad.
    let pieces = [0..5, 5..16, 16..17, 17..37, 37..37, 37..40];
    let expected_released = [0, 16, 0, 16, 0, 0];

    let (mut enc, iv) = Enc::do_encrypt_init(&key::<16>()).unwrap();
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
    assert_eq!(Dec::decrypt(&key::<16>(), &iv, &ciphertext).unwrap(), plaintext);

    // Decrypt the same ciphertext through `do_decrypt` in uneven pieces: the decryptor holds back
    // the block that might carry the padding, so some pieces release nothing.
    let mut dec = Dec::do_decrypt_init(&key::<16>(), &iv).unwrap();
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
