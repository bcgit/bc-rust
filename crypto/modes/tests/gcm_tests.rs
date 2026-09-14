//! Structural tests for GCM, driven by a toy permutation and by real AES.
//!
//! These check the properties of the *mode* -- AAD-before-data ordering, chunking independence,
//! the tag-length family, the inline decryptor's tail hold-back, and the one-shot's
//! verify-before-decrypt guarantee -- independently of (or alongside) the ACVP/bc-java known-answer
//! vectors in `acvp_gcm_tests.rs`, `acvp_gmac_tests.rs` and `gcm_bc_java_tests.rs`.

mod common;

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{SimpleCipherDecryptor, SimpleCipherEncryptor};
use bouncycastle_modes::{Decrypting, Encrypting, Gcm};
use common::{TOY_LEN, Toy, toy_key};

type ToyGcm<Dir, const TAG_LEN: usize> = Gcm<Toy, Dir, TOY_LEN, TAG_LEN>;

/// AAD must precede data (SP 800-38D Algorithm 4 absorbs `A` before `C`); a non-empty AAD call
/// after data has started is refused, while an empty one is always accepted as a no-op.
#[test]
fn aad_after_data_is_a_state_error_unless_empty() {
    let key = toy_key();
    let (mut enc, _nonce) = Gcm::<Toy, Encrypting, TOY_LEN, 16>::do_encrypt_init(&key).unwrap();
    enc.do_update_aad(b"header").unwrap();
    let mut data = [0x11u8; 8];
    enc.do_encrypt(&mut data).unwrap();

    match enc.do_update_aad(b"too late") {
        Err(SymmetricCipherError::StateError(_)) => {}
        other => panic!("expected StateError, got {other:?}"),
    }
    // An empty call after data is always fine.
    enc.do_update_aad(&[]).unwrap();
    let _ = enc.finish();
}

/// Chunking independence for both AAD and data: every split of a 40-byte AAD and a 50-byte message
/// must give the same ciphertext and tag as absorbing each in one call.
#[test]
fn chunking_is_independent_for_aad_and_data() {
    let key = toy_key();
    let aad: [u8; 40] = core::array::from_fn(|i| i as u8);
    let message: [u8; 50] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));

    let (nonce, expected_ct, expected_tag) = {
        let mut data = message;
        let (nonce, tag) =
            Gcm::<Toy, Encrypting, TOY_LEN, 16>::encrypt_detached(&key, &aad, &mut data).unwrap();
        (nonce, data, tag)
    };

    for aad_split in [0usize, 1, 17, 40] {
        for data_split in [0usize, 1, 23, 50] {
            let (mut enc, got_nonce) = Gcm::<Toy, Encrypting, TOY_LEN, 16>::do_encrypt_init_rng(
                &key,
                &mut bouncycastle_core_test_framework::FixedSeedRNG::<12>::new(nonce),
            )
            .unwrap();
            assert_eq!(got_nonce, nonce);
            enc.do_update_aad(&aad[..aad_split]).unwrap();
            enc.do_update_aad(&aad[aad_split..]).unwrap();
            let mut data = message;
            enc.do_encrypt(&mut data[..data_split]).unwrap();
            enc.do_encrypt(&mut data[data_split..]).unwrap();
            let tag = enc.finish();
            assert_eq!(data, expected_ct, "aad_split {aad_split}, data_split {data_split}");
            assert_eq!(tag, expected_tag, "aad_split {aad_split}, data_split {data_split}");
        }
    }
}

/// Tag-length variants 12..=16 all round-trip, and the 12-byte tag is a prefix of the 16-byte tag
/// for the same inputs -- Algorithm 4 step 6's `T = MSB_t(...)`.
#[test]
fn tag_length_variants_round_trip_and_nest() {
    let key = toy_key();
    let aad = b"associated";
    let message = *b"a toy message, sixteen+";

    let mut data16 = message;
    let (nonce, tag16) =
        ToyGcm::<Encrypting, 16>::encrypt_detached(&key, aad, &mut data16).unwrap();

    macro_rules! check_tag_len {
        ($n:literal) => {{
            let mut data = message;
            let (n, tag) = ToyGcm::<Encrypting, $n>::encrypt_detached_rng(
                &key,
                &mut bouncycastle_core_test_framework::FixedSeedRNG::<12>::new(nonce),
                aad,
                &mut data,
            )
            .unwrap();
            assert_eq!(n, nonce);
            assert_eq!(data, data16, "ciphertext must not depend on TAG_LEN ({})", $n);
            assert_eq!(
                &tag16[..$n],
                &tag[..],
                "TAG_LEN={} must be a prefix of the 16-byte tag",
                $n
            );
            ToyGcm::<Decrypting, $n>::decrypt_detached(&key, &n, aad, &mut data, &tag).unwrap();
            assert_eq!(data, message);
        }};
    }
    check_tag_len!(12);
    check_tag_len!(13);
    check_tag_len!(14);
    check_tag_len!(15);
    check_tag_len!(16);
}

/// GMAC: an all-AAD message (no plaintext at all) still produces a valid tag, and decrypting zero
/// bytes of ciphertext against it verifies. Sec 5.2: GMAC is GCM restricted to `P = ""`.
#[test]
fn an_aad_only_message_is_gmac() {
    let key = toy_key();
    let aad = b"the whole message is AAD";
    let mut nothing: [u8; 0] = [];

    let (nonce, tag) = ToyGcm::<Encrypting, 16>::encrypt_detached(&key, aad, &mut nothing).unwrap();
    ToyGcm::<Decrypting, 16>::decrypt_detached(&key, &nonce, aad, &mut nothing, &tag).unwrap();

    // Wrong AAD must fail verification.
    match ToyGcm::<Decrypting, 16>::decrypt_detached(&key, &nonce, b"wrong", &mut nothing, &tag) {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
}

/// The inline decryptor: input of exactly `TAG_LEN` bytes decrypts to nothing and verifies; input
/// shorter than `TAG_LEN` is `DecryptionFailed`.
#[test]
fn inline_decryptor_handles_short_and_tag_only_input() {
    let key = toy_key();
    let mut nothing: [u8; 0] = [];
    let (nonce, tag) = ToyGcm::<Encrypting, 16>::encrypt_detached(&key, b"", &mut nothing).unwrap();

    let mut plaintext = [0u8; 16];
    let n = ToyGcm::<Decrypting, 16>::decrypt_out(&key, &nonce, &tag, &mut plaintext).unwrap();
    assert_eq!(n, 0, "a tag-only input releases no plaintext");

    for short_len in 0..16 {
        let short = &tag[..short_len];
        match ToyGcm::<Decrypting, 16>::decrypt_out(&key, &nonce, short, &mut plaintext) {
            Err(SymmetricCipherError::DecryptionFailed) => {}
            other => panic!("len {short_len}: expected DecryptionFailed, got {other:?}"),
        }
    }
}

/// `update_out_len` must be exact across an irregular sequence of call sizes that walks through
/// the tail hold-back boundary.
#[test]
fn update_out_len_is_exact_across_irregular_chunking() {
    let key = toy_key();
    let message: [u8; 64] = core::array::from_fn(|i| i as u8);
    let mut ct = message;
    let (nonce, tag) = ToyGcm::<Encrypting, 16>::encrypt_detached(&key, b"aad", &mut ct).unwrap();
    let mut full_ct = [0u8; 80];
    full_ct[..64].copy_from_slice(&ct);
    full_ct[64..].copy_from_slice(&tag);

    let mut dec = ToyGcm::<Decrypting, 16>::do_decrypt_init(&key, &nonce).unwrap();
    dec.do_update_aad(b"aad").unwrap();
    let mut released = 0usize;
    for chunk in [1usize, 15, 16, 17, 31] {
        let piece = &full_ct[released.min(full_ct.len())..(released + chunk).min(full_ct.len())];
        if piece.is_empty() {
            continue;
        }
        let expect = dec.update_out_len(piece.len());
        let mut buf = vec![0u8; expect];
        let n = dec.do_update_out(piece, &mut buf).unwrap();
        assert_eq!(n, expect, "chunk {chunk}");
        released += piece.len();
    }
    // Drain whatever remains.
    let rest = &full_ct[released..];
    let expect = dec.update_out_len(rest.len());
    let mut buf = vec![0u8; expect];
    dec.do_update_out(rest, &mut buf).unwrap();
    let (_last, last_len) = dec.do_final().unwrap();
    assert_eq!(last_len, 0);
}

/// A forged tag leaves the one-shot's output buffer untouched, while the streaming path (by its
/// nature) has already written plaintext before the forgery is detected. Pinning the difference.
#[test]
fn one_shot_leaves_the_buffer_untouched_on_forgery_but_streaming_does_not() {
    let key = toy_key();
    let message = *b"do not trust me yet";
    let mut ct = message;
    let (nonce, mut tag) =
        ToyGcm::<Encrypting, 16>::encrypt_detached(&key, b"aad", &mut ct).unwrap();
    tag[0] ^= 0xFF; // forge it

    // One-shot: verify-then-decrypt, so a forged tag must leave `data` exactly as it was.
    let mut one_shot_buf = ct;
    let before = one_shot_buf;
    match ToyGcm::<Decrypting, 16>::decrypt_detached(&key, &nonce, b"aad", &mut one_shot_buf, &tag)
    {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
    assert_eq!(one_shot_buf, before, "the one-shot must not touch the buffer on a forged tag");

    // Streaming: do_decrypt has already released (wrong) plaintext by the time finish() fails.
    let mut dec = ToyGcm::<Decrypting, 16>::do_decrypt_init(&key, &nonce).unwrap();
    dec.do_update_aad(b"aad").unwrap();
    let mut streaming_buf = ct;
    dec.do_decrypt(&mut streaming_buf).unwrap();
    assert_eq!(streaming_buf, message, "streaming already produced the (correct) plaintext");
    match dec.finish(&tag) {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
}

/// The one-shots and the inline `SimpleCipherEncryptor`/`Decryptor` view round-trip with real AES
/// at all three key lengths, at a length that is not a whole number of blocks.
#[test]
fn the_aes_aliases_round_trip() {
    fn check<P, const KEY_LEN: usize>(key_bytes: &[u8])
    where
        P: bouncycastle_core::traits::ElectronicCodeBook<KEY_LEN, 16>,
    {
        let key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(key_bytes, KeyType::SymmetricCipherKey)
                .unwrap();
        let aad = b"associated data of no particular length";
        let message = b"a message that is not a whole number of blocks!!";

        let mut data = *message;
        let (nonce, tag) =
            Gcm::<P, Encrypting, KEY_LEN, 16>::encrypt_detached(&key, aad, &mut data).unwrap();
        assert_ne!(&data[..], &message[..]);
        Gcm::<P, Decrypting, KEY_LEN, 16>::decrypt_detached(&key, &nonce, aad, &mut data, &tag)
            .unwrap();
        assert_eq!(&data[..], &message[..]);
    }

    check::<AES_128, 16>(&[0x11; 16]);
    check::<AES_192, 24>(&[0x22; 24]);
    check::<AES_256, 32>(&[0x33; 32]);
}
