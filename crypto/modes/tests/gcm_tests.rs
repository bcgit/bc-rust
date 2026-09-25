//! Structural tests for GCM, driven by a toy permutation and by real AES.
//!
//! These check the properties of the *mode* -- AAD-before-data ordering, chunking independence,
//! the tag-length family, the inline decryptor's tail hold-back, and the one-shot's
//! verify-before-decrypt guarantee -- independently of (or alongside) the ACVP/bc-java known-answer
//! vectors in `acvp_gcm_tests.rs`, `acvp_gmac_tests.rs` and `gcm_bc_java_tests.rs`.

mod common;

use bouncycastle_aes::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_modes::{Decrypting, Encrypting, Gcm};
use common::{TOY_LEN, Toy, toy_key};

type ToyGcm<Dir, const TAG_LEN: usize> = Gcm<Toy, Dir, TOY_LEN, TAG_LEN>;

/// Encrypts `message` under `aad` through the detached one-shot, with the nonce driven by `seed`
/// so repeated calls are comparable. Returns the nonce, the ciphertext and the tag.
fn toy_encrypt<const TAG_LEN: usize>(
    aad: &[u8],
    message: &[u8],
    seed: [u8; 12],
) -> ([u8; 12], Vec<u8>, [u8; TAG_LEN]) {
    let mut ct = vec![0u8; message.len()];
    let (nonce, _, tag) = ToyGcm::<Encrypting, TAG_LEN>::encrypt_out_rng_detached(
        &toy_key(),
        &mut FixedSeedRNG::<12>::new(seed),
        aad,
        message,
        &mut ct,
    )
    .unwrap();
    (nonce, ct, tag)
}

/// AAD must precede data (SP 800-38D Algorithm 4 absorbs `A` before `C`); a non-empty AAD call
/// after data has started is refused, while an empty one is always accepted as a no-op.
#[test]
fn aad_after_data_is_a_state_error_unless_empty() {
    let key = toy_key();
    let (mut enc, _nonce) = ToyGcm::<Encrypting, 16>::do_encrypt_init(&key).unwrap();
    enc.do_update_aad(b"header").unwrap();
    let mut out = [0u8; 8];
    enc.do_update_out(&[0x11u8; 8], &mut out).unwrap();

    match enc.do_update_aad(b"too late") {
        Err(SymmetricCipherError::StateError(_)) => {}
        other => panic!("expected StateError, got {other:?}"),
    }
    // An empty call after data is always fine.
    enc.do_update_aad(&[]).unwrap();
    let _ = enc.do_final_detached().unwrap();
}

/// The decryptor holds back the last `TAG_LEN` bytes it has seen, so a first `do_update_out` of
/// fewer than `TAG_LEN` bytes releases nothing -- but data has still started, and AAD after it
/// must be refused all the same, or it would be absorbed as if it came before the ciphertext.
#[test]
fn aad_after_held_back_data_is_still_a_state_error() {
    let key = toy_key();
    let mut dec = ToyGcm::<Decrypting, 16>::do_decrypt_init(&key, &[0u8; 12]).unwrap();
    let mut nothing = [0u8; 0];
    assert_eq!(dec.do_update_out(&[0x22u8; 5], &mut nothing).unwrap(), 0, "all held back");
    match dec.do_update_aad(b"too late") {
        Err(SymmetricCipherError::StateError(_)) => {}
        other => panic!("expected StateError, got {other:?}"),
    }
}

/// Chunking independence for both AAD and data: every split of a 40-byte AAD and a 50-byte message
/// must give the same ciphertext and tag as absorbing each in one call.
#[test]
fn chunking_is_independent_for_aad_and_data() {
    let key = toy_key();
    let aad: [u8; 40] = core::array::from_fn(|i| i as u8);
    let message: [u8; 50] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
    let seed = [0x5Au8; 12];
    let (nonce, expected_ct, expected_tag) = toy_encrypt::<16>(&aad, &message, seed);

    for aad_split in [0usize, 1, 17, 40] {
        for data_split in [0usize, 1, 23, 50] {
            let (mut enc, got_nonce) = ToyGcm::<Encrypting, 16>::do_encrypt_init_rng(
                &key,
                &mut FixedSeedRNG::<12>::new(seed),
            )
            .unwrap();
            assert_eq!(got_nonce, nonce);
            enc.do_update_aad(&aad[..aad_split]).unwrap();
            enc.do_update_aad(&aad[aad_split..]).unwrap();
            let mut ct = [0u8; 50];
            let n = enc.do_update_out(&message[..data_split], &mut ct).unwrap();
            enc.do_update_out(&message[data_split..], &mut ct[n..]).unwrap();
            let (_, _, tag) = enc.do_final_detached().unwrap();
            assert_eq!(&ct[..], &expected_ct[..], "aad_split {aad_split}, data_split {data_split}");
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
    let seed = [0x6Bu8; 12];
    let (_, ct16, tag16) = toy_encrypt::<16>(aad, &message, seed);

    macro_rules! check_tag_len {
        ($n:literal) => {{
            let (nonce, ct, tag) = toy_encrypt::<$n>(aad, &message, seed);
            assert_eq!(ct, ct16, "ciphertext must not depend on TAG_LEN ({})", $n);
            assert_eq!(
                &tag16[..$n],
                &tag[..],
                "TAG_LEN={} must be a prefix of the 16-byte tag",
                $n
            );
            let mut pt = [0u8; 23];
            ToyGcm::<Decrypting, $n>::decrypt_out_detached(&key, &nonce, aad, &ct, &tag, &mut pt)
                .unwrap();
            assert_eq!(pt, message);
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
    let (nonce, _, tag) = toy_encrypt::<16>(aad, &[], [0x7Cu8; 12]);
    ToyGcm::<Decrypting, 16>::decrypt_out_detached(&key, &nonce, aad, &[], &tag, &mut []).unwrap();

    // Wrong AAD must fail verification.
    match ToyGcm::<Decrypting, 16>::decrypt_out_detached(&key, &nonce, b"wrong", &[], &tag, &mut [])
    {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
}

/// The inline decryptor: input of exactly `TAG_LEN` bytes decrypts to nothing and verifies; input
/// shorter than `TAG_LEN` is `DecryptionFailed`.
#[test]
fn inline_decryptor_handles_short_and_tag_only_input() {
    let key = toy_key();
    let (nonce, _, tag) = toy_encrypt::<16>(b"", &[], [0x8Du8; 12]);

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
    let (nonce, ct, tag) = toy_encrypt::<16>(b"aad", &message, [0x9Eu8; 12]);
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

/// A forged tag leaves the one-shot's output buffer zeroized, while the streaming path (by its
/// nature) has already released plaintext before the forgery is detected. Pinning the difference.
#[test]
fn one_shot_releases_nothing_on_forgery_but_streaming_does() {
    let key = toy_key();
    let message = *b"do not trust me yet";
    let (nonce, ct, mut tag) = toy_encrypt::<16>(b"aad", &message, [0xAFu8; 12]);
    tag[0] ^= 0xFF; // forge it

    // One-shot: verify-then-decrypt, so a forged tag leaves nothing but zeros behind.
    let mut one_shot_buf = [0xEEu8; 19];
    match ToyGcm::<Decrypting, 16>::decrypt_out_detached(
        &key, &nonce, b"aad", &ct, &tag, &mut one_shot_buf,
    ) {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
    assert_eq!(one_shot_buf, [0u8; 19], "the one-shot must zeroize its buffer on a forged tag");

    // Streaming: everything but the held-back last 16 bytes has already been released as
    // plaintext by the time the final call rejects the tag.
    let mut dec = ToyGcm::<Decrypting, 16>::do_decrypt_init(&key, &nonce).unwrap();
    dec.do_update_aad(b"aad").unwrap();
    let mut streaming_buf = [0u8; 19];
    let released = dec.do_update_out(&ct, &mut streaming_buf).unwrap();
    assert_eq!(released, 3, "19 bytes in, the last 16 held back");
    assert_eq!(&streaming_buf[..3], &message[..3], "streaming already produced plaintext");
    match dec.do_final_detached(&tag) {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
}

/// The one-shots round-trip with real AES at all three key lengths, at a length that is not a
/// whole number of blocks.
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

        let mut ct = [0u8; 48];
        let (nonce, _, tag) =
            Gcm::<P, Encrypting, KEY_LEN, 16>::encrypt_out_detached(&key, aad, message, &mut ct)
                .unwrap();
        assert_ne!(&ct[..], &message[..]);
        let mut pt = [0u8; 48];
        Gcm::<P, Decrypting, KEY_LEN, 16>::decrypt_out_detached(
            &key, &nonce, aad, &ct, &tag, &mut pt,
        )
        .unwrap();
        assert_eq!(&pt[..], &message[..]);
    }

    check::<AES128Internal, 16>(&[0x11; 16]);
    check::<AES192Internal, 24>(&[0x22; 24]);
    check::<AES256Internal, 32>(&[0x33; 32]);
}

/// The whole [`AEADCipherEncryptor`] / [`AEADCipherDecryptor`] contract -- which runs the
/// symmetric-cipher suite first -- through the shared framework, over real AES at two key lengths
/// and at both ends of the tag-length range. `FINAL_LEN` is `TAG_LEN`: GCM holds nothing back on
/// encryption and exactly the possible tag on decryption.
///
/// [`AEADCipherEncryptor`]: bouncycastle_core::traits::AEADCipherEncryptor
/// [`AEADCipherDecryptor`]: bouncycastle_core::traits::AEADCipherDecryptor
#[test]
fn aead_trait_framework() {
    use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkAEADCipher;
    TestFrameworkAEADCipher::new().test_encryptor_decryptor::<
        16,
        12,
        16,
        16,
        Gcm<AES128Internal, Encrypting, 16, 16>,
        Gcm<AES128Internal, Decrypting, 16, 16>,
    >();
    TestFrameworkAEADCipher::new().test_encryptor_decryptor::<
        32,
        12,
        12,
        12,
        Gcm<AES256Internal, Encrypting, 32, 12>,
        Gcm<AES256Internal, Decrypting, 32, 12>,
    >();
}

/// The trait one-shots check the tag before decrypting anything, as the inherent
/// `decrypt_detached` does, and on a forgery leave the caller's buffer zeroized -- the trait
/// contract -- rather than holding the ciphertext they staged there.
#[test]
fn aead_trait_one_shots_release_nothing_on_forgery() {
    type Enc = Gcm<AES128Internal, Encrypting, 16, 16>;
    type Dec = Gcm<AES128Internal, Decrypting, 16, 16>;

    let key =
        KeyMaterial::<16>::from_bytes_as_type(&[0x42u8; 16], KeyType::SymmetricCipherKey).unwrap();
    let mut ct = [0u8; 32 + 16];
    let (nonce, n) = Enc::encrypt_out_with_aad(&key, b"aad", &[0x33u8; 32], &mut ct).unwrap();
    ct[0] ^= 1;

    let mut out = [0xEEu8; 32];
    assert!(matches!(
        Dec::decrypt_out_with_aad(&key, &nonce, b"aad", &ct[..n], &mut out),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(out, [0u8; 32], "decrypt_out_with_aad must zeroize on a failed tag check");

    let tag: [u8; 16] = ct[32..48].try_into().unwrap();
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        <Dec as AEADCipherDecryptor<16, 12, 16, 16>>::decrypt_out_detached(
            &key,
            &nonce,
            b"aad",
            &ct[..32],
            &tag,
            &mut out
        ),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(out, [0u8; 32], "decrypt_out_detached must zeroize on a failed tag check");
}
