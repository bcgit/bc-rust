//! Structural tests for GCM, driven by a toy permutation.
//!
//! These check the properties of the *mode* -- AAD-before-data ordering, chunking independence,
//! the tag-length family, the inline decryptor's tail hold-back, and the one-shot's
//! verify-before-decrypt guarantee -- independently of (or alongside) the ACVP/bc-java known-answer
//! vectors in the `aes` crate's `gcm_bc-test-data.rs`, `gmac_bc-test-data.rs` and
//! `gcm_bc_java_tests.rs`.

mod common;
#[path = "../common/toy_key.rs"]
mod toy_key;

use bouncycastle_cipher::modes::ModeNames;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use common::{ForwardOnlyToy, TOY_LEN, Toy, toy_key};
use toy_key::{ToyGCM, ToyKey, os_rng};

type ToyGcmKey<const TAG_LEN: usize = 16> = ToyKey<Toy, ToyGCM<TAG_LEN>>;

fn gcm_key<const TAG_LEN: usize>() -> ToyGcmKey<TAG_LEN> {
    ToyGcmKey::from_key_material(&toy_key()).expect("the toy key")
}

/// Encrypts `message` under `aad` through the detached one-shot, with the nonce driven by `seed`
/// so repeated calls are comparable. Returns the nonce, the ciphertext and the tag.
fn toy_encrypt<const TAG_LEN: usize>(
    aad: &[u8],
    message: &[u8],
    seed: [u8; 12],
) -> ([u8; 12], Vec<u8>, [u8; TAG_LEN]) {
    let mut ct = vec![0u8; message.len()];
    let (_, nonce, tag) = gcm_key::<TAG_LEN>()
        .encrypt_detached_out(&mut FixedSeedRNG::<12>::new(seed), aad, message, &mut ct)
        .unwrap();
    (nonce, ct, tag)
}

/// AAD must precede data (SP 800-38D Algorithm 4 absorbs `A` before `C`); a non-empty AAD call
/// after data has started is refused, while an empty one is always accepted as a no-op.
#[test]
fn aad_after_data_is_a_state_error_unless_empty() {
    let key = gcm_key::<16>();
    let (mut enc, _nonce) = key.create_encryptor(&mut os_rng()).unwrap();
    enc.do_update_aad(b"header").unwrap();
    let mut out = [0u8; 8];
    enc.do_encrypt_out(&[0x11u8; 8], &mut out).unwrap();

    match enc.do_update_aad(b"too late") {
        Err(SymmetricCipherError::StateError(_)) => {}
        other => panic!("expected StateError, got {other:?}"),
    }
    // An empty call after data is always fine.
    enc.do_update_aad(&[]).unwrap();
    let _ = enc.do_encrypt_final_detached().unwrap();
}

/// The decryptor holds back the last `TAG_LEN` bytes it has seen, so a first `do_update_out` of
/// fewer than `TAG_LEN` bytes releases nothing -- but data has still started, and AAD after it
/// must be refused all the same, or it would be absorbed as if it came before the ciphertext.
#[test]
fn aad_after_held_back_data_is_still_a_state_error() {
    let key = gcm_key::<16>();
    let mut dec = key.create_decryptor(&[0u8; 12]);
    let mut nothing = [0u8; 0];
    assert_eq!(dec.do_decrypt_out(&[0x22u8; 5], &mut nothing).unwrap(), 0, "all held back");
    match dec.do_update_aad(b"too late") {
        Err(SymmetricCipherError::StateError(_)) => {}
        other => panic!("expected StateError, got {other:?}"),
    }
}

/// Chunking independence for both AAD and data: every split of a 40-byte AAD and a 50-byte message
/// must give the same ciphertext and tag as absorbing each in one call.
#[test]
fn chunking_is_independent_for_aad_and_data() {
    let key = gcm_key::<16>();
    let aad: [u8; 40] = core::array::from_fn(|i| i as u8);
    let message: [u8; 50] = core::array::from_fn(|i| (i as u8).wrapping_mul(3).wrapping_add(1));
    let seed = [0x5Au8; 12];
    let (nonce, expected_ct, expected_tag) = toy_encrypt::<16>(&aad, &message, seed);

    for aad_split in [0usize, 1, 17, 40] {
        for data_split in [0usize, 1, 23, 50] {
            let (mut enc, got_nonce) =
                key.create_encryptor(&mut FixedSeedRNG::<12>::new(seed)).unwrap();
            assert_eq!(got_nonce, nonce);
            enc.do_update_aad(&aad[..aad_split]).unwrap();
            enc.do_update_aad(&aad[aad_split..]).unwrap();
            let mut ct = [0u8; 50];
            let n = enc.do_encrypt_out(&message[..data_split], &mut ct).unwrap();
            enc.do_encrypt_out(&message[data_split..], &mut ct[n..]).unwrap();
            let (_, _, tag) = enc.do_encrypt_final_detached().unwrap();
            assert_eq!(&ct[..], &expected_ct[..], "aad_split {aad_split}, data_split {data_split}");
            assert_eq!(tag, expected_tag, "aad_split {aad_split}, data_split {data_split}");
        }
    }
}

/// Tag-length variants 12..=16 all round-trip, and the 12-byte tag is a prefix of the 16-byte tag
/// for the same inputs -- Algorithm 4 step 6's `T = MSB_t(...)`.
#[test]
fn tag_length_variants_round_trip_and_nest() {
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
            gcm_key::<$n>().decrypt_detached_out(&nonce, aad, &ct, &tag, &mut pt).unwrap();
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
    let key = gcm_key::<16>();
    let aad = b"the whole message is AAD";
    let (nonce, _, tag) = toy_encrypt::<16>(aad, &[], [0x7Cu8; 12]);
    key.decrypt_detached_out(&nonce, aad, &[], &tag, &mut []).unwrap();

    // Wrong AAD must fail verification.
    match key.decrypt_detached_out(&nonce, b"wrong", &[], &tag, &mut []) {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
}

/// The inline decryptor: input of exactly `TAG_LEN` bytes decrypts to nothing and verifies; input
/// shorter than `TAG_LEN` is `DecryptionFailed`.
#[test]
fn inline_decryptor_handles_short_and_tag_only_input() {
    let key = gcm_key::<16>();
    let (nonce, _, tag) = toy_encrypt::<16>(b"", &[], [0x8Du8; 12]);

    let mut plaintext = [0u8; 16];
    let n = key.decrypt_with_aad_out(&nonce, &[], &tag, &mut plaintext).unwrap();
    assert_eq!(n, 0, "a tag-only input releases no plaintext");

    for short_len in 0..16 {
        let short = &tag[..short_len];
        match key.decrypt_with_aad_out(&nonce, &[], short, &mut plaintext) {
            Err(SymmetricCipherError::DecryptionFailed) => {}
            other => panic!("len {short_len}: expected DecryptionFailed, got {other:?}"),
        }
    }
}

/// `update_out_len` must be exact across an irregular sequence of call sizes that walks through
/// the tail hold-back boundary.
#[test]
fn update_out_len_is_exact_across_irregular_chunking() {
    let key = gcm_key::<16>();
    let message: [u8; 64] = core::array::from_fn(|i| i as u8);
    let (nonce, ct, tag) = toy_encrypt::<16>(b"aad", &message, [0x9Eu8; 12]);
    let mut full_ct = [0u8; 80];
    full_ct[..64].copy_from_slice(&ct);
    full_ct[64..].copy_from_slice(&tag);

    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(b"aad").unwrap();
    let mut released = 0usize;
    for chunk in [1usize, 15, 16, 17, 31] {
        let piece = &full_ct[released.min(full_ct.len())..(released + chunk).min(full_ct.len())];
        if piece.is_empty() {
            continue;
        }
        let expect = dec.do_decrypt_out_len(piece.len());
        let mut buf = vec![0u8; expect];
        let n = dec.do_decrypt_out(piece, &mut buf).unwrap();
        assert_eq!(n, expect, "chunk {chunk}");
        released += piece.len();
    }
    // Drain whatever remains.
    let rest = &full_ct[released..];
    let expect = dec.do_decrypt_out_len(rest.len());
    let mut buf = vec![0u8; expect];
    dec.do_decrypt_out(rest, &mut buf).unwrap();
    let (_last, last_len) = dec.do_decrypt_final().unwrap();
    assert_eq!(last_len, 0);
}

/// A forged tag leaves the one-shot's output buffer zeroized, while the streaming path (by its
/// nature) has already released plaintext before the forgery is detected. Pinning the difference.
#[test]
fn one_shot_releases_nothing_on_forgery_but_streaming_does() {
    let key = gcm_key::<16>();
    let message = *b"do not trust me yet";
    let (nonce, ct, mut tag) = toy_encrypt::<16>(b"aad", &message, [0xAFu8; 12]);
    tag[0] ^= 0xFF; // forge it

    // One-shot: a forged tag leaves nothing but zeros behind.
    let mut one_shot_buf = [0xEEu8; 19];
    match key.decrypt_detached_out(&nonce, b"aad", &ct, &tag, &mut one_shot_buf) {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
    assert_eq!(one_shot_buf, [0u8; 19], "the one-shot must zeroize its buffer on a forged tag");

    // Streaming: everything but the held-back last 16 bytes has already been released as
    // plaintext by the time the final call rejects the tag.
    let mut dec = key.create_decryptor(&nonce);
    dec.do_update_aad(b"aad").unwrap();
    let mut streaming_buf = [0u8; 19];
    let released = dec.do_decrypt_out(&ct, &mut streaming_buf).unwrap();
    assert_eq!(released, 3, "19 bytes in, the last 16 held back");
    assert_eq!(&streaming_buf[..3], &message[..3], "streaming already produced plaintext");
    match dec.do_decrypt_final_detached(&tag) {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
}

/// The streaming detached final decrypts the held-back tail into the caller's buffer before it
/// checks the tag, so on a forged tag it must zeroize that buffer before returning the error.
#[test]
fn streaming_detached_final_zeroizes_its_buffer_on_forgery() {
    let key = toy_key();
    let message = *b"do not trust me yet";
    let (nonce, ct, mut tag) = toy_encrypt::<16>(b"aad", &message, [0xAFu8; 12]);
    tag[0] ^= 0xFF; // forge it

    let mut dec = ToyGcm::<Decrypting, 16>::do_decrypt_init(&key, &nonce).unwrap();
    dec.do_update_aad(b"aad").unwrap();
    dec.do_decrypt_out(&ct, &mut [0u8; 19]).unwrap();
    // Pre-filled with a non-zero byte, so a buffer the decryptor never wrote is not mistaken for
    // one it zeroized.
    let mut final_buf = [0xEEu8; 16];
    match dec.do_decrypt_final_detached_out(&tag, &mut final_buf) {
        Err(SymmetricCipherError::AEADTagCheckFailed) => {}
        other => panic!("expected AEADTagCheckFailed, got {other:?}"),
    }
    assert_eq!(final_buf, [0u8; 16], "the held-back tail must not survive a forged tag");
}

/// SP 800-38D Sec 5.1: "GCM does not employ the inverse cipher function." GCTR (Sec 6.5) applies
/// `CIPH_K` to counter blocks in both directions and GHASH (Sec 6.4) is field arithmetic, so a
/// permutation that implements only the forward direction works. [`ForwardOnlyToy`] panics from
/// every inverse entry point; a detached one-shot round trip over it, at a length that is not a
/// whole number of blocks, must therefore agree with [`Toy`] and succeed.
#[test]
fn neither_direction_uses_the_inverse_cipher() {
    fn round_trip<P>() -> ([u8; 48], [u8; 16])
    where
        P: bouncycastle_core::hazmat::ElectronicCodeBook<TOY_LEN, TOY_LEN> + ModeNames + Clone,
    {
        let key = ToyKey::<P, ToyGCM<16>>::from_key_material(&toy_key()).unwrap();
        let aad = b"associated data of no particular length";
        let message = b"a message that is not a whole number of blocks!!";

        let mut ct = [0u8; 48];
        let (_, nonce, tag) = key
            .encrypt_detached_out(&mut FixedSeedRNG::<12>::new([0x4Du8; 12]), aad, message, &mut ct)
            .unwrap();
        assert_ne!(&ct[..], &message[..]);
        let mut pt = [0u8; 48];
        key.decrypt_detached_out(&nonce, aad, &ct, &tag, &mut pt).unwrap();
        assert_eq!(&pt[..], &message[..]);
        (ct, tag)
    }

    // The forward-only toy must agree with the real one, or the round trip proves nothing.
    assert_eq!(round_trip::<ForwardOnlyToy>(), round_trip::<Toy>(), "the two toys must agree");
}

/// The whole AEAD key contract -- which runs the symmetric-cipher suite first -- through the
/// shared framework, over the toy at both ends of the tag-length range. `FINAL_LEN` is
/// `TAG_LEN`: GCM holds nothing back on encryption and exactly the possible tag on decryption.
#[test]
fn aead_key_framework() {
    use bouncycastle_core_test_framework::aead::TestFrameworkAEADCipher;
    TestFrameworkAEADCipher::new()
        .test_key::<TOY_LEN, 12, 16, 16, _>(&gcm_key::<16>(), &mut os_rng());
    TestFrameworkAEADCipher::new()
        .test_key::<TOY_LEN, 12, 12, 12, _>(&gcm_key::<12>(), &mut os_rng());
}

/// The key's construction suite: the type, binding and strength policy of `from_key_material`.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<TOY_LEN, ToyGcmKey>(Toy::GCM_ALG_NAME, SecurityStrength::_128bit);
}

/// The key's one-shots leave the caller's buffer zeroized on a forgery -- the role contract --
/// rather than holding the ciphertext they staged there.
#[test]
fn the_key_one_shots_release_nothing_on_forgery() {
    let key = gcm_key::<16>();
    let mut ct = [0u8; 32 + 16];
    let (n, nonce) =
        key.encrypt_with_aad_out(&mut os_rng(), b"aad", &[0x33u8; 32], &mut ct).unwrap();
    ct[0] ^= 1;

    let mut out = [0xEEu8; 32];
    assert!(matches!(
        key.decrypt_with_aad_out(&nonce, b"aad", &ct[..n], &mut out),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(out, [0u8; 32], "decrypt_with_aad_out must zeroize on a failed tag check");

    let tag: [u8; 16] = ct[32..48].try_into().unwrap();
    let mut out = [0xEEu8; 32];
    assert!(matches!(
        key.decrypt_detached_out(&nonce, b"aad", &ct[..32], &tag, &mut out),
        Err(SymmetricCipherError::AEADTagCheckFailed)
    ));
    assert_eq!(out, [0u8; 32], "decrypt_detached_out must zeroize on a failed tag check");
}
