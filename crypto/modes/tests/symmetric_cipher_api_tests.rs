//! The stream modes through the [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] API.
//!
//! `Cfb`, `Cfb8` and `Ctr` implement the stream traits directly and get the symmetric-cipher traits
//! from the blanket impls in `bouncycastle-core`, with `FINAL_LEN = 0`. That is what lets a caller
//! hold any of the five modes through one trait: a padded `Cbc` or `Ecb` with the padded block as
//! its final output, and a stream mode with nothing.
//!
//! What is worth testing here is the bridge, not the ciphers, which their own suites cover:
//!
//! * that the modes really do satisfy the shared conformance suite for those traits, the same one
//!   the padding adapters run;
//! * that the separate-output API agrees byte for byte with the in-place one, since the blanket
//!   impl is written in terms of it;
//! * that it leaves the caller's input alone, which is the one thing the in-place API cannot offer
//!   and therefore the reason to have both;
//! * and that the length predictions are exact, not upper bounds.
//!
//! # Both traits in scope at once
//!
//! This file imports the stream traits *and* the symmetric ones, so `do_encrypt_init` is ambiguous
//! here and every call has to name the trait it means. That is the one ergonomic cost of a mode
//! implementing both, so it is worth having a file that demonstrates it is workable; the two
//! resolve to the same function.

mod common;

use bouncycastle_aes::AES_128;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{
    StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkSymmetricCipher;
use bouncycastle_modes::{Cfb, Cfb8, Ctr, Decrypting, Encrypting};
use common::{TOY_LEN, Toy, toy_key};

type ToyCfb<Dir> = Cfb<Toy, Dir, TOY_LEN, TOY_LEN>;
type ToyCfb8<Dir> = Cfb8<Toy, Dir, TOY_LEN, TOY_LEN>;
type ToyCtr<Dir> = Ctr<Toy, Dir, TOY_LEN, TOY_LEN, 12>;

/// All three stream modes must satisfy the shared conformance suite for the symmetric-cipher
/// traits -- the same suite the padded adapters run, with `required_alignment` left at 1 because a
/// stream cipher accepts every length.
///
/// It pins the whole contract: one-shot round trips at every length, the `std` one-shots against
/// the `_out` ones, streaming in eight chunkings with `update_out_len` exact on every call,
/// `do_final_out` against `do_final`, a driven RNG reproducing its init data, corruption detection,
/// short output buffers refused with the required length, and the key-type and security-strength
/// policy.
#[test]
fn the_stream_modes_conform_to_the_symmetric_cipher_suite() {
    let framework = TestFrameworkSymmetricCipher::new();
    framework
        .test_encryptor_decryptor::<TOY_LEN, TOY_LEN, 0, ToyCfb<Encrypting>, ToyCfb<Decrypting>>();
    framework
        .test_encryptor_decryptor::<TOY_LEN, TOY_LEN, 0, ToyCfb8<Encrypting>, ToyCfb8<Decrypting>>(
        );
    framework.test_encryptor_decryptor::<TOY_LEN, 12, 0, ToyCtr<Encrypting>, ToyCtr<Decrypting>>();
}

/// The separate-output API must produce exactly what the in-place API produces, for the same key
/// and init data. The blanket impl is written in terms of `do_encrypt`, so this is the check that
/// the bridge adds nothing and loses nothing.
#[test]
fn the_two_apis_agree_byte_for_byte() {
    fn check<E, D, const KEY_LEN: usize, const INIT_DATA_LEN: usize>(
        name: &str,
        key: &KeyMaterial<KEY_LEN>,
    ) where
        E: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>
            + SymmetricCipherEncryptor<KEY_LEN, INIT_DATA_LEN, 0>,
        D: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>
            + SymmetricCipherDecryptor<KEY_LEN, INIT_DATA_LEN, 0>,
    {
        for len in [0usize, 1, 15, 16, 17, 63, 64, 171] {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();

            // The in-place API, which the mode implements directly.
            let (mut enc, init) =
                <E as StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>>::do_encrypt_init(key).unwrap();
            let mut in_place = plaintext.clone();
            enc.do_encrypt(&mut in_place).unwrap();

            // The separate-output API, under the same init data, reached through the blanket impl.
            let mut dec_as_sym =
                <D as SymmetricCipherDecryptor<KEY_LEN, INIT_DATA_LEN, 0>>::do_decrypt_init(
                    key, &init,
                )
                .unwrap();
            let mut out = vec![0u8; plaintext.len()];
            let n = dec_as_sym.do_update_out(&in_place, &mut out).unwrap();
            let (last, last_len) = dec_as_sym.do_final().unwrap();
            assert_eq!(n, plaintext.len(), "{name}, len {len}: everything is released immediately");
            assert_eq!(last, [0u8; 0], "{name}: a stream cipher has no final output");
            assert_eq!(last_len, 0, "{name}: ...and none of it is data");
            assert_eq!(out, plaintext, "{name}, len {len}: the two APIs must agree");
        }
    }

    check::<ToyCfb<Encrypting>, ToyCfb<Decrypting>, TOY_LEN, TOY_LEN>("Cfb", &toy_key());
    check::<ToyCfb8<Encrypting>, ToyCfb8<Decrypting>, TOY_LEN, TOY_LEN>("Cfb8", &toy_key());
    check::<ToyCtr<Encrypting>, ToyCtr<Decrypting>, TOY_LEN, 12>("Ctr", &toy_key());
}

/// The separate-output API must leave the caller's input untouched. That is the whole reason a
/// stream cipher wants it as well as the in-place one, so it is worth asserting rather than
/// assuming.
#[test]
fn the_input_buffer_is_not_modified() {
    let key = toy_key();
    let plaintext: Vec<u8> = (0..100u8).collect();
    let original = plaintext.clone();

    let (mut enc, _init) =
        <ToyCfb<Encrypting> as SymmetricCipherEncryptor<TOY_LEN, TOY_LEN, 0>>::do_encrypt_init(
            &key,
        )
        .unwrap();
    let mut ciphertext = vec![0u8; plaintext.len()];
    enc.do_update_out(&plaintext, &mut ciphertext).unwrap();

    assert_eq!(plaintext, original, "the plaintext must be left alone");
    assert_ne!(ciphertext, original, "...and the ciphertext must actually be encrypted");
}

/// The length predictions are exact for a stream cipher, not upper bounds: what goes in comes out.
#[test]
fn the_length_predictions_are_exact() {
    let key = toy_key();
    for len in [0usize, 1, 15, 16, 17, 1000] {
        assert_eq!(
            <ToyCtr<Encrypting> as SymmetricCipherEncryptor<TOY_LEN, 12, 0>>::encrypt_out_len(len),
            len,
            "encrypt_out_len is the identity"
        );
        assert_eq!(
            <ToyCtr<Decrypting> as SymmetricCipherDecryptor<TOY_LEN, 12, 0>>::decrypt_out_max_len(
                len
            ),
            len,
            "decrypt_out_max_len is exact, not an upper bound"
        );

        let (enc, _) =
            <ToyCtr<Encrypting> as SymmetricCipherEncryptor<TOY_LEN, 12, 0>>::do_encrypt_init(&key)
                .unwrap();
        assert_eq!(enc.update_out_len(len), len, "update_out_len is the identity");
    }
}

/// A short output buffer is refused with the length it needed, and nothing is consumed -- so the
/// same call with a big enough buffer then succeeds and gives the answer it would have given.
#[test]
fn a_short_output_buffer_is_refused_without_consuming_anything() {
    use bouncycastle_core::errors::SymmetricCipherError;

    let key = toy_key();
    let plaintext: Vec<u8> = (0..32u8).collect();

    let (mut enc, init) =
        <ToyCfb<Encrypting> as SymmetricCipherEncryptor<TOY_LEN, TOY_LEN, 0>>::do_encrypt_init(
            &key,
        )
        .unwrap();

    let mut too_small = vec![0u8; plaintext.len() - 1];
    match enc.do_update_out(&plaintext, &mut too_small) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(what, needed)) => {
            assert_eq!(what, "ciphertext");
            assert_eq!(needed, plaintext.len(), "the error carries the required length");
        }
        other => panic!("expected IncorrectOutputBufferLength, got {other:?}"),
    }

    // Nothing was consumed, so the keystream has not advanced: the retry must give exactly what a
    // fresh encryptor under the same init data would.
    let mut big_enough = vec![0u8; plaintext.len()];
    enc.do_update_out(&plaintext, &mut big_enough).unwrap();

    let (mut fresh, _) =
        <ToyCfb<Encrypting> as StreamCipherEncryptor<TOY_LEN, TOY_LEN>>::do_encrypt_init_rng(
            &key,
            &mut bouncycastle_core_test_framework::FixedSeedRNG::<TOY_LEN>::new(init),
        )
        .unwrap();
    let mut reference = plaintext.clone();
    fresh.do_encrypt(&mut reference).unwrap();
    assert_eq!(big_enough, reference, "the refused call must not have advanced the keystream");
}

/// The decrypt side refuses a short output buffer too, with the length it needed.
///
/// The mirror of the encryptor test above. Worth having separately rather than assuming symmetry:
/// the two are separate blanket impls with their own buffer check, and mutation testing showed the
/// decryptor's comparison was unexercised until this existed.
#[test]
fn a_short_output_buffer_is_refused_when_decrypting_too() {
    use bouncycastle_core::errors::SymmetricCipherError;

    let key = toy_key();
    let plaintext: Vec<u8> = (0..32u8).collect();

    // Encrypt normally, then try to decrypt into a buffer one byte too small.
    let (mut enc, init) =
        <ToyCfb<Encrypting> as StreamCipherEncryptor<TOY_LEN, TOY_LEN>>::do_encrypt_init(&key)
            .unwrap();
    let mut ciphertext = plaintext.clone();
    enc.do_encrypt(&mut ciphertext).unwrap();

    let mut dec =
        <ToyCfb<Decrypting> as SymmetricCipherDecryptor<TOY_LEN, TOY_LEN, 0>>::do_decrypt_init(
            &key, &init,
        )
        .unwrap();

    let mut too_small = vec![0u8; ciphertext.len() - 1];
    match dec.do_update_out(&ciphertext, &mut too_small) {
        Err(SymmetricCipherError::IncorrectOutputBufferLength(what, needed)) => {
            assert_eq!(what, "plaintext");
            assert_eq!(needed, ciphertext.len(), "the error carries the required length");
        }
        other => panic!("expected IncorrectOutputBufferLength, got {other:?}"),
    }

    // Nothing was consumed, so the retry recovers the plaintext exactly.
    let mut big_enough = vec![0u8; ciphertext.len()];
    let n = dec.do_update_out(&ciphertext, &mut big_enough).unwrap();
    assert_eq!(n, ciphertext.len());
    assert_eq!(big_enough, plaintext, "the refused call must not have advanced the keystream");

    // An oversized buffer is fine, and only the leading bytes are written: the check is "too
    // short", not "not exactly equal".
    let mut oversized = vec![0xAAu8; ciphertext.len() + 8];
    let mut dec =
        <ToyCfb<Decrypting> as SymmetricCipherDecryptor<TOY_LEN, TOY_LEN, 0>>::do_decrypt_init(
            &key, &init,
        )
        .unwrap();
    let n = dec.do_update_out(&ciphertext, &mut oversized).expect("an oversized buffer is fine");
    assert_eq!(n, ciphertext.len());
    assert_eq!(&oversized[..n], &plaintext[..], "the data lands in the leading bytes");
    assert!(oversized[n..].iter().all(|&b| b == 0xAA), "the rest is left alone");
}

/// The one-shots work with real AES, at a length that is not a whole number of blocks, for all
/// three stream modes -- the shape a caller most often wants from this API.
#[test]
fn the_one_shots_round_trip_with_real_aes() {
    let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
        .expect("a valid AES-128 key");
    let message = b"a message of no particular length at all";

    // CFB128
    let (iv, ct) =
        <Cfb<AES_128, Encrypting, 16, 16> as SymmetricCipherEncryptor<16, 16, 0>>::encrypt(
            &key, message,
        )
        .unwrap();
    assert_eq!(ct.len(), message.len(), "a stream cipher does not change the length");
    let back = <Cfb<AES_128, Decrypting, 16, 16> as SymmetricCipherDecryptor<16, 16, 0>>::decrypt(
        &key, &iv, &ct,
    )
    .unwrap();
    assert_eq!(back, message);

    // CFB8
    let (iv, ct) =
        <Cfb8<AES_128, Encrypting, 16, 16> as SymmetricCipherEncryptor<16, 16, 0>>::encrypt(
            &key, message,
        )
        .unwrap();
    let back = <Cfb8<AES_128, Decrypting, 16, 16> as SymmetricCipherDecryptor<16, 16, 0>>::decrypt(
        &key, &iv, &ct,
    )
    .unwrap();
    assert_eq!(back, message);

    // CTR
    let (nonce, ct) =
        <Ctr<AES_128, Encrypting, 16, 16, 12> as SymmetricCipherEncryptor<16, 12, 0>>::encrypt(
            &key, message,
        )
        .unwrap();
    assert_eq!(nonce.len(), 12, "CTR's init data is its 12-byte nonce");
    let back =
        <Ctr<AES_128, Decrypting, 16, 16, 12> as SymmetricCipherDecryptor<16, 12, 0>>::decrypt(
            &key, &nonce, &ct,
        )
        .unwrap();
    assert_eq!(back, message);
}
