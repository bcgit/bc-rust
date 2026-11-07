//! Tests for the `camellia128-cfb8`, `camellia192-cfb8` and `camellia256-cfb8` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-cfb8`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_cfb8.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: the three key lengths, that the
//! commands exist and round-trip at any length, and that what comes out really is CFB8 over
//! Camellia.
//!
//! There is no published Camellia CFB8 vector -- OpenSSL's `evpciph_camellia.txt` says in as many
//! words that it does not carry `CFB{1,8}-CAMELLIAxxx` -- so instead the commands are required to
//! agree with `bouncycastle_cipher::modes::Cfb8` over the Camellia permutation, which
//! `crypto/camellia/tests/stream_mode_tests.rs` pins against the SP 800-38A Sec 6.3 equations at
//! `s = 8`.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, key_object, large_payload_on_an_error_path,
    library_stream_decrypt, listed_in_help, pseudo_random, round_trips, run_ok, unhex,
    wrong_key_lengths,
};

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// What each command emits must be exactly what `Cfb8` over the matching permutation produces:
/// take the IV the CLI generated, hand the body to the library, and the plaintext must come back.
#[test]
fn the_commands_are_cfb8_over_camellia() {
    use bouncycastle::camellia::{Camellia128Key, Camellia192Key, Camellia256Key};
    use bouncycastle::cipher::modes::CFB8;

    for len in [1usize, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);

        let out = run_ok(&["camellia128-cfb8", "-d", "encrypt", "--key", KEY_128], &plaintext);
        let (iv, body) = out.split_at(16);
        let mut recovered = body.to_vec();
        library_stream_decrypt::<16, 16, _>(
            &key_object::<16, Camellia128Key<CFB8>>(KEY_128),
            iv,
            &mut recovered,
        );
        assert_eq!(recovered, plaintext, "camellia128-cfb8, len {len}");

        let out = run_ok(&["camellia192-cfb8", "-d", "encrypt", "--key", KEY_192], &plaintext);
        let (iv, body) = out.split_at(16);
        let mut recovered = body.to_vec();
        library_stream_decrypt::<24, 16, _>(
            &key_object::<24, Camellia192Key<CFB8>>(KEY_192),
            iv,
            &mut recovered,
        );
        assert_eq!(recovered, plaintext, "camellia192-cfb8, len {len}");

        let out = run_ok(&["camellia256-cfb8", "-d", "encrypt", "--key", KEY_256], &plaintext);
        let (iv, body) = out.split_at(16);
        let mut recovered = body.to_vec();
        library_stream_decrypt::<32, 16, _>(
            &key_object::<32, Camellia256Key<CFB8>>(KEY_256),
            iv,
            &mut recovered,
        );
        assert_eq!(recovered, plaintext, "camellia256-cfb8, len {len}");
    }
}

/// With `--iv` the output is the ciphertext alone, and it is still `Cfb8` over Camellia under
/// that IV.
#[test]
fn a_supplied_iv_is_used_and_not_written() {
    use bouncycastle::camellia::Camellia128Key;
    use bouncycastle::cipher::modes::CFB8;

    let iv = "000102030405060708090a0b0c0d0e0f";
    let plaintext = pseudo_random(37, 5);
    let out =
        run_ok(&["camellia128-cfb8", "-d", "encrypt", "--key", KEY_128, "--iv", iv], &plaintext);
    assert_eq!(out.len(), plaintext.len(), "ciphertext only, no IV in band");

    let mut recovered = out.clone();
    library_stream_decrypt::<16, 16, _>(
        &key_object::<16, Camellia128Key<CFB8>>(KEY_128),
        &unhex(iv),
        &mut recovered,
    );
    assert_eq!(recovered, plaintext, "the CLI should agree with the library under that IV");

    let back = run_ok(&["camellia128-cfb8", "-d", "decrypt", "--key", KEY_128, "--iv", iv], &out);
    assert_eq!(back, plaintext);
}

/// CFB8 and CFB128 are different modes, and `camellia128-cfb8` must not be a second name for
/// `camellia128-cfb`: handed the same IV and ciphertext, the two commands disagree past the first
/// byte.
#[test]
fn cfb8_is_not_cfb() {
    let iv = "000102030405060708090a0b0c0d0e0f";
    let body = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
    let input = unhex(&format!("{iv}{body}"));

    let as_cfb8 = run_ok(&["camellia128-cfb8", "-d", "decrypt", "--key", KEY_128], &input);
    let as_cfb = run_ok(&["camellia128-cfb", "-d", "decrypt", "--key", KEY_128], &input);

    assert_eq!(
        as_cfb8[0], as_cfb[0],
        "both XOR the first byte with MSB_8 of the same output block"
    );
    assert_ne!(as_cfb8[1..], as_cfb[1..], "and they diverge from the second byte on");
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("camellia128-cfb8", KEY16), ("camellia192-cfb8", KEY24), ("camellia256-cfb8", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length(
        "camellia128-cfb8",
        KEY16,
        &[],
        Framing { prefix: 16, suffix: 0, pads: false },
    );
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("camellia128-cfb8", KEY32, "Camellia-128 needs a 16-byte key, got 32 bytes"),
            ("camellia192-cfb8", KEY32, "Camellia-192 needs a 24-byte key, got 32 bytes"),
            ("camellia256-cfb8", KEY24, "Camellia-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    large_payload_on_an_error_path("camellia128-cfb8", KEY32, "Camellia-128 needs a 16-byte key");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["camellia128-cfb8", "camellia192-cfb8", "camellia256-cfb8"]);
}
