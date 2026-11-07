//! Tests for the `sm4-cfb8` subcommand.
//!
//! `sm4-cfb8` shares its key and IV loaders, streaming loops and error paths with the `aes*-cfb8`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_cfb8.sh` covers those
//! exhaustively. This file pins what is specific to SM4: the 16-byte key length, that the command
//! exists and round-trips at any length, and that what comes out really is CFB8 over SM4 rather
//! than some other mode.
//!
//! draft-ribose-cfrg-sm4-10 defines SM4-CFB-8 (Sec 8.5.1) but publishes no example of it, so there
//! is no vector to decrypt here. Instead the command is required to agree with
//! `bouncycastle_cipher::modes::Cfb8` over the SM4 permutation, which
//! `crypto/sm4/tests/stream_mode_tests.rs` pins against the Sec 8.5.2 equations. That is the same
//! thing the AES CFB8 suite gets from SP 800-38A F.3, one step removed.

mod common;
use bouncycastle::cipher::modes::CFB8;
use bouncycastle::sm4::SM4Key;
use common::{
    Framing, KEY16, KEY32, any_input_length, key_object, large_payload_on_an_error_path,
    library_stream_decrypt, listed_in_help, pseudo_random, round_trips, run_ok, unhex,
    wrong_key_lengths,
};

/// The single SM4 key length.
const KEY: &str = "0123456789abcdeffedcba9876543210";

/// What the command emits must be exactly what `Cfb8` over `SM4` produces: take the IV the CLI
/// generated, hand the body to the library, and the plaintext must come back.
#[test]
fn the_command_is_cfb8_over_sm4() {
    for len in [1usize, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);
        let out = run_ok(&["sm4-cfb8", "-d", "encrypt", "--key", KEY], &plaintext);
        assert_eq!(out.len(), 16 + len, "len {len}: IV block plus an equal-length body");

        let (iv, body) = out.split_at(16);
        let mut recovered = body.to_vec();
        library_stream_decrypt::<16, 16, _>(
            &key_object::<16, SM4Key<CFB8>>(KEY),
            iv,
            &mut recovered,
        );
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");
    }
}

/// With `--iv` the output is the ciphertext alone, and it is still `Cfb8` over `SM4` under that
/// IV.
#[test]
fn a_supplied_iv_is_used_and_not_written() {
    let iv = "000102030405060708090a0b0c0d0e0f";
    let plaintext = pseudo_random(37, 5);
    let out = run_ok(&["sm4-cfb8", "-d", "encrypt", "--key", KEY, "--iv", iv], &plaintext);
    assert_eq!(out.len(), plaintext.len(), "ciphertext only, no IV in band");

    let mut recovered = out.clone();
    library_stream_decrypt::<16, 16, _>(
        &key_object::<16, SM4Key<CFB8>>(KEY),
        &unhex(iv),
        &mut recovered,
    );
    assert_eq!(recovered, plaintext, "the CLI should agree with the library under that IV");

    let back = run_ok(&["sm4-cfb8", "-d", "decrypt", "--key", KEY, "--iv", iv], &out);
    assert_eq!(back, plaintext);
}

/// CFB8 and CFB128 are different modes, and `sm4-cfb8` must not be a second name for `sm4-cfb`:
/// handed the same IV and ciphertext, the two commands disagree past the first byte.
#[test]
fn sm4_cfb8_is_not_sm4_cfb() {
    let iv = "000102030405060708090a0b0c0d0e0f";
    let body = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb";
    let input = unhex(&format!("{iv}{body}"));

    let as_cfb8 = run_ok(&["sm4-cfb8", "-d", "decrypt", "--key", KEY], &input);
    let as_cfb = run_ok(&["sm4-cfb", "-d", "decrypt", "--key", KEY], &input);

    assert_eq!(
        as_cfb8[0], as_cfb[0],
        "both XOR the first byte with MSB_8 of the same output block"
    );
    assert_ne!(as_cfb8[1..], as_cfb[1..], "and they diverge from the second byte on");
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(&[("sm4-cfb8", KEY16)], &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("sm4-cfb8", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(&[("sm4-cfb8", KEY32, "SM4 needs a 16-byte key, got 32 bytes")], &[]);
}

#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    large_payload_on_an_error_path("sm4-cfb8", KEY32, "SM4 needs a 16-byte key");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["sm4-cfb8"]);
}
