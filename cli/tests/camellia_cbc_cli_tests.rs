//! Tests for the `camellia128-cbc`, `camellia192-cbc` and `camellia256-cbc` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-cbc`
//! commands (`cli/src/helpers/block_mode_helpers.rs`), and `test_aes_cbc.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: the known-answer vectors in both
//! directions, the three key lengths, and that the commands exist and round-trip.
//!
//! Vectors are the `CAMELLIA-*-CBC` entries of OpenSSL's `evpciph_camellia.txt` (OpenSSL 3.6.2):
//! for each key length the first three entries chain into one three-block message under the IV
//! `000102..0f`; see `crypto/camellia/tests/openssl_cbc_tests.rs`. They are unpadded, so under
//! the commands' PKCS7 framing the three blocks are followed by one block of padding, computed
//! here from the permutation.

mod common;
use bouncycastle::camellia::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal,
};
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, large_payload_on_an_error_path, listed_in_help,
    round_trips, run_err, run_ok, tohex, unhex, wrong_key_lengths,
};

/// The IV of the first entry of every chain.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The three chained plaintext blocks.
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
);

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const CT_128: &str = concat!(
    "1607cf494b36bbf00daeb0b503c831ab",
    "a2f2cf671629ef7840c5a5dfb5074887",
    "0f06165008cf8b8b5a63586362543e54",
);

const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const CT_192: &str = concat!(
    "2a4830ab5ac4a1a2405955fd2195cf93",
    "5d5a869bd14ce54264f892a6dd2ec3d5",
    "37d359c3349836d884e310addf68c449",
);

const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const CT_256: &str = concat!(
    "e6cfa35fc02b134a4d2c0b6737ac3eda",
    "36cbeb73bd504b4070b1b7de2b21eb50",
    "e31a6055297d96ca3330cdf1b1860a83",
);

const VARIANTS: [(&str, &str, &str); 3] = [
    ("camellia128-cbc", KEY_128, CT_128),
    ("camellia192-cbc", KEY_192, CT_192),
    ("camellia256-cbc", KEY_256, CT_256),
];

/// `encrypt --iv` reproduces the OpenSSL ciphertext followed by the PKCS7 block, for all three
/// key lengths, and `decrypt --iv` takes that back to the plaintext.
#[test]
fn encrypt_matches_the_openssl_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let out = run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        let want = format!("{ct}{}", pkcs7_block(key, &ct[64..]));
        assert_eq!(tohex(&out), want, "{cmd} encrypt --iv should give the ciphertext");

        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key, "--iv", IV], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{cmd}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext and the
/// PKCS7 block, for all three key lengths.
#[test]
fn decrypt_matches_the_openssl_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{IV}{ct}{}", pkcs7_block(key, &ct[64..])));
        let out = run_ok(&[cmd, "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_256}{}", pkcs7_block(KEY_256, &CT_256[64..])));
    let out = run_ok(&["camellia256-cbc", "-d", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// A ciphertext without PKCS7 padding is rejected: the bare OpenSSL ciphertext ends in a block
/// that does not unpad.
#[test]
fn a_ciphertext_without_pkcs7_padding_is_rejected() {
    let input = unhex(&format!("{IV}{CT_128}"));
    let err = run_err(&["camellia128-cbc", "-d", "decrypt", "--key", KEY_128], &input);
    assert!(err.contains("decryption failed"), "stderr was: {err}");
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("camellia128-cbc", KEY16), ("camellia192-cbc", KEY24), ("camellia256-cbc", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: true },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("camellia128-cbc", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: true });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("camellia128-cbc", KEY32, "Camellia-128 needs a 16-byte key, got 32 bytes"),
            ("camellia192-cbc", KEY32, "Camellia-192 needs a 24-byte key, got 32 bytes"),
            ("camellia256-cbc", KEY24, "Camellia-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    large_payload_on_an_error_path("camellia128-cbc", KEY32, "Camellia-128 needs a 16-byte key");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["camellia128-cbc", "camellia192-cbc", "camellia256-cbc"]);
}

/// [`common::pkcs7_block`] at the key length `key_hex` has.
fn pkcs7_block(key_hex: &str, prev_hex: &str) -> String {
    match key_hex.len() / 2 {
        16 => common::pkcs7_block::<Camellia128Internal, 16>(key_hex, prev_hex),
        24 => common::pkcs7_block::<Camellia192Internal, 24>(key_hex, prev_hex),
        32 => common::pkcs7_block::<Camellia256Internal, 32>(key_hex, prev_hex),
        _ => panic!("not a Camellia key length"),
    }
}
