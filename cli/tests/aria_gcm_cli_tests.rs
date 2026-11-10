//! Tests for the `aria128-gcm`, `aria192-gcm` and `aria256-gcm` subcommands.
//!
//! They share their key, IV and AAD loaders, streaming loops and error paths with the `aes*-gcm`
//! commands (`cli/src/helpers/aead_cipher_helpers.rs`), and `test_aes_gcm.sh` covers those
//! exhaustively. This file pins what is specific to ARIA: a Wycheproof known answer in both
//! directions, the three key lengths, the tag check, and that the commands exist and round-trip.
//!
//! The known answer is Project Wycheproof's `testvectors_v1/aria_gcm_test.json` tcId 9 (ARIA-128,
//! a 96-bit IV, a 128-bit tag, 1 byte of AAD, a 20-byte message), which the crate's
//! `gcm_wycheproof.rs` runs with the rest of the file.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, listed_in_help, round_trips, run_err, run_ok,
    tohex, unhex, wrong_key_lengths,
};

const WP_KEY: &str = "28ff3def08179311e2734c6d1c4e2871";
const WP_IV: &str = "32bcb9b569e3b852d37c766a";
const WP_AAD: &str = "c3";
const WP_MSG: &str = "dfc61a20df8505b53e3cd59f25770d5018add3d6";
const WP_CT: &str = "8071025813ba6138d92d16449f95c9dbdfa50bd0";
const WP_TAG: &str = "e766554d68d47e6974d51aaed467f3fb";

/// `encrypt --iv` reproduces the Wycheproof ciphertext and tag, as `ciphertext || tag`, and
/// `decrypt --iv` takes them back to the message.
#[test]
fn encrypt_and_decrypt_match_the_wycheproof_vector() {
    let args = ["aria128-gcm", "--key", WP_KEY, "--iv", WP_IV, "--aad", WP_AAD];
    let out = run_ok(&[&args[..], &["-d", "encrypt"]].concat(), &unhex(WP_MSG));
    assert_eq!(tohex(&out), format!("{WP_CT}{WP_TAG}"), "ciphertext || tag");
    let back = run_ok(&[&args[..], &["-d", "decrypt"]].concat(), &out);
    assert_eq!(tohex(&back), WP_MSG);
}

/// A flipped ciphertext bit, a flipped tag bit, other AAD or another key fails the tag check.
#[test]
fn tampering_fails_the_tag_check() {
    let mut ct = unhex(&format!("{WP_CT}{WP_TAG}"));
    let args = ["aria128-gcm", "-d", "decrypt", "--key", WP_KEY, "--iv", WP_IV, "--aad", WP_AAD];
    run_ok(&args, &ct);
    ct[0] ^= 1;
    assert!(run_err(&args, &ct).contains("authentication failed"));
    ct[0] ^= 1;
    let last = ct.len() - 1;
    ct[last] ^= 1;
    assert!(run_err(&args, &ct).contains("authentication failed"));
    ct[last] ^= 1;
    let other_aad = ["aria128-gcm", "-d", "decrypt", "--key", WP_KEY, "--iv", WP_IV, "--aad", "c4"];
    assert!(run_err(&other_aad, &ct).contains("authentication failed"));
    let other_key = [
        "aria128-gcm",
        "-d",
        "decrypt",
        "--key",
        "28ff3def08179311e2734c6d1c4e2870",
        "--iv",
        WP_IV,
        "--aad",
        WP_AAD,
    ];
    assert!(run_err(&other_key, &ct).contains("authentication failed"));
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("aria128-gcm", KEY16), ("aria192-gcm", KEY24), ("aria256-gcm", KEY32)],
        &[],
        Framing { prefix: 12, suffix: 16, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("aria128-gcm", KEY16, &[], Framing { prefix: 12, suffix: 16, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("aria128-gcm", KEY32, "ARIA-128 needs a 16-byte key, got 32 bytes"),
            ("aria192-gcm", KEY32, "ARIA-192 needs a 24-byte key, got 32 bytes"),
            ("aria256-gcm", KEY24, "ARIA-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["aria128-gcm", "aria192-gcm", "aria256-gcm"]);
}
