//! Tests for the `camellia128-ccm`, `camellia192-ccm` and `camellia256-ccm` subcommands.
//!
//! They are the `aes*-ccm` commands' runner over the Camellia keys (`cli/src/aes_ccm_cmd.rs`), and
//! `test_aes_ccm.sh` covers the nonce and tag-length rules, the AAD flags and the error paths.
//! This file pins what is specific to Camellia: a Wycheproof known answer in both directions at two
//! key lengths, the tag check, and that the commands exist and round-trip.
//!
//! The known answers are Project Wycheproof's `testvectors_v1/camellia_ccm_test.json` tcId 12
//! (Camellia-128) and tcId 168 (Camellia-256), both with a 12-byte nonce, a 16-byte tag, 8 bytes of AAD
//! and a 16-byte message; the crate's `ccm_wycheproof.rs` runs them with the rest of the file.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, listed_in_help, round_trips, run, run_err,
    run_ok, tohex, unhex, wrong_key_lengths,
};

/// (command, key, nonce, aad, msg, ct, tag)
const VECTORS: [(&str, &str, &str, &str, &str, &str, &str); 2] = [
    (
        "camellia128-ccm",
        "9415f925bcb41dc25e86c826dbc8bf68",
        "bdffaa763b916ff0ee3f3ce4",
        "705d676cd8a94451",
        "feb36167eafc02c8e2bd6e13817686ba",
        "5e9f70ff539eb2bc8dd347885a364fe4",
        "bda220f3fb6e62b4b72b0cf59fb66436",
    ),
    (
        "camellia256-ccm",
        "b907a45075513fe8a8019edee3f2591487b2a030b03c6e1d771c862571d2ea1e",
        "118a6964c2d3e380071f5266",
        "034585621af8d7ff",
        "55a465644f5b650928cbee7c063214d6",
        "577955b16fd98bc26040d52c574b5377",
        "009906b169bb506d524a0a11f758b465",
    ),
];

/// `encrypt` reproduces the Wycheproof ciphertext and tag, as `ciphertext || tag`, and
/// `decrypt` takes them back to the message, at both key lengths.
#[test]
fn encrypt_and_decrypt_match_the_wycheproof_vectors() {
    for (cmd, key, nonce, aad, msg, ct, tag) in VECTORS {
        let args = [cmd, "--key", key, "--nonce", nonce, "--aad", aad];
        let out = run_ok(&[&args[..], &["-d", "encrypt"]].concat(), &unhex(msg));
        assert_eq!(tohex(&out), format!("{ct}{tag}"), "{cmd}: ciphertext || tag");
        let back = run_ok(&[&args[..], &["-d", "decrypt"]].concat(), &out);
        assert_eq!(tohex(&back), msg, "{cmd}");
    }
}

/// A flipped ciphertext bit, a flipped tag bit, other AAD or another nonce fails the tag check,
/// and nothing is written.
#[test]
fn tampering_fails_the_tag_check() {
    let (cmd, key, nonce, aad, _msg, ct, tag) = VECTORS[0];
    let mut bytes = unhex(&format!("{ct}{tag}"));
    let args = [cmd, "-d", "decrypt", "--key", key, "--nonce", nonce, "--aad", aad];
    run_ok(&args, &bytes);
    bytes[0] ^= 1;
    assert!(run_err(&args, &bytes).contains("authentic"));
    bytes[0] ^= 1;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let out = run(&args, &bytes);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "no plaintext before the tag has verified");
    bytes[last] ^= 1;
    let other_aad =
        [cmd, "-d", "decrypt", "--key", key, "--nonce", nonce, "--aad", "705d676cd8a94450"];
    assert!(run_err(&other_aad, &bytes).contains("authentic"));
    let other_nonce =
        [cmd, "-d", "decrypt", "--key", key, "--nonce", "bdffaa763b916ff0ee3f3ce5", "--aad", aad];
    assert!(run_err(&other_nonce, &bytes).contains("authentic"));
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("camellia128-ccm", KEY16), ("camellia192-ccm", KEY24), ("camellia256-ccm", KEY32)],
        &["--nonce", "000102030405060708090a0b"],
        Framing { prefix: 0, suffix: 16, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length(
        "camellia128-ccm",
        KEY16,
        &["--nonce", "000102030405060708090a0b"],
        Framing { prefix: 0, suffix: 16, pads: false },
    );
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("camellia128-ccm", KEY32, "Camellia-128 needs a 16-byte key, got 32 bytes"),
            ("camellia192-ccm", KEY32, "Camellia-192 needs a 24-byte key, got 32 bytes"),
            ("camellia256-ccm", KEY24, "Camellia-256 needs a 32-byte key, got 24 bytes"),
        ],
        &["--nonce", "000102030405060708090a0b"],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["camellia128-ccm", "camellia192-ccm", "camellia256-ccm"]);
}
