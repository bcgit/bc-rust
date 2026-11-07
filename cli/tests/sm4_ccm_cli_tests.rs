//! Tests for the `sm4-ccm` subcommand.
//!
//! It is the `aes*-ccm` commands' runner over the SM4 key (`cli/src/aes_ccm_cmd.rs`), and
//! `test_aes_ccm.sh` covers the nonce and tag-length rules, the AAD flags and the error paths.
//! This file pins what is specific to SM4: RFC 8998 Appendix A.2's `AEAD_SM4_CCM` vector and a
//! Wycheproof known answer in both directions, the tag check, and that the command exists and
//! round-trips.
//!
//! The Wycheproof case is `testvectors_v1/sm4_ccm_test.json` tcId 12 (a 12-byte nonce, a 16-byte
//! tag, 8 bytes of AAD, a 16-byte message), which the crate's `ccm_wycheproof.rs` runs with the
//! rest of the file; RFC 8998's vector is transcribed from the downloaded text of the RFC and
//! pinned in the crate's `rfc8998_tests.rs` too.

mod common;
use common::{
    Framing, KEY16, KEY32, any_input_length, listed_in_help, round_trips, run, run_err, run_ok,
    tohex, unhex, wrong_key_lengths,
};

/// (command, key, nonce, aad, msg, ct, tag): RFC 8998 Appendix A.2, then Wycheproof tcId 12.
const VECTORS: [(&str, &str, &str, &str, &str, &str, &str); 2] = [
    (
        "sm4-ccm",
        "0123456789abcdeffedcba9876543210",
        "00001234567800000000abcd",
        "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
        "48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b",
        "16842d4fa186f56ab33256971fa110f4",
    ),
    (
        "sm4-ccm",
        "9415f925bcb41dc25e86c826dbc8bf68",
        "bdffaa763b916ff0ee3f3ce4",
        "705d676cd8a94451",
        "feb36167eafc02c8e2bd6e13817686ba",
        "d6301ac033e319d1ee7be5ac3520b78c",
        "ac84f69adb93437df53a8b0c4a8a81e1",
    ),
];

/// `encrypt` reproduces the RFC 8998 and Wycheproof ciphertexts and tags, as `ciphertext || tag`,
/// and `decrypt` takes them back to the message.
#[test]
fn encrypt_and_decrypt_match_the_published_vectors() {
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
    let (cmd, key, nonce, aad, _msg, ct, tag) = VECTORS[1];
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
        &[("sm4-ccm", KEY16)],
        &["--nonce", "000102030405060708090a0b"],
        Framing { prefix: 0, suffix: 16, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length(
        "sm4-ccm",
        KEY16,
        &["--nonce", "000102030405060708090a0b"],
        Framing { prefix: 0, suffix: 16, pads: false },
    );
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[("sm4-ccm", KEY32, "SM4 needs a 16-byte key, got 32 bytes")],
        &["--nonce", "000102030405060708090a0b"],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["sm4-ccm"]);
}
