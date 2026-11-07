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

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

const WP_KEY: &str = "28ff3def08179311e2734c6d1c4e2871";
const WP_IV: &str = "32bcb9b569e3b852d37c766a";
const WP_AAD: &str = "c3";
const WP_MSG: &str = "dfc61a20df8505b53e3cd59f25770d5018add3d6";
const WP_CT: &str = "8071025813ba6138d92d16449f95c9dbdfa50bd0";
const WP_TAG: &str = "e766554d68d47e6974d51aaed467f3fb";

fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");
    match child.stdin.as_mut().expect("stdin piped").write_all(stdin_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to stdin: {e}"),
    }
    child.wait_with_output().expect("failed to wait for bc-rust")
}

fn run_ok(args: &[&str], stdin_bytes: &[u8]) -> Vec<u8> {
    let out = run(args, stdin_bytes);
    assert!(
        out.status.success(),
        "expected success from {args:?}, got {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn run_err(args: &[&str], stdin_bytes: &[u8]) -> String {
    let out = run(args, stdin_bytes);
    assert!(!out.status.success(), "expected failure from {args:?}, but it succeeded");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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

/// Without `--iv` the command draws one and writes it first; the round trip works at every key
/// length and the output is 12 + len + 16 bytes.
#[test]
fn encrypt_then_decrypt_round_trips_at_every_key_length() {
    let message: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    for (cmd, key) in [
        ("aria128-gcm", "000102030405060708090a0b0c0d0e0f"),
        ("aria192-gcm", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("aria256-gcm", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    ] {
        let ct = run_ok(&[cmd, "-d", "encrypt", "--key", key], &message);
        assert_eq!(ct.len(), 12 + message.len() + 16, "{cmd}: IV || ciphertext || tag");
        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key], &ct);
        assert_eq!(back, message, "{cmd}");
        let again = run_ok(&[cmd, "-d", "encrypt", "--key", key], &message);
        assert_ne!(again[..12], ct[..12], "{cmd}: a fresh IV each time");
    }
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["aria128-gcm", "-d", "encrypt", "--key", "0011"], b"x");
    assert!(err.contains("16-byte key"), "{err}");
    let err = run_err(&["aria256-gcm", "-d", "encrypt", "--key", WP_KEY], b"x");
    assert!(err.contains("32-byte key"), "{err}");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    let help = String::from_utf8(run_ok(&["--help"], b"")).unwrap();
    for name in ["aria128-gcm", "aria192-gcm", "aria256-gcm"] {
        assert!(help.contains(name), "--help should list {name}");
    }
}
