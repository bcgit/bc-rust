//! Tests for the `aria128-ccm`, `aria192-ccm` and `aria256-ccm` subcommands.
//!
//! They are the `aes*-ccm` commands' runner over the ARIA keys (`cli/src/aes_ccm_cmd.rs`), and
//! `test_aes_ccm.sh` covers the nonce and tag-length rules, the AAD flags and the error paths.
//! This file pins what is specific to ARIA: a Wycheproof known answer in both directions at two
//! key lengths, the tag check, and that the commands exist and round-trip.
//!
//! The known answers are Project Wycheproof's `testvectors_v1/aria_ccm_test.json` tcId 12
//! (ARIA-128) and tcId 168 (ARIA-256), both with a 12-byte nonce, a 16-byte tag, 8 bytes of AAD
//! and a 16-byte message; the crate's `ccm_wycheproof.rs` runs them with the rest of the file.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// (command, key, nonce, aad, msg, ct, tag)
const VECTORS: [(&str, &str, &str, &str, &str, &str, &str); 2] = [
    (
        "aria128-ccm",
        "9415f925bcb41dc25e86c826dbc8bf68",
        "bdffaa763b916ff0ee3f3ce4",
        "705d676cd8a94451",
        "feb36167eafc02c8e2bd6e13817686ba",
        "bc36f9442e9424fa66f644e59c7ff2bf",
        "331458cc757b0664724f492231c833b4",
    ),
    (
        "aria256-ccm",
        "b907a45075513fe8a8019edee3f2591487b2a030b03c6e1d771c862571d2ea1e",
        "118a6964c2d3e380071f5266",
        "034585621af8d7ff",
        "55a465644f5b650928cbee7c063214d6",
        "37d564930061ffe706bc494ce71b4c3a",
        "045d2149987ecce6ec6b089ab5c9ae84",
    ),
];

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

/// Any length round-trips at every key length, with the default 16-byte tag and a shorter one.
#[test]
fn encrypt_then_decrypt_round_trips_at_every_key_length() {
    let message: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    for (cmd, key) in [
        ("aria128-ccm", "000102030405060708090a0b0c0d0e0f"),
        ("aria192-ccm", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("aria256-ccm", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    ] {
        for tag_len in ["16", "8"] {
            let nonce = "000102030405060708090a0b";
            let base = [cmd, "--key", key, "--nonce", nonce, "--tag-len", tag_len];
            let ct = run_ok(&[&base[..], &["-d", "encrypt"]].concat(), &message);
            assert_eq!(ct.len(), message.len() + tag_len.parse::<usize>().unwrap(), "{cmd}");
            let back = run_ok(&[&base[..], &["-d", "decrypt"]].concat(), &ct);
            assert_eq!(back, message, "{cmd}");
        }
    }
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(
        &["aria128-ccm", "-d", "encrypt", "--key", "0011", "--nonce", "000102030405060708090a0b"],
        b"x",
    );
    assert!(err.contains("16-byte key"), "{err}");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    let help = String::from_utf8(run_ok(&["--help"], b"")).unwrap();
    for name in ["aria128-ccm", "aria192-ccm", "aria256-ccm"] {
        assert!(help.contains(name), "--help should list {name}");
    }
}
