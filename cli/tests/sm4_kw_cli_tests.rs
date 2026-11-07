//! Tests for the `sm4-kw` and `sm4-kwp` subcommands.
//!
//! They share everything but the key type with the `aes*-kw` / `aes*-kwp` commands, whose
//! `test_aes_kw.sh` covers the command-line contract exhaustively. No key-wrap vectors are
//! published for SM4 (the composition is pinned against RFC 3394 and RFC 5649 in
//! `crypto/sm4/tests/kw_reference_tests.rs`), so this file checks the commands against the
//! library's own answer, and that they exist, fail closed and are listed.

use bouncycastle::cipher::modes::{KW, KWP};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::symmetric_key::{FromKeyMaterial, KeyWrappingKey};
use bouncycastle::sm4::SM4Key;
use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

const KEK: &str = "0123456789abcdeffedcba9876543210";
const KEY_DATA: &str = "00112233445566778899aabbccddeeff0011223344556677";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");
    // A command that exits before reading stdin makes this write race its exit; that is the
    // expected outcome for the error-path tests, which assert on the status and stderr only.
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
    assert!(
        !out.status.success(),
        "expected failure from {args:?}, but it succeeded\nstdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(out.stdout.is_empty(), "a rejected unwrap must write nothing: {args:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The library's own answer for `data` under `KEK`, wrapped (`kwp == false`) or padded.
fn library_wrap(data: &[u8], kwp: bool) -> Vec<u8> {
    let kek: [u8; 16] = unhex(KEK).try_into().unwrap();
    let material = KeyMaterial::<16>::from_bytes_as_type(&kek, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    if kwp {
        SM4Key::<KWP>::from_key_material(&material).unwrap().wrap(data).unwrap()
    } else {
        SM4Key::<KW>::from_key_material(&material).unwrap().wrap(data).unwrap()
    }
}

#[test]
fn the_commands_agree_with_the_library_in_both_directions() {
    for (cmd, kwp) in [("sm4-kw", false), ("sm4-kwp", true)] {
        let expected = library_wrap(&unhex(KEY_DATA), kwp);
        let wrapped = run_ok(&[cmd, "-d", "encrypt", "--key", KEK], &unhex(KEY_DATA));
        assert_eq!(wrapped, expected, "{cmd} wrap");
        let hex = run_ok(&[cmd, "-d", "encrypt", "--key", KEK, "-x"], &unhex(KEY_DATA));
        assert_eq!(String::from_utf8_lossy(&hex).trim(), tohex(&expected), "{cmd} wrap -x");
        let unwrapped = run_ok(&[cmd, "-d", "decrypt", "--key", KEK], &expected);
        assert_eq!(tohex(&unwrapped), KEY_DATA, "{cmd} unwrap");
    }
}

#[test]
fn a_tampered_ciphertext_and_the_wrong_kek_are_rejected() {
    for (cmd, kwp) in [("sm4-kw", false), ("sm4-kwp", true)] {
        let ct = library_wrap(&unhex(KEY_DATA), kwp);
        let mut bad = ct.clone();
        bad[13] ^= 0x01;
        let err = run_err(&[cmd, "-d", "decrypt", "--key", KEK], &bad);
        assert!(err.contains("not an authentic"), "{cmd}: {err}");
        let mut wrong = unhex(KEK);
        wrong[0] ^= 0x01;
        let err = run_err(&[cmd, "-d", "decrypt", "--key", &tohex(&wrong)], &ct);
        assert!(err.contains("not an authentic"), "{cmd}: {err}");
    }
}

#[test]
fn kw_refuses_what_kwp_takes() {
    let unaligned = [0x5Au8; 20];
    let err = run_err(&["sm4-kw", "-d", "encrypt", "--key", KEK], &unaligned);
    assert!(err.contains("20 bytes rejected"), "{err}");
    let wrapped = run_ok(&["sm4-kwp", "-d", "encrypt", "--key", KEK], &unaligned);
    assert_eq!(wrapped.len(), 32, "20 bytes pad to 24, plus the header");
    let back = run_ok(&["sm4-kwp", "-d", "decrypt", "--key", KEK], &wrapped);
    assert_eq!(back, unaligned);
}

#[test]
fn the_subcommands_are_listed_in_help() {
    let help = String::from_utf8(run_ok(&["--help"], b"")).unwrap();
    for cmd in ["sm4-kw", "sm4-kwp"] {
        assert!(help.contains(cmd), "--help should list {cmd}");
    }
}
