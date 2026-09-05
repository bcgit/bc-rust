//! Tests for the `sm4-cbc` subcommand.
//!
//! `sm4-cbc` shares its key loader, streaming loops and error paths with the `aes*-cbc` commands
//! (`cli/src/cbc_cmd.rs`), and `aes_cbc_cli_tests.rs` covers those exhaustively. This file pins
//! what is specific to SM4: the known-answer vectors, the 16-byte key length, and that the
//! command exists and round-trips.
//!
//! Vectors are the SM4-CBC examples of draft-ribose-cfrg-sm4-10 Appendix A.2.2.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// Appendix A.2 IV, shared by both CBC examples.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The two Appendix A.2 plaintext blocks.
const PLAINTEXT: &str = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb";

/// A.2.2.1 key and ciphertext.
const KEY_1: &str = "0123456789abcdeffedcba9876543210";
const CT_1: &str = "78ebb11cc40b0a48312aaeb2040244cb4cb7016951909226979b0d15dc6a8f6d";

/// A.2.2.2 key and ciphertext.
const KEY_2: &str = "fedcba98765432100123456789abcdef";
const CT_2: &str = "0d3a6ddc2d21c698857215587b7bb59a91f2c147911a4144665e1fa1d40bae38";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");

    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(stdin_bytes)
        .expect("failed to write to stdin");

    child.wait_with_output().expect("failed to wait for bc-rust")
}

/// Runs a command that is expected to succeed, returning stdout.
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

/// Runs a command that is expected to fail, returning stderr as a string.
fn run_err(args: &[&str], stdin_bytes: &[u8]) -> String {
    let out = run(args, stdin_bytes);
    assert!(
        !out.status.success(),
        "expected failure from {args:?}, but it succeeded\nstdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `decrypt` reproduces the draft's plaintext when handed the draft's IV followed by its
/// ciphertext, for both Appendix A.2.2 examples.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round trip below and, at
/// the library level, by `crypto/sm4/tests/draft_modes_tests.rs`.
#[test]
fn decrypt_matches_appendix_a_2_2_vectors() {
    for (section, key, ct) in [("A.2.2.1", KEY_1, CT_1), ("A.2.2.2", KEY_2, CT_2)] {
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&["sm4-cbc", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{section}: sm4-cbc decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_1}"));
    let out = run_ok(&["sm4-cbc", "decrypt", "--key", KEY_1, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// `encrypt | decrypt` composes: the IV rides in the first block, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect();

    let ciphertext = run_ok(&["sm4-cbc", "encrypt", "--key", KEY_1], &plaintext);
    assert_eq!(ciphertext.len(), 16 + plaintext.len(), "IV block plus one block per input block");
    assert_ne!(&ciphertext[16..], &plaintext[..]);

    let recovered = run_ok(&["sm4-cbc", "decrypt", "--key", KEY_1], &ciphertext);
    assert_eq!(recovered, plaintext);
}

/// SM4 has exactly one key length. An AES-256-sized key is an error naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    let err = run_err(&["sm4-cbc", "encrypt", "--key", key_256], &[0u8; 16]);
    assert!(err.contains("SM4 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
}

/// Unaligned input is rejected, as for the AES commands.
#[test]
fn unaligned_input_is_rejected() {
    let err = run_err(&["sm4-cbc", "encrypt", "--key", KEY_1], &[0u8; 17]);
    assert!(err.contains("not a whole number of 16-byte blocks"), "stderr was: {err}");
}
