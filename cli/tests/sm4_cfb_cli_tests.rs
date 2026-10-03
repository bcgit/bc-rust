//! Tests for the `sm4-cfb` subcommand.
//!
//! `sm4-cfb` shares its key loader, streaming loops and error paths with the `aes*-cfb` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_cfb_cli_tests.rs` covers those exhaustively.
//! This file pins what is specific to SM4: the known-answer vectors, the 16-byte key length, and
//! that the command exists and round-trips at any length.
//!
//! Vectors are the SM4-CFB examples of draft-ribose-cfrg-sm4-10 Appendix A.2.4.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// Appendix A.2 IV, shared by both CFB examples.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The two Appendix A.2.4 plaintext blocks.
const PLAINTEXT: &str = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb";

/// A.2.4.1 key and ciphertext.
const KEY_1: &str = "0123456789abcdeffedcba9876543210";
const CT_1: &str = "ac3236cb861dd316e6413b4e3c7524b769d4c54ed433b9a0346009beb37b2b3f";

/// A.2.4.2 key and ciphertext.
const KEY_2: &str = "fedcba98765432100123456789abcdef";
const CT_2: &str = "5dcccd25a84ba16560d7f265887068490d9b86ff20c3bfe115ffa02ca6192cc5";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");

    // The error-path tests hand a rejected key to a command that `exit`s before it ever reads
    // stdin, so this write races the child's exit and sometimes loses -- reliably so on a loaded
    // CI runner. That is an expected outcome, not a harness failure: `wait_with_output` still
    // returns the exit status and stderr, which is all those tests assert on. Any other write
    // error is a real problem and still panics.
    match child.stdin.as_mut().expect("stdin piped").write_all(stdin_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to stdin: {e}"),
    }

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

/// Deterministic pseudo-random bytes, so the tests do not depend on an RNG.
fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}
/// `decrypt` reproduces the draft's plaintext when handed the draft's IV followed by its
/// ciphertext, for both Appendix A.2.4 examples.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round trip below and, at
/// the library level, by `crypto/sm4/tests/stream_mode_tests.rs`.
#[test]
fn decrypt_matches_appendix_a_2_4_vectors() {
    for (section, key, ct) in [("A.2.4.1", KEY_1, CT_1), ("A.2.4.2", KEY_2, CT_2)] {
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&["sm4-cfb", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{section}: sm4-cfb decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_1}"));
    let out = run_ok(&["sm4-cfb", "decrypt", "--key", KEY_1, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// `encrypt | decrypt` composes: the IV rides in the first block, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext = pseudo_random(4096, 0xC0FFEE);

    let ciphertext = run_ok(&["sm4-cfb", "encrypt", "--key", KEY_1], &plaintext);
    assert_eq!(ciphertext.len(), 16 + plaintext.len(), "IV block plus an equal-length body");
    assert_ne!(&ciphertext[16..], &plaintext[..]);

    let recovered = run_ok(&["sm4-cfb", "decrypt", "--key", KEY_1], &ciphertext);
    assert_eq!(recovered, plaintext);
}

/// Unlike `sm4-cbc`, any length is accepted and nothing is padded: CFB is a stream cipher.
#[test]
fn any_input_length_is_accepted() {
    for len in [0usize, 1, 15, 17, 33] {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&["sm4-cfb", "encrypt", "--key", KEY_1], &plaintext);
        assert_eq!(ciphertext.len(), 16 + len, "len {len}: IV plus an equal-length body");
        let recovered = run_ok(&["sm4-cfb", "decrypt", "--key", KEY_1], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// SM4 has exactly one key length. An AES-256-sized key is an error naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    let err = run_err(&["sm4-cfb", "encrypt", "--key", key_256], &[0u8; 16]);
    assert!(err.contains("SM4 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
}

/// The subcommand is discoverable.
#[test]
fn the_subcommand_is_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    assert!(String::from_utf8_lossy(&out).contains("sm4-cfb"), "`--help` should list sm4-cfb");
}
