//! Tests for the `camellia128-cbc`, `camellia192-cbc` and `camellia256-cbc` subcommands.
//!
//! They share their key loader, streaming loops and error paths with the `aes*-cbc` commands
//! (`cli/src/cbc_cmd.rs`), and `aes_cbc_cli_tests.rs` covers those exhaustively. This file pins
//! what is specific to Camellia: the known-answer vectors, the three key lengths, and that the
//! commands exist and round-trip.
//!
//! Vectors are the `CAMELLIA-*-CBC` entries of OpenSSL's `evpciph_camellia.txt` (OpenSSL 3.6.2):
//! for each key length the first three entries chain into one three-block message under the IV
//! `000102..0f`; see `crypto/camellia/tests/openssl_cbc_tests.rs`.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The IV of the first entry of every chain.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The three chained plaintext blocks.
const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52ef";

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const CT_128: &str = "1607cf494b36bbf00daeb0b503c831aba2f2cf671629ef7840c5a5dfb50748870f06165008cf8b8b5a63586362543e54";

const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const CT_192: &str = "2a4830ab5ac4a1a2405955fd2195cf935d5a869bd14ce54264f892a6dd2ec3d537d359c3349836d884e310addf68c449";

const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const CT_256: &str = "e6cfa35fc02b134a4d2c0b6737ac3eda36cbeb73bd504b4070b1b7de2b21eb50e31a6055297d96ca3330cdf1b1860a83";

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

const VARIANTS: [(&str, &str, &str); 3] = [
    ("camellia128-cbc", KEY_128, CT_128),
    ("camellia192-cbc", KEY_192, CT_192),
    ("camellia256-cbc", KEY_256, CT_256),
];

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext, for all
/// three key lengths.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round trip below and, at
/// the library level, by `crypto/camellia/tests/openssl_cbc_tests.rs`.
#[test]
fn decrypt_matches_the_openssl_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_256}"));
    let out = run_ok(&["camellia256-cbc", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// `encrypt | decrypt` composes: the IV rides in the first block, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect();

    for (cmd, key, _) in VARIANTS {
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
        assert_eq!(
            ciphertext.len(),
            16 + plaintext.len(),
            "{cmd}: IV block plus one block per input block"
        );
        assert_ne!(&ciphertext[16..], &plaintext[..]);

        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}");
    }
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and the
/// 128-bit key to the 192-bit command, are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["camellia128-cbc", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("Camellia-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia192-cbc", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("Camellia-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia256-cbc", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("Camellia-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// Unaligned input is rejected, as for the AES commands.
#[test]
fn unaligned_input_is_rejected() {
    let err = run_err(&["camellia128-cbc", "encrypt", "--key", KEY_128], &[0u8; 17]);
    assert!(err.contains("not a whole number of 16-byte blocks"), "stderr was: {err}");
}
