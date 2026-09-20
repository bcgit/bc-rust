//! Tests for the `sm4-ctr` subcommand.
//!
//! `sm4-ctr` shares its key loader, streaming loops and error paths with the `aes*-ctr` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_ctr_cli_tests.rs` covers those exhaustively. This file
//! pins what is specific to SM4: the 16-byte key length, the **12-byte** nonce, and that what comes
//! out really is CTR over SM4.
//!
//! draft-ribose-cfrg-sm4-10's Appendix A.2.5 examples make the whole 16-byte IV the first counter
//! block, which the 12-byte-nonce split these commands use cannot produce (see the `SM4_CTR` docs),
//! so there is no vector to decrypt here. Instead the command is required to agree with
//! `bouncycastle_modes::Ctr` over the SM4 permutation, which
//! `crypto/sm4/tests/stream_mode_tests.rs` pins against the Sec 8.7.1 equations.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The single SM4 key length.
const KEY: &str = "0123456789abcdeffedcba9876543210";

/// CTR writes a 12-byte nonce, not the 16-byte IV the other modes write.
const NONCE_LEN: usize = 12;

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
/// The library's answer for the same key, nonce and ciphertext, so the CLI can be held to it.
fn library_ctr_decrypt(key_hex: &str, nonce: &[u8], data: &mut [u8]) {
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::core::traits::StreamCipherDecryptor;
    use bouncycastle::modes::{Ctr, Decrypting};
    use bouncycastle::sm4::{CTR_NONCE_LEN, SM4};

    let key_bytes: [u8; 16] = unhex(key_hex).try_into().expect("a 16-byte key");
    let key = KeyMaterial::<16>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let nonce: [u8; CTR_NONCE_LEN] = nonce.try_into().expect("a 12-byte nonce");
    Ctr::<SM4, Decrypting, 16, 16, CTR_NONCE_LEN>::decrypt(&key, &nonce, data).expect("decryption");
}

/// What the command emits must be exactly what `Ctr` over `SM4` produces.
#[test]
fn the_command_is_ctr_over_sm4() {
    for len in [1usize, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);
        let out = run_ok(&["sm4-ctr", "encrypt", "--key", KEY], &plaintext);
        assert_eq!(out.len(), NONCE_LEN + len, "len {len}: nonce plus an equal-length body");

        let (nonce, body) = out.split_at(NONCE_LEN);
        let mut recovered = body.to_vec();
        library_ctr_decrypt(KEY, nonce, &mut recovered);
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");
    }
}

/// CTR writes a **12-byte** nonce where the other SM4 modes write a 16-byte IV, so the output is 12
/// bytes longer than the input rather than 16. Getting this wrong would shift every byte of the
/// payload.
#[test]
fn the_nonce_is_twelve_bytes_not_sixteen() {
    let plaintext = pseudo_random(64, 7);
    let out = run_ok(&["sm4-ctr", "encrypt", "--key", KEY], &plaintext);
    assert_eq!(out.len(), plaintext.len() + NONCE_LEN, "a 12-byte nonce plus the ciphertext");

    let via_cfb = run_ok(&["sm4-cfb", "encrypt", "--key", KEY], &plaintext);
    assert_eq!(via_cfb.len(), plaintext.len() + 16, "sm4-cfb writes a 16-byte IV");

    let back = run_ok(&["sm4-ctr", "decrypt", "--key", KEY], &out);
    assert_eq!(back, plaintext);
}

/// `encrypt | decrypt` composes at any length, with nothing padded.
#[test]
fn any_input_length_is_accepted_and_round_trips() {
    for len in [0usize, 1, 15, 17, 33, 4096] {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&["sm4-ctr", "encrypt", "--key", KEY], &plaintext);
        assert_eq!(ciphertext.len(), NONCE_LEN + len, "len {len}: nonce plus an equal-length body");
        let recovered = run_ok(&["sm4-ctr", "decrypt", "--key", KEY], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// A fresh nonce per invocation. For CTR this is the whole security argument: a repeated nonce
/// under one key repeats the keystream and leaks the XOR of the two messages.
#[test]
fn each_invocation_uses_a_fresh_nonce() {
    let plaintext = pseudo_random(64, 11);
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let ciphertext = run_ok(&["sm4-ctr", "encrypt", "--key", KEY], &plaintext);
        assert!(seen.insert(ciphertext[..NONCE_LEN].to_vec()), "the CLI reused a nonce");
        let recovered = run_ok(&["sm4-ctr", "decrypt", "--key", KEY], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let plaintext = pseudo_random(32, 3);
    let ciphertext = run_ok(&["sm4-ctr", "encrypt", "--key", KEY], &plaintext);

    let binary = run_ok(&["sm4-ctr", "decrypt", "--key", KEY], &ciphertext);
    let hex_out = run_ok(&["sm4-ctr", "decrypt", "--key", KEY, "-x"], &ciphertext);
    let hex_str = String::from_utf8(hex_out).expect("hex output is text");

    assert_eq!(hex_str, format!("{}\n", tohex(&binary)));
    assert_eq!(binary, plaintext);
}

/// SM4 has exactly one key length. An AES-256-sized key is an error naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    let err = run_err(&["sm4-ctr", "encrypt", "--key", key_256], &[0u8; 16]);
    assert!(err.contains("SM4 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
}

/// The subcommand is discoverable, and its help states the 12-byte nonce.
#[test]
fn the_subcommand_is_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    assert!(String::from_utf8_lossy(&out).contains("sm4-ctr"), "`--help` should list sm4-ctr");

    let out = run_ok(&["sm4-ctr", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(
        help.contains("FIRST 12 BYTES") || help.contains("first 12 bytes"),
        "help should say the nonce is 12 bytes: {help}"
    );
}
