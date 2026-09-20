//! Tests for the `camellia128-ctr`, `camellia192-ctr` and `camellia256-ctr` subcommands.
//!
//! They share their key loader, streaming loops and error paths with the `aes*-ctr` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_ctr_cli_tests.rs` covers those exhaustively. This file
//! pins what is specific to Camellia: the three key lengths, the **12-byte** nonce, and that what
//! comes out really is CTR over Camellia.
//!
//! RFC 5528's nine Camellia-CTR vectors divide the counter block differently -- a 4-octet nonce, an
//! 8-octet IV and a counter starting at one -- so they are not ones these commands can produce (see
//! the `Camellia_CTR_128` docs). Instead the commands are required to agree with
//! `bouncycastle_modes::Ctr` over the Camellia permutation, which
//! `crypto/camellia/tests/stream_mode_tests.rs` pins against the SP 800-38A Sec 6.5 equations, RFC
//! 5528's vectors included.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// CTR writes a 12-byte nonce, not the 16-byte IV the other modes write.
const NONCE_LEN: usize = 12;

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

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
fn library_ctr_decrypt<const KEY_LEN: usize, P>(key_hex: &str, nonce: &[u8], data: &mut [u8])
where
    P: bouncycastle::core::traits::ElectronicCodeBook<KEY_LEN, 16>,
{
    use bouncycastle::camellia::CTR_NONCE_LEN;
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::core::traits::StreamCipherDecryptor;
    use bouncycastle::modes::{Ctr, Decrypting};

    let key_bytes: [u8; KEY_LEN] = unhex(key_hex).try_into().expect("the right key length");
    let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let nonce: [u8; CTR_NONCE_LEN] = nonce.try_into().expect("a 12-byte nonce");
    Ctr::<P, Decrypting, KEY_LEN, 16, CTR_NONCE_LEN>::decrypt(&key, &nonce, data)
        .expect("decryption");
}

/// What each command emits must be exactly what `Ctr` over the matching permutation produces.
#[test]
fn the_commands_are_ctr_over_camellia() {
    use bouncycastle::camellia::{Camellia_128, Camellia_192, Camellia_256};

    for len in [1usize, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);

        let out = run_ok(&["camellia128-ctr", "encrypt", "--key", KEY_128], &plaintext);
        let (nonce, body) = out.split_at(NONCE_LEN);
        let mut recovered = body.to_vec();
        library_ctr_decrypt::<16, Camellia_128>(KEY_128, nonce, &mut recovered);
        assert_eq!(recovered, plaintext, "camellia128-ctr, len {len}");

        let out = run_ok(&["camellia192-ctr", "encrypt", "--key", KEY_192], &plaintext);
        let (nonce, body) = out.split_at(NONCE_LEN);
        let mut recovered = body.to_vec();
        library_ctr_decrypt::<24, Camellia_192>(KEY_192, nonce, &mut recovered);
        assert_eq!(recovered, plaintext, "camellia192-ctr, len {len}");

        let out = run_ok(&["camellia256-ctr", "encrypt", "--key", KEY_256], &plaintext);
        let (nonce, body) = out.split_at(NONCE_LEN);
        let mut recovered = body.to_vec();
        library_ctr_decrypt::<32, Camellia_256>(KEY_256, nonce, &mut recovered);
        assert_eq!(recovered, plaintext, "camellia256-ctr, len {len}");
    }
}

/// CTR writes a **12-byte** nonce where the other Camellia modes write a 16-byte IV, so the output
/// is 12 bytes longer than the input rather than 16. Getting this wrong would shift every byte of
/// the payload.
#[test]
fn the_nonce_is_twelve_bytes_not_sixteen() {
    let plaintext = pseudo_random(64, 7);
    let out = run_ok(&["camellia128-ctr", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(out.len(), plaintext.len() + NONCE_LEN, "a 12-byte nonce plus the ciphertext");

    let via_cfb = run_ok(&["camellia128-cfb", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(via_cfb.len(), plaintext.len() + 16, "camellia128-cfb writes a 16-byte IV");

    let back = run_ok(&["camellia128-ctr", "decrypt", "--key", KEY_128], &out);
    assert_eq!(back, plaintext);
}

/// `encrypt | decrypt` composes at any length, with nothing padded.
#[test]
fn any_input_length_is_accepted_and_round_trips() {
    for (cmd, key) in
        [("camellia128-ctr", KEY_128), ("camellia192-ctr", KEY_192), ("camellia256-ctr", KEY_256)]
    {
        for len in [0usize, 1, 15, 17, 33, 4096] {
            let plaintext = pseudo_random(len, len as u32);
            let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
            assert_eq!(ciphertext.len(), NONCE_LEN + len, "{cmd}, len {len}: nonce plus body");
            let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
            assert_eq!(recovered, plaintext, "{cmd}, len {len}: round trip");
        }
    }
}

/// A fresh nonce per invocation. For CTR this is the whole security argument: a repeated nonce
/// under one key repeats the keystream and leaks the XOR of the two messages.
#[test]
fn each_invocation_uses_a_fresh_nonce() {
    let plaintext = pseudo_random(64, 11);
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let ciphertext = run_ok(&["camellia128-ctr", "encrypt", "--key", KEY_128], &plaintext);
        assert!(seen.insert(ciphertext[..NONCE_LEN].to_vec()), "the CLI reused a nonce");
        let recovered = run_ok(&["camellia128-ctr", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let plaintext = pseudo_random(32, 3);
    let ciphertext = run_ok(&["camellia256-ctr", "encrypt", "--key", KEY_256], &plaintext);

    let binary = run_ok(&["camellia256-ctr", "decrypt", "--key", KEY_256], &ciphertext);
    let hex_out = run_ok(&["camellia256-ctr", "decrypt", "--key", KEY_256, "-x"], &ciphertext);
    let hex_str = String::from_utf8(hex_out).expect("hex output is text");

    assert_eq!(hex_str, format!("{}\n", tohex(&binary)));
    assert_eq!(binary, plaintext);
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and so on,
/// are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["camellia128-ctr", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("Camellia-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia192-ctr", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("Camellia-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia256-ctr", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("Camellia-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// The subcommands are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["camellia128-ctr", "camellia192-ctr", "camellia256-ctr"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}
