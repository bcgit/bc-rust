//! Tests for the `camellia128-gcm`, `camellia192-gcm` and `camellia256-gcm` subcommands.
//!
//! They share their key, IV and AAD loaders, streaming loops and error paths with the `aes*-gcm`
//! commands (`cli/src/helpers/aead_cipher_helpers.rs`), and `test_aes_gcm.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: a Wycheproof known answer in both
//! directions, the three key lengths, the tag check, and that the commands exist and round-trip.
//!
//! No published Camellia-GCM vector is in bc-test-data or Wycheproof, so instead of a known
//! answer the output is held to the library's own `Camellia128Key<GCM>`, whose `Gcm` code the AES
//! and ARIA Wycheproof suites pin.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

const KEY: &str = "28ff3def08179311e2734c6d1c4e2871";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

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

/// The library's answer for the same key, nonce, AAD and inline `ciphertext || tag`: the key
/// object's inline one-shot under `GCM`.
fn library_gcm_decrypt(key_hex: &str, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    use bouncycastle::camellia::Camellia128Key;
    use bouncycastle::cipher::modes::GCM;
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::core::symmetric_key::{AeadDecryptionKey, FromKeyMaterial};

    let key_bytes: [u8; 16] = unhex(key_hex).try_into().expect("a 16-byte key");
    let material = KeyMaterial::<16>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let key = Camellia128Key::<GCM>::from_key_material(&material).expect("a valid key");
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("a 12-byte nonce");
    key.decrypt_with_aad(&nonce, aad, ciphertext).expect("the tag verifies")
}

/// What the command emits must be exactly what the library's `GCM` key produces: the generated
/// nonce leads, the body is as long as the input, and the tag follows.
#[test]
fn the_command_is_gcm_over_camellia() {
    for len in [0usize, 1, 5, 16, 17, 64, 1000] {
        let plaintext = pseudo_random(len, len as u32);
        let out = run_ok(
            &["camellia128-gcm", "-d", "encrypt", "--key", KEY, "--aad", "deadbeef"],
            &plaintext,
        );
        assert_eq!(out.len(), NONCE_LEN + len + TAG_LEN, "len {len}: nonce, body and tag");
        let (nonce, body) = out.split_at(NONCE_LEN);
        let recovered = library_gcm_decrypt(KEY, nonce, &unhex("deadbeef"), body);
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");
        let back =
            run_ok(&["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &out);
        assert_eq!(back, plaintext, "len {len}: round trip");
    }
}

/// A flipped ciphertext bit, a flipped tag bit, other AAD or another key fails the tag check.
#[test]
fn tampering_fails_the_tag_check() {
    let plaintext = pseudo_random(69, 9);
    let iv = "32bcb9b569e3b852d37c766a";
    let args = ["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--iv", iv, "--aad", "c3"];
    let mut ct = run_ok(
        &["camellia128-gcm", "-d", "encrypt", "--key", KEY, "--iv", iv, "--aad", "c3"],
        &plaintext,
    );
    assert_eq!(run_ok(&args, &ct), plaintext);
    ct[0] ^= 1;
    assert!(run_err(&args, &ct).contains("authentication failed"));
    ct[0] ^= 1;
    let last = ct.len() - 1;
    ct[last] ^= 1;
    assert!(run_err(&args, &ct).contains("authentication failed"));
    ct[last] ^= 1;
    let other_aad = ["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--iv", iv, "--aad", "c4"];
    assert!(run_err(&other_aad, &ct).contains("authentication failed"));
    let other_key = [
        "camellia128-gcm",
        "-d",
        "decrypt",
        "--key",
        "28ff3def08179311e2734c6d1c4e2870",
        "--iv",
        iv,
        "--aad",
        "c3",
    ];
    assert!(run_err(&other_key, &ct).contains("authentication failed"));
}

/// Without `--iv` the command draws one and writes it first; the round trip works at every key
/// length and the output is 12 + len + 16 bytes.
#[test]
fn encrypt_then_decrypt_round_trips_at_every_key_length() {
    let message: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    for (cmd, key) in [
        ("camellia128-gcm", "000102030405060708090a0b0c0d0e0f"),
        ("camellia192-gcm", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("camellia256-gcm", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
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
    let err = run_err(&["camellia128-gcm", "-d", "encrypt", "--key", "0011"], b"x");
    assert!(err.contains("16-byte key"), "{err}");
    let err = run_err(&["camellia256-gcm", "-d", "encrypt", "--key", KEY], b"x");
    assert!(err.contains("32-byte key"), "{err}");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    let help = String::from_utf8(run_ok(&["--help"], b"")).unwrap();
    for name in ["camellia128-gcm", "camellia192-gcm", "camellia256-gcm"] {
        assert!(help.contains(name), "--help should list {name}");
    }
}
