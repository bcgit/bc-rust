//! Tests for the `sm4-gcm` subcommand.
//!
//! `sm4-gcm` shares its key, IV and AAD loaders, streaming loops and error paths with the
//! `aes*-gcm` commands (`cli/src/helpers/aead_cipher_helpers.rs`), and `test_aes_gcm.sh` covers
//! those exhaustively. This file pins what is specific to SM4: the 16-byte key length, and that
//! what comes out really is GCM over SM4, held to RFC 8998 Appendix A.1's `AEAD_SM4_GCM` vector
//! and to the library's own `SM4Key<GCM>`.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The single SM4 key length.
const KEY: &str = "0123456789abcdeffedcba9876543210";

/// GCM's framing: the 12-byte nonce leads and the 16-byte tag follows the ciphertext.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

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
/// The library's answer for the same key, nonce, AAD and inline `ciphertext || tag`, so the
/// CLI can be held to it: the key object's inline one-shot under `GCM`.
fn library_gcm_decrypt(key_hex: &str, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    use bouncycastle::cipher::modes::GCM;
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::core::symmetric_key::{AeadDecryptionKey, FromKeyMaterial};
    use bouncycastle::sm4::SM4Key;

    let key_bytes: [u8; 16] = unhex(key_hex).try_into().expect("a 16-byte key");
    let material = KeyMaterial::<16>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let key = SM4Key::<GCM>::from_key_material(&material).expect("a valid key");
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("a 12-byte nonce");
    key.decrypt_with_aad(&nonce, aad, ciphertext).expect("the tag verifies")
}

/// RFC 8998 Appendix A.1, the `AEAD_SM4_GCM` vector, through the command with the vector's
/// nonce supplied: the output is exactly `ciphertext || tag`, and it decrypts back.
#[test]
fn the_command_reproduces_rfc_8998_a_1() {
    const KEY_A1: &str = "0123456789ABCDEFFEDCBA9876543210";
    const NONCE_A1: &str = "00001234567800000000ABCD";
    const AAD_A1: &str = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2";
    const PT_A1: &str = concat!(
        "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB",
        "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD",
        "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF",
        "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA",
    );
    const CT_A1: &str = concat!(
        "17F399F08C67D5EE19D0DC9969C4BB7D",
        "5FD46FD3756489069157B282BB200735",
        "D82710CA5C22F0CCFA7CBF93D496AC15",
        "A56834CBCF98C397B4024A2691233B8D",
    );
    const TAG_A1: &str = "83DE3541E4C2B58177E065A9BF7B62EC";

    let args = ["sm4-gcm", "--key", KEY_A1, "--iv", NONCE_A1, "--aad", AAD_A1];
    let out = run_ok(&[&args[..], &["-d", "encrypt"]].concat(), &unhex(PT_A1));
    assert_eq!(tohex(&out), format!("{CT_A1}{TAG_A1}").to_lowercase());

    let back = run_ok(&[&args[..], &["-d", "decrypt"]].concat(), &out);
    assert_eq!(tohex(&back), PT_A1.to_lowercase());
}

/// What the command emits must be exactly what the library's `GCM` key produces: the generated
/// nonce leads, the body is as long as the input, and the tag follows.
#[test]
fn the_command_is_gcm_over_sm4() {
    for len in [0usize, 1, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);
        let out =
            run_ok(&["sm4-gcm", "-d", "encrypt", "--key", KEY, "--aad", "deadbeef"], &plaintext);
        assert_eq!(out.len(), NONCE_LEN + len + TAG_LEN, "len {len}: nonce, body and tag");

        let (nonce, body) = out.split_at(NONCE_LEN);
        let recovered = library_gcm_decrypt(KEY, nonce, &unhex("deadbeef"), body);
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");

        let back = run_ok(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &out);
        assert_eq!(back, plaintext, "len {len}: round trip");
    }
}

/// The AAD is covered by the tag: a different AAD, or none, on the decrypt side fails
/// authentication with a non-zero exit, and a flipped ciphertext or tag byte does too.
#[test]
fn tampering_and_a_changed_aad_fail_authentication() {
    let plaintext = pseudo_random(69, 9);
    let out = run_ok(&["sm4-gcm", "-d", "encrypt", "--key", KEY, "--aad", "deadbeef"], &plaintext);

    let err = run_err(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "--aad", "00112233"], &out);
    assert!(err.contains("authentication failed"), "stderr was: {err}");
    let err = run_err(&["sm4-gcm", "-d", "decrypt", "--key", KEY], &out);
    assert!(err.contains("authentication failed"), "stderr was: {err}");

    let mut body_flipped = out.clone();
    body_flipped[NONCE_LEN] ^= 1;
    let err =
        run_err(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &body_flipped);
    assert!(err.contains("authentication failed"), "stderr was: {err}");

    let mut tag_flipped = out.clone();
    let last = tag_flipped.len() - 1;
    tag_flipped[last] ^= 1;
    let err =
        run_err(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &tag_flipped);
    assert!(err.contains("authentication failed"), "stderr was: {err}");
}

/// A fresh nonce per invocation: a repeated GCM nonce under one key also gives away the hash
/// subkey, so this is the whole security argument for the default framing.
#[test]
fn each_invocation_uses_a_fresh_nonce() {
    let plaintext = pseudo_random(64, 11);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..8 {
        let ciphertext = run_ok(&["sm4-gcm", "-d", "encrypt", "--key", KEY], &plaintext);
        assert!(seen.insert(ciphertext[..NONCE_LEN].to_vec()), "the CLI reused a nonce");
        let recovered = run_ok(&["sm4-gcm", "-d", "decrypt", "--key", KEY], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let plaintext = pseudo_random(32, 3);
    let ciphertext = run_ok(&["sm4-gcm", "-d", "encrypt", "--key", KEY], &plaintext);

    let binary = run_ok(&["sm4-gcm", "-d", "decrypt", "--key", KEY], &ciphertext);
    let hex_out = run_ok(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "-x"], &ciphertext);
    let hex_str = String::from_utf8(hex_out).expect("hex output is text");

    assert_eq!(hex_str, format!("{}\n", tohex(&binary)));
    assert_eq!(binary, plaintext);
}

/// SM4 has exactly one key length. An AES-256-sized key is an error naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    let err = run_err(&["sm4-gcm", "-d", "encrypt", "--key", key_256], &[0u8; 16]);
    assert!(err.contains("SM4 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
}

/// The subcommand is discoverable, and its help says it authenticates and takes AAD.
#[test]
fn the_subcommand_is_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    assert!(String::from_utf8_lossy(&out).contains("sm4-gcm"), "`--help` should list sm4-gcm");

    let out = run_ok(&["sm4-gcm", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.to_lowercase().contains("authenticat"), "help should mention authentication");
    assert!(help.contains("aad"), "help should mention AAD: {help}");
}
