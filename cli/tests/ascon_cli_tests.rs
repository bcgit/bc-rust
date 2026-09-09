//! Tests for the `ascon-hash256` / `ascon-xof128` / `ascon-cxof128` / `ascon-aead128`
//! subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, because the behaviour worth testing is
//! the command-line contract itself -- KAT-level correctness through the pipe, the `ciphertext ||
//! tag` layout, `--key-file`/`--nonce-file` loading, AAD, and exit codes -- none of which is
//! reachable from the library API, which `crypto/ascon/tests/*.rs` already covers directly.
//!
//! The KAT values below are taken from the embedded vectors already pinned in
//! `crypto/ascon/tests/{hash256,xof128,cxof128,aead128}_tests.rs` (themselves NIST LWC vectors),
//! not retyped from memory.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The NIST LWC AEAD KAT convention uses key == nonce for the embedded vectors (see
/// `crypto/ascon/tests/aead128_tests.rs`'s `aead128_embedded_kat`).
const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
///
/// See `aes_ctr_cli_tests.rs::run` for why stdin is written from a separate thread (a pipe with a
/// bounded buffer deadlocks otherwise) and why a `BrokenPipe` write error is swallowed (an
/// error-path command may exit before draining stdin).
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");

    let mut stdin = child.stdin.take().expect("stdin piped");
    let payload = stdin_bytes.to_vec();
    let writer = thread::spawn(move || {
        match stdin.write_all(&payload) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write to stdin: {e}"),
        }
        // `stdin` drops here, closing the pipe so the child sees EOF and can exit.
    });

    let output = child.wait_with_output().expect("failed to wait for bc-rust");
    writer.join().expect("the stdin writer thread panicked");
    output
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

/// Deterministic pseudo-random bytes, so the tests do not depend on an RNG or on `/dev/urandom`.
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

fn hex_stdout(args: &[&str], stdin_bytes: &[u8]) -> String {
    let out = run_ok(args, stdin_bytes);
    String::from_utf8(out).expect("hex output is text").trim_end().to_string()
}

// ---- ascon-hash256 ------------------------------------------------------------------------

/// LWC_HASH_KAT_256.txt Count 1: the digest of the empty message.
#[test]
fn ascon_hash256_matches_the_embedded_kat_for_the_empty_message() {
    let out = hex_stdout(&["ascon-hash256", "-x"], &[]);
    assert_eq!(out, "0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2");
}

/// A non-empty message, matching LWC_HASH_KAT_256.txt Count 9.
#[test]
fn ascon_hash256_matches_the_embedded_kat_for_a_multi_byte_message() {
    let out = hex_stdout(&["ascon-hash256", "-x"], &unhex("0001020304050607"));
    assert_eq!(out, "b88e497ae8e6fb641b87ef622eb8f2fca0ed95383f7ffebe167acf1099ba764f");
}

// ---- ascon-xof128 --------------------------------------------------------------------------

/// LWC_XOF_KAT_128_512.txt Count 1: 64 bytes squeezed after absorbing the empty message.
#[test]
fn ascon_xof128_matches_the_embedded_kat_for_the_empty_message() {
    let out = hex_stdout(&["ascon-xof128", "64", "-x"], &[]);
    assert_eq!(
        out,
        "473d5e6164f58b39dfd84aacdb8ae42ec2d91fed33388ee0d960d9b3993295c\
         6ad77855a5d3b13fe6ad9e6098988373af7d0956d05a8f1665d2c67d1a3ad10ff"
    );
}

/// The output length is the caller's choice, and shorter output is a prefix of longer output
/// (every XOF's defining property) -- pinned here through the CLI specifically, since the CLI is
/// what turns the length into a positional argument.
#[test]
fn ascon_xof128_output_length_is_a_prefix_of_a_longer_squeeze() {
    let full = hex_stdout(&["ascon-xof128", "64", "-x"], &[]);
    let short = hex_stdout(&["ascon-xof128", "16", "-x"], &[]);
    assert_eq!(short.len(), 32, "16 bytes is 32 hex characters");
    assert!(full.starts_with(&short));
}

// ---- ascon-cxof128 -------------------------------------------------------------------------

/// LWC_CXOF_KAT_128_512.txt Count 4: message `00`, customization `10`.
#[test]
fn ascon_cxof128_matches_the_embedded_kat() {
    let out = hex_stdout(&["ascon-cxof128", "64", "--customization", "10", "-x"], &unhex("00"));
    assert_eq!(
        out,
        "63fa8ba86382f2d544580f51322d080424b42c556eb74503cd73cf052bb993\
         bd6f5210984c71c9c445f43ccc5b158226e509bd339cd634414377f79411aa8d5c"
    );
}

/// No `--customization` at all must give the same output as an empty one: `AsconCXof128::new()`
/// versus `with_customization(&[])`, both reachable only through the library elsewhere -- here we
/// pin that the CLI's `Option<String>` plumbing treats "absent" and "empty" identically.
#[test]
fn ascon_cxof128_with_no_customization_matches_an_empty_one() {
    let without = hex_stdout(&["ascon-cxof128", "64", "-x"], &[]);
    let with_empty = hex_stdout(&["ascon-cxof128", "64", "--customization", "", "-x"], &[]);
    assert_eq!(without, with_empty);
    // LWC_CXOF_KAT_128_512.txt Count 1: message and customization both empty.
    assert_eq!(
        without,
        "4f50159ef70bb3dad8807e034eaebd44c4fa2cbbc8cf1f05511ab66cdcc5299\
         05ca12083fc186ad899b270b1473dc5f7ec88d1052082dcdfe69fb75d269e7b74"
    );
}

// ---- ascon-aead128 -------------------------------------------------------------------------

/// LWC_AEAD_KAT_128_128.txt Count 1: the tag over an empty message with no AAD (key == nonce).
#[test]
fn ascon_aead128_matches_the_embedded_kat_for_an_empty_message() {
    let out = hex_stdout(&["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "-x"], &[]);
    assert_eq!(out, "4427d64b8e1e1451fc445960f0839bb0");
}

/// Encrypt then `--decrypt` round-trips a multi-KB payload, byte for byte, and the ciphertext is
/// exactly the plaintext plus the 16-byte tag.
#[test]
fn ascon_aead128_encrypt_then_decrypt_round_trips() {
    let plaintext = pseudo_random(4096, 0xC0FFEE);
    let ciphertext = run_ok(&["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX], &plaintext);
    assert_eq!(ciphertext.len(), plaintext.len() + 16, "ciphertext is plaintext plus the tag");

    let recovered =
        run_ok(&["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "--decrypt"], &ciphertext);
    assert_eq!(recovered, plaintext);
}

/// Associated data is authenticated on both sides of a round trip.
#[test]
fn ascon_aead128_associated_data_round_trips() {
    let plaintext = pseudo_random(256, 7);
    let ciphertext = run_ok(
        &["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "--ad", "deadbeef"],
        &plaintext,
    );
    let recovered = run_ok(
        &["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "--ad", "deadbeef", "--decrypt"],
        &ciphertext,
    );
    assert_eq!(recovered, plaintext);
}

/// Decrypting with the wrong associated data must fail the tag check, the same as tampering with
/// the ciphertext itself.
#[test]
fn ascon_aead128_wrong_associated_data_is_rejected() {
    let plaintext = pseudo_random(64, 11);
    let ciphertext = run_ok(
        &["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "--ad", "deadbeef"],
        &plaintext,
    );
    let stderr = run_err(
        &["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "--ad", "cafebabe", "--decrypt"],
        &ciphertext,
    );
    assert!(stderr.contains("authentication failed"), "stderr: {stderr}");
}

/// A single flipped ciphertext byte must fail the tag check on decrypt, with a non-zero exit and
/// an explanatory stderr message -- the security-relevant contract the streaming decrypt path
/// (`ascon_cmd.rs::aead128_decrypt_stream`) exists to uphold.
#[test]
fn ascon_aead128_a_flipped_ciphertext_byte_is_rejected() {
    let plaintext = pseudo_random(64, 1);
    let mut ciphertext =
        run_ok(&["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX], &plaintext);
    ciphertext[0] ^= 0x01;

    let stderr =
        run_err(&["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "--decrypt"], &ciphertext);
    assert!(stderr.contains("authentication failed"), "stderr: {stderr}");
}

/// A flipped tag byte (the last byte of the stream) must be rejected the same way.
#[test]
fn ascon_aead128_a_flipped_tag_byte_is_rejected() {
    let plaintext = pseudo_random(64, 2);
    let mut ciphertext =
        run_ok(&["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX], &plaintext);
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    let stderr =
        run_err(&["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "--decrypt"], &ciphertext);
    assert!(stderr.contains("authentication failed"), "stderr: {stderr}");
}

/// Decrypt input shorter than the 16-byte tag is rejected before any tag check is attempted,
/// including the empty-input case.
#[test]
fn ascon_aead128_decrypt_input_shorter_than_the_tag_is_rejected() {
    for len in [0usize, 1, 15] {
        let stderr = run_err(
            &["ascon-aead128", "--key", KEY_HEX, "--nonce", KEY_HEX, "--decrypt"],
            &pseudo_random(len, len as u32 + 1),
        );
        assert!(
            stderr.contains("shorter than the 16-byte tag"),
            "len {len}: stderr should explain the missing tag: {stderr}"
        );
    }
}

/// `--key-file`/`--nonce-file` accept binary content, not just hex, the same as the AES commands'
/// `--key-file` (see `key_file_accepts_hex_and_binary` in `aes_ctr_cli_tests.rs`).
#[test]
fn ascon_aead128_key_file_and_nonce_file_accept_binary_content() {
    let dir = std::env::temp_dir().join(format!("ascon_cli_test_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let key_path = dir.join("key.bin");
    let nonce_path = dir.join("nonce.bin");
    std::fs::write(&key_path, unhex(KEY_HEX)).expect("write key file");
    std::fs::write(&nonce_path, unhex(KEY_HEX)).expect("write nonce file");

    let out = hex_stdout(
        &[
            "ascon-aead128",
            "--key-file",
            key_path.to_str().unwrap(),
            "--nonce-file",
            nonce_path.to_str().unwrap(),
            "-x",
        ],
        &[],
    );
    assert_eq!(out, "4427d64b8e1e1451fc445960f0839bb0");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The subcommands are listed in top-level help.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let text = String::from_utf8_lossy(&out);
    for name in ["ascon-hash256", "ascon-xof128", "ascon-cxof128", "ascon-aead128"] {
        assert!(text.contains(name), "--help should list {name}");
    }
}
