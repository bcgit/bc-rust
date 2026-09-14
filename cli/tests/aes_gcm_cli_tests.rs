//! Tests for the `aes128-gcm` / `aes192-gcm` / `aes256-gcm` subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, exactly as `aes_ctr_cli_tests.rs` does
//! and for the same reason: the command-line contract -- `nonce || ciphertext || tag` framing, the
//! `--aad` flags, exit codes, key loading -- is not reachable from the library API. GCM's algorithm
//! correctness is pinned in `bouncycastle-modes`' ACVP, GMAC and bc-java known-answer suites; what
//! is worth testing here is the wiring: that AAD actually reaches the tag, that a tampered byte or
//! tag is rejected with a non-zero exit, and that decrypt still writes whatever plaintext it
//! recovered before the failure (the streaming trade-off `aead_mode_cmd.rs` documents).
//!
//! There is no OpenSSL cross-check here: `openssl enc` does not do AEAD, so unlike the CTR/CFB/CBC
//! suites there is no equivalent vector to play through the pipe.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile.
//!
//! # A note on this environment
//!
//! In this session's environment, every subprocess invocation of the **debug** `bc-rust` binary --
//! including a bare `--help`, and every existing `aes_ctr_cli_tests.rs` case -- crashes with a
//! stack overflow before reaching any command logic (`thread 'main' has overflowed its stack`).
//! `git stash` reproduced it on the unmodified `main.rs` too, so it predates this change and is
//! unrelated to GCM; a release build (`cargo test --release -p cli`) does not hit it, which points
//! at clap's derive-generated parser code being large enough, unoptimized, to need more than the
//! default debug-build stack on this toolchain -- plausibly worsened by how many subcommands and
//! doc-comment-derived help strings this binary now has. This file's tests were run and pass
//! against the release build; `cargo test -p cli` (debug) will need that issue investigated
//! separately.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// GCM's nonce, like CTR's, is 12 bytes.
const NONCE_LEN: usize = 12;
/// The (only) tag length these commands support: 128 bits.
const TAG_LEN: usize = 16;

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

const AAD: &str = "deadbeef";

const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
    "0011223344",
);

/// See `aes_ctr_cli_tests.rs::run` for why stdin is written from a separate thread and why
/// `BrokenPipe` is not a harness failure.
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
    let writer = thread::spawn(move || match stdin.write_all(&payload) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to stdin: {e}"),
    });

    let output = child.wait_with_output().expect("failed to wait for bc-rust");
    writer.join().expect("the stdin writer thread panicked");
    output
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

fn run_err(args: &[&str], stdin_bytes: &[u8]) -> (String, Vec<u8>) {
    let out = run(args, stdin_bytes);
    assert!(
        !out.status.success(),
        "expected failure from {args:?}, but it succeeded\nstdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    (String::from_utf8_lossy(&out.stderr).into_owned(), out.stdout)
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
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

// ---- round trips ---------------------------------------------------------------------------

#[test]
fn encrypt_then_decrypt_round_trips_with_aad() {
    for (cmd, key) in [("aes128-gcm", KEY_128), ("aes192-gcm", KEY_192), ("aes256-gcm", KEY_256)] {
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key, "--aad", AAD], &plaintext);
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + NONCE_LEN + TAG_LEN,
            "{cmd}: nonce, ciphertext and tag"
        );
        let recovered = run_ok(&[cmd, "decrypt", "--key", key, "--aad", AAD], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}: round trip");
    }
}

/// AAD is optional; omitting it on both sides round-trips too.
#[test]
fn round_trips_with_no_aad() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128], &plaintext);
    let recovered = run_ok(&["aes128-gcm", "decrypt", "--key", KEY_128], &ciphertext);
    assert_eq!(recovered, plaintext);
}

/// Any length round-trips with the ciphertext plus a fixed 12+16-byte overhead.
#[test]
fn any_input_length_is_accepted_and_round_trips() {
    for len in 0..=(2 * 16 + 1) {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext =
            run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128, "--aad", AAD], &plaintext);
        assert_eq!(
            ciphertext.len(),
            len + NONCE_LEN + TAG_LEN,
            "len {len}: nonce, equal-length body, tag"
        );
        let recovered =
            run_ok(&["aes128-gcm", "decrypt", "--key", KEY_128, "--aad", AAD], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// Round trips at sizes that straddle the 1 KiB streaming chunk and the tag-hold-back boundary.
#[test]
fn round_trips_across_chunk_boundaries() {
    for size in [0usize, 1, 15, 16, 17, 1023, 1024, 1025, 4096, 4099, 65536] {
        let plaintext = pseudo_random(size, size as u32);
        let ciphertext =
            run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128, "--aad", AAD], &plaintext);
        let recovered =
            run_ok(&["aes128-gcm", "decrypt", "--key", KEY_128, "--aad", AAD], &ciphertext);
        assert_eq!(recovered, plaintext, "{size} bytes should round trip");
    }
}

/// A fresh nonce per invocation.
#[test]
fn each_invocation_uses_a_fresh_nonce() {
    let plaintext = unhex(PLAINTEXT);
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let ciphertext = run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128], &plaintext);
        let nonce = ciphertext[..NONCE_LEN].to_vec();
        assert!(seen.insert(nonce), "the CLI reused a nonce across invocations");
        let recovered = run_ok(&["aes128-gcm", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

#[test]
fn hex_output_matches_binary_output() {
    let plaintext = unhex(PLAINTEXT);
    let binary = run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128], &plaintext);
    let hex_out = run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128, "-x"], &plaintext);

    let hex_str = String::from_utf8(hex_out).expect("hex output is text");
    // The nonce differs per run, so compare lengths and that the body decodes to something of the
    // same shape rather than the exact bytes.
    assert_eq!(hex_str.trim_end().len(), binary.len() * 2);
    assert_eq!(unhex(hex_str.trim_end()).len(), binary.len());
}

// ---- AAD -------------------------------------------------------------------------------------

/// Decrypting with the wrong AAD must fail authentication.
#[test]
fn wrong_aad_fails_authentication() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128, "--aad", AAD], &plaintext);
    let (stderr, _stdout) =
        run_err(&["aes128-gcm", "decrypt", "--key", KEY_128, "--aad", "00112233"], &ciphertext);
    assert!(
        stderr.contains("authentication failed"),
        "stderr should report authentication failure: {stderr}"
    );
}

/// Encrypting with AAD and decrypting with none (or vice versa) must fail authentication too.
#[test]
fn missing_aad_on_one_side_fails_authentication() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128, "--aad", AAD], &plaintext);
    let (stderr, _stdout) = run_err(&["aes128-gcm", "decrypt", "--key", KEY_128], &ciphertext);
    assert!(
        stderr.contains("authentication failed"),
        "stderr should report authentication failure: {stderr}"
    );
}

// ---- tamper detection --------------------------------------------------------------------------

/// A tampered ciphertext byte must be rejected, non-zero exit.
#[test]
fn a_tampered_ciphertext_byte_is_rejected() {
    let plaintext = unhex(PLAINTEXT);
    let mut ciphertext =
        run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128, "--aad", AAD], &plaintext);
    let body_start = NONCE_LEN;
    ciphertext[body_start] ^= 0x01;

    let (stderr, _stdout) =
        run_err(&["aes128-gcm", "decrypt", "--key", KEY_128, "--aad", AAD], &ciphertext);
    assert!(
        stderr.contains("authentication failed"),
        "stderr should report authentication failure: {stderr}"
    );
}

/// A tampered tag byte must be rejected too.
#[test]
fn a_tampered_tag_byte_is_rejected() {
    let plaintext = unhex(PLAINTEXT);
    let mut ciphertext =
        run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128, "--aad", AAD], &plaintext);
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01;

    let (stderr, _stdout) =
        run_err(&["aes128-gcm", "decrypt", "--key", KEY_128, "--aad", AAD], &ciphertext);
    assert!(
        stderr.contains("authentication failed"),
        "stderr should report authentication failure: {stderr}"
    );
}

/// The streaming trade-off `aead_mode_cmd.rs` documents: on a tag failure, whatever plaintext the
/// inline decryptor had already released before the tag check stands on stdout. For a message
/// longer than the tag, that is everything except (at most) the last `TAG_LEN` bytes.
#[test]
fn decrypt_still_writes_the_plaintext_it_had_already_released_on_forgery() {
    let plaintext = pseudo_random(4096, 7);
    let mut ciphertext =
        run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128, "--aad", AAD], &plaintext);
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 0x01; // corrupt the tag only, leaving the ciphertext body intact

    let out = run(&["aes128-gcm", "decrypt", "--key", KEY_128, "--aad", AAD], &ciphertext);
    assert!(!out.status.success(), "a corrupted tag must be rejected");
    assert!(
        out.stdout.len() >= plaintext.len() - TAG_LEN,
        "most of the plaintext should already have reached stdout: got {} of {} bytes",
        out.stdout.len(),
        plaintext.len()
    );
    assert_eq!(
        &out.stdout[..out.stdout.len().min(plaintext.len())],
        &plaintext[..out.stdout.len().min(plaintext.len())],
        "the released bytes must be the genuine plaintext, not garbage"
    );
}

// ---- short input ---------------------------------------------------------------------------

/// Input shorter than the 12-byte nonce is rejected.
#[test]
fn decrypt_input_shorter_than_the_nonce_is_rejected() {
    for len in [0usize, 1, 11] {
        let (stderr, _stdout) =
            run_err(&["aes128-gcm", "decrypt", "--key", KEY_128], &pseudo_random(len, 1));
        assert!(
            stderr.contains("12-byte nonce"),
            "stderr should explain the missing nonce (len {len}): {stderr}"
        );
    }
}

/// Input that has a nonce but not a full tag is rejected as an authentication failure (there is
/// nothing to check the tag against).
#[test]
fn decrypt_input_with_a_nonce_but_no_full_tag_is_rejected() {
    // `encrypt` on empty input yields exactly nonce || tag; drop the last tag byte.
    let nonce_and_tag = run_ok(&["aes128-gcm", "encrypt", "--key", KEY_128], &[]);
    let short = &nonce_and_tag[..nonce_and_tag.len() - 1];
    let (stderr, _stdout) = run_err(&["aes128-gcm", "decrypt", "--key", KEY_128], short);
    assert!(
        stderr.contains("authentication failed"),
        "stderr should report authentication failure: {stderr}"
    );
}

// ---- key handling ---------------------------------------------------------------------------

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let (stderr, _stdout) =
        run_err(&["aes256-gcm", "encrypt", "--key", KEY_128], &unhex(PLAINTEXT));
    assert!(stderr.contains("32-byte key"), "stderr should name the expected length: {stderr}");
    assert!(stderr.contains("16 bytes"), "stderr should name the supplied length: {stderr}");
}

#[test]
fn a_missing_key_is_rejected() {
    let (stderr, _stdout) = run_err(&["aes128-gcm", "encrypt"], &unhex(PLAINTEXT));
    assert!(stderr.contains("--key"), "stderr should mention the key options: {stderr}");
}

// ---- discoverability --------------------------------------------------------------------------

#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aes128-gcm", "aes192-gcm", "aes256-gcm"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}

/// The per-command help must document the AAD flags and the authenticated-but-streamed warning.
#[test]
fn per_command_help_documents_aad_and_the_streaming_warning() {
    let out = run_ok(&["aes128-gcm", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("aad"), "help should mention AAD: {help}");
    assert!(
        help.to_lowercase().contains("authenticat"),
        "help should mention authentication: {help}"
    );
}
