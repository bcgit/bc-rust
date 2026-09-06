//! Tests for the `aes128-cfb8` / `aes192-cfb8` / `aes256-cfb8` subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, because the behaviour worth testing is
//! the command-line contract itself -- the IV riding in the first block, the chunked streaming
//! loop, exit codes, key loading -- none of which is reachable from the library API.
//!
//! The commands share their streaming loop with `aes*-cfb` (`cli/src/stream_mode_cmd.rs`) and their
//! key loading with `aes*-cbc` (`cli/src/block_mode_cmd.rs`), so this file deliberately repeats
//! that coverage rather than assuming it: the shared code is generic over the mode, and a wiring
//! mistake in the CFB8 dispatcher would not show up in the other suites. What is tested only here
//! is the F.3.7/F.3.9/F.3.11 vectors, CFB8's own Appendix D error propagation -- a 16-byte damage
//! window followed by resynchronisation -- and the guard that CFB8 and CFB128 ciphertexts are not
//! interchangeable.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// SP 800-38A Appendix F IV, shared by every F.3 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The 18 one-byte plaintext segments the CFB8 subsections use: the Appendix F plaintext truncated
/// to 18 bytes.
const PLAINTEXT: &str = "6bc1bee22e409f96e93d7e117393172aae2d";

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// F.3.7 CFB8-AES128.Encrypt ciphertext.
const CT_128: &str = "3b79424c9c0dd436bace9e0ed4586a4f32b9";
/// F.3.9 CFB8-AES192.Encrypt ciphertext.
const CT_192: &str = "cda2521ef0a905ca44cd057cbf0d47a0678a";
/// F.3.11 CFB8-AES256.Encrypt ciphertext.
const CT_256: &str = "dc1f1a8520a64db55fcc8ac554844e889700";

/// F.3.13 CFB128-AES128.Encrypt ciphertext, first 18 bytes, for the cross-mode guard. Same key, IV
/// and plaintext as `CT_128`, so the two are directly comparable.
const CFB128_CT_128: &str = "3b3fd92eb72dad20333449f8e83cfb4ac8a6";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
///
/// # Why stdin is written from a thread
///
/// stdin, stdout and stderr are all pipes with a bounded buffer (typically 64 KiB). Writing all of
/// stdin from *this* thread before reading any output deadlocks as soon as the payload is large
/// enough: the child fills its stdout buffer and blocks, so it stops draining stdin, so our write
/// blocks too, and neither side can move. That is a hang rather than a failure, so it would surface
/// as a CI timeout. Writing on a separate thread leaves this one free to drain stdout and stderr
/// via `wait_with_output`, which breaks the cycle. `a_payload_larger_than_the_pipe_buffer_round_trips`
/// pins it.
///
/// Dropping the pipe when the write finishes is what signals EOF to the child, so the writer thread
/// owns the handle (`take`, not `as_mut`) and must run to completion.
///
/// # Why `BrokenPipe` is ignored
///
/// The error-path tests hand a rejected key to a command that `exit`s before it reads stdin, so the
/// write races the child's exit and loses. That is an expected outcome, not a
/// harness failure: those tests assert the exit status and stderr, both of which `wait_with_output`
/// still returns. Any *other* write error is a real problem and still panics.
/// `a_large_payload_on_an_error_path_does_not_break_the_harness` pins it.
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

    // Drain stdout and stderr first: the writer may still be blocked on a full stdin buffer, and it
    // cannot finish until the child consumes more, which it cannot do while its output is backed up.
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

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
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

// ---- the harness itself ------------------------------------------------------------------
//
// These two pin `run`'s pipe handling, exactly as in the CBC and CFB suites; each file has its own
// copy of `run`, so each needs its own pair.

/// Far beyond any pipe buffer, so a write cannot complete before the child has drained it.
///
/// Smaller than the CFB suite's, because CFB8 spends a full AES call per byte and this test is
/// about the pipe rather than the cipher.
const OVERSIZED: usize = 256 * 1024;

/// An error path must not take the harness down with it.
#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    let stderr = run_err(&["aes128-cfb8", "encrypt"], &vec![0u8; OVERSIZED]);
    assert!(stderr.contains("--key"), "the CLI's own error must still be reported: {stderr}");
}

/// A payload larger than the pipe buffer must round-trip rather than deadlock.
#[test]
fn a_payload_larger_than_the_pipe_buffer_round_trips() {
    let plaintext = pseudo_random(OVERSIZED, 0xC0FFEE);
    let ciphertext = run_ok(&["aes128-cfb8", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(ciphertext.len(), plaintext.len() + 16, "IV plus the ciphertext");

    let recovered = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &ciphertext);
    assert_eq!(recovered, plaintext, "{OVERSIZED} bytes should round trip");
}

// ---- the SP 800-38A F.3 vectors, through the CLI -----------------------------------------

/// `decrypt` reproduces the spec plaintext when handed the spec's IV followed by the spec's
/// ciphertext, for F.3.7/F.3.9/F.3.11 (CFB8-AES128/192/256).
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round-trip tests below
/// and, at the library level, by `crypto/modes/tests/sp800_38a_cfb8_tests.rs`.
#[test]
fn decrypt_matches_sp800_38a_f3_vectors() {
    for (cmd, key, ct) in [
        ("aes128-cfb8", KEY_128, CT_128),
        ("aes192-cfb8", KEY_192, CT_192),
        ("aes256-cfb8", KEY_256, CT_256),
    ] {
        // The CLI expects the IV as the first block of its input, which is exactly how `encrypt`
        // emits it.
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(
            tohex(&out),
            PLAINTEXT,
            "{cmd} decrypt should reproduce the Appendix F.3 plaintext"
        );
    }
}

/// The same, with `-x`, which should give the identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_128}"));
    let binary = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &input);
    let hex_out = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128, "-x"], &input);

    let hex_str = String::from_utf8(hex_out).expect("hex output is text");
    assert_eq!(hex_str.trim_end(), tohex(&binary));
    assert_eq!(hex_str.trim_end(), PLAINTEXT);
}

// ---- round trips ------------------------------------------------------------------------

/// `encrypt | decrypt` recovers the input, for all three key lengths.
#[test]
fn encrypt_then_decrypt_round_trips() {
    for (cmd, key) in [("aes128-cfb8", KEY_128), ("aes192-cfb8", KEY_192), ("aes256-cfb8", KEY_256)]
    {
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + 16,
            "{cmd}: output should be the 16-byte IV plus the ciphertext"
        );

        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}: round trip");
    }
}

/// Input of any length is accepted and round-trips, and the ciphertext is exactly as long as the
/// plaintext. CFB8's segment is a single byte, so there is no alignment rule at all.
#[test]
fn any_input_length_is_accepted_and_round_trips() {
    for len in 0..=(2 * 16 + 1) {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&["aes128-cfb8", "encrypt", "--key", KEY_128], &plaintext);
        assert_eq!(ciphertext.len(), len + 16, "len {len}: IV plus an equal-length ciphertext");

        let recovered = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// Round trips at sizes that straddle the 1 KiB streaming chunk, including sizes that leave the
/// chunk boundary in the middle of the 8-byte batch the decryptor uses.
#[test]
fn round_trips_across_chunk_boundaries() {
    for size in [1usize, 8, 9, 1023, 1024, 1025, 4096, 4099] {
        let plaintext = pseudo_random(size, size as u32);
        let ciphertext = run_ok(&["aes128-cfb8", "encrypt", "--key", KEY_128], &plaintext);
        let recovered = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "{size} bytes should round trip");
    }
}

/// A fresh IV per invocation, so the same plaintext under the same key gives different output.
#[test]
fn each_invocation_uses_a_fresh_iv() {
    let plaintext = unhex(PLAINTEXT);
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let ciphertext = run_ok(&["aes128-cfb8", "encrypt", "--key", KEY_128], &plaintext);
        let iv = ciphertext[..16].to_vec();
        assert!(seen.insert(iv), "the CLI reused an IV across invocations");
        let recovered = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

// ---- key handling -----------------------------------------------------------------------

/// `--key-file` accepts both a hex file and a raw binary file, and agrees with `--key`.
#[test]
fn key_file_accepts_hex_and_binary() {
    let dir = std::env::temp_dir().join(format!("bc_rust_cfb8_cli_key_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let hex_path = dir.join("key.hex");
    let bin_path = dir.join("key.bin");
    std::fs::write(&hex_path, KEY_128).expect("write hex key");
    std::fs::write(&bin_path, unhex(KEY_128)).expect("write binary key");

    let input = unhex(&format!("{IV}{CT_128}"));
    let expected = unhex(PLAINTEXT);

    for path in [&hex_path, &bin_path] {
        let out = run_ok(&["aes128-cfb8", "decrypt", "--key-file", path.to_str().unwrap()], &input);
        assert_eq!(out, expected, "--key-file {path:?}");
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// A key of the wrong length for the chosen variant is rejected, naming both lengths.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let stderr = run_err(&["aes256-cfb8", "encrypt", "--key", KEY_128], &unhex(PLAINTEXT));
    assert!(stderr.contains("32-byte key"), "stderr should name the expected length: {stderr}");
    assert!(stderr.contains("16 bytes"), "stderr should name the supplied length: {stderr}");
}

/// Omitting the key entirely is an error, not a default.
#[test]
fn a_missing_key_is_rejected() {
    let stderr = run_err(&["aes128-cfb8", "encrypt"], &unhex(PLAINTEXT));
    assert!(stderr.contains("--key"), "stderr should mention the key options: {stderr}");
}

/// An all-zero key warns but proceeds, matching the other mode commands. NIST publishes
/// all-zero-key vectors, so refusing outright would make some of them untestable from the CLI.
#[test]
fn an_all_zero_key_warns_but_proceeds() {
    let zero_key = "0".repeat(32);
    let out = run(&["aes128-cfb8", "encrypt", "--key", &zero_key], &unhex(PLAINTEXT));
    assert!(out.status.success(), "an all-zero key should still work");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("warning"), "an all-zero key should warn: {stderr}");
    assert_eq!(out.stdout.len(), 16 + 18, "IV plus the 18 ciphertext bytes");
}

// ---- framing ----------------------------------------------------------------------------

/// Decrypt input shorter than the IV it must start with is rejected, and says so.
#[test]
fn decrypt_input_shorter_than_the_iv_is_rejected() {
    for len in [0usize, 1, 15] {
        let stderr = run_err(&["aes128-cfb8", "decrypt", "--key", KEY_128], &pseudo_random(len, 1));
        assert!(
            stderr.contains("IV"),
            "stderr should explain the missing IV (len {len}): {stderr}"
        );
    }
}

/// Empty input to `encrypt` produces just the IV.
#[test]
fn empty_input_produces_only_the_iv() {
    let out = run_ok(&["aes128-cfb8", "encrypt", "--key", KEY_128], &[]);
    assert_eq!(out.len(), 16, "empty input should yield exactly the IV");

    let back = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &out);
    assert!(back.is_empty(), "decrypting an IV with no body should give nothing");
}

// ---- SP 800-38A Appendix D, through the CLI ----------------------------------------------

/// Appendix D, Table D.2 for CFB: "SBE in the decryption of Cj" plus "RBE in the decryption of
/// Cj+1,...,Cj+b/s". With `s = 8` on a 16-byte block, `b/s` is 16, so a flipped ciphertext bit
/// flips the same bit of the same plaintext byte, corrupts the next 16 bytes, and then decryption
/// **resynchronises exactly**.
///
/// That last part is the self-synchronising property CFB8 exists for, and it is also a sharp
/// end-to-end check that the CLI is running CFB8 rather than CFB128, whose damage window is one
/// block rather than sixteen bytes measured from the corrupted byte.
#[test]
fn a_ciphertext_bit_flip_damages_exactly_sixteen_following_bytes() {
    // A message long enough to have a clean prefix, a full 16-byte window and a clean tail.
    let plaintext = pseudo_random(48, 0xD00D);
    let ciphertext = run_ok(&["aes128-cfb8", "encrypt", "--key", KEY_128], &plaintext);

    // Byte 8 of the ciphertext body, which starts after the 16-byte IV.
    const J: usize = 8;
    const MASK: u8 = 0b0010_0000;
    let mut corrupt = ciphertext.clone();
    corrupt[16 + J] ^= MASK;

    let out = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &corrupt);
    assert_eq!(out.len(), plaintext.len());

    assert_eq!(&out[..J], &plaintext[..J], "earlier bytes are unaffected");
    assert_eq!(out[J], plaintext[J] ^ MASK, "SBE: exactly the flipped bit, in the targeted byte");
    assert_ne!(
        &out[J + 1..J + 17],
        &plaintext[J + 1..J + 17],
        "the next b/s = 16 bytes should be randomised"
    );
    assert_eq!(
        &out[J + 17..],
        &plaintext[J + 17..],
        "byte j + 17 onwards must be exactly right again: CFB8 resynchronises"
    );
}

// ---- cross-variant and cross-mode behaviour ---------------------------------------------

/// Decrypting with the wrong key cannot succeed silently.
#[test]
fn a_wrong_key_does_not_recover_the_plaintext() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-cfb8", "encrypt", "--key", KEY_128], &plaintext);

    let wrong_key = "ff".repeat(16);
    let out = run_ok(&["aes128-cfb8", "decrypt", "--key", &wrong_key], &ciphertext);
    assert_ne!(out, plaintext, "a wrong key must not recover the plaintext");
    assert_eq!(out.len(), plaintext.len(), "but the length is unchanged: CFB8 is unauthenticated");
}

/// CFB8 and CFB128 ciphertexts are not interchangeable, in either direction.
///
/// Both spec ciphertexts are for the same key, IV and plaintext, so this is a clean comparison:
/// each mode must reproduce the plaintext only from its own ciphertext. They agree on the first
/// byte -- `P1 XOR MSB_8(CIPH_K(IV))` in both -- and diverge immediately after, which is exactly
/// what "different mode, not a variant" means.
#[test]
fn cfb8_and_cfb128_are_not_interchangeable() {
    let plaintext = unhex(PLAINTEXT);
    let cfb8_input = unhex(&format!("{IV}{CT_128}"));
    let cfb128_input = unhex(&format!("{IV}{CFB128_CT_128}"));

    // Each mode with its own ciphertext: correct.
    assert_eq!(run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &cfb8_input), plaintext);
    assert_eq!(run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &cfb128_input), plaintext);

    // Each mode with the other's ciphertext: wrong, but silently so -- neither mode is
    // authenticated, so there is nothing to detect the mismatch.
    let cfb8_reads_cfb128 = run_ok(&["aes128-cfb8", "decrypt", "--key", KEY_128], &cfb128_input);
    assert_ne!(cfb8_reads_cfb128, plaintext, "CFB8 must not decrypt a CFB128 ciphertext");
    assert_eq!(cfb8_reads_cfb128[0], plaintext[0], "...though the first byte necessarily agrees");

    let cfb128_reads_cfb8 = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &cfb8_input);
    assert_ne!(cfb128_reads_cfb8, plaintext, "CFB128 must not decrypt a CFB8 ciphertext");
}

// ---- discoverability --------------------------------------------------------------------

/// The subcommands appear in `--help`, so they are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aes128-cfb8", "aes192-cfb8", "aes256-cfb8"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}

/// Each subcommand's own help names the two actions, the IV convention, and -- because CFB8 and
/// CFB128 are different, non-interoperable modes -- says which one this is and what it costs.
#[test]
fn per_command_help_documents_the_segment_size_and_the_cost() {
    let out = run_ok(&["aes128-cfb8", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("encrypt"), "help should list the encrypt action");
    assert!(help.contains("decrypt"), "help should list the decrypt action");
    assert!(
        help.contains("FIRST 16 BYTES") || help.contains("first 16 bytes"),
        "help should explain where the IV goes: {help}"
    );
    assert!(help.contains("CFB8"), "help should say which CFB variant this is: {help}");
    assert!(
        help.contains("NON-INTEROPERABLE") || help.contains("non-interoperable"),
        "help should warn that CFB8 is not CFB128: {help}"
    );
}
