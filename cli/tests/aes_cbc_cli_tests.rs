//! Tests for the `aes128-cbc` / `aes192-cbc` / `aes256-cbc` subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, because the behaviour worth testing is
//! the command-line contract itself -- the IV riding in the first block, block-alignment
//! enforcement, exit codes, key loading -- none of which is reachable from the library API.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// SP 800-38A Appendix F IV, shared by every F.2 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four SP 800-38A Appendix F plaintext blocks.
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// F.2.1 CBC-AES128.Encrypt ciphertext.
const CT_128: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
);
/// F.2.3 CBC-AES192.Encrypt ciphertext.
const CT_192: &str = concat!(
    "4f021db243bc633d7178183a9fa071e8",
    "b4d9ada9ad7dedf4e5e738763f69145a",
    "571b242012fb7ae07fa9baac3df102e0",
    "08b0e27988598881d920a9e64f5615cd",
);
/// F.2.5 CBC-AES256.Encrypt ciphertext.
const CT_256: &str = concat!(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    "9cfc4e967edb808d679f777bc6702c7d",
    "39f23369a9d9bacfa530e26304231461",
    "b2eb05e2c39be9fcda6c19078c6a9d1b",
);

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
/// The error-path tests hand a rejected key or a misaligned length to a command that `exit`s before
/// it reads stdin, so the write races the child's exit and loses. That is an expected outcome, not a
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
// These two pin `run`'s pipe handling. Both bugs they cover are timing-dependent: they pass on a
// fast machine with a small payload and fail on a slow or loaded runner, which is exactly how the
// first one reached CI. Forcing the condition with an oversized payload makes them deterministic
// instead of waiting for a bad day. The same pair exists in `aes_cfb_cli_tests.rs`, because each
// file has its own copy of `run`.

/// Far beyond any pipe buffer, so a write cannot complete before the child has drained it.
const OVERSIZED: usize = 4 * 1024 * 1024;

/// An error path must not take the harness down with it.
///
/// `encrypt` with no `--key` prints its complaint and exits without reading stdin, so the write
/// loses the race and the pipe breaks. Before `run` tolerated `ErrorKind::BrokenPipe` this panicked
/// with "failed to write to stdin" (os error 109 on Windows, EPIPE elsewhere) instead of reporting
/// the CLI's actual error, which is what the other error-path tests assert on.
#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    let stderr = run_err(&["aes128-cbc", "encrypt"], &vec![0u8; OVERSIZED]);
    assert!(stderr.contains("--key"), "the CLI's own error must still be reported: {stderr}");
}

/// A payload larger than the pipe buffer must round-trip rather than deadlock.
///
/// This is the reason `run` writes stdin from a separate thread. Writing it inline wedges once both
/// pipes fill: the child blocks writing stdout, so it stops reading stdin, so the harness blocks
/// writing stdin. Nothing times out on its own -- the test just hangs until CI kills the job -- so
/// this is the check that would have caught it.
#[test]
fn a_payload_larger_than_the_pipe_buffer_round_trips() {
    let plaintext = pseudo_random(OVERSIZED, 0xC0FFEE);
    let ciphertext = run_ok(&["aes128-cbc", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(ciphertext.len(), plaintext.len() + 16, "IV plus the ciphertext");

    let recovered = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &ciphertext);
    assert_eq!(recovered, plaintext, "{OVERSIZED} bytes should round trip");
}

// ---- the SP 800-38A F.2 vectors, through the CLI -----------------------------------------

/// `decrypt` reproduces the spec plaintext when handed the spec's IV followed by the spec's
/// ciphertext.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round-trip tests below
/// and, at the library level, by `crypto/modes/tests/sp800_38a_tests.rs`.
#[test]
fn decrypt_matches_sp800_38a_f2_vectors() {
    for (cmd, key, ct) in [
        ("aes128-cbc", KEY_128, CT_128),
        ("aes192-cbc", KEY_192, CT_192),
        ("aes256-cbc", KEY_256, CT_256),
    ] {
        // The CLI expects the IV as the first block of its input, which is exactly how `encrypt`
        // emits it.
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(
            tohex(&out),
            PLAINTEXT,
            "{cmd} decrypt should reproduce the Appendix F.2 plaintext"
        );
    }
}

/// The same, with `-x`, which should give the identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_128}"));
    let binary = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &input);
    let hex_out = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128, "-x"], &input);

    let hex_str = String::from_utf8(hex_out).expect("hex output is text");
    assert_eq!(hex_str.trim_end(), tohex(&binary));
    assert_eq!(hex_str.trim_end(), PLAINTEXT);
}

// ---- round trips ------------------------------------------------------------------------

/// `encrypt | decrypt` recovers the input, for all three key lengths.
///
/// Also checks the output length: the ciphertext is one block longer than the plaintext, because
/// the IV is prepended.
#[test]
fn encrypt_then_decrypt_round_trips() {
    for (cmd, key) in [("aes128-cbc", KEY_128), ("aes192-cbc", KEY_192), ("aes256-cbc", KEY_256)] {
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

/// Round trips at sizes that straddle the 1 KiB streaming chunk and the block boundary.
///
/// 1024 is exactly one chunk; 1040 is a chunk plus one block, which exercises the tail path; 4112
/// is four chunks plus a block; 65536 is many chunks.
#[test]
fn round_trips_across_chunk_boundaries() {
    for size in [16usize, 32, 1024, 1040, 4096, 4112, 65536] {
        let plaintext = pseudo_random(size, size as u32);
        let ciphertext = run_ok(&["aes128-cbc", "encrypt", "--key", KEY_128], &plaintext);
        let recovered = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "{size} bytes should round trip");
    }
}

/// A fresh IV per invocation, so the same plaintext under the same key gives different output.
///
/// This is the operational requirement CBC lives or dies by, and the CLI is where it is easiest to
/// get wrong (e.g. by seeding from a fixed value).
#[test]
fn each_invocation_uses_a_fresh_iv() {
    let plaintext = unhex(PLAINTEXT);
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let ciphertext = run_ok(&["aes128-cbc", "encrypt", "--key", KEY_128], &plaintext);
        let iv = ciphertext[..16].to_vec();
        assert!(seen.insert(iv), "the CLI reused an IV across invocations");
        // ...and the body differs too, not just the IV.
        let recovered = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

// ---- key handling -----------------------------------------------------------------------

/// `--key-file` accepts both a hex file and a raw binary file, and agrees with `--key`.
#[test]
fn key_file_accepts_hex_and_binary() {
    let dir = std::env::temp_dir().join(format!("bc_rust_cli_key_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let hex_path = dir.join("key.hex");
    let bin_path = dir.join("key.bin");
    std::fs::write(&hex_path, KEY_128).expect("write hex key");
    std::fs::write(&bin_path, unhex(KEY_128)).expect("write binary key");

    let input = unhex(&format!("{IV}{CT_128}"));
    let expected = unhex(PLAINTEXT);

    for path in [&hex_path, &bin_path] {
        let out = run_ok(&["aes128-cbc", "decrypt", "--key-file", path.to_str().unwrap()], &input);
        assert_eq!(out, expected, "--key-file {path:?}");
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// A key of the wrong length for the chosen variant is rejected, naming both lengths.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let stderr = run_err(&["aes256-cbc", "encrypt", "--key", KEY_128], &unhex(PLAINTEXT));
    assert!(stderr.contains("32-byte key"), "stderr should name the expected length: {stderr}");
    assert!(stderr.contains("16 bytes"), "stderr should name the supplied length: {stderr}");
}

/// Omitting the key entirely is an error, not a default.
#[test]
fn a_missing_key_is_rejected() {
    let stderr = run_err(&["aes128-cbc", "encrypt"], &unhex(PLAINTEXT));
    assert!(stderr.contains("--key"), "stderr should mention the key options: {stderr}");
}

/// An all-zero key warns but proceeds, matching `helpers::parse_seed`'s stance. NIST publishes
/// all-zero-key vectors, so refusing outright would make some of them untestable from the CLI.
#[test]
fn an_all_zero_key_warns_but_proceeds() {
    let zero_key = "0".repeat(32);
    let out = run(&["aes128-cbc", "encrypt", "--key", &zero_key], &unhex(PLAINTEXT));
    assert!(out.status.success(), "an all-zero key should still work");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("warning"), "an all-zero key should warn: {stderr}");
    assert_eq!(out.stdout.len(), 16 + 64, "IV plus four ciphertext blocks");
}

// ---- block alignment and framing --------------------------------------------------------

/// Input that is not a whole number of blocks is rejected, with a message that explains why
/// rather than just failing. CBC has no answer for a partial block and there is no padding layer.
#[test]
fn unaligned_input_is_rejected_with_an_explanation() {
    for extra in [1usize, 7, 15] {
        let plaintext = pseudo_random(32 + extra, extra as u32);
        let stderr = run_err(&["aes128-cbc", "encrypt", "--key", KEY_128], &plaintext);
        assert!(
            stderr.contains("whole number of 16-byte blocks"),
            "stderr should explain the alignment requirement: {stderr}"
        );
        assert!(
            stderr.contains("padding"),
            "stderr should point at the missing padding layer: {stderr}"
        );
    }
}

/// Decrypt input shorter than the IV it must start with is rejected, and says so.
#[test]
fn decrypt_input_shorter_than_the_iv_is_rejected() {
    for len in [0usize, 1, 15] {
        let stderr = run_err(&["aes128-cbc", "decrypt", "--key", KEY_128], &pseudo_random(len, 1));
        assert!(
            stderr.contains("IV"),
            "stderr should explain the missing IV (len {len}): {stderr}"
        );
    }
}

/// Decrypt input that carries the IV but then an unaligned body is rejected too.
#[test]
fn decrypt_rejects_an_unaligned_body() {
    let mut input = unhex(IV);
    input.extend_from_slice(&pseudo_random(20, 3)); // 20 is not a multiple of 16
    let stderr = run_err(&["aes128-cbc", "decrypt", "--key", KEY_128], &input);
    assert!(
        stderr.contains("whole number of 16-byte blocks"),
        "stderr should explain the alignment requirement: {stderr}"
    );
}

/// Empty input to `encrypt` produces just the IV: zero blocks in, zero blocks out.
///
/// Worth pinning because it is the one input length that is block-aligned but has no blocks, and
/// it is easy for a streaming loop to mishandle.
#[test]
fn empty_input_produces_only_the_iv() {
    let out = run_ok(&["aes128-cbc", "encrypt", "--key", KEY_128], &[]);
    assert_eq!(out.len(), 16, "empty input should yield exactly the IV");

    // ...and feeding that straight back gives empty output.
    let back = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &out);
    assert!(back.is_empty(), "decrypting an IV with no body should give nothing");
}

// ---- cross-variant behaviour ------------------------------------------------------------

/// Decrypting with a different key length than was used to encrypt cannot succeed silently.
#[test]
fn the_three_variants_are_not_interchangeable() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-cbc", "encrypt", "--key", KEY_128], &plaintext);

    // Right length, wrong key: decryption "succeeds" but must not recover the plaintext. CBC is
    // unauthenticated, so garbage out is the expected behaviour, not an error -- which is exactly
    // why the crate docs insist on authenticating separately.
    let wrong_key = "ff".repeat(16);
    let out = run_ok(&["aes128-cbc", "decrypt", "--key", &wrong_key], &ciphertext);
    assert_ne!(out, plaintext, "a wrong key must not recover the plaintext");
    assert_eq!(out.len(), plaintext.len(), "but the length is unchanged: CBC is unauthenticated");
}

/// The subcommands appear in `--help`, so they are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aes128-cbc", "aes192-cbc", "aes256-cbc"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}

/// Each subcommand's own help names the two actions and the IV convention.
#[test]
fn per_command_help_documents_the_iv_convention() {
    let out = run_ok(&["aes128-cbc", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("encrypt"), "help should list the encrypt action");
    assert!(help.contains("decrypt"), "help should list the decrypt action");
    assert!(
        help.contains("FIRST 16 BYTES") || help.contains("first 16 bytes"),
        "help should explain where the IV goes: {help}"
    );
}
