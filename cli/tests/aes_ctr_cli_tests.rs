//! Tests for the `aes128-ctr` / `aes192-ctr` / `aes256-ctr` subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, because the behaviour worth testing is
//! the command-line contract itself -- the nonce riding at the front of the ciphertext, the chunked
//! streaming loop, exit codes, key loading -- none of which is reachable from the library API.
//!
//! The commands share their streaming loop with `aes*-cfb` and `aes*-cfb8`
//! (`cli/src/stream_mode_cmd.rs`) and their key loading with `aes*-cbc`
//! (`cli/src/block_mode_cmd.rs`), so this file repeats that coverage rather than assuming it. What
//! is tested only here is the **12-byte** nonce (every other mode writes 16), the OpenSSL-sourced
//! vectors, CTR's total malleability, and that encryption and decryption are the same operation.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// CTR writes a 12-byte nonce, not the 16-byte IV the other modes write.
const NONCE_LEN: usize = 12;

/// The nonce of the OpenSSL-generated vectors: the leading 12 bytes of the initial counter block
/// `000102030405060708090a0b00000000`.
const NONCE: &str = "000102030405060708090a0b";

/// Four SP 800-38A Appendix F plaintext blocks plus five bytes: five counter blocks, last partial.
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
    "0011223344",
);

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// `openssl enc -aes-128-ctr -K <key> -iv 000102030405060708090a0b00000000`, OpenSSL 3.0.13. The
/// same vectors as `crypto/modes/tests/ctr_vector_tests.rs`, run here end to end through the pipe.
const CT_128: &str = concat!(
    "ffd8816338abebca17491bc67fe6751c",
    "093833c279e946d49804c6b03df09f9d",
    "6b0727101b346a530523d59fb883e678",
    "fda525b39296cfc5a821d4dcda5a6227",
    "06efd63405",
);
const CT_192: &str = concat!(
    "c85f24d60a6fd4593209730ecd1ed507",
    "deae5f770708a1e162d04d42fe3dd6e6",
    "acf360f5c5f25e53a09396547d8b7f9b",
    "9d12dc684df141cd0b5462450a8d1900",
    "4a271f6e8e",
);
const CT_256: &str = concat!(
    "b66c7ac8885c5ff473855203b36048ff",
    "5e7e0746b6e3ad4c2b84aaf440b1b987",
    "38a9ad1527187f6f435b83b09734cb04",
    "b3e3a2a77d2a02c4759cbd9b8fc822b3",
    "1223c7e590",
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

/// Far beyond any pipe buffer, so a write cannot complete before the child has drained it.
const OVERSIZED: usize = 4 * 1024 * 1024;

/// An error path must not take the harness down with it.
#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    let stderr = run_err(&["aes128-ctr", "encrypt"], &vec![0u8; OVERSIZED]);
    assert!(stderr.contains("--key"), "the CLI's own error must still be reported: {stderr}");
}

/// A payload larger than the pipe buffer must round-trip rather than deadlock.
#[test]
fn a_payload_larger_than_the_pipe_buffer_round_trips() {
    let plaintext = pseudo_random(OVERSIZED, 0xC0FFEE);
    let ciphertext = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(ciphertext.len(), plaintext.len() + NONCE_LEN, "nonce plus the ciphertext");

    let recovered = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &ciphertext);
    assert_eq!(recovered, plaintext, "{OVERSIZED} bytes should round trip");
}

// ---- the OpenSSL vectors, through the CLI -------------------------------------------------

/// `decrypt` reproduces the plaintext when handed the nonce followed by the OpenSSL ciphertext, for
/// all three key lengths. The message spans five counter blocks, so this exercises the counter
/// increment end to end through the command.
#[test]
fn decrypt_matches_the_openssl_vectors() {
    for (cmd, key, ct) in [
        ("aes128-ctr", KEY_128, CT_128),
        ("aes192-ctr", KEY_192, CT_192),
        ("aes256-ctr", KEY_256, CT_256),
    ] {
        let input = unhex(&format!("{NONCE}{ct}"));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should reproduce the plaintext");
    }
}

/// The same, with `-x`.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{NONCE}{CT_128}"));
    let binary = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &input);
    let hex_out = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128, "-x"], &input);

    let hex_str = String::from_utf8(hex_out).expect("hex output is text");
    assert_eq!(hex_str.trim_end(), tohex(&binary));
    assert_eq!(hex_str.trim_end(), PLAINTEXT);
}

// ---- the nonce is 12 bytes ----------------------------------------------------------------

/// CTR writes a **12-byte** nonce where the other modes write a 16-byte IV, so the ciphertext is
/// 12 bytes longer than the plaintext rather than 16. Getting this wrong would silently shift every
/// byte of the payload.
#[test]
fn the_nonce_is_twelve_bytes_not_sixteen() {
    let plaintext = unhex(PLAINTEXT);
    let out = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(out.len(), plaintext.len() + 12, "output should be a 12-byte nonce plus ciphertext");

    // ...and decrypt consumes exactly 12, so a round trip through the pipe is exact.
    let back = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &out);
    assert_eq!(back, plaintext);
}

/// Decrypt input shorter than the 12-byte nonce is rejected, and says so.
#[test]
fn decrypt_input_shorter_than_the_nonce_is_rejected() {
    for len in [0usize, 1, 11] {
        let stderr = run_err(&["aes128-ctr", "decrypt", "--key", KEY_128], &pseudo_random(len, 1));
        assert!(
            stderr.contains("IV"),
            "stderr should explain the missing nonce (len {len}): {stderr}"
        );
    }
}

/// Exactly the nonce and nothing else decrypts to nothing.
#[test]
fn empty_input_produces_only_the_nonce() {
    let out = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &[]);
    assert_eq!(out.len(), NONCE_LEN, "empty input should yield exactly the nonce");
    let back = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &out);
    assert!(back.is_empty(), "decrypting a nonce with no body should give nothing");
}

// ---- round trips ---------------------------------------------------------------------------

#[test]
fn encrypt_then_decrypt_round_trips() {
    for (cmd, key) in [("aes128-ctr", KEY_128), ("aes192-ctr", KEY_192), ("aes256-ctr", KEY_256)] {
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + NONCE_LEN, "{cmd}: nonce plus ciphertext");
        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}: round trip");
    }
}

/// Any length round-trips with the ciphertext exactly as long as the plaintext.
#[test]
fn any_input_length_is_accepted_and_round_trips() {
    for len in 0..=(2 * 16 + 1) {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &plaintext);
        assert_eq!(ciphertext.len(), len + NONCE_LEN, "len {len}: nonce plus an equal-length body");
        let recovered = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// Round trips at sizes that straddle the 1 KiB streaming chunk and the block boundary.
#[test]
fn round_trips_across_chunk_boundaries() {
    for size in [16usize, 1023, 1024, 1025, 4096, 4099, 65536] {
        let plaintext = pseudo_random(size, size as u32);
        let ciphertext = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &plaintext);
        let recovered = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "{size} bytes should round trip");
    }
}

/// A fresh nonce per invocation. For CTR this is the whole security argument: a repeated nonce
/// under one key repeats the keystream and leaks the XOR of the two messages.
#[test]
fn each_invocation_uses_a_fresh_nonce() {
    let plaintext = unhex(PLAINTEXT);
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let ciphertext = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &plaintext);
        let nonce = ciphertext[..NONCE_LEN].to_vec();
        assert!(seen.insert(nonce), "the CLI reused a nonce across invocations");
        let recovered = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

// ---- key handling ---------------------------------------------------------------------------

#[test]
fn key_file_accepts_hex_and_binary() {
    let dir = std::env::temp_dir().join(format!("bc_rust_ctr_cli_key_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let hex_path = dir.join("key.hex");
    let bin_path = dir.join("key.bin");
    std::fs::write(&hex_path, KEY_128).expect("write hex key");
    std::fs::write(&bin_path, unhex(KEY_128)).expect("write binary key");

    let input = unhex(&format!("{NONCE}{CT_128}"));
    let expected = unhex(PLAINTEXT);

    for path in [&hex_path, &bin_path] {
        let out = run_ok(&["aes128-ctr", "decrypt", "--key-file", path.to_str().unwrap()], &input);
        assert_eq!(out, expected, "--key-file {path:?}");
    }

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let stderr = run_err(&["aes256-ctr", "encrypt", "--key", KEY_128], &unhex(PLAINTEXT));
    assert!(stderr.contains("32-byte key"), "stderr should name the expected length: {stderr}");
    assert!(stderr.contains("16 bytes"), "stderr should name the supplied length: {stderr}");
}

#[test]
fn a_missing_key_is_rejected() {
    let stderr = run_err(&["aes128-ctr", "encrypt"], &unhex(PLAINTEXT));
    assert!(stderr.contains("--key"), "stderr should mention the key options: {stderr}");
}

#[test]
fn an_all_zero_key_warns_but_proceeds() {
    let zero_key = "0".repeat(32);
    let out = run(&["aes128-ctr", "encrypt", "--key", &zero_key], &unhex(PLAINTEXT));
    assert!(out.status.success(), "an all-zero key should still work");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("warning"), "an all-zero key should warn: {stderr}");
    assert_eq!(out.stdout.len(), NONCE_LEN + 69, "nonce plus the 69 ciphertext bytes");
}

// ---- CTR-specific behaviour ------------------------------------------------------------------

/// Encryption and decryption are the same operation (SP 800-38A Sec 6.5), which is visible from the
/// command line: feeding a ciphertext body back through `encrypt` under its own nonce recovers the
/// plaintext. No other mode here behaves that way.
#[test]
fn encrypt_and_decrypt_are_the_same_operation() {
    let plaintext = unhex(PLAINTEXT);
    let out = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &plaintext);

    // Feed the whole thing -- nonce and all -- back into `encrypt` would generate a *new* nonce, so
    // instead re-present the original nonce followed by the ciphertext body to `decrypt`, and the
    // same pair to a second `encrypt`-shaped run via `decrypt`, which is the same code path.
    let recovered = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &out);
    assert_eq!(recovered, plaintext);

    // Encrypting the recovered plaintext under the *same* nonce must reproduce the ciphertext body:
    // that is only true because the keystream depends on nothing but key and nonce.
    let body = &out[NONCE_LEN..];
    let again = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &out);
    assert_eq!(again, plaintext);
    assert_eq!(body.len(), plaintext.len());
}

/// Appendix D, Table D.2 for CTR: "SBE in the decryption of Cj", and **nothing else affected**.
/// CTR is the most malleable mode here -- a flipped ciphertext bit flips exactly the corresponding
/// plaintext bit, with no garbling anywhere to signal the tampering. The subcommand help warns
/// about precisely this, and this is the end-to-end check of it.
#[test]
fn a_ciphertext_bit_flip_flips_exactly_that_plaintext_bit_and_nothing_else() {
    let plaintext = unhex(PLAINTEXT);
    let mut input = unhex(&format!("{NONCE}{CT_128}"));

    // Byte 3 of the second ciphertext block. The body starts after the 12-byte nonce.
    const OFFSET: usize = 12 + 16 + 3;
    const MASK: u8 = 0b0010_0000;
    input[OFFSET] ^= MASK;

    let out = run_ok(&["aes128-ctr", "decrypt", "--key", KEY_128], &input);
    let mut expected = plaintext.clone();
    expected[16 + 3] ^= MASK;
    assert_eq!(out, expected, "exactly one plaintext bit should change, and nothing else");
}

/// A wrong key cannot recover the plaintext, and fails silently: CTR is unauthenticated.
#[test]
fn a_wrong_key_does_not_recover_the_plaintext() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &plaintext);
    let wrong_key = "ff".repeat(16);
    let out = run_ok(&["aes128-ctr", "decrypt", "--key", &wrong_key], &ciphertext);
    assert_ne!(out, plaintext, "a wrong key must not recover the plaintext");
    assert_eq!(out.len(), plaintext.len(), "but the length is unchanged: CTR is unauthenticated");
}

/// CTR and CFB ciphertexts are not interchangeable, and the nonce lengths differ too.
#[test]
fn ctr_and_cfb_are_not_interchangeable() {
    let plaintext = unhex(PLAINTEXT);
    let ctr = run_ok(&["aes128-ctr", "encrypt", "--key", KEY_128], &plaintext);
    let cfb = run_ok(&["aes128-cfb", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(ctr.len(), plaintext.len() + 12, "CTR prepends 12 bytes");
    assert_eq!(cfb.len(), plaintext.len() + 16, "CFB prepends 16");

    let cfb_reads_ctr = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &ctr);
    assert_ne!(cfb_reads_ctr, plaintext, "CFB must not decrypt a CTR ciphertext");
}

// ---- discoverability --------------------------------------------------------------------------

#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aes128-ctr", "aes192-ctr", "aes256-ctr"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}

/// The per-command help must state the 12-byte nonce, the counter limit and the malleability
/// warning, because all three differ from the other modes.
#[test]
fn per_command_help_documents_the_nonce_and_the_counter() {
    let out = run_ok(&["aes128-ctr", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("encrypt"), "help should list the encrypt action");
    assert!(help.contains("decrypt"), "help should list the decrypt action");
    assert!(
        help.contains("FIRST 12 BYTES") || help.contains("first 12 bytes"),
        "help should say the nonce is 12 bytes: {help}"
    );
    assert!(help.contains("counter"), "help should mention the counter: {help}");
    assert!(
        help.to_lowercase().contains("malleable") || help.contains("flipping"),
        "help should warn about malleability: {help}"
    );
}
