//! Tests for the `aes128-ecb` / `aes192-ecb` / `aes256-ecb` subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, because the behaviour worth testing is
//! the command-line contract itself -- no IV framing, block-alignment enforcement, exit codes, key
//! loading -- none of which is reachable from the library API.
//!
//! The commands share their plumbing with `aes*-cbc` and `aes*-cfb` (`cli/src/block_mode_cmd.rs`),
//! generic over the mode's `INIT_DATA_LEN`, which for ECB is 0. So this file repeats the key and
//! alignment coverage of the other suites (a wiring mistake in the ECB dispatcher would not show up
//! there) and adds what is ECB-specific: the F.1 vectors in *both* directions (no IV means `encrypt`
//! is reproducible), output exactly as long as input, determinism across invocations, the codebook
//! property, Appendix D error propagation confined to one block, and the guard that ECB and CBC
//! ciphertexts are not interchangeable.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

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

/// F.1.1 ECB-AES128.Encrypt ciphertext.
const CT_128: &str = concat!(
    "3ad77bb40d7a3660a89ecaf32466ef97",
    "f5d3d58503b9699de785895a96fdbaaf",
    "43b1cd7f598ece23881b00e3ed030688",
    "7b0c785e27e8ad3f8223207104725dd4",
);
/// F.1.3 ECB-AES192.Encrypt ciphertext.
const CT_192: &str = concat!(
    "bd334f1d6e45f25ff712a214571fa5cc",
    "974104846d0ad3ad7734ecb3ecee4eef",
    "ef7afd2270e2e60adce0ba2face6444e",
    "9a4b41ba738d6c72fb16691603c18e0e",
);
/// F.1.5 ECB-AES256.Encrypt ciphertext.
const CT_256: &str = concat!(
    "f3eed1bdb5d2a03c064b5a7e3db181f8",
    "591ccb10d410ed26dc5ba74a31362870",
    "b6ed21b99ca6f4f9f153e7b1beafed1d",
    "23304b7a39f9f3ff067d8d8f9e24ecc7",
);

/// F.2.1 CBC-AES128.Encrypt: the Appendix F IV and ciphertext, for the cross-mode guard.
const CBC_IV: &str = "000102030405060708090a0b0c0d0e0f";
const CBC_CT_128: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
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
// These two pin `run`'s pipe handling, as in the CBC and CFB suites; each file has its own `run`.

/// Far beyond any pipe buffer, so a write cannot complete before the child has drained it.
const OVERSIZED: usize = 4 * 1024 * 1024;

#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    let stderr = run_err(&["aes128-ecb", "encrypt"], &vec![0u8; OVERSIZED]);
    assert!(stderr.contains("--key"), "the CLI's own error must still be reported: {stderr}");
}

#[test]
fn a_payload_larger_than_the_pipe_buffer_round_trips() {
    let plaintext = pseudo_random(OVERSIZED, 0xC0FFEE);
    let ciphertext = run_ok(&["aes128-ecb", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(
        ciphertext.len(),
        plaintext.len(),
        "no IV: the ciphertext is as long as the plaintext"
    );
    let recovered = run_ok(&["aes128-ecb", "decrypt", "--key", KEY_128], &ciphertext);
    assert_eq!(recovered, plaintext, "{OVERSIZED} bytes should round trip");
}

// ---- the SP 800-38A F.1 vectors, through the CLI -----------------------------------------

/// With no IV, `encrypt` is reproducible, so both directions can be pinned to the published
/// vectors: F.1.1/F.1.3/F.1.5 encrypt and F.1.2/F.1.4/F.1.6 decrypt.
#[test]
fn both_directions_match_sp800_38a_f1_vectors() {
    for (cmd, key, ct) in [
        ("aes128-ecb", KEY_128, CT_128),
        ("aes192-ecb", KEY_192, CT_192),
        ("aes256-ecb", KEY_256, CT_256),
    ] {
        let enc = run_ok(&[cmd, "encrypt", "--key", key], &unhex(PLAINTEXT));
        assert_eq!(tohex(&enc), ct, "{cmd} encrypt should reproduce the Appendix F.1 ciphertext");
        let dec = run_ok(&[cmd, "decrypt", "--key", key], &unhex(ct));
        assert_eq!(
            tohex(&dec),
            PLAINTEXT,
            "{cmd} decrypt should reproduce the Appendix F.1 plaintext"
        );
    }
}

/// The same, with `-x`, which should give the identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let binary = run_ok(&["aes128-ecb", "encrypt", "--key", KEY_128], &unhex(PLAINTEXT));
    let hex_out = run_ok(&["aes128-ecb", "encrypt", "--key", KEY_128, "-x"], &unhex(PLAINTEXT));
    let hex_str = String::from_utf8(hex_out).expect("hex output is text");
    assert_eq!(hex_str.trim_end(), tohex(&binary));
    assert_eq!(hex_str.trim_end(), CT_128);
}

// ---- round trips and framing ------------------------------------------------------------

/// `encrypt | decrypt` recovers the input for all three key lengths, and nothing is prepended.
#[test]
fn encrypt_then_decrypt_round_trips_with_no_iv() {
    for (cmd, key) in [("aes128-ecb", KEY_128), ("aes192-ecb", KEY_192), ("aes256-ecb", KEY_256)] {
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
        assert_eq!(ciphertext.len(), plaintext.len(), "{cmd}: no IV is written");
        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}: round trip");
    }
}

/// Round trips at sizes that straddle the 1 KiB streaming chunk, the four-block batch and the
/// block boundary: 128 is two fours; 144 is two fours plus one block; 1040 is a chunk plus a block.
#[test]
fn round_trips_across_chunk_and_batch_boundaries() {
    for size in [16usize, 32, 128, 144, 1024, 1040, 4096, 4112, 65536] {
        let plaintext = pseudo_random(size, size as u32);
        let ciphertext = run_ok(&["aes128-ecb", "encrypt", "--key", KEY_128], &plaintext);
        assert_eq!(ciphertext.len(), size);
        let recovered = run_ok(&["aes128-ecb", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "{size} bytes should round trip");
    }
}

/// Empty input gives empty output in both directions: there is no IV to emit or require.
#[test]
fn empty_input_produces_empty_output() {
    assert!(run_ok(&["aes128-ecb", "encrypt", "--key", KEY_128], &[]).is_empty());
    assert!(run_ok(&["aes128-ecb", "decrypt", "--key", KEY_128], &[]).is_empty());
}

// ---- the codebook property, visible on the wire -----------------------------------------

/// SP 800-38A Sec 6.1: the same plaintext block under the same key always gives the same
/// ciphertext block. Across invocations the output is identical (no IV to vary it), and within a
/// message equal blocks stay equal. This is the reason the help text warns against using ECB for
/// data, and it is pinned so the command cannot quietly become something else.
#[test]
fn ecb_is_deterministic_and_shows_repeated_blocks() {
    let block = unhex("00112233445566778899aabbccddeeff");
    let mut plaintext = block.clone();
    plaintext.extend_from_slice(&unhex("ffeeddccbbaa99887766554433221100"));
    plaintext.extend_from_slice(&block);

    let first = run_ok(&["aes128-ecb", "encrypt", "--key", KEY_128], &plaintext);
    let second = run_ok(&["aes128-ecb", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(first, second, "the same input gives the same output every time");
    assert_eq!(first[..16], first[32..], "equal plaintext blocks give equal ciphertext blocks");
    assert_ne!(first[..16], first[16..32]);
}

// ---- key handling -----------------------------------------------------------------------

#[test]
fn key_file_accepts_hex_and_binary() {
    let dir = std::env::temp_dir().join(format!("bc_rust_ecb_cli_key_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let hex_path = dir.join("key.hex");
    let bin_path = dir.join("key.bin");
    std::fs::write(&hex_path, KEY_128).expect("write hex key");
    std::fs::write(&bin_path, unhex(KEY_128)).expect("write binary key");
    for path in [&hex_path, &bin_path] {
        let out = run_ok(
            &["aes128-ecb", "decrypt", "--key-file", path.to_str().unwrap()],
            &unhex(CT_128),
        );
        assert_eq!(out, unhex(PLAINTEXT), "--key-file {path:?}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let stderr = run_err(&["aes256-ecb", "encrypt", "--key", KEY_128], &unhex(PLAINTEXT));
    assert!(stderr.contains("32-byte key"), "stderr should name the expected length: {stderr}");
    assert!(stderr.contains("16 bytes"), "stderr should name the supplied length: {stderr}");
}

#[test]
fn a_missing_key_is_rejected() {
    let stderr = run_err(&["aes128-ecb", "encrypt"], &unhex(PLAINTEXT));
    assert!(stderr.contains("--key"), "stderr should mention the key options: {stderr}");
}

#[test]
fn an_all_zero_key_warns_but_proceeds() {
    let zero_key = "0".repeat(32);
    let out = run(&["aes128-ecb", "encrypt", "--key", &zero_key], &unhex(PLAINTEXT));
    assert!(out.status.success(), "an all-zero key should still work");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("warning"), "an all-zero key should warn: {stderr}");
    assert_eq!(out.stdout.len(), 64, "four ciphertext blocks and no IV");
}

// ---- block alignment ------------------------------------------------------------------

/// Unaligned input is rejected in both directions, with the mode named and padding pointed at.
#[test]
fn unaligned_input_is_rejected_with_an_explanation() {
    for extra in [1usize, 7, 15] {
        for action in ["encrypt", "decrypt"] {
            let data = pseudo_random(32 + extra, extra as u32);
            let stderr = run_err(&["aes128-ecb", action, "--key", KEY_128], &data);
            assert!(stderr.contains("whole number of 16-byte blocks"), "{action}: {stderr}");
            assert!(stderr.contains("padding"), "{action}: {stderr}");
            assert!(stderr.contains("ECB"), "{action}: stderr should name the mode: {stderr}");
        }
    }
}

// ---- SP 800-38A Appendix D, through the CLI ----------------------------------------------

/// Table D.2 for ECB: a bit error in `Cj` gives "RBE in the decryption of Cj" -- random bit errors
/// in that block -- and Appendix D adds that ECB bit errors "do not affect the decryption of any
/// other blocks". So the corrupted block is randomised and every other block is intact. This is
/// also an end-to-end check that the CLI is running ECB and not CBC (where the next block would
/// show the flipped bit) or CFB (where the same block would).
#[test]
fn a_ciphertext_bit_flip_randomises_only_its_own_block() {
    let plaintext = unhex(PLAINTEXT);
    let mut input = unhex(CT_128);
    input[16 + 3] ^= 0b0010_0000; // byte 3 of C2

    let out = run_ok(&["aes128-ecb", "decrypt", "--key", KEY_128], &input);
    assert_eq!(out.len(), 64);
    assert_eq!(&out[0..16], &plaintext[0..16], "P1 is unaffected");
    let differing: u32 =
        out[16..32].iter().zip(&plaintext[16..32]).map(|(a, b)| (a ^ b).count_ones()).sum();
    assert!(differing > 1, "P2 should be randomised, not flipped in place ({differing} bit(s))");
    assert_eq!(&out[32..48], &plaintext[32..48], "P3 is unaffected: nothing chains");
    assert_eq!(&out[48..64], &plaintext[48..64], "P4 is unaffected");
}

// ---- cross-variant and cross-mode behaviour ---------------------------------------------

#[test]
fn the_three_variants_are_not_interchangeable() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-ecb", "encrypt", "--key", KEY_128], &plaintext);
    let wrong_key = "ff".repeat(16);
    let out = run_ok(&["aes128-ecb", "decrypt", "--key", &wrong_key], &ciphertext);
    assert_ne!(out, plaintext, "a wrong key must not recover the plaintext");
    assert_eq!(out.len(), plaintext.len(), "but the length is unchanged: ECB is unauthenticated");
}

/// ECB and CBC ciphertexts are not interchangeable. The CBC command frames an IV and the ECB
/// command does not, so feeding one to the other is the kind of mistake nothing but this catches:
/// the CBC ciphertext body run through ECB is not the plaintext, and the ECB ciphertext run through
/// CBC (its first block consumed as an IV) is neither the plaintext nor the right length.
#[test]
fn ecb_and_cbc_are_not_interchangeable() {
    let plaintext = unhex(PLAINTEXT);
    let ecb_ct = unhex(CT_128);
    let cbc_input = unhex(&format!("{CBC_IV}{CBC_CT_128}"));

    assert_eq!(run_ok(&["aes128-ecb", "decrypt", "--key", KEY_128], &ecb_ct), plaintext);
    assert_eq!(run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &cbc_input), plaintext);

    let ecb_reads_cbc = run_ok(&["aes128-ecb", "decrypt", "--key", KEY_128], &unhex(CBC_CT_128));
    assert_ne!(ecb_reads_cbc, plaintext, "ECB must not decrypt a CBC ciphertext");

    let cbc_reads_ecb = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &ecb_ct);
    assert_eq!(cbc_reads_ecb.len(), 48, "CBC consumes the first block as an IV");
    assert_ne!(cbc_reads_ecb, plaintext[16..].to_vec(), "CBC must not decrypt an ECB ciphertext");
}

// ---- discoverability --------------------------------------------------------------------

#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aes128-ecb", "aes192-ecb", "aes256-ecb"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}

/// Each subcommand's own help names the two actions, says there is no IV, and carries the warning
/// that ECB is not for data.
#[test]
fn per_command_help_warns_and_documents_the_missing_iv() {
    let out = run_ok(&["aes128-ecb", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("encrypt"), "help should list the encrypt action");
    assert!(help.contains("decrypt"), "help should list the decrypt action");
    assert!(help.contains("NO IV"), "help should say there is no IV: {help}");
    assert!(help.contains("WARNING"), "help should warn against using ECB for data: {help}");
    assert!(help.contains("ECB"), "help should name the mode: {help}");
}
