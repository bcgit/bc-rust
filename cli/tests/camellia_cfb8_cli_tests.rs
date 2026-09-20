//! Tests for the `camellia128-cfb8`, `camellia192-cfb8` and `camellia256-cfb8` subcommands.
//!
//! They share their key loader, streaming loops and error paths with the `aes*-cfb8` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_cfb8_cli_tests.rs` covers those exhaustively. This file
//! pins what is specific to Camellia: the three key lengths, that the commands exist and round-trip
//! at any length, and that what comes out really is CFB8 over Camellia.
//!
//! There is no published Camellia CFB8 vector -- OpenSSL's `evpciph_camellia.txt` says in as many
//! words that it does not carry `CFB{1,8}-CAMELLIAxxx` -- so instead the commands are required to
//! agree with `bouncycastle_modes::Cfb8` over the Camellia permutation, which
//! `crypto/camellia/tests/stream_mode_tests.rs` pins against the SP 800-38A Sec 6.3 equations at
//! `s = 8`.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

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

/// The library's answer for the same key, IV and ciphertext, so the CLI can be held to it.
fn library_cfb8_decrypt<const KEY_LEN: usize, P>(key_hex: &str, iv: &[u8], data: &mut [u8])
where
    P: bouncycastle::core::traits::ElectronicCodeBook<KEY_LEN, 16>,
{
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::core::traits::StreamCipherDecryptor;
    use bouncycastle::modes::{Cfb8, Decrypting};

    let key_bytes: [u8; KEY_LEN] = unhex(key_hex).try_into().expect("the right key length");
    let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let iv: [u8; 16] = iv.try_into().expect("a 16-byte IV");
    Cfb8::<P, Decrypting, KEY_LEN, 16>::decrypt(&key, &iv, data).expect("decryption");
}

/// What each command emits must be exactly what `Cfb8` over the matching permutation produces:
/// take the IV the CLI generated, hand the body to the library, and the plaintext must come back.
#[test]
fn the_commands_are_cfb8_over_camellia() {
    use bouncycastle::camellia::{Camellia_128, Camellia_192, Camellia_256};

    for len in [1usize, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);

        let out = run_ok(&["camellia128-cfb8", "encrypt", "--key", KEY_128], &plaintext);
        let (iv, body) = out.split_at(16);
        let mut recovered = body.to_vec();
        library_cfb8_decrypt::<16, Camellia_128>(KEY_128, iv, &mut recovered);
        assert_eq!(recovered, plaintext, "camellia128-cfb8, len {len}");

        let out = run_ok(&["camellia192-cfb8", "encrypt", "--key", KEY_192], &plaintext);
        let (iv, body) = out.split_at(16);
        let mut recovered = body.to_vec();
        library_cfb8_decrypt::<24, Camellia_192>(KEY_192, iv, &mut recovered);
        assert_eq!(recovered, plaintext, "camellia192-cfb8, len {len}");

        let out = run_ok(&["camellia256-cfb8", "encrypt", "--key", KEY_256], &plaintext);
        let (iv, body) = out.split_at(16);
        let mut recovered = body.to_vec();
        library_cfb8_decrypt::<32, Camellia_256>(KEY_256, iv, &mut recovered);
        assert_eq!(recovered, plaintext, "camellia256-cfb8, len {len}");
    }
}

/// `encrypt | decrypt` composes at any length, with nothing padded.
#[test]
fn any_input_length_is_accepted_and_round_trips() {
    for cmd in ["camellia128-cfb8", "camellia192-cfb8", "camellia256-cfb8"] {
        let key = match cmd {
            "camellia128-cfb8" => KEY_128,
            "camellia192-cfb8" => KEY_192,
            _ => KEY_256,
        };
        for len in [0usize, 1, 15, 17, 33, 1024] {
            let plaintext = pseudo_random(len, len as u32);
            let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
            assert_eq!(
                ciphertext.len(),
                16 + len,
                "{cmd}, len {len}: IV plus an equal-length body"
            );
            let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
            assert_eq!(recovered, plaintext, "{cmd}, len {len}: round trip");
        }
    }
}

/// CFB8 and CFB128 are different modes, and `camellia128-cfb8` must not be a second name for
/// `camellia128-cfb`: handed the same IV and ciphertext, the two commands disagree past the first
/// byte.
#[test]
fn cfb8_is_not_cfb() {
    let iv = "000102030405060708090a0b0c0d0e0f";
    let body = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51";
    let input = unhex(&format!("{iv}{body}"));

    let as_cfb8 = run_ok(&["camellia128-cfb8", "decrypt", "--key", KEY_128], &input);
    let as_cfb = run_ok(&["camellia128-cfb", "decrypt", "--key", KEY_128], &input);

    assert_eq!(
        as_cfb8[0], as_cfb[0],
        "both XOR the first byte with MSB_8 of the same output block"
    );
    assert_ne!(as_cfb8[1..], as_cfb[1..], "and they diverge from the second byte on");
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and so on,
/// are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["camellia128-cfb8", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("Camellia-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia192-cfb8", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("Camellia-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia256-cfb8", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("Camellia-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// The harness above must survive a write that loses the race with the child's exit. This pins it
/// deterministically: the key is rejected so `camellia128-cfb8` exits before reading a byte, and
/// the payload is far larger than any pipe buffer, so the write is certain to get EPIPE rather
/// than merely likely to. It guards the `run` helper that every test in this file -- and, copy
/// for copy, the sibling cfb and ctr suites -- depends on.
#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    let err =
        run_err(&["camellia128-cfb8", "encrypt", "--key", KEY_256], &vec![0u8; 4 * 1024 * 1024]);
    assert!(err.contains("Camellia-128 needs a 16-byte key"), "stderr was: {err}");
}

/// The subcommands are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["camellia128-cfb8", "camellia192-cfb8", "camellia256-cfb8"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}
