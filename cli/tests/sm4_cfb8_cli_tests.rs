//! Tests for the `sm4-cfb8` subcommand.
//!
//! `sm4-cfb8` shares its key loader, streaming loops and error paths with the `aes*-cfb8` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_cfb8_cli_tests.rs` covers those exhaustively. This file
//! pins what is specific to SM4: the 16-byte key length, that the command exists and round-trips at
//! any length, and that what comes out really is CFB8 over SM4 rather than some other mode.
//!
//! draft-ribose-cfrg-sm4-10 defines SM4-CFB-8 (Sec 8.5.1) but publishes no example of it, so there
//! is no vector to decrypt here. Instead the command is required to agree with
//! `bouncycastle_modes::Cfb8` over the SM4 permutation, which `crypto/sm4/tests/stream_mode_tests.rs`
//! pins against the Sec 8.5.2 equations. That is the same thing the AES CFB8 suite gets from
//! SP 800-38A F.3, one step removed.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The single SM4 key length.
const KEY: &str = "0123456789abcdeffedcba9876543210";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");

    child
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(stdin_bytes)
        .expect("failed to write to stdin");

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
/// The library's answer for the same key, IV and plaintext, so the CLI can be held to it.
fn library_cfb8_decrypt(key_hex: &str, iv: &[u8], data: &mut [u8]) {
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::core::traits::StreamCipherDecryptor;
    use bouncycastle::modes::{Cfb8, Decrypting};
    use bouncycastle::sm4::SM4;

    let key_bytes: [u8; 16] = unhex(key_hex).try_into().expect("a 16-byte key");
    let key = KeyMaterial::<16>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let iv: [u8; 16] = iv.try_into().expect("a 16-byte IV");
    Cfb8::<SM4, Decrypting, 16, 16>::decrypt(&key, &iv, data).expect("decryption");
}

/// What the command emits must be exactly what `Cfb8` over `SM4` produces: take the IV the CLI
/// generated, hand the body to the library, and the plaintext must come back.
#[test]
fn the_command_is_cfb8_over_sm4() {
    for len in [1usize, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);
        let out = run_ok(&["sm4-cfb8", "encrypt", "--key", KEY], &plaintext);
        assert_eq!(out.len(), 16 + len, "len {len}: IV block plus an equal-length body");

        let (iv, body) = out.split_at(16);
        let mut recovered = body.to_vec();
        library_cfb8_decrypt(KEY, iv, &mut recovered);
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");
    }
}

/// `encrypt | decrypt` composes: the IV rides in the first block, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext = pseudo_random(4096, 0xC0FFEE);

    let ciphertext = run_ok(&["sm4-cfb8", "encrypt", "--key", KEY], &plaintext);
    assert_eq!(ciphertext.len(), 16 + plaintext.len(), "IV block plus an equal-length body");
    assert_ne!(&ciphertext[16..], &plaintext[..]);

    let recovered = run_ok(&["sm4-cfb8", "decrypt", "--key", KEY], &ciphertext);
    assert_eq!(recovered, plaintext);
}

/// Any length is accepted and nothing is padded: CFB8's segment is a single byte.
#[test]
fn any_input_length_is_accepted() {
    for len in [0usize, 1, 15, 17, 33] {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&["sm4-cfb8", "encrypt", "--key", KEY], &plaintext);
        assert_eq!(ciphertext.len(), 16 + len, "len {len}: IV plus an equal-length body");
        let recovered = run_ok(&["sm4-cfb8", "decrypt", "--key", KEY], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// CFB8 and CFB128 are different modes, and `sm4-cfb8` must not be a second name for `sm4-cfb`:
/// handed the same IV and ciphertext, the two commands disagree past the first byte.
#[test]
fn sm4_cfb8_is_not_sm4_cfb() {
    let iv = "000102030405060708090a0b0c0d0e0f";
    let body = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb";
    let input = unhex(&format!("{iv}{body}"));

    let as_cfb8 = run_ok(&["sm4-cfb8", "decrypt", "--key", KEY], &input);
    let as_cfb = run_ok(&["sm4-cfb", "decrypt", "--key", KEY], &input);

    assert_eq!(
        as_cfb8[0], as_cfb[0],
        "both XOR the first byte with MSB_8 of the same output block"
    );
    assert_ne!(as_cfb8[1..], as_cfb[1..], "and they diverge from the second byte on");
}

/// SM4 has exactly one key length. An AES-256-sized key is an error naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    let err = run_err(&["sm4-cfb8", "encrypt", "--key", key_256], &[0u8; 16]);
    assert!(err.contains("SM4 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
}

/// The subcommand is discoverable.
#[test]
fn the_subcommand_is_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    assert!(String::from_utf8_lossy(&out).contains("sm4-cfb8"), "`--help` should list sm4-cfb8");
}
