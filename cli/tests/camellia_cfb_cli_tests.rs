//! Tests for the `camellia128-cfb`, `camellia192-cfb` and `camellia256-cfb` subcommands.
//!
//! They share their key loader, streaming loops and error paths with the `aes*-cfb` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_cfb_cli_tests.rs` covers those exhaustively. This file
//! pins what is specific to Camellia: the known-answer vectors, the three key lengths, and that the
//! commands exist and round-trip at any length.
//!
//! Vectors are the `CAMELLIA-*-CFB` entries of OpenSSL's `evpciph_camellia.txt` (OpenSSL 3.6.2):
//! for each key length the four entries chain into one four-block CFB128 message under the IV
//! `000102..0f`; see `crypto/camellia/tests/stream_mode_tests.rs`.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The IV of the first entry of every chain.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four chained plaintext blocks (SP 800-38A Appendix F's).
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

const CT_128: &str = concat!(
    "14f7646187817eb586599146b82bd719",
    "a53d28bb82df741103ea4f921a44880b",
    "9c2157a664626d1def9ea420fde69b96",
    "742a25f0542340c7baef24ca8482bb09",
);
const CT_192: &str = concat!(
    "c832bb9780677daa82d9b6860dcd565e",
    "86f8491627906d780c7a6d46ea331f98",
    "69511cce594cf710cb98bb63d7221f01",
    "d5b5378a3abed55803f25565d8907b84",
);
const CT_256: &str = concat!(
    "cf6107bb0cea7d7fb1bd31f5e7b06c93",
    "89bedb4ccdd864ea11ba4cbe849b5e2b",
    "555fc3f34bdd2d54c62d9e3bf338c1c4",
    "5953adce14db8c7f39f1bd39f359bffa",
);

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

const VARIANTS: [(&str, &str, &str); 3] = [
    ("camellia128-cfb", KEY_128, CT_128),
    ("camellia192-cfb", KEY_192, CT_192),
    ("camellia256-cfb", KEY_256, CT_256),
];

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext, for all three
/// key lengths.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round trip below and, at
/// the library level, by `crypto/camellia/tests/stream_mode_tests.rs`.
#[test]
fn decrypt_matches_the_openssl_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_256}"));
    let out = run_ok(&["camellia256-cfb", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// `encrypt | decrypt` composes: the IV rides in the first block, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext = pseudo_random(4096, 0xC0FFEE);

    for (cmd, key, _) in VARIANTS {
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
        assert_eq!(ciphertext.len(), 16 + plaintext.len(), "{cmd}: IV plus an equal-length body");
        assert_ne!(&ciphertext[16..], &plaintext[..]);

        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}");
    }
}

/// Unlike `camellia*-cbc`, any length is accepted and nothing is padded: CFB is a stream cipher.
#[test]
fn any_input_length_is_accepted() {
    for len in [0usize, 1, 15, 17, 33] {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&["camellia128-cfb", "encrypt", "--key", KEY_128], &plaintext);
        assert_eq!(ciphertext.len(), 16 + len, "len {len}: IV plus an equal-length body");
        let recovered = run_ok(&["camellia128-cfb", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and so on,
/// are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["camellia128-cfb", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("Camellia-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia192-cfb", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("Camellia-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia256-cfb", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("Camellia-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// The subcommands are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["camellia128-cfb", "camellia192-cfb", "camellia256-cfb"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}
