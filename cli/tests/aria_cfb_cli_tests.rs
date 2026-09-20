//! Tests for the `aria128-cfb`, `aria192-cfb` and `aria256-cfb` subcommands.
//!
//! They share their key loader, streaming loops and error paths with the `aes*-cfb` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_cfb_cli_tests.rs` covers those exhaustively. This
//! file pins what is specific to ARIA: the known-answer vectors, the three key lengths, and that the
//! commands exist and round-trip at any length.
//!
//! Vectors are the `ARIA-*-CFB` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2), which are KISA's
//! published ARIA test vectors; see `crypto/aria/tests/stream_mode_tests.rs`.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The IV the CFB128 and CFB8 vectors share -- the same one the CBC vectors use.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The 160-byte plaintext shared by all nine KISA mode vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `ARIA-128-CFB` ciphertext (CFB128).
const CT_128: &str = concat!(
    "3720e53ba7d615383406b09f0a05a200",
    "c07c21e6370f413a5d132500a6828501",
    "7c61b434c7b7ca9685a51071861e4d4b",
    "b873b599b479e2d573dddeafba89f812",
    "ac6a9e44d554078eb3be94839db4b33d",
    "a3f59c063123a7ef6f20e10579fa4fd2",
    "39100ca73b52d4fcafeadee73f139f78",
    "f9b7614c2b3b9dbe010f87db06a89a94",
    "35f79ce8121431371f4e87b984e0230c",
    "22a6dacb32fc42dcc6accef33285bf11",
);

/// `ARIA-192-CFB` ciphertext (CFB128).
const CT_192: &str = concat!(
    "4171f7192bf4495494d2736129640f5c",
    "4d87a9a213664c9448477c6ecc201359",
    "8d9766952dd8c3868f17e36ef66fd84b",
    "fa45d1593d2d6ee3ea2115047d710d4f",
    "b66187caa3a315b3c8ea2d313962edcf",
    "e5a3e2028d5ba9a09fd5c65c19d3440e",
    "477f0cab0628ec6902c73ee02f1afee9",
    "f80115be7b9df82d1e28228e28581a20",
    "560e195cbb9e2b327bf56fd2d0ae5502",
    "e42c13e9b4015d4da42dc859252e7da4",
);

/// `ARIA-256-CFB` ciphertext (CFB128).
const CT_256: &str = concat!(
    "26834705b0f2c0e2588d4a7f09009635",
    "f28bb93d8c31f870ec1e0bdb082b66fa",
    "402dd9c202be300c4517d196b14d4ce1",
    "1dce97f7aaba54341b0d872cc9b63753",
    "a3e8556a14be6f7b3e27e3cfc39caf80",
    "f2a355aa50dc83c09c7b11828694f8e4",
    "aa726c528976b53f2c877f4991a3a8d2",
    "8adb63bd751846ffb2350265e179d499",
    "0753ae8485ff9b4133ddad5875b84a90",
    "cbcfa62a045d726df71b6bda0eeca0be",
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
    ("aria128-cfb", KEY_128, CT_128),
    ("aria192-cfb", KEY_192, CT_192),
    ("aria256-cfb", KEY_256, CT_256),
];

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext, for
/// all three key lengths.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it
/// cannot be asked to reproduce a published ciphertext. `encrypt` is covered by the round trip
/// below and, at the library level, by `crypto/aria/tests/stream_mode_tests.rs`.
#[test]
fn decrypt_matches_the_kisa_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{}{ct}", IV));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{}{}", IV, CT_256));
    let out = run_ok(&["aria256-cfb", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// `encrypt | decrypt` composes: the init data rides at the front, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext = pseudo_random(4096, 0xC0FFEE);

    for (cmd, key, _) in VARIANTS {
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
        assert_eq!(
            ciphertext.len(),
            16 + plaintext.len(),
            "{cmd}: init data plus an equal-length body"
        );
        assert_ne!(&ciphertext[16..], &plaintext[..]);

        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}");
    }
}

/// Unlike `aria*-cbc`, any length is accepted and nothing is padded: this is a stream cipher.
#[test]
fn any_input_length_is_accepted() {
    for len in [0usize, 1, 15, 17, 33] {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&["aria128-cfb", "encrypt", "--key", KEY_128], &plaintext);
        assert_eq!(ciphertext.len(), 16 + len, "len {len}: init data plus an equal-length body");
        let recovered = run_ok(&["aria128-cfb", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and so on,
/// are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["aria128-cfb", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("ARIA-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["aria192-cfb", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("ARIA-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["aria256-cfb", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("ARIA-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// The subcommands are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aria128-cfb", "aria192-cfb", "aria256-cfb"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}
