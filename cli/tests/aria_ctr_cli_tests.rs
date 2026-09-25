//! Tests for the `aria128-ctr`, `aria192-ctr` and `aria256-ctr` subcommands.
//!
//! They share their key loader, streaming loops and error paths with the `aes*-ctr` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_ctr_cli_tests.rs` covers those exhaustively. This
//! file pins what is specific to ARIA: the known-answer vectors, the three key lengths, and
//! that the commands exist and round-trip at any length.
//!
//! Vectors are the `ARIA-*-CTR` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2),
//! which are KISA's published ARIA test vectors; see `crypto/aria/tests/stream_mode_tests.rs`.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The nonce the CTR vectors imply: their counter block is all zeros, and these commands split the
/// leading 12 bytes of it off as the nonce.
const NONCE: &str = "000000000000000000000000";

/// The 160-byte plaintext shared by all nine KISA mode vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `ARIA-128-CTR` ciphertext (CTR).
const CT_128: &str = concat!(
    "ac5d7de805a0bf1c57c854501af60fa1",
    "1497e2a34519dea1569e91e5b5ccae2f",
    "f3bfa1bf975f4571f48be191613546c3",
    "911163c085f871f0e7ae5f2a085b8185",
    "1c2a3ddf20ecb8fa51901aec8ee4ba32",
    "a35dab67bb72cd9140ad188a967ac0fb",
    "bdfa94ea6cce47dcf8525ab5a814cfeb",
    "2bb60ee2b126e2d9d847c1a9e96f9019",
    "e3e6a7fe40d3829afb73db1cc245646a",
    "ddb62d9b907baaafbe46a73dbc131d3d",
);

/// `ARIA-192-CTR` ciphertext (CTR).
const CT_192: &str = concat!(
    "08625ca8fe569c19ba7af3760a6ed1ce",
    "f4d199263e999dde14082dbba7560b79",
    "a4c6b456b8707dce751f9854f18893df",
    "db3f4e5afa539733e6f1e70b98ba3789",
    "1f8f81e95df8efc26c7ce043504cb189",
    "58b865e4e316cd2aa1c97f31bf23dc04",
    "6ef326b95a692a191ba0f2a41c5fe9ae",
    "070f236ff7078e703b42666caafbdd20",
    "bad74ac4c20c0f46c7ca24c151716575",
    "c947da16c90cfe1bf217a41cfebe7531",
);

/// `ARIA-256-CTR` ciphertext (CTR).
const CT_256: &str = concat!(
    "30026c329666141721178b99c0a1f1b2",
    "f06940253f7b3089e2a30ea86aa3c88f",
    "5940f05ad7ee41d71347bb7261e348f1",
    "8360473fdf7d4e7723bffb4411cc13f6",
    "cdd89f3bc7b9c768145022c7a74f14d7",
    "c305cd012a10f16050c23f1ae5c23f45",
    "998d13fbaa041e51619577e077276489",
    "6a5d4516d8ffceb3bf7e05f613edd9a6",
    "0cdcedaff9cfcaf4e00d445a54334f73",
    "ab2cad944e51d266548e61c6eb0aa1cd",
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
    ("aria128-ctr", KEY_128, CT_128),
    ("aria192-ctr", KEY_192, CT_192),
    ("aria256-ctr", KEY_256, CT_256),
];

/// `decrypt` reproduces the plaintext when handed the NONCE followed by the ciphertext, for
/// all three key lengths.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own NONCE, so it
/// cannot be asked to reproduce a published ciphertext. `encrypt` is covered by the round trip
/// below and, at the library level, by `crypto/aria/tests/stream_mode_tests.rs`.
#[test]
fn decrypt_matches_the_kisa_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{}{ct}", NONCE));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{}{}", NONCE, CT_256));
    let out = run_ok(&["aria256-ctr", "decrypt", "--key", KEY_256, "-x"], &input);
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
            12 + plaintext.len(),
            "{cmd}: init data plus an equal-length body"
        );
        assert_ne!(&ciphertext[12..], &plaintext[..]);

        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}");
    }
}

/// Unlike `aria*-cbc`, any length is accepted and nothing is padded: this is a stream cipher.
#[test]
fn any_input_length_is_accepted() {
    for len in [0usize, 1, 15, 17, 33] {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&["aria128-ctr", "encrypt", "--key", KEY_128], &plaintext);
        assert_eq!(ciphertext.len(), 12 + len, "len {len}: init data plus an equal-length body");
        let recovered = run_ok(&["aria128-ctr", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// CTR writes a **12-byte** nonce where the other ARIA modes write a 16-byte IV, so the output is
/// 12 bytes longer than the input rather than 16. Getting this wrong would shift every byte of the
/// payload.
#[test]
fn the_nonce_is_twelve_bytes_not_sixteen() {
    let plaintext = pseudo_random(64, 7);
    let out = run_ok(&["aria128-ctr", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(out.len(), plaintext.len() + 12, "a 12-byte nonce plus the ciphertext");

    let via_cfb = run_ok(&["aria128-cfb", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(via_cfb.len(), plaintext.len() + 16, "aria128-cfb writes a 16-byte IV");

    let back = run_ok(&["aria128-ctr", "decrypt", "--key", KEY_128], &out);
    assert_eq!(back, plaintext);
}

/// A fresh nonce per invocation. For CTR this is the whole security argument: a repeated nonce
/// under one key repeats the keystream and leaks the XOR of the two messages.
#[test]
fn each_invocation_uses_a_fresh_nonce() {
    let plaintext = pseudo_random(64, 11);
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let ciphertext = run_ok(&["aria128-ctr", "encrypt", "--key", KEY_128], &plaintext);
        assert!(seen.insert(ciphertext[..12].to_vec()), "the CLI reused a nonce");
        let recovered = run_ok(&["aria128-ctr", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and so on,
/// are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["aria128-ctr", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("ARIA-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["aria192-ctr", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("ARIA-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["aria256-ctr", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("ARIA-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// The subcommands are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aria128-ctr", "aria192-ctr", "aria256-ctr"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}
