//! Tests for the `aria128-cfb8`, `aria192-cfb8` and `aria256-cfb8` subcommands.
//!
//! They share their key loader, streaming loops and error paths with the `aes*-cfb8` commands
//! (`cli/src/stream_mode_cmd.rs`), and `aes_cfb8_cli_tests.rs` covers those exhaustively. This
//! file pins what is specific to ARIA: the known-answer vectors, the three key lengths, and that the
//! commands exist and round-trip at any length.
//!
//! Vectors are the `ARIA-*-CFB8` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2), which are KISA's
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

/// `ARIA-128-CFB8` ciphertext (CFB8).
const CT_128: &str = concat!(
    "373c8f6a965599ec785cc8f8149f6c81",
    "b632ccb8e0c6eb6a9707ae52c59257a4",
    "1f94701c1096933127a90195ed0c8e98",
    "690547572423bb45c3d70e4a18ee56b9",
    "67c10e000ba4df5fba7c404134a343d8",
    "375d04b151d161ef83417fe1748447d3",
    "0a6723c406733df7d18aa39a20752d23",
    "81942e244811bb97f72eae446b1815aa",
    "690cd1b1adcbd007c0088ecdc91cb2e2",
    "caf0e11e72459878137eea64ac62a9a1",
);

/// `ARIA-192-CFB8` ciphertext (CFB8).
const CT_192: &str = concat!(
    "411d3b4f57f705aa4d13c46e2cf426af",
    "7c8c916ed7923d889f0047bbf11471b6",
    "d54f8757ef519339105be3cb69babb97",
    "6a57d5631fc23cc3051fe9d36e8b8e27",
    "a2b2c0c4d31928ccbf30ea8239b46ba1",
    "b77f6198e7ecd2ce27b35958148e826f",
    "06aaf385bd30362ff141583e7c1d8924",
    "d44d36a1133094074631e18adafa9d2e",
    "55de98f6895c89d4266ebd33f3d4be51",
    "53a96fa12132ece2e81e66e55baa7ade",
);

/// `ARIA-256-CFB8` ciphertext (CFB8).
const CT_256: &str = concat!(
    "26baa33651e1f66434fec88ef27fd2b9",
    "a79e246dd89a3ffa00e8bdb37155433e",
    "6c24bd0b87d9a85baa9f485ccb984f5e",
    "c24d6a3ef5e3c81396177f039cf580df",
    "db55d6e1c47a28921dfe369e12fd357b",
    "289ad3a5544e1c1bd616d454db9c5f91",
    "f603373f29d5b2ed1b4b51de80f28537",
    "bbd43d5e3b5dd071dc91153cbbe732df",
    "c325821b06ed8acaae656dcf2da9f13e",
    "4f29db671476f1e644ff06d9b67d6bd4",
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
    ("aria128-cfb8", KEY_128, CT_128),
    ("aria192-cfb8", KEY_192, CT_192),
    ("aria256-cfb8", KEY_256, CT_256),
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
    let out = run_ok(&["aria256-cfb8", "decrypt", "--key", KEY_256, "-x"], &input);
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
        let ciphertext = run_ok(&["aria128-cfb8", "encrypt", "--key", KEY_128], &plaintext);
        assert_eq!(ciphertext.len(), 16 + len, "len {len}: init data plus an equal-length body");
        let recovered = run_ok(&["aria128-cfb8", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and so on,
/// are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["aria128-cfb8", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("ARIA-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["aria192-cfb8", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("ARIA-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["aria256-cfb8", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("ARIA-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// The subcommands are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aria128-cfb8", "aria192-cfb8", "aria256-cfb8"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}
