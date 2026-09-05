//! Tests for the `aria128-cbc`, `aria192-cbc` and `aria256-cbc` subcommands.
//!
//! They share their key loader, streaming loops and error paths with the `aes*-cbc` commands
//! (`cli/src/cbc_cmd.rs`), and `aes_cbc_cli_tests.rs` covers those exhaustively. This file pins
//! what is specific to ARIA: the known-answer vectors, the three key lengths, and that the
//! commands exist and round-trip.
//!
//! Vectors are the `ARIA-*-CBC` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2), which
//! are KISA's published ARIA test vectors: a 10-block message under each key length; see
//! `crypto/aria/tests/kisa_vectors_tests.rs`.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The IV shared by the three CBC vectors.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The 160-byte plaintext shared by all three vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const CT_128: &str = "49d61860b14909109cef0d22a9268134fadf9fb23151e9645fba75018bdb1538b53334634bbf7d4cd4b5377033060c155fe3948ca75de1031e1d85619e0ad61eb419a866b3c2dbfd10a4ed18b22149f75897f0b8668b0c1c542c687778835fb7cd46e45f85eaa7072437dd9fa6793d6f8d4ccefc4eb1ac641ac1bd30b18c6d64c49bca137eb21c2e04da62712ca2b4f540c57112c38791852cfac7a5d19ed83a";

const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const CT_192: &str = "afe6cf23974b533c672a826264ea785f4e4f7f780dc7f3f1e0962b80902386d514e9c3e77259de92dd1102ffab086c1ea52a71260db5920a83295c25320e421147ca45d532f327b856ea947cd2196ae2e040826548b4c891b0ed0ca6e714dbc4631998d548110d666b3d54c2a091955c6f05beb4f62309368696c9791fc4c551564a2637f194346ec45fbca6c72a5b4612e208d531d6c34cc5c64eac6bd0cf8c";

const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const CT_256: &str = "523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12fa682edd2d23c8b9c5f043c18b17c1ec4b5867918270fbec1027c19ed6af833da5d620994668ca22f599791d292dd6273b2959082aafb7a996167cce1eec5f0cfd15f610d87e2dda9ba68ce1260ca54b222491418374294e7909b1e8551cd8de";

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

const VARIANTS: [(&str, &str, &str); 3] = [
    ("aria128-cbc", KEY_128, CT_128),
    ("aria192-cbc", KEY_192, CT_192),
    ("aria256-cbc", KEY_256, CT_256),
];

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext, for all
/// three key lengths.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round trip below and, at
/// the library level, by `crypto/aria/tests/kisa_vectors_tests.rs`.
#[test]
fn decrypt_matches_the_kisa_vectors() {
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
    let out = run_ok(&["aria256-cbc", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// `encrypt | decrypt` composes: the IV rides in the first block, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect();

    for (cmd, key, _) in VARIANTS {
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
        assert_eq!(
            ciphertext.len(),
            16 + plaintext.len(),
            "{cmd}: IV block plus one block per input block"
        );
        assert_ne!(&ciphertext[16..], &plaintext[..]);

        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}");
    }
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and the
/// 128-bit key to the 192-bit command, are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["aria128-cbc", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("ARIA-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["aria192-cbc", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("ARIA-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["aria256-cbc", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("ARIA-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// Unaligned input is rejected, as for the AES commands.
#[test]
fn unaligned_input_is_rejected() {
    let err = run_err(&["aria128-cbc", "encrypt", "--key", KEY_128], &[0u8; 17]);
    assert!(err.contains("not a whole number of 16-byte blocks"), "stderr was: {err}");
}
