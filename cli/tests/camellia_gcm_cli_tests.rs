//! Tests for the `camellia128-gcm`, `camellia192-gcm` and `camellia256-gcm` subcommands.
//!
//! They share their key, IV and AAD loaders, streaming loops and error paths with the `aes*-gcm`
//! commands (`cli/src/helpers/aead_cipher_helpers.rs`), and `test_aes_gcm.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: a known answer in both directions
//! at each key length, the three key lengths, the tag check, and that the commands exist and
//! round-trip.
//!
//! No standard or vector suite publishes a Camellia-GCM answer (the crate's `gcm_authors_tests.rs`
//! has the Camellia authors' cases, at 128 and 256 bits), so the known answers here, at all three
//! key lengths, are Bouncy Castle Java's, produced as `gcm_bc_java_tests.rs` describes (bc-java 1.87's
//! `GCMBlockCipher` over `CamelliaEngine`, the RFC 3713 keys, a counting nonce, AAD and message);
//! the generated-nonce output is held to the library's own `Camellia128Key<GCM>` as well.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

const KEY: &str = "28ff3def08179311e2734c6d1c4e2871";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");
    match child.stdin.as_mut().expect("stdin piped").write_all(stdin_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to stdin: {e}"),
    }
    child.wait_with_output().expect("failed to wait for bc-rust")
}

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

fn run_err(args: &[&str], stdin_bytes: &[u8]) -> String {
    let out = run(args, stdin_bytes);
    assert!(!out.status.success(), "expected failure from {args:?}, but it succeeded");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

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

/// The library's answer for the same key, nonce, AAD and inline `ciphertext || tag`: the key
/// object's inline one-shot under `GCM`.
fn library_gcm_decrypt(key_hex: &str, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    use bouncycastle::camellia::Camellia128Key;
    use bouncycastle::cipher::modes::GCM;
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::core::symmetric_key::{AeadDecryptionKey, FromKeyMaterial};

    let key_bytes: [u8; 16] = unhex(key_hex).try_into().expect("a 16-byte key");
    let material = KeyMaterial::<16>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let key = Camellia128Key::<GCM>::from_key_material(&material).expect("a valid key");
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("a 12-byte nonce");
    key.decrypt_with_aad(&nonce, aad, ciphertext).expect("the tag verifies")
}

/// (command, key, ct, tag) over the shared nonce, AAD and message below, from bc-java 1.87.
const VECTORS: [(&str, &str, &str, &str); 3] = [
    (
        "camellia128-gcm",
        "0123456789abcdeffedcba9876543210",
        "7a49673f1fc95a61bdbd4fd9991e69ce66e11221900db3fe0477c8db0fde7c3f86f9fb95ddcfd29d32fba91dc8",
        "254bc51b6e3af975424eab7b4cf3bd25",
    ),
    (
        "camellia192-gcm",
        "0123456789abcdeffedcba98765432100011223344556677",
        "ed112533b2cfe17a9db68a9c230c10a83cc3abef4991ee76baf0faf8d14bd0c87091ad693bd85a062f022c3fc2",
        "157cb0bc12aed1c6a327cc7d0d7d93ca",
    ),
    (
        "camellia256-gcm",
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "a8f62afcade453f94e2773f6d2318693ea4d48319cd2ee0268ba9bd4c5c88f57b78226b445b5440e3006df2118",
        "e66a02576a8bad35da49a0c073cae837",
    ),
];
const VECTOR_NONCE: &str = "101112131415161718191a1b";
const VECTOR_AAD: &str = "202122232425262728292a2b2c2d2e2f30313233";
const VECTOR_MSG: &str =
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c";

/// `encrypt` under `--iv` reproduces bc-java's ciphertext and tag, as `ciphertext || tag`, and
/// `decrypt` takes them back to the message, at each key length.
#[test]
fn encrypt_and_decrypt_match_the_bc_java_vectors() {
    for (cmd, key, ct, tag) in VECTORS {
        let args = [cmd, "--key", key, "--iv", VECTOR_NONCE, "--aad", VECTOR_AAD];
        let expected = unhex(&format!("{ct}{tag}"));
        let out = run_ok(&[&args[..], &["-d", "encrypt"]].concat(), &unhex(VECTOR_MSG));
        assert_eq!(out, expected, "{cmd}: ciphertext || tag");
        let back = run_ok(&[&args[..], &["-d", "decrypt"]].concat(), &expected);
        assert_eq!(back, unhex(VECTOR_MSG), "{cmd}: decrypt");
    }
}

/// What the command emits must be exactly what the library's `GCM` key produces: the generated
/// nonce leads, the body is as long as the input, and the tag follows.
#[test]
fn the_command_is_gcm_over_camellia() {
    for len in [0usize, 1, 5, 16, 17, 64, 1000] {
        let plaintext = pseudo_random(len, len as u32);
        let out = run_ok(
            &["camellia128-gcm", "-d", "encrypt", "--key", KEY, "--aad", "deadbeef"],
            &plaintext,
        );
        assert_eq!(out.len(), NONCE_LEN + len + TAG_LEN, "len {len}: nonce, body and tag");
        let (nonce, body) = out.split_at(NONCE_LEN);
        let recovered = library_gcm_decrypt(KEY, nonce, &unhex("deadbeef"), body);
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");
        let back =
            run_ok(&["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &out);
        assert_eq!(back, plaintext, "len {len}: round trip");
    }
}

/// A flipped ciphertext bit, a flipped tag bit, other AAD or another key fails the tag check.
#[test]
fn tampering_fails_the_tag_check() {
    let plaintext = pseudo_random(69, 9);
    let iv = "32bcb9b569e3b852d37c766a";
    let args = ["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--iv", iv, "--aad", "c3"];
    let mut ct = run_ok(
        &["camellia128-gcm", "-d", "encrypt", "--key", KEY, "--iv", iv, "--aad", "c3"],
        &plaintext,
    );
    assert_eq!(run_ok(&args, &ct), plaintext);
    ct[0] ^= 1;
    assert!(run_err(&args, &ct).contains("authentication failed"));
    ct[0] ^= 1;
    let last = ct.len() - 1;
    ct[last] ^= 1;
    assert!(run_err(&args, &ct).contains("authentication failed"));
    ct[last] ^= 1;
    let other_aad = ["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--iv", iv, "--aad", "c4"];
    assert!(run_err(&other_aad, &ct).contains("authentication failed"));
    let other_key = [
        "camellia128-gcm",
        "-d",
        "decrypt",
        "--key",
        "28ff3def08179311e2734c6d1c4e2870",
        "--iv",
        iv,
        "--aad",
        "c3",
    ];
    assert!(run_err(&other_key, &ct).contains("authentication failed"));
}

/// Without `--iv` the command draws one and writes it first; the round trip works at every key
/// length and the output is 12 + len + 16 bytes.
#[test]
fn encrypt_then_decrypt_round_trips_at_every_key_length() {
    let message: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    for (cmd, key) in [
        ("camellia128-gcm", "000102030405060708090a0b0c0d0e0f"),
        ("camellia192-gcm", "000102030405060708090a0b0c0d0e0f1011121314151617"),
        ("camellia256-gcm", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
    ] {
        let ct = run_ok(&[cmd, "-d", "encrypt", "--key", key], &message);
        assert_eq!(ct.len(), 12 + message.len() + 16, "{cmd}: IV || ciphertext || tag");
        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key], &ct);
        assert_eq!(back, message, "{cmd}");
        let again = run_ok(&[cmd, "-d", "encrypt", "--key", key], &message);
        assert_ne!(again[..12], ct[..12], "{cmd}: a fresh IV each time");
    }
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["camellia128-gcm", "-d", "encrypt", "--key", "0011"], b"x");
    assert!(err.contains("16-byte key"), "{err}");
    let err = run_err(&["camellia256-gcm", "-d", "encrypt", "--key", KEY], b"x");
    assert!(err.contains("32-byte key"), "{err}");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    let help = String::from_utf8(run_ok(&["--help"], b"")).unwrap();
    for name in ["camellia128-gcm", "camellia192-gcm", "camellia256-gcm"] {
        assert!(help.contains(name), "--help should list {name}");
    }
}
