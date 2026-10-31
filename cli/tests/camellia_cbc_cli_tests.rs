//! Tests for the `camellia128-cbc`, `camellia192-cbc` and `camellia256-cbc` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-cbc`
//! commands (`cli/src/helpers/block_mode_helpers.rs`), and `test_aes_cbc.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: the known-answer vectors in both
//! directions, the three key lengths, and that the commands exist and round-trip.
//!
//! Vectors are the `CAMELLIA-*-CBC` entries of OpenSSL's `evpciph_camellia.txt` (OpenSSL 3.6.2):
//! for each key length the first three entries chain into one three-block message under the IV
//! `000102..0f`; see `crypto/camellia/tests/openssl_cbc_tests.rs`. They are unpadded, so under
//! the commands' PKCS7 framing the three blocks are followed by one block of padding, computed
//! here from the permutation.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// The IV of the first entry of every chain.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The three chained plaintext blocks.
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
);

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const CT_128: &str = concat!(
    "1607cf494b36bbf00daeb0b503c831ab",
    "a2f2cf671629ef7840c5a5dfb5074887",
    "0f06165008cf8b8b5a63586362543e54",
);

const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const CT_192: &str = concat!(
    "2a4830ab5ac4a1a2405955fd2195cf93",
    "5d5a869bd14ce54264f892a6dd2ec3d5",
    "37d359c3349836d884e310addf68c449",
);

const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
const CT_256: &str = concat!(
    "e6cfa35fc02b134a4d2c0b6737ac3eda",
    "36cbeb73bd504b4070b1b7de2b21eb50",
    "e31a6055297d96ca3330cdf1b1860a83",
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

const VARIANTS: [(&str, &str, &str); 3] = [
    ("camellia128-cbc", KEY_128, CT_128),
    ("camellia192-cbc", KEY_192, CT_192),
    ("camellia256-cbc", KEY_256, CT_256),
];

/// The CBC ciphertext block that a full block of PKCS7 padding (sixteen `0x10` bytes) encrypts
/// to under `key_hex` after the ciphertext block `prev_hex`: `E_K(prev xor 10..10)`, from the
/// permutation of the key's length. Appended to an unpadded known-answer ciphertext whose
/// plaintext is block-aligned, it gives the PKCS7 ciphertext of the same plaintext, which is how
/// the commands frame it.
fn pkcs7_block(key_hex: &str, prev_hex: &str) -> String {
    use bouncycastle::camellia::hazmat::{
        Camellia128Internal, Camellia192Internal, Camellia256Internal,
    };
    use bouncycastle::core::hazmat::{BlockPermutation, ElectronicCodeBook};
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};

    fn material<const N: usize>(key_hex: &str) -> KeyMaterial<N> {
        let key_bytes: [u8; N] = unhex(key_hex).try_into().expect("the right key length");
        KeyMaterial::<N>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
            .expect("a valid symmetric cipher key")
    }
    let mut block: [u8; 16] = unhex(prev_hex).try_into().expect("a 16-byte block");
    block.iter_mut().for_each(|b| *b ^= 0x10);
    match key_hex.len() / 2 {
        16 => Camellia128Internal::new(&material::<16>(key_hex)).unwrap().encrypt_block(&mut block),
        24 => Camellia192Internal::new(&material::<24>(key_hex)).unwrap().encrypt_block(&mut block),
        32 => Camellia256Internal::new(&material::<32>(key_hex)).unwrap().encrypt_block(&mut block),
        _ => panic!("not a Camellia key length"),
    }
    tohex(&block)
}

/// `encrypt --iv` reproduces the OpenSSL ciphertext followed by the PKCS7 block, for all three
/// key lengths, and `decrypt --iv` takes that back to the plaintext.
#[test]
fn encrypt_matches_the_openssl_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let out = run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        let want = format!("{ct}{}", pkcs7_block(key, &ct[64..]));
        assert_eq!(tohex(&out), want, "{cmd} encrypt --iv should give the ciphertext");

        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key, "--iv", IV], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{cmd}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext and the
/// PKCS7 block, for all three key lengths.
#[test]
fn decrypt_matches_the_openssl_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{IV}{ct}{}", pkcs7_block(key, &ct[64..])));
        let out = run_ok(&[cmd, "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_256}{}", pkcs7_block(KEY_256, &CT_256[64..])));
    let out = run_ok(&["camellia256-cbc", "-d", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// `encrypt | decrypt` composes: the IV rides in the first block, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect();

    for (cmd, key, _) in VARIANTS {
        let ciphertext = run_ok(&[cmd, "-d", "encrypt", "--key", key], &plaintext);
        assert_eq!(
            ciphertext.len(),
            16 + plaintext.len() + 16,
            "{cmd}: IV, the blocks, a padding block"
        );
        assert_ne!(&ciphertext[16..], &plaintext[..]);

        let recovered = run_ok(&[cmd, "-d", "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}");
    }
}

/// Each command wants exactly its key length. The 256-bit key to the 128-bit command, and the
/// 128-bit key to the 192-bit command, are errors naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["camellia128-cbc", "-d", "encrypt", "--key", KEY_256], &[0u8; 16]);
    assert!(err.contains("Camellia-128 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia192-cbc", "-d", "encrypt", "--key", KEY_128], &[0u8; 16]);
    assert!(err.contains("Camellia-192 needs a 24-byte key, got 16 bytes"), "stderr was: {err}");
    let err = run_err(&["camellia256-cbc", "-d", "encrypt", "--key", KEY_192], &[0u8; 16]);
    assert!(err.contains("Camellia-256 needs a 32-byte key, got 24 bytes"), "stderr was: {err}");
}

/// The harness above must survive a write that loses the race with the child's exit. This pins it
/// deterministically: the key is rejected so `camellia128-cbc` exits before reading a byte, and
/// the payload is far larger than any pipe buffer, so the write is certain to get EPIPE rather
/// than merely likely to.
#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    let err = run_err(
        &["camellia128-cbc", "-d", "encrypt", "--key", KEY_256],
        &vec![0u8; 4 * 1024 * 1024],
    );
    assert!(err.contains("Camellia-128 needs a 16-byte key"), "stderr was: {err}");
}

/// Any length is accepted and padded to the next whole block, as for the AES commands.
#[test]
fn any_input_length_is_accepted_and_padded() {
    for len in [0usize, 1, 15, 16, 17, 33] {
        let plaintext = vec![0x5Au8; len];
        let ciphertext =
            run_ok(&["camellia128-cbc", "-d", "encrypt", "--key", KEY_128], &plaintext);
        assert_eq!(ciphertext.len(), 16 + (len / 16 + 1) * 16, "len {len}: IV plus padded body");
        let recovered =
            run_ok(&["camellia128-cbc", "-d", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// A ciphertext without PKCS7 padding is rejected: the bare OpenSSL ciphertext ends in a block
/// that does not unpad.
#[test]
fn a_ciphertext_without_pkcs7_padding_is_rejected() {
    let input = unhex(&format!("{IV}{CT_128}"));
    let err = run_err(&["camellia128-cbc", "-d", "decrypt", "--key", KEY_128], &input);
    assert!(err.contains("decryption failed"), "stderr was: {err}");
}
