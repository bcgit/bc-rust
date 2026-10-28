//! Tests for the `sm4-cbc` subcommand.
//!
//! `sm4-cbc` shares its key and IV loaders, streaming loops and error paths with the `aes*-cbc`
//! commands (`cli/src/helpers/block_mode_helpers.rs`), and `test_aes_cbc.sh` covers those
//! exhaustively. This file pins what is specific to SM4: the known-answer vectors in both
//! directions, the 16-byte key length, and that the command exists and round-trips.
//!
//! Vectors are the SM4-CBC examples of draft-ribose-cfrg-sm4-10 Appendix A.2.2. The appendix
//! applies no padding, so under the command's PKCS7 framing its two ciphertext blocks are
//! followed by one block of padding, computed here from the permutation.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// Appendix A.2 IV, shared by both CBC examples.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The two Appendix A.2 plaintext blocks.
const PLAINTEXT: &str = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb";

/// A.2.2.1 key and ciphertext.
const KEY_1: &str = "0123456789abcdeffedcba9876543210";
const CT_1: &str = "78ebb11cc40b0a48312aaeb2040244cb4cb7016951909226979b0d15dc6a8f6d";

/// A.2.2.2 key and ciphertext.
const KEY_2: &str = "fedcba98765432100123456789abcdef";
const CT_2: &str = "0d3a6ddc2d21c698857215587b7bb59a91f2c147911a4144665e1fa1d40bae38";

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

/// The CBC ciphertext block that a full block of PKCS7 padding (sixteen `0x10` bytes) encrypts
/// to under `key_hex` after the ciphertext block `prev_hex`: `E_K(prev xor 10..10)`, from the
/// permutation. Appended to an unpadded known-answer ciphertext whose plaintext is
/// block-aligned, it gives the PKCS7 ciphertext of the same plaintext, which is how the command
/// frames it.
fn pkcs7_block(key_hex: &str, prev_hex: &str) -> String {
    use bouncycastle::core::hazmat::{BlockPermutation, ElectronicCodeBook};
    use bouncycastle::core::key_material::{KeyMaterial, KeyType};
    use bouncycastle::sm4::hazmat::SM4Internal;

    let key_bytes: [u8; 16] = unhex(key_hex).try_into().expect("a 16-byte key");
    let material = KeyMaterial::<16>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    let sm4 = SM4Internal::new(&material).expect("a valid key");
    let mut block: [u8; 16] = unhex(prev_hex).try_into().expect("a 16-byte block");
    block.iter_mut().for_each(|b| *b ^= 0x10);
    sm4.encrypt_block(&mut block);
    tohex(&block)
}

/// `encrypt --iv` reproduces the draft's ciphertext for both Appendix A.2.2 examples, followed
/// by the PKCS7 block, and `decrypt --iv` takes that back to the plaintext.
#[test]
fn encrypt_matches_appendix_a_2_2_vectors() {
    for (section, key, ct) in [("A.2.2.1", KEY_1, CT_1), ("A.2.2.2", KEY_2, CT_2)] {
        let out =
            run_ok(&["sm4-cbc", "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        let want = format!("{ct}{}", pkcs7_block(key, &ct[32..]));
        assert_eq!(tohex(&out), want, "{section}: sm4-cbc encrypt --iv should give the ciphertext");

        let back = run_ok(&["sm4-cbc", "-d", "decrypt", "--key", key, "--iv", IV], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{section}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the draft's plaintext when handed the draft's IV followed by its
/// ciphertext and the PKCS7 block, for both Appendix A.2.2 examples.
#[test]
fn decrypt_matches_appendix_a_2_2_vectors() {
    for (section, key, ct) in [("A.2.2.1", KEY_1, CT_1), ("A.2.2.2", KEY_2, CT_2)] {
        let input = unhex(&format!("{IV}{ct}{}", pkcs7_block(key, &ct[32..])));
        let out = run_ok(&["sm4-cbc", "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{section}: sm4-cbc decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_1}{}", pkcs7_block(KEY_1, &CT_1[32..])));
    let out = run_ok(&["sm4-cbc", "-d", "decrypt", "--key", KEY_1, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// `encrypt | decrypt` composes: the IV rides in the first block, and the plaintext comes back.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect();

    let ciphertext = run_ok(&["sm4-cbc", "-d", "encrypt", "--key", KEY_1], &plaintext);
    assert_eq!(ciphertext.len(), 16 + plaintext.len() + 16, "IV, the blocks, a padding block");
    assert_ne!(&ciphertext[16..], &plaintext[..]);

    let recovered = run_ok(&["sm4-cbc", "-d", "decrypt", "--key", KEY_1], &ciphertext);
    assert_eq!(recovered, plaintext);
}

/// Any length is accepted and padded to the next whole block, as for the AES commands.
#[test]
fn any_input_length_is_accepted_and_padded() {
    for len in [0usize, 1, 15, 16, 17, 33] {
        let plaintext = vec![0x5Au8; len];
        let ciphertext = run_ok(&["sm4-cbc", "-d", "encrypt", "--key", KEY_1], &plaintext);
        assert_eq!(ciphertext.len(), 16 + (len / 16 + 1) * 16, "len {len}: IV plus padded body");
        let recovered = run_ok(&["sm4-cbc", "-d", "decrypt", "--key", KEY_1], &ciphertext);
        assert_eq!(recovered, plaintext, "len {len}: round trip");
    }
}

/// SM4 has exactly one key length. An AES-256-sized key is an error naming the algorithm.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let key_256 = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
    let err = run_err(&["sm4-cbc", "-d", "encrypt", "--key", key_256], &[0u8; 16]);
    assert!(err.contains("SM4 needs a 16-byte key, got 32 bytes"), "stderr was: {err}");
}

/// The harness above must survive a write that loses the race with the child's exit. This pins it
/// deterministically: the key is rejected so `sm4-cbc` exits before reading a byte, and the payload
/// is far larger than any pipe buffer, so the write is certain to get EPIPE rather than merely
/// likely to.
#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    let err = run_err(
        &[
            "sm4-cbc",
            "-d",
            "encrypt",
            "--key",
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        ],
        &vec![0u8; 4 * 1024 * 1024],
    );
    assert!(err.contains("SM4 needs a 16-byte key"), "stderr was: {err}");
}

/// A ciphertext without PKCS7 padding is rejected: the bare A.2.2.1 ciphertext ends in a block
/// that does not unpad.
#[test]
fn a_ciphertext_without_pkcs7_padding_is_rejected() {
    let input = unhex(&format!("{IV}{CT_1}"));
    let err = run_err(&["sm4-cbc", "-d", "decrypt", "--key", KEY_1], &input);
    assert!(err.contains("decryption failed"), "stderr was: {err}");
}
