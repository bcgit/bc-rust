//! The harness the block cipher command tests share: running the binary, hex and filler
//! helpers, the library-side answers a command is held to, and the checks that hold of every
//! cipher's commands -- round trips, the input lengths, the key-length errors, the fresh IV per
//! invocation and the help listing. Each `*_cli_tests.rs` keeps what is its cipher's: the known
//! answers and the tests that name them.

#![allow(dead_code)]

use bouncycastle::cipher::BlockCipherKey;
use bouncycastle::cipher::modes::{GCM, ModeNames};
use bouncycastle::core::hazmat::{BlockPermutation, ElectronicCodeBook, KeyExpansion};
use bouncycastle::core::key_material::{KeyMaterial, KeyType};
use bouncycastle::core::symmetric_key::{
    AeadDecryptionKey, FromKeyMaterial, SymmetricDecryptionKey,
};
use bouncycastle::core::traits::StreamCipherDecryptor;
use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
pub const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// Counting keys of the three lengths, for the checks that need a key but not a known answer.
pub const KEY16: &str = "000102030405060708090a0b0c0d0e0f";
/// See [`KEY16`].
pub const KEY24: &str = "000102030405060708090a0b0c0d0e0f1011121314151617";
/// See [`KEY16`].
pub const KEY32: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
///
/// The error-path tests hand a rejected key to a command that `exit`s before it ever reads
/// stdin, so this write races the child's exit and sometimes loses -- reliably so on a loaded CI
/// runner. That is an expected outcome, not a harness failure: `wait_with_output` still returns
/// the exit status and stderr, which is all those tests assert on. Any other write error is a
/// real problem and still panics.
pub fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
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

/// Runs a command that is expected to succeed, returning stdout.
pub fn run_ok(args: &[&str], stdin_bytes: &[u8]) -> Vec<u8> {
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
pub fn run_err(args: &[&str], stdin_bytes: &[u8]) -> String {
    let out = run(args, stdin_bytes);
    assert!(
        !out.status.success(),
        "expected failure from {args:?}, but it succeeded\nstdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// As [`run_err`], and the command must have written nothing: a rejected unwrap or a failed tag
/// check that is detected before any output.
pub fn run_err_silent(args: &[&str], stdin_bytes: &[u8]) -> String {
    let out = run(args, stdin_bytes);
    assert!(
        !out.status.success(),
        "expected failure from {args:?}, but it succeeded\nstdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(out.stdout.is_empty(), "a rejected input must write nothing: {args:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

pub fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex string must have even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

pub fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deterministic pseudo-random bytes, so the tests do not depend on an RNG.
pub fn pseudo_random(len: usize, seed: u32) -> Vec<u8> {
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

/// The key object for `key_hex`, under the mode the command uses.
pub fn key_object<const KEY_LEN: usize, K: FromKeyMaterial<KEY_LEN>>(key_hex: &str) -> K {
    let key_bytes: [u8; KEY_LEN] = unhex(key_hex).try_into().expect("the right key length");
    let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key");
    K::from_key_material(&key).expect("a valid key")
}

/// The CBC ciphertext block that a full block of PKCS7 padding (sixteen `0x10` bytes) encrypts
/// to under `key_hex` after the ciphertext block `prev_hex`: `E_K(prev xor 10..10)`, from the
/// permutation. Appended to an unpadded known-answer ciphertext whose plaintext is
/// block-aligned, it gives the PKCS7 ciphertext of the same plaintext, which is how the commands
/// frame it.
pub fn pkcs7_block<P, const KEY_LEN: usize>(key_hex: &str, prev_hex: &str) -> String
where
    P: KeyExpansion<KEY_LEN> + BlockPermutation<16>,
{
    let key_bytes: [u8; KEY_LEN] = unhex(key_hex).try_into().expect("the right key length");
    let material =
        KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
            .expect("a valid symmetric cipher key");
    let perm = P::new(&material).expect("a valid key");
    let mut block: [u8; 16] = unhex(prev_hex).try_into().expect("a 16-byte block");
    block.iter_mut().for_each(|b| *b ^= 0x10);
    perm.encrypt_block(&mut block);
    tohex(&block)
}

/// The library's answer for the same key, init data and ciphertext under a stream mode, so the
/// CLI can be held to it: the key object's in-place decryption.
pub fn library_stream_decrypt<'k, const KEY_LEN: usize, const INIT_LEN: usize, K>(
    key: &'k K,
    init: &[u8],
    data: &mut [u8],
) where
    K: SymmetricDecryptionKey<KEY_LEN, INIT_LEN, 0>,
    K::Decryptor<'k>: StreamCipherDecryptor<INIT_LEN>,
{
    let init: [u8; INIT_LEN] = init.try_into().expect("the mode's init data length");
    key.decrypt_inplace(&init, data).expect("decryption");
}

/// The library's answer for the same key, nonce, AAD and inline `ciphertext || tag` under GCM,
/// so the CLI can be held to it: the key object's inline one-shot.
pub fn library_gcm_decrypt<P, const KEY_LEN: usize>(
    key_hex: &str,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Vec<u8>
where
    P: ElectronicCodeBook<KEY_LEN, 16> + ModeNames + Clone,
{
    let key = key_object::<KEY_LEN, BlockCipherKey<P, GCM>>(key_hex);
    let nonce: [u8; 12] = nonce.try_into().expect("a 12-byte nonce");
    key.decrypt_with_aad(&nonce, aad, ciphertext).expect("the tag verifies")
}

/// The framing of a command's output around the body: what it writes before the body (a drawn
/// IV or nonce), what after (a tag), and whether the body is padded to whole blocks.
#[derive(Clone, Copy)]
pub struct Framing {
    /// Bytes written ahead of the body: the IV or nonce, or 0 when one is supplied or there is none.
    pub prefix: usize,
    /// Bytes written after the body: the tag, or 0.
    pub suffix: usize,
    /// Whether the body is padded to the next whole 16-byte block.
    pub pads: bool,
}

impl Framing {
    /// The output length for an input of `len` bytes.
    pub fn output_len(&self, len: usize) -> usize {
        let body = if self.pads { (len / 16 + 1) * 16 } else { len };
        self.prefix + body + self.suffix
    }
}

/// `encrypt | decrypt` composes under each `(command, key)`: the output has the framing's
/// length, the body is not the plaintext, the plaintext comes back, and where the command draws
/// its own IV or nonce a second encryption draws a different one. `extra` is passed to both
/// directions, for the flags a mode needs (CCM's `--nonce`).
pub fn round_trips(cmds: &[(&str, &str)], extra: &[&str], framing: Framing) {
    let plaintext = pseudo_random(4096, 0xC0FFEE);
    for (cmd, key) in cmds {
        let enc = [&[cmd, "-d", "encrypt", "--key", key], extra].concat();
        let dec = [&[cmd, "-d", "decrypt", "--key", key], extra].concat();
        let ciphertext = run_ok(&enc, &plaintext);
        assert_eq!(ciphertext.len(), framing.output_len(plaintext.len()), "{cmd}: framing");
        assert_ne!(&ciphertext[framing.prefix..framing.prefix + 64], &plaintext[..64], "{cmd}");
        let recovered = run_ok(&dec, &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}: round trip");
        if framing.prefix > 0 {
            let again = run_ok(&enc, &plaintext);
            assert_ne!(again[..framing.prefix], ciphertext[..framing.prefix], "{cmd}: a fresh IV");
        }
    }
}

/// Every input length round-trips under the framing, including the empty input.
pub fn any_input_length(cmd: &str, key: &str, extra: &[&str], framing: Framing) {
    let enc = [&[cmd, "-d", "encrypt", "--key", key], extra].concat();
    let dec = [&[cmd, "-d", "decrypt", "--key", key], extra].concat();
    for len in [0usize, 1, 15, 16, 17, 33] {
        let plaintext = pseudo_random(len, len as u32);
        let ciphertext = run_ok(&enc, &plaintext);
        assert_eq!(ciphertext.len(), framing.output_len(len), "{cmd}, len {len}: framing");
        let recovered = run_ok(&dec, &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}, len {len}: round trip");
    }
}

/// Each command wants exactly its key length: `cases` are `(command, key of another length,
/// the message naming the algorithm)`.
pub fn wrong_key_lengths(cases: &[(&str, &str, &str)], extra: &[&str]) {
    for (cmd, key, msg) in cases {
        let args = [&[cmd, "-d", "encrypt", "--key", key], extra].concat();
        let err = run_err(&args, &[0u8; 16]);
        assert!(err.contains(msg), "{cmd}: stderr was: {err}");
    }
}

/// The harness must survive a write that loses the race with the child's exit: the key is
/// rejected so the command exits before reading a byte, and the payload is far larger than any
/// pipe buffer, so the write is certain to get EPIPE rather than merely likely to.
pub fn large_payload_on_an_error_path(cmd: &str, bad_key: &str, msg: &str) {
    let err = run_err(&[cmd, "-d", "encrypt", "--key", bad_key], &vec![0u8; 4 * 1024 * 1024]);
    assert!(err.contains(msg), "stderr was: {err}");
}

/// A fresh IV or nonce per invocation, of `prefix` bytes at the front of the output.
pub fn fresh_prefix_per_invocation(cmd: &str, key: &str, prefix: usize) {
    let plaintext = pseudo_random(64, 11);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..8 {
        let ciphertext = run_ok(&[cmd, "-d", "encrypt", "--key", key], &plaintext);
        assert!(seen.insert(ciphertext[..prefix].to_vec()), "{cmd} reused an IV or nonce");
        let recovered = run_ok(&[cmd, "-d", "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

/// The subcommands are discoverable.
pub fn listed_in_help(cmds: &[&str]) {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in cmds {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}
