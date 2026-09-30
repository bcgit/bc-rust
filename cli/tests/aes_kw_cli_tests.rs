//! Tests for the `aes{128,192,256}-kw` and `aes{128,192,256}-kwp` subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, because what is worth testing is the
//! command-line contract: the `wrap` / `unwrap` spelling, no IV framing, whole-input reading, the
//! input-length rules, exit codes on a rejected ciphertext, and key loading. The algorithms are
//! tested in `bouncycastle-modes` against the RFC and ACVP vectors; the same RFC vectors are
//! replayed here in both directions, which key wrap's determinism makes possible.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// RFC 3394 Sec 4: every example uses these KEK bytes (truncated to the key length) and this key
/// data (truncated to the data length).
const RFC3394_KEK: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const RFC3394_KEY_DATA: &str = "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f";
/// Sec 4.1: 128 bits of key data, 128-bit KEK.
const RFC3394_4_1_CT: &str = "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5";
/// Sec 4.4: 192 bits of key data, 192-bit KEK.
const RFC3394_4_4_CT: &str = "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2";
/// Sec 4.6: 256 bits of key data, 256-bit KEK.
const RFC3394_4_6_CT: &str =
    "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21";

/// RFC 5649 Sec 6: both examples use a 192-bit KEK.
const RFC5649_KEK: &str = "5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8";
const RFC5649_KEY_20: &str = "c37b7e6492584340bed12207808941155068f738";
const RFC5649_CT_20: &str = "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a";
const RFC5649_KEY_7: &str = "466f7250617369";
const RFC5649_CT_7: &str = "afbeb0f07dfbf5419200f2ccb50bb24f";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
///
/// stdin is written from a separate thread so that a large payload cannot deadlock against a
/// full stdout pipe; see the same helper in `aes_ecb_cli_tests.rs` for the full reasoning. A
/// broken pipe on write is expected when the child exits early on an error path.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");

    let mut stdin = child.stdin.take().expect("stdin piped");
    let payload = stdin_bytes.to_vec();
    let writer = thread::spawn(move || {
        match stdin.write_all(&payload) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
            Err(e) => panic!("failed to write to stdin: {e}"),
        }
        // `stdin` drops here, closing the pipe so the child sees EOF and can exit.
    });

    let output = child.wait_with_output().expect("failed to wait for bc-rust");
    writer.join().expect("the stdin writer thread panicked");
    output
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

/// Runs a command that is expected to fail, returning stderr as a string and asserting that
/// nothing was written to stdout.
fn run_err(args: &[&str], stdin_bytes: &[u8]) -> String {
    let out = run(args, stdin_bytes);
    assert!(
        !out.status.success(),
        "expected failure from {args:?}, but it succeeded\nstdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(out.stdout.is_empty(), "a failed command must write nothing to stdout");
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

// ---- the RFC vectors, both directions ------------------------------------------------------

#[test]
fn aes128_kw_matches_rfc3394_4_1_in_both_directions() {
    let kek = &RFC3394_KEK[..32];
    let key_data = unhex(&RFC3394_KEY_DATA[..32]);

    let wrapped = run_ok(&["aes128-kw", "wrap", "--key", kek], &key_data);
    assert_eq!(tohex(&wrapped), RFC3394_4_1_CT);

    let unwrapped = run_ok(&["aes128-kw", "unwrap", "--key", kek], &wrapped);
    assert_eq!(unwrapped, key_data);
}

#[test]
fn aes192_kw_matches_rfc3394_4_4_in_both_directions() {
    let kek = &RFC3394_KEK[..48];
    let key_data = unhex(&RFC3394_KEY_DATA[..48]);

    let wrapped = run_ok(&["aes192-kw", "wrap", "--key", kek], &key_data);
    assert_eq!(tohex(&wrapped), RFC3394_4_4_CT);
    assert_eq!(run_ok(&["aes192-kw", "unwrap", "--key", kek], &wrapped), key_data);
}

#[test]
fn aes256_kw_matches_rfc3394_4_6_in_both_directions() {
    let key_data = unhex(RFC3394_KEY_DATA);

    let wrapped = run_ok(&["aes256-kw", "wrap", "--key", RFC3394_KEK], &key_data);
    assert_eq!(tohex(&wrapped), RFC3394_4_6_CT);
    assert_eq!(run_ok(&["aes256-kw", "unwrap", "--key", RFC3394_KEK], &wrapped), key_data);
}

#[test]
fn aes192_kwp_matches_rfc5649_in_both_directions() {
    // 20 octets: padded to 24, through the wrapping function.
    let key_20 = unhex(RFC5649_KEY_20);
    let wrapped = run_ok(&["aes192-kwp", "wrap", "--key", RFC5649_KEK], &key_20);
    assert_eq!(tohex(&wrapped), RFC5649_CT_20);
    assert_eq!(run_ok(&["aes192-kwp", "unwrap", "--key", RFC5649_KEK], &wrapped), key_20);

    // 7 octets: a single block. The unwrapped output is exactly 7 bytes, not the padded 8.
    let key_7 = unhex(RFC5649_KEY_7);
    let wrapped = run_ok(&["aes192-kwp", "wrap", "--key", RFC5649_KEK], &key_7);
    assert_eq!(tohex(&wrapped), RFC5649_CT_7);
    assert_eq!(run_ok(&["aes192-kwp", "unwrap", "--key", RFC5649_KEK], &wrapped), key_7);
}

// ---- the command-line contract -------------------------------------------------------------

#[test]
fn hex_output_matches_binary_output() {
    let key_data = unhex(&RFC3394_KEY_DATA[..32]);
    let binary = run_ok(&["aes128-kw", "wrap", "--key", &RFC3394_KEK[..32]], &key_data);
    let hex = run_ok(&["aes128-kw", "wrap", "--key", &RFC3394_KEK[..32], "-x"], &key_data);
    assert_eq!(String::from_utf8(hex).unwrap(), tohex(&binary));
}

#[test]
fn wrapping_is_deterministic_and_adds_exactly_one_semiblock() {
    let kek = &RFC3394_KEK[..32];
    let key_data = [0x5Au8; 32];
    let a = run_ok(&["aes128-kw", "wrap", "--key", kek], &key_data);
    let b = run_ok(&["aes128-kw", "wrap", "--key", kek], &key_data);
    assert_eq!(a, b, "no IV, so the same input always gives the same output");
    assert_eq!(a.len(), key_data.len() + 8);

    let a = run_ok(&["aes128-kwp", "wrap", "--key", kek], &key_data);
    assert_eq!(a.len(), key_data.len() + 8, "aligned data costs KWP nothing extra");
    let a = run_ok(&["aes128-kwp", "wrap", "--key", kek], &key_data[..13]);
    assert_eq!(a.len(), 16 + 8, "13 bytes pad to 16");
}

#[test]
fn a_tampered_ciphertext_is_rejected_with_no_output() {
    let kek = &RFC3394_KEK[..32];
    let mut wrapped = unhex(RFC3394_4_1_CT);
    wrapped[11] ^= 0x01;
    let err = run_err(&["aes128-kw", "unwrap", "--key", kek], &wrapped);
    assert!(err.contains("not an authentic"), "stderr should explain: {err}");

    let mut wrapped = unhex(RFC5649_CT_7);
    wrapped[0] ^= 0x80;
    let err = run_err(&["aes192-kwp", "unwrap", "--key", RFC5649_KEK], &wrapped);
    assert!(err.contains("not an authentic"), "stderr should explain: {err}");
}

#[test]
fn the_wrong_kek_is_rejected() {
    let wrapped = unhex(RFC3394_4_1_CT);
    let wrong_kek = "0f0e0d0c0b0a09080706050403020100";
    let err = run_err(&["aes128-kw", "unwrap", "--key", wrong_kek], &wrapped);
    assert!(err.contains("not an authentic"), "stderr should explain: {err}");
}

#[test]
fn kw_and_kwp_are_not_interchangeable() {
    let kek = &RFC3394_KEK[..32];
    let key_data = [0x5Au8; 16];
    let kw = run_ok(&["aes128-kw", "wrap", "--key", kek], &key_data);
    let kwp = run_ok(&["aes128-kwp", "wrap", "--key", kek], &key_data);
    assert_ne!(kw, kwp);
    run_err(&["aes128-kwp", "unwrap", "--key", kek], &kw);
    run_err(&["aes128-kw", "unwrap", "--key", kek], &kwp);
}

#[test]
fn kw_rejects_inputs_that_are_not_whole_semiblocks() {
    let kek = &RFC3394_KEK[..32];
    // wrap: 8 bytes is one semiblock (two are needed); 20 is not a whole number of them.
    let err = run_err(&["aes128-kw", "wrap", "--key", kek], &[0u8; 8]);
    assert!(err.contains("8 bytes rejected"), "stderr should name the length: {err}");
    let err = run_err(&["aes128-kw", "wrap", "--key", kek], &[0u8; 20]);
    assert!(err.contains("20 bytes rejected"), "stderr should name the length: {err}");
    // unwrap: 16 bytes is two semiblocks (three are needed).
    let err = run_err(&["aes128-kw", "unwrap", "--key", kek], &[0u8; 16]);
    assert!(err.contains("16 bytes rejected"), "stderr should name the length: {err}");
    // KWP takes the unaligned length KW refused.
    assert_eq!(run_ok(&["aes128-kwp", "wrap", "--key", kek], &[0u8; 20]).len(), 32);
}

#[test]
fn empty_input_is_rejected_by_both() {
    let kek = &RFC3394_KEK[..32];
    let err = run_err(&["aes128-kw", "wrap", "--key", kek], &[]);
    assert!(err.contains("0 bytes rejected"), "stderr should name the length: {err}");
    let err = run_err(&["aes128-kwp", "wrap", "--key", kek], &[]);
    assert!(err.contains("0 bytes rejected"), "stderr should name the length: {err}");
    let err = run_err(&["aes128-kwp", "unwrap", "--key", kek], &[]);
    assert!(err.contains("0 bytes rejected"), "stderr should name the length: {err}");
}

#[test]
fn a_larger_payload_round_trips_through_kwp() {
    let kek = &RFC3394_KEK[..32];
    // An "encoded private key" sized payload that is not a multiple of 8.
    let payload: Vec<u8> =
        (0..3001u32).map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8).collect();
    let wrapped = run_ok(&["aes256-kwp", "wrap", "--key", RFC3394_KEK], &payload);
    assert_eq!(wrapped.len(), 3008 + 8);
    assert_eq!(run_ok(&["aes256-kwp", "unwrap", "--key", RFC3394_KEK], &wrapped), payload);
    // ... and KW refuses it, because it is not aligned.
    run_err(&["aes256-kw", "wrap", "--key", kek], &payload);
}

#[test]
fn key_file_accepts_hex_and_binary() {
    let dir = std::env::temp_dir().join(format!("bc-rust-kw-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let hex_path = dir.join("kek.hex");
    let bin_path = dir.join("kek.bin");
    std::fs::write(&hex_path, &RFC3394_KEK[..32]).unwrap();
    std::fs::write(&bin_path, unhex(&RFC3394_KEK[..32])).unwrap();

    let key_data = unhex(&RFC3394_KEY_DATA[..32]);
    let from_hex =
        run_ok(&["aes128-kw", "wrap", "--key-file", hex_path.to_str().unwrap()], &key_data);
    let from_bin =
        run_ok(&["aes128-kw", "wrap", "--key-file", bin_path.to_str().unwrap()], &key_data);
    assert_eq!(tohex(&from_hex), RFC3394_4_1_CT);
    assert_eq!(from_hex, from_bin);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let err = run_err(&["aes128-kw", "wrap", "--key", &RFC3394_KEK[..48]], &[0u8; 16]);
    assert!(err.contains("16-byte key"), "stderr should say what was expected: {err}");
    let err = run_err(&["aes256-kwp", "wrap", "--key", &RFC3394_KEK[..32]], &[0u8; 16]);
    assert!(err.contains("32-byte key"), "stderr should say what was expected: {err}");
}

#[test]
fn a_missing_key_is_rejected() {
    let err = run_err(&["aes128-kw", "wrap"], &[0u8; 16]);
    assert!(err.contains("--key"), "stderr should point at the option: {err}");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    let help = String::from_utf8(run_ok(&["--help"], &[])).unwrap();
    for name in ["aes128-kw", "aes192-kw", "aes256-kw", "aes128-kwp", "aes192-kwp", "aes256-kwp"] {
        assert!(help.contains(name), "{name} should be listed in --help");
    }
    let help = String::from_utf8(run_ok(&["aes128-kw", "--help"], &[])).unwrap();
    assert!(help.contains("wrap") && help.contains("unwrap"));
    assert!(help.contains("RFC 3394"));
}
