//! Tests for the `tdes-tkw` and `tdes2-tkw` subcommands.
//!
//! They share everything but the key type and the semiblock width with the `aes*-kw` commands,
//! whose `test_aes_kw.sh` covers the command-line contract exhaustively. This file pins what is
//! specific to TKW: the CAVP known answers in both directions, a CAVP forgery, the 4-byte
//! alignment rule, and that the two-key command unwraps only.
//!
//! The known answers are `COUNT = 0` of the 64- and 128-bit sections of the NIST CAVP `TKW_AE.txt`
//! sample file, and the first `FAIL` of `TKW_AD.txt`, read from `../bc-test-data` at test time;
//! without it those tests print a warning and pass, as the crate's suite does.

use std::io::{ErrorKind, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// A three-key bundle of distinct, non-weak components, for the tests that need no vector.
const KEY_3: &str = "0123456789abcdef23456789abcdef01456789abcdef0123";
/// A two-key bundle of distinct, non-weak components.
const KEY_2: &str = "0123456789abcdef23456789abcdef01";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin and returns the completed output.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");
    // A command that exits before reading stdin makes this write race its exit; that is the
    // expected outcome for the error-path tests, which assert on the status and stderr only.
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
    assert!(
        !out.status.success(),
        "expected failure from {args:?}, but it succeeded\nstdout: {:?}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(out.stdout.is_empty(), "a rejected command must write nothing: {args:?}");
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn tohex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The text of a CAVP sample file, or `None` (with a warning) when `bc-test-data` is not cloned
/// beside this repository.
fn cavp_file(file: &str) -> Option<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bc-test-data");
    let path = root.join("crypto/aes_tdes_vectors/TDES").join(file);
    if !root.exists() {
        println!(
            "WARNING: bc-test-data not found at {}; the CAVP tests are skipped",
            root.display()
        );
        return None;
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // The CAVS files have CRLF line ends.
    Some(text.replace('\r', ""))
}

/// `(K, P, C)` of `COUNT = 0` in the `[PLAINTEXT LENGTH = bits]` section of `file`; `P` is empty
/// for a `FAIL` case.
fn case(file: &str, bits: u32, count: u32) -> Option<(String, String, String)> {
    let text = cavp_file(file)?;
    let section = text.split(&format!("[PLAINTEXT LENGTH = {bits}]")).nth(1).expect("the section");
    let body = section.split(&format!("COUNT = {count}\n")).nth(1).expect("the case");
    let body = body.split("COUNT = ").next().unwrap();
    let field = |name: &str| -> String {
        body.lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix(&format!("{name} = ")))
            .unwrap_or_default()
            .to_lowercase()
    };
    Some((field("K"), field("P"), field("C")))
}

#[test]
fn tdes_tkw_matches_the_cavp_vectors_in_both_directions() {
    for bits in [64, 128] {
        let Some((k, p, c)) = case("TKW_AE.txt", bits, 0) else { return };
        let wrapped = run_ok(&["tdes-tkw", "-d", "encrypt", "--key", &k], &unhex(&p));
        assert_eq!(tohex(&wrapped), c, "{bits}-bit wrap");
        let hex = run_ok(&["tdes-tkw", "-d", "encrypt", "--key", &k, "-x"], &unhex(&p));
        assert_eq!(String::from_utf8_lossy(&hex).trim(), c, "{bits}-bit wrap -x");
        let unwrapped = run_ok(&["tdes-tkw", "-d", "decrypt", "--key", &k], &unhex(&c));
        assert_eq!(tohex(&unwrapped), p, "{bits}-bit unwrap");
    }
}

#[test]
fn tdes_tkw_rejects_a_cavp_forgery() {
    let Some(text) = cavp_file("TKW_AD.txt") else { return };
    // The first FAIL: its K and C are the two `NAME = value` lines just above it.
    let before = text.split("\nFAIL").next().expect("a FAIL line");
    let mut lines = before.lines().rev().map(str::trim);
    let c = lines.next().unwrap().strip_prefix("C = ").expect("C before FAIL").to_lowercase();
    let k = lines.next().unwrap().strip_prefix("K = ").expect("K before C").to_lowercase();
    let err = run_err(&["tdes-tkw", "-d", "decrypt", "--key", &k], &unhex(&c));
    assert!(err.contains("not an authentic"), "{err}");
}

#[test]
fn tkw_takes_whole_4_byte_semiblocks_and_at_least_two() {
    let err = run_err(&["tdes-tkw", "-d", "encrypt", "--key", KEY_3], &[0x5Au8; 4]);
    assert!(err.contains("4 bytes rejected"), "{err}");
    let err = run_err(&["tdes-tkw", "-d", "encrypt", "--key", KEY_3], &[0x5Au8; 10]);
    assert!(err.contains("10 bytes rejected"), "{err}");
    let wrapped = run_ok(&["tdes-tkw", "-d", "encrypt", "--key", KEY_3], &[0x5Au8; 12]);
    assert_eq!(wrapped.len(), 16, "12 bytes wrap to 16");
    let back = run_ok(&["tdes-tkw", "-d", "decrypt", "--key", KEY_3], &wrapped);
    assert_eq!(back, [0x5Au8; 12]);
}

#[test]
fn tdes2_tkw_unwraps_only() {
    // `encrypt` is not a value of the two-key direction at all.
    let err = run_err(&["tdes2-tkw", "-d", "encrypt", "--key", KEY_2], &[0x5Au8; 8]);
    assert!(err.contains("encrypt"), "{err}");
    // A ciphertext this key never made is rejected, not unwrapped to garbage.
    let err = run_err(&["tdes2-tkw", "-d", "decrypt", "--key", KEY_2], &[0x5Au8; 12]);
    assert!(err.contains("not an authentic"), "{err}");
    // A three-key bundle is not a two-key one.
    let err = run_err(&["tdes2-tkw", "-d", "decrypt", "--key", KEY_3], &[0x5Au8; 12]);
    assert!(err.contains("16-byte key"), "{err}");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    let help = String::from_utf8(run_ok(&["--help"], b"")).unwrap();
    for cmd in ["tdes-tkw", "tdes2-tkw"] {
        assert!(help.contains(cmd), "--help should list {cmd}");
    }
}
