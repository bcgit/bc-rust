//! Tests for the `aes128-ccm` / `aes192-ccm` / `aes256-ccm` subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, because the behaviour worth testing is
//! the command-line contract itself -- the supplied nonce, the AAD flag, the tag riding at the end
//! of the ciphertext, the exit code on a failed tag check -- none of which is reachable from the
//! library API.
//!
//! Key loading is shared with `aes*-cbc` (`cli/src/block_mode_cmd.rs`), so that coverage is
//! repeated here rather than assumed. What is tested only here is everything CCM does differently
//! from the other five modes:
//!
//! * the **nonce is a required flag** and is *not* written to the output, unlike every other mode's
//!   generated IV;
//! * `--aad` is authenticated but not encrypted, and must match on both sides;
//! * `--tag-len` changes the output length, and must match on both sides;
//! * `decrypt` **fails with a non-zero exit and writes nothing** when the input is inauthentic;
//! * the nonce length and tag length are validated against SP 800-38C Appendix A.1, and the nonce
//!   length caps the payload.
//!
//! The known-answer test is SP 800-38C Appendix C.1, run end to end through the pipe, so the CLI is
//! pinned against the specification and not merely against itself.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::{ErrorKind, Write};
use std::process::{Command, Output, Stdio};
use std::thread;

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// A 12-byte nonce, the length these tests use unless they are about nonce length.
const NONCE: &str = "000102030405060708090a0b";

/// Runs `bc-rust <args...>` with `stdin_bytes` on stdin. See `aes_ctr_cli_tests.rs` for why stdin
/// is written from a separate thread and why `BrokenPipe` is ignored; the reasoning is identical.
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
    let writer = thread::spawn(move || match stdin.write_all(&payload) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::BrokenPipe => {}
        Err(e) => panic!("failed to write to stdin: {e}"),
    });

    let output = child.wait_with_output().expect("failed to wait for bc-rust");
    writer.join().expect("the stdin writer thread panicked");
    output
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
        "expected failure from {args:?}, but it succeeded\nstdout: {} bytes",
        out.stdout.len()
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex must be an even number of characters");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// SP 800-38C Appendix C.1, end to end: `Klen = 128, Tlen = 32, Nlen = 56, Alen = 64, Plen = 32`.
///
/// The appendix's `C` is `7162015b 4dac255d`, which is the 4-byte ciphertext followed by the 4-byte
/// tag -- exactly what this command writes. This is the one test here that pins the CLI against the
/// specification rather than against a round trip.
#[test]
fn encrypt_matches_sp800_38c_appendix_c1() {
    let out = run_ok(
        &[
            "aes128-ccm",
            "encrypt",
            "--key",
            "404142434445464748494a4b4c4d4e4f",
            "--nonce",
            "10111213141516",
            "--aad",
            "0001020304050607",
            "--tag-len",
            "4",
        ],
        &unhex("20212223"),
    );
    assert_eq!(hex(&out), "7162015b4dac255d", "Appendix C.1's C string");

    // And back again. The appendix gives no decryption example, but says one is "straightforward to
    // construct" from each.
    let back = run_ok(
        &[
            "aes128-ccm",
            "decrypt",
            "--key",
            "404142434445464748494a4b4c4d4e4f",
            "--nonce",
            "10111213141516",
            "--aad",
            "0001020304050607",
            "--tag-len",
            "4",
        ],
        &out,
    );
    assert_eq!(hex(&back), "20212223", "Appendix C.1's P");
}

/// A round trip at each key length, with AAD, over a payload that spans several blocks and does not
/// end on a block boundary.
#[test]
fn encrypt_then_decrypt_round_trips() {
    let plaintext: Vec<u8> = (0..=200u8).collect();
    for (cmd, key) in [("aes128-ccm", KEY_128), ("aes192-ccm", KEY_192), ("aes256-ccm", KEY_256)] {
        let sealed = run_ok(
            &[cmd, "encrypt", "--key", key, "--nonce", NONCE, "--aad", "cafebabe"],
            &plaintext,
        );
        assert_eq!(
            sealed.len(),
            plaintext.len() + 16,
            "{cmd}: the default tag length is 16, and the nonce is not written"
        );
        let opened =
            run_ok(&[cmd, "decrypt", "--key", key, "--nonce", NONCE, "--aad", "cafebabe"], &sealed);
        assert_eq!(opened, plaintext, "{cmd}: round trip");
    }
}

/// The three commands are not interchangeable: a ciphertext from one must not decrypt under
/// another, even with the right-length key, and the failure is the tag check rather than garbage.
#[test]
fn the_three_variants_are_not_interchangeable() {
    let sealed =
        run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE], b"a short message");
    let stderr = run_err(&["aes256-ccm", "decrypt", "--key", KEY_256, "--nonce", NONCE], &sealed);
    assert!(
        stderr.contains("authentication failed"),
        "expected a tag-check failure, got: {stderr}"
    );
}

/// The nonce is **not** written to the output, so `decrypt` needs the same `--nonce`. This is the
/// sharpest difference from the other five commands, all of which prepend their generated IV.
#[test]
fn the_nonce_is_not_written_to_the_output_and_is_required_to_decrypt() {
    let plaintext = b"the nonce rides out of band";
    let sealed = run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE], plaintext);
    assert_eq!(
        sealed.len(),
        plaintext.len() + 16,
        "output is plaintext + tag only; no nonce prefix"
    );

    // A different nonce must fail: it changes both B0 and every counter block.
    let mut other = unhex(NONCE);
    other[0] ^= 1;
    let stderr =
        run_err(&["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", &hex(&other)], &sealed);
    assert!(stderr.contains("authentication failed"), "got: {stderr}");
}

/// Omitting the nonce is refused, and the message says why there is no generated one.
#[test]
fn a_missing_nonce_is_rejected_with_an_explanation() {
    let stderr = run_err(&["aes128-ccm", "encrypt", "--key", KEY_128], b"data");
    assert!(stderr.contains("--nonce"), "stderr should name the flag: {stderr}");
    assert!(
        stderr.contains("no generated nonce"),
        "stderr should say why there is no generated nonce: {stderr}"
    );
}

/// The AAD is authenticated but not encrypted: it does not change the ciphertext length, it does
/// change the tag, and a mismatch on decryption is caught.
#[test]
fn the_aad_is_authenticated_but_not_encrypted() {
    let plaintext = b"payload";
    let with = run_ok(
        &["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE, "--aad", "0011"],
        plaintext,
    );
    let without = run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE], plaintext);

    assert_eq!(with.len(), without.len(), "AAD does not change the output length");
    assert_eq!(
        with[..plaintext.len()],
        without[..plaintext.len()],
        "AAD does not change the ciphertext, only the tag"
    );
    assert_ne!(with[plaintext.len()..], without[plaintext.len()..], "AAD changes the tag");

    // Wrong AAD, missing AAD and extra AAD must all be caught.
    for args in [
        vec!["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", NONCE, "--aad", "0012"],
        vec!["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", NONCE],
        vec!["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", NONCE, "--aad", "001100"],
    ] {
        let stderr = run_err(&args, &with);
        assert!(stderr.contains("authentication failed"), "{args:?} gave: {stderr}");
    }
}

/// A failed tag check must exit non-zero **and write nothing**. This is what buffering the input
/// buys, and it is stronger than `ascon-aead128`'s contract; SP 800-38C Sec 6.2 requires that on
/// INVALID "the payload P and the MAC T shall not be revealed".
#[test]
fn a_tampered_ciphertext_produces_no_output_at_all() {
    let plaintext: Vec<u8> = (0..=255u8).collect();
    let sealed = run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE], &plaintext);

    // Flip a bit in the ciphertext, then in the tag; both must be caught with empty stdout.
    for pos in [0usize, plaintext.len() - 1, plaintext.len(), sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[pos] ^= 0x01;
        let out = run(&["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", NONCE], &bad);
        assert!(!out.status.success(), "a flipped bit at {pos} must fail");
        assert!(
            out.stdout.is_empty(),
            "no plaintext may be written when the tag check fails (flipped byte {pos}), \
             got {} bytes",
            out.stdout.len()
        );
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("authentication failed"),
            "flipped byte {pos}"
        );
    }
}

/// `--tag-len` changes the output length and must match on both sides, and only A.1's values are
/// accepted.
#[test]
fn tag_len_is_validated_and_must_match() {
    let plaintext = b"tag length matters";

    for t in [4usize, 6, 8, 10, 12, 14, 16] {
        let t_str = t.to_string();
        let sealed = run_ok(
            &["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE, "--tag-len", &t_str],
            plaintext,
        );
        assert_eq!(sealed.len(), plaintext.len() + t, "tag-len {t}");
        let opened = run_ok(
            &["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", NONCE, "--tag-len", &t_str],
            &sealed,
        );
        assert_eq!(opened, plaintext, "tag-len {t} round trip");
    }

    // A.1: t is an element of {4, 6, 8, 10, 12, 14, 16}. Odd values and out-of-range are refused.
    for bad in ["0", "2", "5", "15", "17", "32"] {
        let stderr = run_err(
            &["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE, "--tag-len", bad],
            b"data",
        );
        assert!(stderr.contains("tag-len"), "tag-len {bad} gave: {stderr}");
        assert!(stderr.contains("A.1"), "the message should cite A.1: {stderr}");
    }

    // A tag-len mismatch between the two sides is caught rather than silently truncating.
    let sealed = run_ok(
        &["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE, "--tag-len", "16"],
        plaintext,
    );
    let stderr = run_err(
        &["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", NONCE, "--tag-len", "8"],
        &sealed,
    );
    assert!(stderr.contains("authentication failed"), "got: {stderr}");
}

/// Every nonce length A.1 permits works, and nothing else does. The nonce length is not written
/// anywhere, so both sides must agree on it too.
#[test]
fn nonce_len_is_validated_across_a_1_s_whole_range() {
    let plaintext = b"nonce lengths";

    for n in 7usize..=13 {
        let nonce = hex(&vec![0x5Au8; n]);
        let sealed =
            run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", &nonce], plaintext);
        let opened =
            run_ok(&["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", &nonce], &sealed);
        assert_eq!(opened, plaintext, "nonce length {n}");
    }

    // A.1: n is an element of {7, ..., 13}.
    for n in [0usize, 1, 6, 14, 16] {
        let nonce = hex(&vec![0x5Au8; n]);
        let stderr =
            run_err(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", &nonce], b"data");
        assert!(
            stderr.contains("7 to 13"),
            "nonce length {n} should be refused with the range: {stderr}"
        );
    }
}

/// The nonce length caps the payload (A.1's `p < 2^8q`, `q = 15 - n`), and the error says so with
/// the numbers rather than just failing.
#[test]
fn a_payload_past_the_q_limit_is_rejected_with_the_numbers() {
    // n = 13 gives q = 2, so the limit is 65535 bytes.
    let nonce = hex(&[0x5Au8; 13]);
    let too_big = vec![0u8; 65536];
    let stderr = run_err(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", &nonce], &too_big);
    assert!(stderr.contains("65535"), "the message should give the limit: {stderr}");
    assert!(stderr.contains("65536"), "and the actual input length: {stderr}");

    // One byte under the limit is fine, which pins the boundary rather than just the rejection.
    let ok = vec![0u8; 65535];
    let sealed = run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", &nonce], &ok);
    assert_eq!(sealed.len(), 65535 + 16);
}

/// Sec 6.2 step 1: a `C` too short to contain a tag is rejected before anything else.
#[test]
fn an_input_shorter_than_the_tag_is_rejected() {
    for len in [0usize, 1, 15] {
        let stderr = run_err(
            &["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", NONCE],
            &vec![0u8; len],
        );
        assert!(
            stderr.contains("shorter than"),
            "a {len}-byte input should be refused as too short: {stderr}"
        );
    }

    // Exactly the tag length is an empty payload plus its tag, which is valid (Sec 5.3 footnote).
    let sealed = run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE], b"");
    assert_eq!(sealed.len(), 16);
    let opened = run_ok(&["aes128-ccm", "decrypt", "--key", KEY_128, "--nonce", NONCE], &sealed);
    assert!(opened.is_empty(), "an empty payload round trips to nothing");
}

/// `-x` writes hex, and it must be the hex of what the binary form writes.
#[test]
fn hex_output_matches_binary_output() {
    let plaintext = b"hex and binary";
    let binary = run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE], plaintext);
    let as_hex =
        run_ok(&["aes128-ccm", "encrypt", "--key", KEY_128, "--nonce", NONCE, "-x"], plaintext);
    assert_eq!(String::from_utf8_lossy(&as_hex).trim(), hex(&binary));
}

/// Key loading errors are the shared `block_mode_cmd` ones, checked here so the CCM commands are
/// not assumed to inherit them.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let stderr = run_err(&["aes128-ccm", "encrypt", "--key", KEY_256, "--nonce", NONCE], b"data");
    assert!(!stderr.is_empty(), "a 32-byte key must be refused by aes128-ccm");

    let stderr = run_err(&["aes128-ccm", "encrypt", "--nonce", NONCE], b"data");
    assert!(stderr.contains("key"), "stderr should mention the key options: {stderr}");
}

/// An input larger than a pipe buffer round trips, which also pins that the non-streaming
/// read-all-of-stdin loop does not deadlock against its own output.
#[test]
fn a_payload_larger_than_the_pipe_buffer_round_trips() {
    // 256 KiB, comfortably past the usual 64 KiB pipe buffer. A 12-byte nonce gives q = 3, so the
    // payload limit is 16 MiB and this is well inside it.
    let plaintext: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let sealed = run_ok(&["aes256-ccm", "encrypt", "--key", KEY_256, "--nonce", NONCE], &plaintext);
    assert_eq!(sealed.len(), plaintext.len() + 16);
    let opened = run_ok(&["aes256-ccm", "decrypt", "--key", KEY_256, "--nonce", NONCE], &sealed);
    assert_eq!(opened, plaintext);
}

/// The subcommands are listed in `--help`, and their own help documents the things that differ from
/// the other modes: the supplied nonce, the non-streaming behaviour, and the nonce-reuse hazard.
#[test]
fn the_subcommands_are_documented_in_help() {
    let help = String::from_utf8_lossy(&run_ok(&["--help"], b"")).into_owned();
    for cmd in ["aes128-ccm", "aes192-ccm", "aes256-ccm"] {
        assert!(help.contains(cmd), "{cmd} should be listed in --help");
    }

    let per_cmd = String::from_utf8_lossy(&run_ok(&["aes128-ccm", "--help"], b"")).into_owned();
    assert!(
        per_cmd.contains("NOT GENERATED") || per_cmd.contains("SUPPLIED"),
        "the help should say the nonce is supplied: {per_cmd}"
    );
    assert!(
        per_cmd.to_lowercase().contains("does not stream"),
        "the help should say it does not stream: {per_cmd}"
    );
    assert!(
        per_cmd.contains("never reuse a nonce"),
        "the help should warn about nonce reuse: {per_cmd}"
    );
}
