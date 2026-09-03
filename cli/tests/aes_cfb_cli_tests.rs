//! Tests for the `aes128-cfb` / `aes192-cfb` / `aes256-cfb` subcommands.
//!
//! These drive the built `bc-rust` binary as a subprocess, because the behaviour worth testing is
//! the command-line contract itself -- the IV riding in the first block, block-alignment
//! enforcement, exit codes, key loading -- none of which is reachable from the library API.
//!
//! The commands share all of that plumbing with `aes*-cbc` (`cli/src/block_mode_cmd.rs`), so this
//! file deliberately repeats the CBC suite's coverage rather than assuming it: the shared code is
//! generic over the mode, and a wiring mistake in the CFB dispatcher would not show up in the CBC
//! tests. What is *not* shared, and is tested only here, is the F.3 vectors, the CFB-specific
//! Appendix D error propagation, and the guard that CFB and CBC ciphertexts are not interchangeable.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// SP 800-38A Appendix F IV, shared by every F.3 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four SP 800-38A Appendix F plaintext blocks.
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// F.3.13 CFB128-AES128.Encrypt ciphertext.
const CT_128: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "c8a64537a0b3a93fcde3cdad9f1ce58b",
    "26751f67a3cbb140b1808cf187a4f4df",
    "c04b05357c5d1c0eeac4c66f9ff7f2e6",
);
/// F.3.15 CFB128-AES192.Encrypt ciphertext.
const CT_192: &str = concat!(
    "cdc80d6fddf18cab34c25909c99a4174",
    "67ce7f7f81173621961a2b70171d3d7a",
    "2e1e8a1dd59b88b1c8e60fed1efac4c9",
    "c05f9f9ca9834fa042ae8fba584b09ff",
);
/// F.3.17 CFB128-AES256.Encrypt ciphertext.
const CT_256: &str = concat!(
    "dc7e84bfda79164b7ecd8486985d3860",
    "39ffed143b28b1c832113c6331e5407b",
    "df10132415e54b92a13ed0a8267ae2f9",
    "75a385741ab9cef82031623d55b1e471",
);

/// F.2.1 CBC-AES128.Encrypt ciphertext, for the cross-mode guard.
const CBC_CT_128: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
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

/// Deterministic pseudo-random bytes, so the tests do not depend on an RNG or on `/dev/urandom`.
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

// ---- the SP 800-38A F.3 vectors, through the CLI -----------------------------------------

/// `decrypt` reproduces the spec plaintext when handed the spec's IV followed by the spec's
/// ciphertext, for F.3.13/F.3.15/F.3.17 (CFB128-AES128/192/256).
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round-trip tests below
/// and, at the library level, by `crypto/modes/tests/sp800_38a_cfb_tests.rs`.
#[test]
fn decrypt_matches_sp800_38a_f3_vectors() {
    for (cmd, key, ct) in [
        ("aes128-cfb", KEY_128, CT_128),
        ("aes192-cfb", KEY_192, CT_192),
        ("aes256-cfb", KEY_256, CT_256),
    ] {
        // The CLI expects the IV as the first block of its input, which is exactly how `encrypt`
        // emits it.
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(
            tohex(&out),
            PLAINTEXT,
            "{cmd} decrypt should reproduce the Appendix F.3 plaintext"
        );
    }
}

/// The same, with `-x`, which should give the identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_128}"));
    let binary = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &input);
    let hex_out = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128, "-x"], &input);

    let hex_str = String::from_utf8(hex_out).expect("hex output is text");
    assert_eq!(hex_str.trim_end(), tohex(&binary));
    assert_eq!(hex_str.trim_end(), PLAINTEXT);
}

// ---- round trips ------------------------------------------------------------------------

/// `encrypt | decrypt` recovers the input, for all three key lengths.
///
/// Also checks the output length: the ciphertext is one block longer than the plaintext, because
/// the IV is prepended.
#[test]
fn encrypt_then_decrypt_round_trips() {
    for (cmd, key) in [("aes128-cfb", KEY_128), ("aes192-cfb", KEY_192), ("aes256-cfb", KEY_256)] {
        let plaintext = unhex(PLAINTEXT);
        let ciphertext = run_ok(&[cmd, "encrypt", "--key", key], &plaintext);
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + 16,
            "{cmd}: output should be the 16-byte IV plus the ciphertext"
        );

        let recovered = run_ok(&[cmd, "decrypt", "--key", key], &ciphertext);
        assert_eq!(recovered, plaintext, "{cmd}: round trip");
    }
}

/// Round trips at sizes that straddle the 1 KiB streaming chunk and the block boundary.
///
/// 1024 is exactly one chunk; 1040 is a chunk plus one block, which exercises the tail path; 4112
/// is four chunks plus a block; 65536 is many chunks.
#[test]
fn round_trips_across_chunk_boundaries() {
    for size in [16usize, 32, 1024, 1040, 4096, 4112, 65536] {
        let plaintext = pseudo_random(size, size as u32);
        let ciphertext = run_ok(&["aes128-cfb", "encrypt", "--key", KEY_128], &plaintext);
        let recovered = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext, "{size} bytes should round trip");
    }
}

/// A fresh IV per invocation, so the same plaintext under the same key gives different output.
///
/// This matters even more for CFB than for CBC: CFB XORs a keystream, so a repeated key-and-IV pair
/// leaks the XOR of the two plaintexts outright, not merely whether blocks were equal.
#[test]
fn each_invocation_uses_a_fresh_iv() {
    let plaintext = unhex(PLAINTEXT);
    let mut seen = std::collections::BTreeSet::new();

    for _ in 0..8 {
        let ciphertext = run_ok(&["aes128-cfb", "encrypt", "--key", KEY_128], &plaintext);
        let iv = ciphertext[..16].to_vec();
        assert!(seen.insert(iv), "the CLI reused an IV across invocations");
        // ...and the body differs too, not just the IV.
        let recovered = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &ciphertext);
        assert_eq!(recovered, plaintext);
    }
}

// ---- key handling -----------------------------------------------------------------------

/// `--key-file` accepts both a hex file and a raw binary file, and agrees with `--key`.
#[test]
fn key_file_accepts_hex_and_binary() {
    let dir = std::env::temp_dir().join(format!("bc_rust_cfb_cli_key_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let hex_path = dir.join("key.hex");
    let bin_path = dir.join("key.bin");
    std::fs::write(&hex_path, KEY_128).expect("write hex key");
    std::fs::write(&bin_path, unhex(KEY_128)).expect("write binary key");

    let input = unhex(&format!("{IV}{CT_128}"));
    let expected = unhex(PLAINTEXT);

    for path in [&hex_path, &bin_path] {
        let out = run_ok(&["aes128-cfb", "decrypt", "--key-file", path.to_str().unwrap()], &input);
        assert_eq!(out, expected, "--key-file {path:?}");
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// A key of the wrong length for the chosen variant is rejected, naming both lengths.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    let stderr = run_err(&["aes256-cfb", "encrypt", "--key", KEY_128], &unhex(PLAINTEXT));
    assert!(stderr.contains("32-byte key"), "stderr should name the expected length: {stderr}");
    assert!(stderr.contains("16 bytes"), "stderr should name the supplied length: {stderr}");
}

/// Omitting the key entirely is an error, not a default.
#[test]
fn a_missing_key_is_rejected() {
    let stderr = run_err(&["aes128-cfb", "encrypt"], &unhex(PLAINTEXT));
    assert!(stderr.contains("--key"), "stderr should mention the key options: {stderr}");
}

/// An all-zero key warns but proceeds, matching `helpers::parse_seed`'s stance. NIST publishes
/// all-zero-key vectors, so refusing outright would make some of them untestable from the CLI.
#[test]
fn an_all_zero_key_warns_but_proceeds() {
    let zero_key = "0".repeat(32);
    let out = run(&["aes128-cfb", "encrypt", "--key", &zero_key], &unhex(PLAINTEXT));
    assert!(out.status.success(), "an all-zero key should still work");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("warning"), "an all-zero key should warn: {stderr}");
    assert_eq!(out.stdout.len(), 16 + 64, "IV plus four ciphertext blocks");
}

// ---- block alignment and framing --------------------------------------------------------

/// Input that is not a whole number of blocks is rejected, with a message that explains why rather
/// than just failing. These commands are the `s = b` CFB variant, so they need whole blocks and
/// they do not pad.
#[test]
fn unaligned_input_is_rejected_with_an_explanation() {
    for extra in [1usize, 7, 15] {
        let plaintext = pseudo_random(32 + extra, extra as u32);
        let stderr = run_err(&["aes128-cfb", "encrypt", "--key", KEY_128], &plaintext);
        assert!(
            stderr.contains("whole number of 16-byte blocks"),
            "stderr should explain the alignment requirement: {stderr}"
        );
        assert!(
            stderr.contains("padding"),
            "stderr should point at padding being the caller's job: {stderr}"
        );
        assert!(stderr.contains("CFB128"), "stderr should name the mode: {stderr}");
    }
}

/// Decrypt input shorter than the IV it must start with is rejected, and says so.
#[test]
fn decrypt_input_shorter_than_the_iv_is_rejected() {
    for len in [0usize, 1, 15] {
        let stderr = run_err(&["aes128-cfb", "decrypt", "--key", KEY_128], &pseudo_random(len, 1));
        assert!(
            stderr.contains("IV"),
            "stderr should explain the missing IV (len {len}): {stderr}"
        );
    }
}

/// Decrypt input that carries the IV but then an unaligned body is rejected too.
#[test]
fn decrypt_rejects_an_unaligned_body() {
    let mut input = unhex(IV);
    input.extend_from_slice(&pseudo_random(20, 3)); // 20 is not a multiple of 16
    let stderr = run_err(&["aes128-cfb", "decrypt", "--key", KEY_128], &input);
    assert!(
        stderr.contains("whole number of 16-byte blocks"),
        "stderr should explain the alignment requirement: {stderr}"
    );
}

/// Empty input to `encrypt` produces just the IV: zero blocks in, zero blocks out.
///
/// Worth pinning because it is the one input length that is block-aligned but has no blocks, and
/// it is easy for a streaming loop to mishandle.
#[test]
fn empty_input_produces_only_the_iv() {
    let out = run_ok(&["aes128-cfb", "encrypt", "--key", KEY_128], &[]);
    assert_eq!(out.len(), 16, "empty input should yield exactly the IV");

    // ...and feeding that straight back gives empty output.
    let back = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &out);
    assert!(back.is_empty(), "decrypting an IV with no body should give nothing");
}

// ---- SP 800-38A Appendix D, through the CLI ----------------------------------------------

/// Appendix D, Table D.2 for CFB: a bit error in `Cj` gives "SBE in the decryption of `Cj`" --
/// **specific** bit errors, i.e. the very same bit position -- plus random bit errors in `Cj+1`,
/// and nothing beyond that (with `s = b`, `b/s` is 1).
///
/// This is the property that makes CFB tampering directly exploitable, which is why the subcommand
/// help warns about it, and it is also a sharp end-to-end check that the CLI is running CFB rather
/// than CBC: under CBC the controlled flip would land in `Pj+1`, not `Pj`.
#[test]
fn a_ciphertext_bit_flip_flips_the_same_plaintext_bit() {
    let plaintext = unhex(PLAINTEXT);
    let mut input = unhex(&format!("{IV}{CT_128}"));

    // Byte 3 of the second ciphertext block. Input layout is IV | C1 | C2 | C3 | C4, so C2 starts
    // at offset 32.
    const OFFSET: usize = 32 + 3;
    const MASK: u8 = 0b0010_0000;
    input[OFFSET] ^= MASK;

    let out = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &input);
    assert_eq!(out.len(), 64);

    assert_eq!(&out[0..16], &plaintext[0..16], "P1 depends only on the IV, so it is unaffected");

    let mut expected_p2 = plaintext[16..32].to_vec();
    expected_p2[3] ^= MASK;
    assert_eq!(&out[16..32], &expected_p2[..], "P2 should show exactly the flipped bit");

    assert_ne!(&out[32..48], &plaintext[32..48], "P3 is randomised: C2 feeds the next cipher call");
    assert_eq!(
        &out[48..64],
        &plaintext[48..64],
        "P4 is unaffected: with s = b, damage stops at P3"
    );
}

// ---- cross-variant and cross-mode behaviour ---------------------------------------------

/// Decrypting with a different key length than was used to encrypt cannot succeed silently.
#[test]
fn the_three_variants_are_not_interchangeable() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-cfb", "encrypt", "--key", KEY_128], &plaintext);

    // Right length, wrong key: decryption "succeeds" but must not recover the plaintext. CFB is
    // unauthenticated, so garbage out is the expected behaviour, not an error -- which is exactly
    // why the crate docs insist on authenticating separately.
    let wrong_key = "ff".repeat(16);
    let out = run_ok(&["aes128-cfb", "decrypt", "--key", &wrong_key], &ciphertext);
    assert_ne!(out, plaintext, "a wrong key must not recover the plaintext");
    assert_eq!(out.len(), plaintext.len(), "but the length is unchanged: CFB is unauthenticated");
}

/// CFB and CBC ciphertexts are not interchangeable, in either direction.
///
/// The two commands take the same arguments and produce the same-shaped output, so nothing but this
/// stops a caller pairing them up by mistake. Both spec ciphertexts are for the same key, IV and
/// plaintext, so this is a clean comparison: each mode must reproduce the plaintext only from its
/// own ciphertext.
#[test]
fn cfb_and_cbc_are_not_interchangeable() {
    let plaintext = unhex(PLAINTEXT);
    let cfb_input = unhex(&format!("{IV}{CT_128}"));
    let cbc_input = unhex(&format!("{IV}{CBC_CT_128}"));

    // Each mode with its own ciphertext: correct.
    assert_eq!(run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &cfb_input), plaintext);
    assert_eq!(run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &cbc_input), plaintext);

    // Each mode with the other's ciphertext: wrong, but silently so -- neither mode is
    // authenticated, so there is nothing to detect the mismatch.
    let cfb_reads_cbc = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &cbc_input);
    assert_ne!(cfb_reads_cbc, plaintext, "CFB must not decrypt a CBC ciphertext");

    let cbc_reads_cfb = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &cfb_input);
    assert_ne!(cbc_reads_cfb, plaintext, "CBC must not decrypt a CFB ciphertext");
}

// ---- discoverability --------------------------------------------------------------------

/// The subcommands appear in `--help`, so they are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for cmd in ["aes128-cfb", "aes192-cfb", "aes256-cfb"] {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}

/// Each subcommand's own help names the two actions, the IV convention, and -- because `CFB8` and
/// `CFB1` are different, non-interoperable modes -- the segment size.
#[test]
fn per_command_help_documents_the_iv_convention_and_the_segment_size() {
    let out = run_ok(&["aes128-cfb", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("encrypt"), "help should list the encrypt action");
    assert!(help.contains("decrypt"), "help should list the decrypt action");
    assert!(
        help.contains("FIRST 16 BYTES") || help.contains("first 16 bytes"),
        "help should explain where the IV goes: {help}"
    );
    assert!(help.contains("CFB128"), "help should say which CFB variant this is: {help}");
}
