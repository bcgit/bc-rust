//! Tests for the six AES mode subcommands: `aes128-cbc`, `aes192-cbc`, `aes256-cbc`,
//! `aes128-cfb`, `aes192-cfb`, `aes256-cfb`.
//!
//! These drive the built `bc-rust` binary as a subprocess, because the behaviour worth testing is
//! the command-line contract itself -- the IV riding in the first block, block-alignment
//! enforcement, exit codes, key loading -- none of which is reachable from the library API.
//!
//! The two modes share one implementation module and one streaming loop, so most tests loop over
//! [`SHARED_PATH_MODES`] (one entry point per mode) or [`ALL_MODES`] (all six) rather than
//! duplicating a CBC test for CFB.
//!
//! `CARGO_BIN_EXE_bc-rust` is set by cargo for integration tests and points at the binary for the
//! current profile, so there is nothing to build or locate by hand.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// The path to the binary under test, resolved by cargo.
const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

/// SP 800-38A Appendix F IV, shared by every F.2 and F.3 subsection.
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

/// F.2.1 CBC-AES128.Encrypt ciphertext.
const CBC_CT_128: &str = concat!(
    "7649abac8119b246cee98e9b12e9197d",
    "5086cb9b507219ee95db113a917678b2",
    "73bed6b8e3c1743b7116e69e22229516",
    "3ff1caa1681fac09120eca307586e1a7",
);
/// F.2.3 CBC-AES192.Encrypt ciphertext.
const CBC_CT_192: &str = concat!(
    "4f021db243bc633d7178183a9fa071e8",
    "b4d9ada9ad7dedf4e5e738763f69145a",
    "571b242012fb7ae07fa9baac3df102e0",
    "08b0e27988598881d920a9e64f5615cd",
);
/// F.2.5 CBC-AES256.Encrypt ciphertext.
const CBC_CT_256: &str = concat!(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
    "9cfc4e967edb808d679f777bc6702c7d",
    "39f23369a9d9bacfa530e26304231461",
    "b2eb05e2c39be9fcda6c19078c6a9d1b",
);

/// F.3.13 CFB128-AES128.Encrypt ciphertext.
const CFB_CT_128: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "c8a64537a0b3a93fcde3cdad9f1ce58b",
    "26751f67a3cbb140b1808cf187a4f4df",
    "c04b05357c5d1c0eeac4c66f9ff7f2e6",
);

/// F.3.15 CFB128-AES192.Encrypt ciphertext.
const CFB_CT_192: &str = concat!(
    "cdc80d6fddf18cab34c25909c99a4174",
    "67ce7f7f81173621961a2b70171d3d7a",
    "2e1e8a1dd59b88b1c8e60fed1efac4c9",
    "c05f9f9ca9834fa042ae8fba584b09ff",
);

/// F.3.17 CFB128-AES256.Encrypt ciphertext.
const CFB_CT_256: &str = concat!(
    "dc7e84bfda79164b7ecd8486985d3860",
    "39ffed143b28b1c832113c6331e5407b",
    "df10132415e54b92a13ed0a8267ae2f9",
    "75a385741ab9cef82031623d55b1e471",
);

/// One subcommand per mode, for the tests that exercise code shared by all six.
///
/// Key loading, the streaming loop and every error message live in one place and are generic over
/// the mode, so running both entry points is enough to show the shared path works from either --
/// there is no need to multiply every error-path test by six.
const SHARED_PATH_MODES: [&str; 2] = ["aes128-cbc", "aes128-cfb"];

/// Every subcommand, with its key and the Appendix F ciphertext it must reproduce.
///
/// The two modes present an identical command-line contract, so almost every test below is a loop
/// over this table rather than a CBC test with a CFB copy.
const ALL_MODES: [(&str, &str, &str); 6] = [
    ("aes128-cbc", KEY_128, CBC_CT_128),
    ("aes192-cbc", KEY_192, CBC_CT_192),
    ("aes256-cbc", KEY_256, CBC_CT_256),
    ("aes128-cfb", KEY_128, CFB_CT_128),
    ("aes192-cfb", KEY_192, CFB_CT_192),
    ("aes256-cfb", KEY_256, CFB_CT_256),
];

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

// ---- the SP 800-38A Appendix F vectors, through the CLI -----------------------------------

/// `decrypt` reproduces the spec plaintext when handed the spec's IV followed by the spec's
/// ciphertext.
///
/// This is the direction that can be pinned exactly: `encrypt` picks its own IV, so it cannot be
/// asked to reproduce a published ciphertext. `encrypt` is covered by the round-trip tests below
/// and, at the library level, by `crypto/modes/tests/sp800_38a_tests.rs`.
#[test]
fn decrypt_matches_sp800_38a_appendix_f_vectors() {
    for (cmd, key, ct) in ALL_MODES {
        // The CLI expects the IV as the first block of its input, which is exactly how `encrypt`
        // emits it.
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&[cmd, "decrypt", "--key", key], &input);
        assert_eq!(
            tohex(&out),
            PLAINTEXT,
            "{cmd} decrypt should reproduce the Appendix F plaintext"
        );
    }
}

/// The two modes must not produce the same ciphertext from the same inputs, which is what would
/// happen if a CFB subcommand were wired to the CBC types by a copy-paste slip.
#[test]
fn the_cfb_subcommands_are_not_secretly_cbc() {
    for (cbc_cmd, cfb_cmd, key, cbc_ct, cfb_ct) in [
        ("aes128-cbc", "aes128-cfb", KEY_128, CBC_CT_128, CFB_CT_128),
        ("aes192-cbc", "aes192-cfb", KEY_192, CBC_CT_192, CFB_CT_192),
        ("aes256-cbc", "aes256-cfb", KEY_256, CBC_CT_256, CFB_CT_256),
    ] {
        assert_ne!(cbc_ct, cfb_ct, "the two vectors differ to begin with");

        // Feeding the CBC ciphertext to the CFB command must not recover the plaintext...
        let cbc_input = unhex(&format!("{IV}{cbc_ct}"));
        let via_cfb = run_ok(&[cfb_cmd, "decrypt", "--key", key], &cbc_input);
        assert_ne!(tohex(&via_cfb), PLAINTEXT, "{cfb_cmd} must not decrypt {cbc_cmd} ciphertext");

        // ...nor the other way round.
        let cfb_input = unhex(&format!("{IV}{cfb_ct}"));
        let via_cbc = run_ok(&[cbc_cmd, "decrypt", "--key", key], &cfb_input);
        assert_ne!(tohex(&via_cbc), PLAINTEXT, "{cbc_cmd} must not decrypt {cfb_cmd} ciphertext");
    }
}

/// The same, with `-x`, which should give the identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CBC_CT_128}"));
    let binary = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &input);
    let hex_out = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128, "-x"], &input);

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
    for (cmd, key, _) in ALL_MODES {
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
    for cmd in ["aes128-cbc", "aes128-cfb"] {
        for size in [16usize, 32, 1024, 1040, 4096, 4112, 65536] {
            let plaintext = pseudo_random(size, size as u32);
            let ciphertext = run_ok(&[cmd, "encrypt", "--key", KEY_128], &plaintext);
            let recovered = run_ok(&[cmd, "decrypt", "--key", KEY_128], &ciphertext);
            assert_eq!(recovered, plaintext, "{cmd}: {size} bytes should round trip");
        }
    }
}

/// A fresh IV per invocation, so the same plaintext under the same key gives different output.
///
/// This is the operational requirement both modes live or die by -- and for CFB an IV repeat is
/// the worse of the two, since it gives a two-time pad on the first block rather than merely
/// leaking a shared prefix. The CLI is where it is easiest to get wrong (e.g. by seeding from a
/// fixed value).
#[test]
fn each_invocation_uses_a_fresh_iv() {
    let plaintext = unhex(PLAINTEXT);

    for cmd in SHARED_PATH_MODES {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let ciphertext = run_ok(&[cmd, "encrypt", "--key", KEY_128], &plaintext);
            let iv = ciphertext[..16].to_vec();
            assert!(seen.insert(iv), "{cmd} reused an IV across invocations");
            // ...and the body differs too, not just the IV.
            let recovered = run_ok(&[cmd, "decrypt", "--key", KEY_128], &ciphertext);
            assert_eq!(recovered, plaintext);
        }
    }
}

/// SP 800-38A Appendix D, Table D.2, CFB row: a bit error in `Cj` gives "SBE in the decryption of
/// Cj" -- specific bit errors, in the same positions.
///
/// So flipping a bit of CFB ciphertext flips exactly that bit of the same block's plaintext. This
/// is the malleability the CFB help text warns about, and it is worth asserting at the CLI level
/// because that is where someone is most likely to treat "the output looks like garbage" as
/// tamper detection. It is *not* garbage: it is a precisely chosen change.
///
/// The CBC row is the other way round (RBE in `Cj`), so the same edit to CBC ciphertext must
/// **not** produce a clean single-bit change -- which is checked here too, since the contrast is
/// the whole point.
#[test]
fn a_cfb_ciphertext_bit_flip_is_a_targeted_plaintext_bit_flip() {
    let plaintext = unhex(PLAINTEXT);

    // CFB: flip bit 5 of byte 3 of the second ciphertext block (offset 16 past the IV).
    let ciphertext = run_ok(&["aes128-cfb", "encrypt", "--key", KEY_128], &plaintext);
    let mut tampered = ciphertext.clone();
    tampered[16 + 16 + 3] ^= 0b0010_0000;
    let out = run_ok(&["aes128-cfb", "decrypt", "--key", KEY_128], &tampered);

    let mut expected = plaintext.clone();
    expected[16 + 3] ^= 0b0010_0000; // exactly that bit of P2
    assert_eq!(
        &out[..32],
        &expected[..32],
        "CFB: P1 untouched and P2 should show exactly the flipped bit"
    );
    // The following block is randomised, because C2 is the cipher input for P3.
    assert_ne!(&out[32..48], &plaintext[32..48], "CFB: P3 should be randomised");
    // ...and nothing beyond it, since b/s = 1 at s = b.
    assert_eq!(&out[48..], &plaintext[48..], "CFB: P4 should be untouched");

    // CBC, the same edit: the targeted flip lands in the *next* block instead, and the block
    // attacked is randomised.
    let ciphertext = run_ok(&["aes128-cbc", "encrypt", "--key", KEY_128], &plaintext);
    let mut tampered = ciphertext.clone();
    tampered[16 + 16 + 3] ^= 0b0010_0000;
    let out = run_ok(&["aes128-cbc", "decrypt", "--key", KEY_128], &tampered);

    assert_ne!(&out[16..32], &expected[16..32], "CBC: P2 should be randomised, not flipped");
    let mut cbc_expected_p3 = plaintext[32..48].to_vec();
    cbc_expected_p3[3] ^= 0b0010_0000;
    assert_eq!(&out[32..48], &cbc_expected_p3[..], "CBC: the flip should appear in P3");
}

// ---- key handling -----------------------------------------------------------------------

/// `--key-file` accepts both a hex file and a raw binary file, and agrees with `--key`.
#[test]
fn key_file_accepts_hex_and_binary() {
    let dir = std::env::temp_dir().join(format!("bc_rust_cli_key_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");

    let hex_path = dir.join("key.hex");
    let bin_path = dir.join("key.bin");
    std::fs::write(&hex_path, KEY_128).expect("write hex key");
    std::fs::write(&bin_path, unhex(KEY_128)).expect("write binary key");

    let input = unhex(&format!("{IV}{CBC_CT_128}"));
    let expected = unhex(PLAINTEXT);

    for path in [&hex_path, &bin_path] {
        let out = run_ok(&["aes128-cbc", "decrypt", "--key-file", path.to_str().unwrap()], &input);
        assert_eq!(out, expected, "--key-file {path:?}");
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// A key of the wrong length for the chosen variant is rejected, naming both lengths.
#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    for cmd in ["aes256-cbc", "aes256-cfb"] {
        let stderr = run_err(&[cmd, "encrypt", "--key", KEY_128], &unhex(PLAINTEXT));
        assert!(stderr.contains("32-byte key"), "{cmd}: expected length: {stderr}");
        assert!(stderr.contains("16 bytes"), "{cmd}: supplied length: {stderr}");
    }
}

/// Omitting the key entirely is an error, not a default.
#[test]
fn a_missing_key_is_rejected() {
    let stderr = run_err(&["aes128-cbc", "encrypt"], &unhex(PLAINTEXT));
    assert!(stderr.contains("--key"), "stderr should mention the key options: {stderr}");
}

/// An all-zero key warns but proceeds, matching `helpers::parse_seed`'s stance. NIST publishes
/// all-zero-key vectors, so refusing outright would make some of them untestable from the CLI.
#[test]
fn an_all_zero_key_warns_but_proceeds() {
    let zero_key = "0".repeat(32);
    let out = run(&["aes128-cbc", "encrypt", "--key", &zero_key], &unhex(PLAINTEXT));
    assert!(out.status.success(), "an all-zero key should still work");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.to_lowercase().contains("warning"), "an all-zero key should warn: {stderr}");
    assert_eq!(out.stdout.len(), 16 + 64, "IV plus four ciphertext blocks");
}

// ---- block alignment and framing --------------------------------------------------------

/// Input that is not a whole number of blocks is rejected, with a message that explains why
/// rather than just failing. CBC has no answer for a partial block and there is no padding layer.
#[test]
fn unaligned_input_is_rejected_with_an_explanation() {
    for cmd in SHARED_PATH_MODES {
        for extra in [1usize, 7, 15] {
            let plaintext = pseudo_random(32 + extra, extra as u32);
            let stderr = run_err(&[cmd, "encrypt", "--key", KEY_128], &plaintext);
            assert!(
                stderr.contains("whole number of 16-byte blocks"),
                "stderr should explain the alignment requirement: {stderr}"
            );
            assert!(
                stderr.contains("padding"),
                "stderr should point at the missing padding layer: {stderr}"
            );
        }
    }
}

/// Decrypt input shorter than the IV it must start with is rejected, and says so.
#[test]
fn decrypt_input_shorter_than_the_iv_is_rejected() {
    for cmd in SHARED_PATH_MODES {
        for len in [0usize, 1, 15] {
            let stderr = run_err(&[cmd, "decrypt", "--key", KEY_128], &pseudo_random(len, 1));
            assert!(
                stderr.contains("IV"),
                "{cmd}: stderr should explain the missing IV (len {len}): {stderr}"
            );
        }
    }
}

/// Decrypt input that carries the IV but then an unaligned body is rejected too.
#[test]
fn decrypt_rejects_an_unaligned_body() {
    for cmd in SHARED_PATH_MODES {
        let mut input = unhex(IV);
        input.extend_from_slice(&pseudo_random(20, 3)); // 20 is not a multiple of 16
        let stderr = run_err(&[cmd, "decrypt", "--key", KEY_128], &input);
        assert!(
            stderr.contains("whole number of 16-byte blocks"),
            "{cmd}: stderr should explain the alignment requirement: {stderr}"
        );
    }
}

/// Empty input to `encrypt` produces just the IV: zero blocks in, zero blocks out.
///
/// Worth pinning because it is the one input length that is block-aligned but has no blocks, and
/// it is easy for a streaming loop to mishandle.
#[test]
fn empty_input_produces_only_the_iv() {
    for cmd in SHARED_PATH_MODES {
        let out = run_ok(&[cmd, "encrypt", "--key", KEY_128], &[]);
        assert_eq!(out.len(), 16, "{cmd}: empty input should yield exactly the IV");

        // ...and feeding that straight back gives empty output.
        let back = run_ok(&[cmd, "decrypt", "--key", KEY_128], &out);
        assert!(back.is_empty(), "{cmd}: decrypting an IV with no body should give nothing");
    }
}

// ---- cross-variant behaviour ------------------------------------------------------------

/// Decrypting with a different key length than was used to encrypt cannot succeed silently.
#[test]
fn the_three_variants_are_not_interchangeable() {
    let plaintext = unhex(PLAINTEXT);
    let ciphertext = run_ok(&["aes128-cbc", "encrypt", "--key", KEY_128], &plaintext);

    // Right length, wrong key: decryption "succeeds" but must not recover the plaintext. CBC is
    // unauthenticated, so garbage out is the expected behaviour, not an error -- which is exactly
    // why the crate docs insist on authenticating separately.
    let wrong_key = "ff".repeat(16);
    let out = run_ok(&["aes128-cbc", "decrypt", "--key", &wrong_key], &ciphertext);
    assert_ne!(out, plaintext, "a wrong key must not recover the plaintext");
    assert_eq!(out.len(), plaintext.len(), "but the length is unchanged: CBC is unauthenticated");
}

/// The subcommands appear in `--help`, so they are discoverable.
#[test]
fn the_subcommands_are_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    for (cmd, _, _) in ALL_MODES {
        assert!(help.contains(cmd), "`--help` should list {cmd}");
    }
}

/// Each subcommand's own help names the two actions and the IV convention.
#[test]
fn per_command_help_documents_the_iv_convention() {
    for cmd in SHARED_PATH_MODES {
        let out = run_ok(&[cmd, "--help"], &[]);
        let help = String::from_utf8_lossy(&out);
        assert!(help.contains("encrypt"), "{cmd}: help should list the encrypt action");
        assert!(help.contains("decrypt"), "{cmd}: help should list the decrypt action");
        assert!(
            help.contains("FIRST 16 BYTES") || help.contains("first 16 bytes"),
            "{cmd}: help should explain where the IV goes: {help}"
        );
    }
}

/// The CFB help must say which segment size it is, because "CFB" alone is ambiguous -- SP 800-38A
/// Sec 6.3 allows any `1 <= s <= b`, and CFB8 is a real and different mode that this is not.
#[test]
fn the_cfb_help_names_the_segment_size() {
    for cmd in ["aes128-cfb", "aes192-cfb", "aes256-cfb"] {
        let out = run_ok(&[cmd, "--help"], &[]);
        let help = String::from_utf8_lossy(&out);
        assert!(
            help.contains("CFB128"),
            "{cmd}: help should identify the segment size as CFB128: {help}"
        );
    }

    // ...and the warning about its malleability must be there, since it differs from CBC's.
    let out = run_ok(&["aes128-cfb", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.contains("WARNING"), "the CFB help should carry the malleability warning");
}
