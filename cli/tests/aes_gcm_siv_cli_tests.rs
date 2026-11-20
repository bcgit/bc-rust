//! Tests for the `aes128-gcm-siv` and `aes256-gcm-siv` subcommands.
//!
//! `test_aes_gcm_siv.sh` covers the flags and the short-input errors, but CI does not run the
//! shell suite. This file pins, under `cargo test`, that each command is wired to its key length
//! and writes `aes*-gcm`'s framing: a known answer in both directions, the tag check writing
//! nothing, the round trip under a drawn nonce, and that the mode has no other commands.
//!
//! The known answers are RFC 8452 Appendix C.1 and C.2, the vector of each with an 18-byte
//! plaintext and 20 bytes of AAD, copied from `crypto/aes/tests/gcm_siv_rfc8452_tests.rs`, which
//! runs the whole appendix.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, fresh_prefix_per_invocation, listed_in_help,
    round_trips, run, run_err, run_err_silent, run_ok, tohex, unhex, wrong_key_lengths,
};

/// (command, key, nonce, plaintext, aad, result), the result being the ciphertext then the tag.
const VECTORS: [(&str, &str, &str, &str, &str, &str); 2] = [
    (
        "aes128-gcm-siv",
        "01000000000000000000000000000000",
        "030000000000000000000000",
        "030000000000000000000000000000000400",
        "0100000000000000000000000000000002000000",
        "44d0aaf6fb2f1f34add5e8064e83e12a2adabff9b2ef00fb47920cc72a0c0f13b9fd",
    ),
    (
        "aes256-gcm-siv",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "030000000000000000000000",
        "030000000000000000000000000000000400",
        "0100000000000000000000000000000002000000",
        "462401724b5ce6588d5a54aae5375513a075cfcdf5042112aa29685c912fc2056543",
    ),
];

/// The framing under a drawn nonce, and under a supplied one.
const DRAWN: Framing = Framing { prefix: 12, suffix: 16, pads: false };
const SUPPLIED: Framing = Framing { prefix: 0, suffix: 16, pads: false };

/// With `--nonce`, `encrypt` writes exactly the RFC's result and `decrypt` takes it back to the
/// plaintext, at both key lengths.
#[test]
fn encrypt_and_decrypt_match_rfc_8452_appendix_c() {
    for (cmd, key, nonce, pt, aad, result) in VECTORS {
        let args = [cmd, "--key", key, "--nonce", nonce, "--aad", aad];
        let out = run_ok(&[&args[..], &["-d", "encrypt"]].concat(), &unhex(pt));
        assert_eq!(tohex(&out), result, "{cmd}: ciphertext || tag");
        let back = run_ok(&[&args[..], &["-d", "decrypt"]].concat(), &out);
        assert_eq!(tohex(&back), pt, "{cmd}");
    }
}

/// A flipped ciphertext bit, a flipped tag bit, other AAD or another nonce fails the tag check,
/// and no plaintext is written.
#[test]
fn tampering_fails_the_tag_check_and_writes_nothing() {
    for (cmd, key, nonce, _pt, aad, result) in VECTORS {
        let mut bytes = unhex(result);
        let args = [cmd, "-d", "decrypt", "--key", key, "--nonce", nonce, "--aad", aad];
        run_ok(&args, &bytes);
        let last = bytes.len() - 1;
        for at in [0, last] {
            bytes[at] ^= 1;
            assert!(run_err_silent(&args, &bytes).contains("authentic"), "{cmd}: byte {at}");
            bytes[at] ^= 1;
        }
        let other_aad = [cmd, "-d", "decrypt", "--key", key, "--nonce", nonce, "--aad", "01"];
        assert!(run_err_silent(&other_aad, &bytes).contains("authentic"), "{cmd}: AAD");
        let other_nonce =
            [cmd, "-d", "decrypt", "--key", key, "--nonce", "040000000000000000000000"];
        assert!(
            run_err_silent(&[&other_nonce[..], &["--aad", aad]].concat(), &bytes)
                .contains("authentic")
        );
    }
}

/// Without `--nonce` a nonce is drawn and leads the output, `decrypt` reads it back, and a
/// tampered message under that framing writes nothing either.
#[test]
fn a_drawn_nonce_round_trips() {
    let cmds = [("aes128-gcm-siv", KEY16), ("aes256-gcm-siv", KEY32)];
    round_trips(&cmds, &["--aad", "cafebabe"], DRAWN);
    for (cmd, key) in cmds {
        fresh_prefix_per_invocation(cmd, key, DRAWN.prefix);
        let mut out = run_ok(&[cmd, "-d", "encrypt", "--key", key], b"some plaintext");
        out[DRAWN.prefix] ^= 1;
        let err = run_err_silent(&[cmd, "-d", "decrypt", "--key", key], &out);
        assert!(err.contains("authentic"), "{cmd}: stderr was: {err}");
    }
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("aes128-gcm-siv", KEY16, &[], DRAWN);
    any_input_length("aes256-gcm-siv", KEY32, &["--nonce", "000102030405060708090a0b"], SUPPLIED);
}

/// An input too short for the framing is refused before any work, with nothing written.
#[test]
fn an_input_too_short_for_the_nonce_or_the_tag_is_rejected() {
    let args = ["aes128-gcm-siv", "-d", "decrypt", "--key", KEY16];
    assert!(run_err_silent(&args, &[0u8; 11]).contains("12-byte nonce"));
    assert!(run_err_silent(&args, &[0u8; 27]).contains("16-byte tag"));
    let supplied = [&args[..], &["--nonce", "000102030405060708090a0b"]].concat();
    assert!(run_err_silent(&supplied, &[0u8; 15]).contains("16-byte tag"));
    // The nonce is 12 bytes and nothing else.
    let long = [&args[..], &["--nonce", "000102030405060708090a0b0c"]].concat();
    assert!(
        run_err(&long, &[0u8; 16]).contains("nonce is 13 bytes; this mode requires exactly 12")
    );
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("aes128-gcm-siv", KEY32, "AES-128 needs a 16-byte key, got 32 bytes"),
            ("aes256-gcm-siv", KEY24, "AES-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

/// RFC 8452 Section 6 defines the mode for AES-128 and AES-256 only, so those are the only two
/// commands.
#[test]
fn only_the_two_rfc_8452_aeads_have_commands() {
    listed_in_help(&["aes128-gcm-siv", "aes256-gcm-siv"]);
    let help = String::from_utf8(run_ok(&["--help"], &[])).expect("help is text");
    assert_eq!(help.matches("-gcm-siv ").count(), 2, "exactly two GCM-SIV commands");
    for cmd in ["aes192-gcm-siv", "aria128-gcm-siv", "camellia128-gcm-siv", "sm4-gcm-siv"] {
        let out = run(&[cmd, "-d", "encrypt", "--key", KEY16], &[]);
        assert!(!out.status.success(), "{cmd} must not exist");
        assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognized subcommand"));
    }
}
