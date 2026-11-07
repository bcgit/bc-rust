//! Tests for the `sm4-cfb` subcommand.
//!
//! `sm4-cfb` shares its key and IV loaders, streaming loops and error paths with the `aes*-cfb`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_cfb.sh` covers those
//! exhaustively. This file pins what is specific to SM4: the known-answer vectors in both
//! directions, the 16-byte key length, and that the command exists and round-trips at any length.
//!
//! Vectors are the SM4-CFB examples of draft-ribose-cfrg-sm4-10 Appendix A.2.4.

mod common;
use common::{
    Framing, KEY16, KEY32, any_input_length, listed_in_help, round_trips, run_ok, tohex, unhex,
    wrong_key_lengths,
};

/// Appendix A.2 IV, shared by both CFB examples.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The two Appendix A.2.4 plaintext blocks.
const PLAINTEXT: &str = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffaaaaaaaabbbbbbbb";

/// A.2.4.1 key and ciphertext.
const KEY_1: &str = "0123456789abcdeffedcba9876543210";
const CT_1: &str = "ac3236cb861dd316e6413b4e3c7524b769d4c54ed433b9a0346009beb37b2b3f";

/// A.2.4.2 key and ciphertext.
const KEY_2: &str = "fedcba98765432100123456789abcdef";
const CT_2: &str = "5dcccd25a84ba16560d7f265887068490d9b86ff20c3bfe115ffa02ca6192cc5";

/// `encrypt --iv` reproduces the draft's ciphertext, and nothing but the ciphertext, for both
/// Appendix A.2.4 examples; `decrypt --iv` takes it back.
#[test]
fn encrypt_matches_appendix_a_2_4_vectors() {
    for (section, key, ct) in [("A.2.4.1", KEY_1, CT_1), ("A.2.4.2", KEY_2, CT_2)] {
        let out =
            run_ok(&["sm4-cfb", "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        assert_eq!(tohex(&out), ct, "{section}: sm4-cfb encrypt --iv should give the ciphertext");

        let back = run_ok(&["sm4-cfb", "-d", "decrypt", "--key", key, "--iv", IV], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{section}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the draft's plaintext when handed the draft's IV followed by its
/// ciphertext, for both Appendix A.2.4 examples.
#[test]
fn decrypt_matches_appendix_a_2_4_vectors() {
    for (section, key, ct) in [("A.2.4.1", KEY_1, CT_1), ("A.2.4.2", KEY_2, CT_2)] {
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&["sm4-cfb", "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{section}: sm4-cfb decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_1}"));
    let out = run_ok(&["sm4-cfb", "-d", "decrypt", "--key", KEY_1, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(&[("sm4-cfb", KEY16)], &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("sm4-cfb", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(&[("sm4-cfb", KEY32, "SM4 needs a 16-byte key, got 32 bytes")], &[]);
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["sm4-cfb"]);
}
