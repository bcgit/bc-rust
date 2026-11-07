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

mod common;
use bouncycastle::sm4::hazmat::SM4Internal;
use common::{
    Framing, KEY16, KEY32, any_input_length, large_payload_on_an_error_path, listed_in_help,
    pkcs7_block, round_trips, run_err, run_ok, tohex, unhex, wrong_key_lengths,
};

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

/// `encrypt --iv` reproduces the draft's ciphertext for both Appendix A.2.2 examples, followed
/// by the PKCS7 block, and `decrypt --iv` takes that back to the plaintext.
#[test]
fn encrypt_matches_appendix_a_2_2_vectors() {
    for (section, key, ct) in [("A.2.2.1", KEY_1, CT_1), ("A.2.2.2", KEY_2, CT_2)] {
        let out =
            run_ok(&["sm4-cbc", "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        let want = format!("{ct}{}", pkcs7_block::<SM4Internal, 16>(key, &ct[32..]));
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
        let input = unhex(&format!("{IV}{ct}{}", pkcs7_block::<SM4Internal, 16>(key, &ct[32..])));
        let out = run_ok(&["sm4-cbc", "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{section}: sm4-cbc decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_1}{}", pkcs7_block::<SM4Internal, 16>(KEY_1, &CT_1[32..])));
    let out = run_ok(&["sm4-cbc", "-d", "decrypt", "--key", KEY_1, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// A ciphertext without PKCS7 padding is rejected: the bare A.2.2.1 ciphertext ends in a block
/// that does not unpad.
#[test]
fn a_ciphertext_without_pkcs7_padding_is_rejected() {
    let input = unhex(&format!("{IV}{CT_1}"));
    let err = run_err(&["sm4-cbc", "-d", "decrypt", "--key", KEY_1], &input);
    assert!(err.contains("decryption failed"), "stderr was: {err}");
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(&[("sm4-cbc", KEY16)], &[], Framing { prefix: 16, suffix: 0, pads: true });
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("sm4-cbc", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: true });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(&[("sm4-cbc", KEY32, "SM4 needs a 16-byte key, got 32 bytes")], &[]);
}

#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    large_payload_on_an_error_path("sm4-cbc", KEY32, "SM4 needs a 16-byte key");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["sm4-cbc"]);
}
