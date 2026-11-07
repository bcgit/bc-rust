//! Tests for the `sm4-gcm` subcommand.
//!
//! `sm4-gcm` shares its key, IV and AAD loaders, streaming loops and error paths with the
//! `aes*-gcm` commands (`cli/src/helpers/aead_cipher_helpers.rs`), and `test_aes_gcm.sh` covers
//! those exhaustively. This file pins what is specific to SM4: the 16-byte key length, and that
//! what comes out really is GCM over SM4, held to RFC 8998 Appendix A.1's `AEAD_SM4_GCM` vector
//! and to the library's own `SM4Key<GCM>`.

mod common;
use bouncycastle::sm4::hazmat::SM4Internal;
use common::{
    Framing, KEY16, KEY32, any_input_length, fresh_prefix_per_invocation, library_gcm_decrypt,
    pseudo_random, round_trips, run_err, run_ok, tohex, unhex, wrong_key_lengths,
};

/// The single SM4 key length.
const KEY: &str = "0123456789abcdeffedcba9876543210";

/// GCM's framing: the 12-byte nonce leads and the 16-byte tag follows the ciphertext.
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// RFC 8998 Appendix A.1, the `AEAD_SM4_GCM` vector, through the command with the vector's
/// nonce supplied: the output is exactly `ciphertext || tag`, and it decrypts back.
#[test]
fn the_command_reproduces_rfc_8998_a_1() {
    const KEY_A1: &str = "0123456789ABCDEFFEDCBA9876543210";
    const NONCE_A1: &str = "00001234567800000000ABCD";
    const AAD_A1: &str = "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2";
    const PT_A1: &str = concat!(
        "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB",
        "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD",
        "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF",
        "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA",
    );
    const CT_A1: &str = concat!(
        "17F399F08C67D5EE19D0DC9969C4BB7D",
        "5FD46FD3756489069157B282BB200735",
        "D82710CA5C22F0CCFA7CBF93D496AC15",
        "A56834CBCF98C397B4024A2691233B8D",
    );
    const TAG_A1: &str = "83DE3541E4C2B58177E065A9BF7B62EC";

    let args = ["sm4-gcm", "--key", KEY_A1, "--iv", NONCE_A1, "--aad", AAD_A1];
    let out = run_ok(&[&args[..], &["-d", "encrypt"]].concat(), &unhex(PT_A1));
    assert_eq!(tohex(&out), format!("{CT_A1}{TAG_A1}").to_lowercase());

    let back = run_ok(&[&args[..], &["-d", "decrypt"]].concat(), &out);
    assert_eq!(tohex(&back), PT_A1.to_lowercase());
}

/// What the command emits must be exactly what the library's `GCM` key produces: the generated
/// nonce leads, the body is as long as the input, and the tag follows.
#[test]
fn the_command_is_gcm_over_sm4() {
    for len in [0usize, 1, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);
        let out =
            run_ok(&["sm4-gcm", "-d", "encrypt", "--key", KEY, "--aad", "deadbeef"], &plaintext);
        assert_eq!(out.len(), NONCE_LEN + len + TAG_LEN, "len {len}: nonce, body and tag");

        let (nonce, body) = out.split_at(NONCE_LEN);
        let recovered =
            library_gcm_decrypt::<SM4Internal, 16>(KEY, nonce, &unhex("deadbeef"), body);
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");

        let back = run_ok(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &out);
        assert_eq!(back, plaintext, "len {len}: round trip");
    }
}

/// The AAD is covered by the tag: a different AAD, or none, on the decrypt side fails
/// authentication with a non-zero exit, and a flipped ciphertext or tag byte does too.
#[test]
fn tampering_and_a_changed_aad_fail_authentication() {
    let plaintext = pseudo_random(69, 9);
    let out = run_ok(&["sm4-gcm", "-d", "encrypt", "--key", KEY, "--aad", "deadbeef"], &plaintext);

    let err = run_err(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "--aad", "00112233"], &out);
    assert!(err.contains("authentication failed"), "stderr was: {err}");
    let err = run_err(&["sm4-gcm", "-d", "decrypt", "--key", KEY], &out);
    assert!(err.contains("authentication failed"), "stderr was: {err}");

    let mut body_flipped = out.clone();
    body_flipped[NONCE_LEN] ^= 1;
    let err =
        run_err(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &body_flipped);
    assert!(err.contains("authentication failed"), "stderr was: {err}");

    let mut tag_flipped = out.clone();
    let last = tag_flipped.len() - 1;
    tag_flipped[last] ^= 1;
    let err =
        run_err(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &tag_flipped);
    assert!(err.contains("authentication failed"), "stderr was: {err}");
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let plaintext = pseudo_random(32, 3);
    let ciphertext = run_ok(&["sm4-gcm", "-d", "encrypt", "--key", KEY], &plaintext);

    let binary = run_ok(&["sm4-gcm", "-d", "decrypt", "--key", KEY], &ciphertext);
    let hex_out = run_ok(&["sm4-gcm", "-d", "decrypt", "--key", KEY, "-x"], &ciphertext);
    let hex_str = String::from_utf8(hex_out).expect("hex output is text");

    assert_eq!(hex_str, format!("{}\n", tohex(&binary)));
    assert_eq!(binary, plaintext);
}

/// The subcommand is discoverable, and its help says it authenticates and takes AAD.
#[test]
fn the_subcommand_is_listed_in_help() {
    let out = run_ok(&["--help"], &[]);
    assert!(String::from_utf8_lossy(&out).contains("sm4-gcm"), "`--help` should list sm4-gcm");

    let out = run_ok(&["sm4-gcm", "--help"], &[]);
    let help = String::from_utf8_lossy(&out);
    assert!(help.to_lowercase().contains("authenticat"), "help should mention authentication");
    assert!(help.contains("aad"), "help should mention AAD: {help}");
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(&[("sm4-gcm", KEY16)], &[], Framing { prefix: 12, suffix: 16, pads: false });
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("sm4-gcm", KEY16, &[], Framing { prefix: 12, suffix: 16, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(&[("sm4-gcm", KEY32, "SM4 needs a 16-byte key, got 32 bytes")], &[]);
}

#[test]
fn each_invocation_uses_a_fresh_nonce() {
    fresh_prefix_per_invocation("sm4-gcm", KEY16, 12);
}
