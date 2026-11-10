//! Tests for the `sm4-ctr` subcommand.
//!
//! `sm4-ctr` shares its key and nonce loaders, streaming loops and error paths with the
//! `aes*-ctr` commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_ctr.sh` covers
//! those exhaustively. This file pins what is specific to SM4: the 16-byte key length, the
//! **12-byte** nonce, and that what comes out really is CTR over SM4.
//!
//! draft-ribose-cfrg-sm4-10's Appendix A.2.5 examples make the whole 16-byte IV the first counter
//! block, which the 12-byte-nonce split these commands use cannot produce (see the `SM4_CTR` docs),
//! so there is no vector to decrypt here. Instead the command is required to agree with
//! `bouncycastle_cipher::modes::Ctr` over the SM4 permutation, which
//! `crypto/sm4/tests/stream_mode_tests.rs` pins against the Sec 8.7.1 equations.

mod common;
use bouncycastle::cipher::modes::CTR;
use bouncycastle::sm4::SM4Key;
use common::{
    Framing, KEY16, KEY32, any_input_length, fresh_prefix_per_invocation, key_object,
    library_stream_decrypt, listed_in_help, pseudo_random, round_trips, run_ok, tohex, unhex,
    wrong_key_lengths,
};

/// The single SM4 key length.
const KEY: &str = "0123456789abcdeffedcba9876543210";

/// CTR writes a 12-byte nonce, not the 16-byte IV the other modes write.
const NONCE_LEN: usize = 12;

/// What the command emits must be exactly what `Ctr` over `SM4` produces.
#[test]
fn the_command_is_ctr_over_sm4() {
    for len in [1usize, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);
        let out = run_ok(&["sm4-ctr", "-d", "encrypt", "--key", KEY], &plaintext);
        assert_eq!(out.len(), NONCE_LEN + len, "len {len}: nonce plus an equal-length body");

        let (nonce, body) = out.split_at(NONCE_LEN);
        let mut recovered = body.to_vec();
        library_stream_decrypt::<16, 12, _>(
            &key_object::<16, SM4Key<CTR>>(KEY),
            nonce,
            &mut recovered,
        );
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");
    }
}

/// With `--iv` the 12-byte nonce is supplied, the output is the ciphertext alone, and it is still
/// `Ctr` over `SM4` under that nonce.
#[test]
fn a_supplied_nonce_is_used_and_not_written() {
    let nonce = "000102030405060708090a0b";
    let plaintext = pseudo_random(37, 5);
    let out = run_ok(&["sm4-ctr", "-d", "encrypt", "--key", KEY, "--iv", nonce], &plaintext);
    assert_eq!(out.len(), plaintext.len(), "ciphertext only, no nonce in band");

    let mut recovered = out.clone();
    library_stream_decrypt::<16, 12, _>(
        &key_object::<16, SM4Key<CTR>>(KEY),
        &unhex(nonce),
        &mut recovered,
    );
    assert_eq!(recovered, plaintext, "the CLI should agree with the library under that nonce");

    let back = run_ok(&["sm4-ctr", "-d", "decrypt", "--key", KEY, "--iv", nonce], &out);
    assert_eq!(back, plaintext);
}

/// CTR writes a **12-byte** nonce where the other SM4 modes write a 16-byte IV, so the output is 12
/// bytes longer than the input rather than 16. Getting this wrong would shift every byte of the
/// payload.
#[test]
fn the_nonce_is_twelve_bytes_not_sixteen() {
    let plaintext = pseudo_random(64, 7);
    let out = run_ok(&["sm4-ctr", "-d", "encrypt", "--key", KEY], &plaintext);
    assert_eq!(out.len(), plaintext.len() + NONCE_LEN, "a 12-byte nonce plus the ciphertext");

    let via_cfb = run_ok(&["sm4-cfb", "-d", "encrypt", "--key", KEY], &plaintext);
    assert_eq!(via_cfb.len(), plaintext.len() + 16, "sm4-cfb writes a 16-byte IV");

    let back = run_ok(&["sm4-ctr", "-d", "decrypt", "--key", KEY], &out);
    assert_eq!(back, plaintext);
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let plaintext = pseudo_random(32, 3);
    let ciphertext = run_ok(&["sm4-ctr", "-d", "encrypt", "--key", KEY], &plaintext);

    let binary = run_ok(&["sm4-ctr", "-d", "decrypt", "--key", KEY], &ciphertext);
    let hex_out = run_ok(&["sm4-ctr", "-d", "decrypt", "--key", KEY, "-x"], &ciphertext);
    let hex_str = String::from_utf8(hex_out).expect("hex output is text");

    assert_eq!(hex_str, format!("{}\n", tohex(&binary)));
    assert_eq!(binary, plaintext);
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(&[("sm4-ctr", KEY16)], &[], Framing { prefix: 12, suffix: 0, pads: false });
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("sm4-ctr", KEY16, &[], Framing { prefix: 12, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(&[("sm4-ctr", KEY32, "SM4 needs a 16-byte key, got 32 bytes")], &[]);
}

#[test]
fn each_invocation_uses_a_fresh_nonce() {
    fresh_prefix_per_invocation("sm4-ctr", KEY16, 12);
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["sm4-ctr"]);
}
