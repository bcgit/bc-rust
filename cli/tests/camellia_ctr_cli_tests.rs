//! Tests for the `camellia128-ctr`, `camellia192-ctr` and `camellia256-ctr` subcommands.
//!
//! They share their key and nonce loaders, streaming loops and error paths with the `aes*-ctr`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_ctr.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: the three key lengths, the
//! **12-byte** nonce, and that what comes out really is CTR over Camellia.
//!
//! RFC 5528's nine Camellia-CTR vectors divide the counter block differently -- a 4-octet nonce, an
//! 8-octet IV and a counter starting at one -- so they are not ones these commands can produce (see
//! the `Camellia_CTR_128` docs). Instead the commands are required to agree with
//! `bouncycastle_cipher::modes::Ctr` over the Camellia permutation, which
//! `crypto/camellia/tests/stream_mode_tests.rs` pins against the SP 800-38A Sec 6.5 equations, RFC
//! 5528's vectors included.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, fresh_prefix_per_invocation, key_object,
    library_stream_decrypt, listed_in_help, pseudo_random, round_trips, run_ok, tohex, unhex,
    wrong_key_lengths,
};

/// CTR writes a 12-byte nonce, not the 16-byte IV the other modes write.
const NONCE_LEN: usize = 12;

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// With `--iv` the 12-byte nonce is supplied, the output is the ciphertext alone, and it is still
/// `Ctr` over Camellia under that nonce.
#[test]
fn a_supplied_nonce_is_used_and_not_written() {
    use bouncycastle::camellia::Camellia128Key;
    use bouncycastle::cipher::modes::CTR;

    let nonce = "000102030405060708090a0b";
    let plaintext = pseudo_random(37, 5);
    let out =
        run_ok(&["camellia128-ctr", "-d", "encrypt", "--key", KEY_128, "--iv", nonce], &plaintext);
    assert_eq!(out.len(), plaintext.len(), "ciphertext only, no nonce in band");

    let mut recovered = out.clone();
    library_stream_decrypt::<16, 12, _>(
        &key_object::<16, Camellia128Key<CTR>>(KEY_128),
        &unhex(nonce),
        &mut recovered,
    );
    assert_eq!(recovered, plaintext, "the CLI should agree with the library under that nonce");

    let back = run_ok(&["camellia128-ctr", "-d", "decrypt", "--key", KEY_128, "--iv", nonce], &out);
    assert_eq!(back, plaintext);
}

/// What each command emits must be exactly what `Ctr` over the matching permutation produces.
#[test]
fn the_commands_are_ctr_over_camellia() {
    use bouncycastle::camellia::{Camellia128Key, Camellia192Key, Camellia256Key};
    use bouncycastle::cipher::modes::CTR;

    for len in [1usize, 5, 16, 17, 64] {
        let plaintext = pseudo_random(len, len as u32);

        let out = run_ok(&["camellia128-ctr", "-d", "encrypt", "--key", KEY_128], &plaintext);
        let (nonce, body) = out.split_at(NONCE_LEN);
        let mut recovered = body.to_vec();
        library_stream_decrypt::<16, 12, _>(
            &key_object::<16, Camellia128Key<CTR>>(KEY_128),
            nonce,
            &mut recovered,
        );
        assert_eq!(recovered, plaintext, "camellia128-ctr, len {len}");

        let out = run_ok(&["camellia192-ctr", "-d", "encrypt", "--key", KEY_192], &plaintext);
        let (nonce, body) = out.split_at(NONCE_LEN);
        let mut recovered = body.to_vec();
        library_stream_decrypt::<24, 12, _>(
            &key_object::<24, Camellia192Key<CTR>>(KEY_192),
            nonce,
            &mut recovered,
        );
        assert_eq!(recovered, plaintext, "camellia192-ctr, len {len}");

        let out = run_ok(&["camellia256-ctr", "-d", "encrypt", "--key", KEY_256], &plaintext);
        let (nonce, body) = out.split_at(NONCE_LEN);
        let mut recovered = body.to_vec();
        library_stream_decrypt::<32, 12, _>(
            &key_object::<32, Camellia256Key<CTR>>(KEY_256),
            nonce,
            &mut recovered,
        );
        assert_eq!(recovered, plaintext, "camellia256-ctr, len {len}");
    }
}

/// CTR writes a **12-byte** nonce where the other Camellia modes write a 16-byte IV, so the output
/// is 12 bytes longer than the input rather than 16. Getting this wrong would shift every byte of
/// the payload.
#[test]
fn the_nonce_is_twelve_bytes_not_sixteen() {
    let plaintext = pseudo_random(64, 7);
    let out = run_ok(&["camellia128-ctr", "-d", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(out.len(), plaintext.len() + NONCE_LEN, "a 12-byte nonce plus the ciphertext");

    let via_cfb = run_ok(&["camellia128-cfb", "-d", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(via_cfb.len(), plaintext.len() + 16, "camellia128-cfb writes a 16-byte IV");

    let back = run_ok(&["camellia128-ctr", "-d", "decrypt", "--key", KEY_128], &out);
    assert_eq!(back, plaintext);
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let plaintext = pseudo_random(32, 3);
    let ciphertext = run_ok(&["camellia256-ctr", "-d", "encrypt", "--key", KEY_256], &plaintext);

    let binary = run_ok(&["camellia256-ctr", "-d", "decrypt", "--key", KEY_256], &ciphertext);
    let hex_out =
        run_ok(&["camellia256-ctr", "-d", "decrypt", "--key", KEY_256, "-x"], &ciphertext);
    let hex_str = String::from_utf8(hex_out).expect("hex output is text");

    assert_eq!(hex_str, format!("{}\n", tohex(&binary)));
    assert_eq!(binary, plaintext);
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("camellia128-ctr", KEY16), ("camellia192-ctr", KEY24), ("camellia256-ctr", KEY32)],
        &[],
        Framing { prefix: 12, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("camellia128-ctr", KEY16, &[], Framing { prefix: 12, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("camellia128-ctr", KEY32, "Camellia-128 needs a 16-byte key, got 32 bytes"),
            ("camellia192-ctr", KEY32, "Camellia-192 needs a 24-byte key, got 32 bytes"),
            ("camellia256-ctr", KEY24, "Camellia-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn each_invocation_uses_a_fresh_nonce() {
    fresh_prefix_per_invocation("camellia128-ctr", KEY16, 12);
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["camellia128-ctr", "camellia192-ctr", "camellia256-ctr"]);
}
