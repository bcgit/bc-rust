//! Tests for the `aria128-cbc`, `aria192-cbc` and `aria256-cbc` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-cbc`
//! commands (`cli/src/helpers/block_mode_helpers.rs`), and `test_aes_cbc.sh` covers those
//! exhaustively. This file pins what is specific to ARIA: the known-answer vectors in both
//! directions, the three key lengths, and that the commands exist and round-trip.
//!
//! Vectors are the `ARIA-*-CBC` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2), which
//! are KISA's published ARIA test vectors: a 10-block message under each key length; see
//! `crypto/aria/tests/kisa_vectors_tests.rs`. They are unpadded, so under the commands' PKCS7
//! framing the ten blocks are followed by one block of padding, computed here from the
//! permutation.

mod common;
use bouncycastle::aria::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal};
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, large_payload_on_an_error_path, listed_in_help,
    round_trips, run_err, run_ok, tohex, unhex, wrong_key_lengths,
};

/// The IV shared by the three CBC vectors.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The 160-byte plaintext shared by all three vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const CT_128: &str = "49d61860b14909109cef0d22a9268134fadf9fb23151e9645fba75018bdb1538b53334634bbf7d4cd4b5377033060c155fe3948ca75de1031e1d85619e0ad61eb419a866b3c2dbfd10a4ed18b22149f75897f0b8668b0c1c542c687778835fb7cd46e45f85eaa7072437dd9fa6793d6f8d4ccefc4eb1ac641ac1bd30b18c6d64c49bca137eb21c2e04da62712ca2b4f540c57112c38791852cfac7a5d19ed83a";

const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const CT_192: &str = "afe6cf23974b533c672a826264ea785f4e4f7f780dc7f3f1e0962b80902386d514e9c3e77259de92dd1102ffab086c1ea52a71260db5920a83295c25320e421147ca45d532f327b856ea947cd2196ae2e040826548b4c891b0ed0ca6e714dbc4631998d548110d666b3d54c2a091955c6f05beb4f62309368696c9791fc4c551564a2637f194346ec45fbca6c72a5b4612e208d531d6c34cc5c64eac6bd0cf8c";

const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const CT_256: &str = "523a8a806ae621f155fdd28dbc34e1ab7b9b42432ad8b2efb96e23b13f0a6e52f36185d50ad002c5f601bee5493f118b243ee2e313642bffc3902e7b2efd9a12fa682edd2d23c8b9c5f043c18b17c1ec4b5867918270fbec1027c19ed6af833da5d620994668ca22f599791d292dd6273b2959082aafb7a996167cce1eec5f0cfd15f610d87e2dda9ba68ce1260ca54b222491418374294e7909b1e8551cd8de";

const VARIANTS: [(&str, &str, &str); 3] = [
    ("aria128-cbc", KEY_128, CT_128),
    ("aria192-cbc", KEY_192, CT_192),
    ("aria256-cbc", KEY_256, CT_256),
];

/// The last ciphertext block of a ten-block vector, which the padding block chains from.
fn last_block(ct: &str) -> &str {
    &ct[ct.len() - 32..]
}

/// `encrypt --iv` reproduces the KISA ciphertext followed by the PKCS7 block, for all three key
/// lengths, and `decrypt --iv` takes that back to the plaintext.
#[test]
fn encrypt_matches_the_kisa_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let out = run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        let want = format!("{ct}{}", pkcs7_block(key, last_block(ct)));
        assert_eq!(tohex(&out), want, "{cmd} encrypt --iv should give the ciphertext");

        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key, "--iv", IV], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{cmd}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext and the
/// PKCS7 block, for all three key lengths.
#[test]
fn decrypt_matches_the_kisa_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{IV}{ct}{}", pkcs7_block(key, last_block(ct))));
        let out = run_ok(&[cmd, "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_256}{}", pkcs7_block(KEY_256, last_block(CT_256))));
    let out = run_ok(&["aria256-cbc", "-d", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// A ciphertext without PKCS7 padding is rejected: the bare KISA ciphertext ends in a block that
/// does not unpad.
#[test]
fn a_ciphertext_without_pkcs7_padding_is_rejected() {
    let input = unhex(&format!("{IV}{CT_128}"));
    let err = run_err(&["aria128-cbc", "-d", "decrypt", "--key", KEY_128], &input);
    assert!(err.contains("decryption failed"), "stderr was: {err}");
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("aria128-cbc", KEY16), ("aria192-cbc", KEY24), ("aria256-cbc", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: true },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("aria128-cbc", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: true });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("aria128-cbc", KEY32, "ARIA-128 needs a 16-byte key, got 32 bytes"),
            ("aria192-cbc", KEY32, "ARIA-192 needs a 24-byte key, got 32 bytes"),
            ("aria256-cbc", KEY24, "ARIA-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    large_payload_on_an_error_path("aria128-cbc", KEY32, "ARIA-128 needs a 16-byte key");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["aria128-cbc", "aria192-cbc", "aria256-cbc"]);
}

/// [`common::pkcs7_block`] at the key length `key_hex` has.
fn pkcs7_block(key_hex: &str, prev_hex: &str) -> String {
    match key_hex.len() / 2 {
        16 => common::pkcs7_block::<ARIA128Internal, 16>(key_hex, prev_hex),
        24 => common::pkcs7_block::<ARIA192Internal, 24>(key_hex, prev_hex),
        32 => common::pkcs7_block::<ARIA256Internal, 32>(key_hex, prev_hex),
        _ => panic!("not a ARIA key length"),
    }
}
