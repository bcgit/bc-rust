//! Tests for the `aria128-cfb`, `aria192-cfb` and `aria256-cfb` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-cfb`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_cfb.sh` covers those
//! exhaustively. This file pins what is specific to ARIA: the known-answer vectors in both
//! directions, the three key lengths, and that the commands exist and round-trip at any length.
//!
//! Vectors are the `ARIA-*-CFB` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2),
//! which are KISA's published ARIA test vectors; see `crypto/aria/tests/stream_mode_tests.rs`.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, listed_in_help, round_trips, run_ok, tohex,
    unhex, wrong_key_lengths,
};

/// The IV the CFB128 and CFB8 vectors share -- the same one the CBC vectors use.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The 160-byte plaintext shared by all nine KISA mode vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `ARIA-128-CFB` ciphertext (CFB128).
const CT_128: &str = concat!(
    "3720e53ba7d615383406b09f0a05a200",
    "c07c21e6370f413a5d132500a6828501",
    "7c61b434c7b7ca9685a51071861e4d4b",
    "b873b599b479e2d573dddeafba89f812",
    "ac6a9e44d554078eb3be94839db4b33d",
    "a3f59c063123a7ef6f20e10579fa4fd2",
    "39100ca73b52d4fcafeadee73f139f78",
    "f9b7614c2b3b9dbe010f87db06a89a94",
    "35f79ce8121431371f4e87b984e0230c",
    "22a6dacb32fc42dcc6accef33285bf11",
);

/// `ARIA-192-CFB` ciphertext (CFB128).
const CT_192: &str = concat!(
    "4171f7192bf4495494d2736129640f5c",
    "4d87a9a213664c9448477c6ecc201359",
    "8d9766952dd8c3868f17e36ef66fd84b",
    "fa45d1593d2d6ee3ea2115047d710d4f",
    "b66187caa3a315b3c8ea2d313962edcf",
    "e5a3e2028d5ba9a09fd5c65c19d3440e",
    "477f0cab0628ec6902c73ee02f1afee9",
    "f80115be7b9df82d1e28228e28581a20",
    "560e195cbb9e2b327bf56fd2d0ae5502",
    "e42c13e9b4015d4da42dc859252e7da4",
);

/// `ARIA-256-CFB` ciphertext (CFB128).
const CT_256: &str = concat!(
    "26834705b0f2c0e2588d4a7f09009635",
    "f28bb93d8c31f870ec1e0bdb082b66fa",
    "402dd9c202be300c4517d196b14d4ce1",
    "1dce97f7aaba54341b0d872cc9b63753",
    "a3e8556a14be6f7b3e27e3cfc39caf80",
    "f2a355aa50dc83c09c7b11828694f8e4",
    "aa726c528976b53f2c877f4991a3a8d2",
    "8adb63bd751846ffb2350265e179d499",
    "0753ae8485ff9b4133ddad5875b84a90",
    "cbcfa62a045d726df71b6bda0eeca0be",
);

const VARIANTS: [(&str, &str, &str); 3] = [
    ("aria128-cfb", KEY_128, CT_128),
    ("aria192-cfb", KEY_192, CT_192),
    ("aria256-cfb", KEY_256, CT_256),
];

/// `encrypt --iv` reproduces the KISA ciphertext, and nothing but the ciphertext, for all three
/// key lengths; `decrypt --iv` takes it back.
#[test]
fn encrypt_matches_the_kisa_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let out = run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        assert_eq!(tohex(&out), ct, "{cmd} encrypt --iv should give the ciphertext");

        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key, "--iv", IV], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{cmd}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext, for
/// all three key lengths.
#[test]
fn decrypt_matches_the_kisa_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&[cmd, "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{IV}{CT_256}"));
    let out = run_ok(&["aria256-cfb", "-d", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("aria128-cfb", KEY16), ("aria192-cfb", KEY24), ("aria256-cfb", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("aria128-cfb", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("aria128-cfb", KEY32, "ARIA-128 needs a 16-byte key, got 32 bytes"),
            ("aria192-cfb", KEY32, "ARIA-192 needs a 24-byte key, got 32 bytes"),
            ("aria256-cfb", KEY24, "ARIA-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["aria128-cfb", "aria192-cfb", "aria256-cfb"]);
}
