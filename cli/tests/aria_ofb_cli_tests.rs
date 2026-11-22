//! Tests for the `aria128-ofb`, `aria192-ofb` and `aria256-ofb` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-ofb`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_ofb.sh` covers those
//! exhaustively. This file pins what is specific to ARIA: the known-answer vectors in both
//! directions, the three key lengths, and that the commands exist and round-trip at any length.
//!
//! Vectors are the `ARIA-*-OFB` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2),
//! which are KISA's published ARIA test vectors; see `crypto/symmetric/tests/aria_stream_mode_tests.rs`.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, listed_in_help, round_trips, run_ok, tohex,
    unhex, wrong_key_lengths,
};

/// The IV the CFB128, CFB8 and OFB vectors share -- the same one the CBC vectors use.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The 160-byte plaintext shared by all twelve KISA mode vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `ARIA-128-OFB` ciphertext.
const CT_128: &str = concat!(
    "3720e53ba7d615383406b09f0a05a200",
    "0063063f0560083483faeb041c8adece",
    "f30cf80cefb002a0d280759168ec01db",
    "3d49f61aced260bd43eec0a2731730ee",
    "c6fa4f2304319cf8ccac2d7be7833e4f",
    "8ae6ce967012c1c6badc5d28e7e4144f",
    "6bf5cebe01253ee202afce4bc61f28de",
    "c069a6f16f6c8a7dd2afae44148f6ff4",
    "d0029d5c607b5fa6b8c8a6301cde5c70",
    "33565cd0b8f0974ab490b236197ba04a",
);

/// `ARIA-192-OFB` ciphertext.
const CT_192: &str = concat!(
    "4171f7192bf4495494d2736129640f5c",
    "c224d26d364b5a06ddde13d0f1e74faa",
    "846de354c63cda77469d1a2d425c47ff",
    "41734c71b3fa1fcdc11e0b2de22bfeed",
    "54898e233df652c75ae136e61de6524e",
    "62b3f806fb2e8e616eb410a1b9500537",
    "e327ffb04f19f7f82fde2b122100261f",
    "81b82723bf936be7beaaf3067d1c0360",
    "01f1ade71422268d274d7dc6c6ae1970",
    "b27a5f2c2f39c1d241fe8cac5ccd74e9",
);

/// `ARIA-256-OFB` ciphertext.
const CT_256: &str = concat!(
    "26834705b0f2c0e2588d4a7f09009635",
    "84c256815c4292b59f8d3f966a75b523",
    "45b4f5f98c785d3f368a8d5ff89b7f95",
    "0ceab3cd63773c2621d652b8ef98b419",
    "6afb2c2b30496bc5b7d9e7f9084f9d85",
    "5f63a511751c8909e7a6deadbe0a67a4",
    "fb89383ca5d209c6f66f793fc471195c",
    "476fb9c1eab2ac91e680e454b4f3ed9a",
    "67fb52f09c29b965b23cfa6f3f6bbb2a",
    "86c6cdbaa2857bf2486f543231892a52",
);

const VARIANTS: [(&str, &str, &str); 3] = [
    ("aria128-ofb", KEY_128, CT_128),
    ("aria192-ofb", KEY_192, CT_192),
    ("aria256-ofb", KEY_256, CT_256),
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
    let out = run_ok(&["aria256-ofb", "-d", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("aria128-ofb", KEY16), ("aria192-ofb", KEY24), ("aria256-ofb", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("aria128-ofb", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("aria128-ofb", KEY32, "ARIA-128 needs a 16-byte key, got 32 bytes"),
            ("aria192-ofb", KEY32, "ARIA-192 needs a 24-byte key, got 32 bytes"),
            ("aria256-ofb", KEY24, "ARIA-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["aria128-ofb", "aria192-ofb", "aria256-ofb"]);
}
