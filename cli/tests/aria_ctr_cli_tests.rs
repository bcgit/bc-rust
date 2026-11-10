//! Tests for the `aria128-ctr`, `aria192-ctr` and `aria256-ctr` subcommands.
//!
//! They share their key and nonce loaders, streaming loops and error paths with the `aes*-ctr`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_ctr.sh` covers those
//! exhaustively. This file pins what is specific to ARIA: the known-answer vectors in both
//! directions, the three key lengths, the **12-byte** nonce, and that the commands exist and
//! round-trip at any length.
//!
//! Vectors are the `ARIA-*-CTR` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2),
//! which are KISA's published ARIA test vectors; see `crypto/aria/tests/stream_mode_tests.rs`.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, fresh_prefix_per_invocation, listed_in_help,
    pseudo_random, round_trips, run_ok, tohex, unhex, wrong_key_lengths,
};

/// The nonce the CTR vectors imply: their counter block is all zeros, and these commands split the
/// leading 12 bytes of it off as the nonce, so `--iv` with twelve zero bytes reproduces them.
const NONCE: &str = "000000000000000000000000";

/// The 160-byte plaintext shared by all nine KISA mode vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `ARIA-128-CTR` ciphertext (CTR).
const CT_128: &str = concat!(
    "ac5d7de805a0bf1c57c854501af60fa1",
    "1497e2a34519dea1569e91e5b5ccae2f",
    "f3bfa1bf975f4571f48be191613546c3",
    "911163c085f871f0e7ae5f2a085b8185",
    "1c2a3ddf20ecb8fa51901aec8ee4ba32",
    "a35dab67bb72cd9140ad188a967ac0fb",
    "bdfa94ea6cce47dcf8525ab5a814cfeb",
    "2bb60ee2b126e2d9d847c1a9e96f9019",
    "e3e6a7fe40d3829afb73db1cc245646a",
    "ddb62d9b907baaafbe46a73dbc131d3d",
);

/// `ARIA-192-CTR` ciphertext (CTR).
const CT_192: &str = concat!(
    "08625ca8fe569c19ba7af3760a6ed1ce",
    "f4d199263e999dde14082dbba7560b79",
    "a4c6b456b8707dce751f9854f18893df",
    "db3f4e5afa539733e6f1e70b98ba3789",
    "1f8f81e95df8efc26c7ce043504cb189",
    "58b865e4e316cd2aa1c97f31bf23dc04",
    "6ef326b95a692a191ba0f2a41c5fe9ae",
    "070f236ff7078e703b42666caafbdd20",
    "bad74ac4c20c0f46c7ca24c151716575",
    "c947da16c90cfe1bf217a41cfebe7531",
);

/// `ARIA-256-CTR` ciphertext (CTR).
const CT_256: &str = concat!(
    "30026c329666141721178b99c0a1f1b2",
    "f06940253f7b3089e2a30ea86aa3c88f",
    "5940f05ad7ee41d71347bb7261e348f1",
    "8360473fdf7d4e7723bffb4411cc13f6",
    "cdd89f3bc7b9c768145022c7a74f14d7",
    "c305cd012a10f16050c23f1ae5c23f45",
    "998d13fbaa041e51619577e077276489",
    "6a5d4516d8ffceb3bf7e05f613edd9a6",
    "0cdcedaff9cfcaf4e00d445a54334f73",
    "ab2cad944e51d266548e61c6eb0aa1cd",
);

const VARIANTS: [(&str, &str, &str); 3] = [
    ("aria128-ctr", KEY_128, CT_128),
    ("aria192-ctr", KEY_192, CT_192),
    ("aria256-ctr", KEY_256, CT_256),
];

/// `encrypt --iv` reproduces the KISA ciphertext, and nothing but the ciphertext, for all three
/// key lengths; `decrypt --iv` takes it back.
#[test]
fn encrypt_matches_the_kisa_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let out = run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", NONCE], &unhex(PLAINTEXT));
        assert_eq!(tohex(&out), ct, "{cmd} encrypt --iv should give the ciphertext");

        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key, "--iv", NONCE], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{cmd}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the plaintext when handed the nonce followed by the ciphertext, for
/// all three key lengths.
#[test]
fn decrypt_matches_the_kisa_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{NONCE}{ct}"));
        let out = run_ok(&[cmd, "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let input = unhex(&format!("{NONCE}{CT_256}"));
    let out = run_ok(&["aria256-ctr", "-d", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// CTR writes a **12-byte** nonce where the other ARIA modes write a 16-byte IV, so the output is
/// 12 bytes longer than the input rather than 16. Getting this wrong would shift every byte of the
/// payload.
#[test]
fn the_nonce_is_twelve_bytes_not_sixteen() {
    let plaintext = pseudo_random(64, 7);
    let out = run_ok(&["aria128-ctr", "-d", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(out.len(), plaintext.len() + 12, "a 12-byte nonce plus the ciphertext");

    let via_cfb = run_ok(&["aria128-cfb", "-d", "encrypt", "--key", KEY_128], &plaintext);
    assert_eq!(via_cfb.len(), plaintext.len() + 16, "aria128-cfb writes a 16-byte IV");

    let back = run_ok(&["aria128-ctr", "-d", "decrypt", "--key", KEY_128], &out);
    assert_eq!(back, plaintext);
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("aria128-ctr", KEY16), ("aria192-ctr", KEY24), ("aria256-ctr", KEY32)],
        &[],
        Framing { prefix: 12, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("aria128-ctr", KEY16, &[], Framing { prefix: 12, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("aria128-ctr", KEY32, "ARIA-128 needs a 16-byte key, got 32 bytes"),
            ("aria192-ctr", KEY32, "ARIA-192 needs a 24-byte key, got 32 bytes"),
            ("aria256-ctr", KEY24, "ARIA-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn each_invocation_uses_a_fresh_nonce() {
    fresh_prefix_per_invocation("aria128-ctr", KEY16, 12);
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["aria128-ctr", "aria192-ctr", "aria256-ctr"]);
}
