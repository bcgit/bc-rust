//! Tests for the `camellia128-cfb`, `camellia192-cfb` and `camellia256-cfb` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-cfb`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_cfb.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: the known-answer vectors in both
//! directions, the three key lengths, and that the commands exist and round-trip at any length.
//!
//! Vectors are the `CAMELLIA-*-CFB` entries of OpenSSL's `evpciph_camellia.txt` (OpenSSL 3.6.2):
//! for each key length the four entries chain into one four-block CFB128 message under the IV
//! `000102..0f`; see `crypto/camellia/tests/stream_mode_tests.rs`.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, listed_in_help, round_trips, run_ok, tohex,
    unhex, wrong_key_lengths,
};

/// The IV of the first entry of every chain.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four chained plaintext blocks (SP 800-38A Appendix F's).
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

const CT_128: &str = concat!(
    "14f7646187817eb586599146b82bd719",
    "a53d28bb82df741103ea4f921a44880b",
    "9c2157a664626d1def9ea420fde69b96",
    "742a25f0542340c7baef24ca8482bb09",
);
const CT_192: &str = concat!(
    "c832bb9780677daa82d9b6860dcd565e",
    "86f8491627906d780c7a6d46ea331f98",
    "69511cce594cf710cb98bb63d7221f01",
    "d5b5378a3abed55803f25565d8907b84",
);
const CT_256: &str = concat!(
    "cf6107bb0cea7d7fb1bd31f5e7b06c93",
    "89bedb4ccdd864ea11ba4cbe849b5e2b",
    "555fc3f34bdd2d54c62d9e3bf338c1c4",
    "5953adce14db8c7f39f1bd39f359bffa",
);

const VARIANTS: [(&str, &str, &str); 3] = [
    ("camellia128-cfb", KEY_128, CT_128),
    ("camellia192-cfb", KEY_192, CT_192),
    ("camellia256-cfb", KEY_256, CT_256),
];

/// `encrypt --iv` reproduces the OpenSSL ciphertext, and nothing but the ciphertext, for all
/// three key lengths; `decrypt --iv` takes it back.
#[test]
fn encrypt_matches_the_openssl_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let out = run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        assert_eq!(tohex(&out), ct, "{cmd} encrypt --iv should give the ciphertext");

        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key, "--iv", IV], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{cmd}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext, for all three
/// key lengths.
#[test]
fn decrypt_matches_the_openssl_vectors() {
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
    let out = run_ok(&["camellia256-cfb", "-d", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("camellia128-cfb", KEY16), ("camellia192-cfb", KEY24), ("camellia256-cfb", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("camellia128-cfb", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("camellia128-cfb", KEY32, "Camellia-128 needs a 16-byte key, got 32 bytes"),
            ("camellia192-cfb", KEY32, "Camellia-192 needs a 24-byte key, got 32 bytes"),
            ("camellia256-cfb", KEY24, "Camellia-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["camellia128-cfb", "camellia192-cfb", "camellia256-cfb"]);
}
