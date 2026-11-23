//! Tests for the `aes128-ofb`, `aes192-ofb` and `aes256-ofb` subcommands.
//!
//! `test_aes_ofb.sh` covers the commands' loaders, streaming loops and error paths, but CI does not
//! run the shell suite. This file pins, under `cargo test`, that each command is wired to its key
//! length: the known-answer vectors in both directions, the three key lengths, and that the
//! commands exist and round-trip at any length.
//!
//! Vectors are NIST SP 800-38A Appendix F.4.1, F.4.3 and F.4.5 (OFB-AES128/192/256.Encrypt); see
//! `crypto/symmetric/tests/aes_sp800_38a_ofb_tests.rs`.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, listed_in_help, round_trips, run_ok, tohex,
    unhex, wrong_key_lengths,
};

/// The IV shared by every Appendix F.4 subsection.
const IV: &str = "000102030405060708090a0b0c0d0e0f";

/// The four plaintext blocks shared by every Appendix F subsection.
const PLAINTEXT: &str = concat!(
    "6bc1bee22e409f96e93d7e117393172a",
    "ae2d8a571e03ac9c9eb76fac45af8e51",
    "30c81c46a35ce411e5fbc1191a0a52ef",
    "f69f2445df4f9b17ad2b417be66c3710",
);

const KEY_128: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const KEY_192: &str = "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b";
const KEY_256: &str = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";

/// F.4.1 OFB-AES128.Encrypt ciphertext.
const CT_128: &str = concat!(
    "3b3fd92eb72dad20333449f8e83cfb4a",
    "7789508d16918f03f53c52dac54ed825",
    "9740051e9c5fecf64344f7a82260edcc",
    "304c6528f659c77866a510d9c1d6ae5e",
);

/// F.4.3 OFB-AES192.Encrypt ciphertext.
const CT_192: &str = concat!(
    "cdc80d6fddf18cab34c25909c99a4174",
    "fcc28b8d4c63837c09e81700c1100401",
    "8d9a9aeac0f6596f559c6d4daf59a5f2",
    "6d9f200857ca6c3e9cac524bd9acc92a",
);

/// F.4.5 OFB-AES256.Encrypt ciphertext.
const CT_256: &str = concat!(
    "dc7e84bfda79164b7ecd8486985d3860",
    "4febdc6740d20b3ac88f6ad82a4fb08d",
    "71ab47a086e86eedf39d1c5bba97c408",
    "0126141d67f37be8538f5a8be740e484",
);

const VARIANTS: [(&str, &str, &str); 3] = [
    ("aes128-ofb", KEY_128, CT_128),
    ("aes192-ofb", KEY_192, CT_192),
    ("aes256-ofb", KEY_256, CT_256),
];

/// `encrypt --iv` reproduces the Appendix F.4 ciphertext, and nothing but the ciphertext, for all
/// three key lengths; `decrypt --iv` takes it back.
#[test]
fn encrypt_matches_the_sp800_38a_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let out = run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", IV], &unhex(PLAINTEXT));
        assert_eq!(tohex(&out), ct, "{cmd} encrypt --iv should give the ciphertext");

        let back = run_ok(&[cmd, "-d", "decrypt", "--key", key, "--iv", IV], &out);
        assert_eq!(tohex(&back), PLAINTEXT, "{cmd}: and decrypt --iv takes it back");
    }
}

/// `decrypt` reproduces the plaintext when handed the IV followed by the ciphertext, for all
/// three key lengths.
#[test]
fn decrypt_matches_the_sp800_38a_vectors() {
    for (cmd, key, ct) in VARIANTS {
        let input = unhex(&format!("{IV}{ct}"));
        let out = run_ok(&[cmd, "-d", "decrypt", "--key", key], &input);
        assert_eq!(tohex(&out), PLAINTEXT, "{cmd} decrypt should give the plaintext");
    }
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("aes128-ofb", KEY16), ("aes192-ofb", KEY24), ("aes256-ofb", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("aes128-ofb", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("aes128-ofb", KEY32, "needs a 16-byte key, got 32 bytes"),
            ("aes192-ofb", KEY32, "needs a 24-byte key, got 32 bytes"),
            ("aes256-ofb", KEY24, "needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["aes128-ofb", "aes192-ofb", "aes256-ofb"]);
}
