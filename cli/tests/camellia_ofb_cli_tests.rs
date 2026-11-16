//! Tests for the `camellia128-ofb`, `camellia192-ofb` and `camellia256-ofb` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-ofb`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_ofb.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: the known-answer vectors in both
//! directions, the three key lengths, and that the commands exist and round-trip at any length.
//!
//! Vectors are the `CAMELLIA-*-OFB` entries of OpenSSL's `evpciph_camellia.txt` (OpenSSL 3.6.2):
//! twelve one-block messages, each under its own IV, which do not chain; see
//! `crypto/camellia/tests/stream_mode_tests.rs`.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, listed_in_help, round_trips, run_ok, tohex,
    unhex, wrong_key_lengths,
};

/// `(command, key, [(IV, plaintext, ciphertext); 4])` per key length.
const VECTORS: [(&str, &str, [(&str, &str, &str); 4]); 3] = [
    (
        "camellia128-ofb",
        "2b7e151628aed2a6abf7158809cf4f3c",
        [
            (
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172a",
                "14f7646187817eb586599146b82bd719",
            ),
            (
                "50fe67cc996d32b6da0937e99bafec60",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "25623db569ca51e01482649977e28d84",
            ),
            (
                "d9a4dada0892239f6b8b3d7680e15674",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "c776634a60729dc657d12b9fca801e98",
            ),
            (
                "a78819583f0308e7a6bf36b1386abf23",
                "f69f2445df4f9b17ad2b417be66c3710",
                "d776379be0e50825e681da1a4c980e8e",
            ),
        ],
    ),
    (
        "camellia192-ofb",
        "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
        [
            (
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172a",
                "c832bb9780677daa82d9b6860dcd565e",
            ),
            (
                "a609b38df3b1133dddff2718ba09565e",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "8eceb7d0350d72c7f78562aebdf99339",
            ),
            (
                "52ef01da52602fe0975f78ac84bf8a50",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "bdd62dbbb9700846c53b507f544696f0",
            ),
            (
                "bd5286ac63aabd7eb067ac54b553f71d",
                "f69f2445df4f9b17ad2b417be66c3710",
                "e28014e046b802f385c4c2e13ead4a72",
            ),
        ],
    ),
    (
        "camellia256-ofb",
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        [
            (
                "000102030405060708090a0b0c0d0e0f",
                "6bc1bee22e409f96e93d7e117393172a",
                "cf6107bb0cea7d7fb1bd31f5e7b06c93",
            ),
            (
                "b7bf3a5df43989dd97f0fa97ebce2f4a",
                "ae2d8a571e03ac9c9eb76fac45af8e51",
                "127ad97e8e3994e4820027d7ba109368",
            ),
            (
                "e1c656305ed1a7a6563805746fe03edc",
                "30c81c46a35ce411e5fbc1191a0a52ef",
                "6bff6265a6a6b7a535bc65a80b17214e",
            ),
            (
                "41635be625b48afc1666dd42a09d96e7",
                "f69f2445df4f9b17ad2b417be66c3710",
                "0a4a0404e26aa78a27cb271e8bf3cf20",
            ),
        ],
    ),
];

/// `encrypt --iv` reproduces each entry's ciphertext, and nothing but the ciphertext; `decrypt`
/// takes the IV followed by the ciphertext back to the plaintext.
#[test]
fn every_entry_matches_in_both_directions() {
    for (cmd, key, entries) in VECTORS {
        for (iv, pt, ct) in entries {
            let out = run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", iv], &unhex(pt));
            assert_eq!(tohex(&out), ct, "{cmd} encrypt --iv {iv}");

            let back = run_ok(&[cmd, "-d", "decrypt", "--key", key], &unhex(&format!("{iv}{ct}")));
            assert_eq!(tohex(&back), pt, "{cmd} decrypt, IV {iv}");
        }
    }
}

/// The same with `-x`: identical answer in hex plus a trailing newline.
#[test]
fn hex_output_matches_binary_output() {
    let (cmd, key, entries) = VECTORS[2];
    let (iv, pt, ct) = entries[0];
    let out = run_ok(&[cmd, "-d", "decrypt", "--key", key, "-x"], &unhex(&format!("{iv}{ct}")));
    assert_eq!(String::from_utf8_lossy(&out), format!("{pt}\n"));
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("camellia128-ofb", KEY16), ("camellia192-ofb", KEY24), ("camellia256-ofb", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("camellia128-ofb", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("camellia128-ofb", KEY32, "Camellia-128 needs a 16-byte key, got 32 bytes"),
            ("camellia192-ofb", KEY32, "Camellia-192 needs a 24-byte key, got 32 bytes"),
            ("camellia256-ofb", KEY24, "Camellia-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["camellia128-ofb", "camellia192-ofb", "camellia256-ofb"]);
}
