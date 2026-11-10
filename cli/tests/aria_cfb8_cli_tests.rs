//! Tests for the `aria128-cfb8`, `aria192-cfb8` and `aria256-cfb8` subcommands.
//!
//! They share their key and IV loaders, streaming loops and error paths with the `aes*-cfb8`
//! commands (`cli/src/helpers/stream_mode_helpers.rs`), and `test_aes_cfb8.sh` covers those
//! exhaustively. This file pins what is specific to ARIA: the known-answer vectors in both
//! directions, the three key lengths, and that the commands exist and round-trip at any length.
//!
//! Vectors are the `ARIA-*-CFB8` entries of OpenSSL's `evpciph_aria.txt` (OpenSSL 3.6.2),
//! which are KISA's published ARIA test vectors; see `crypto/aria/tests/stream_mode_tests.rs`.

mod common;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, large_payload_on_an_error_path, listed_in_help,
    round_trips, run_ok, tohex, unhex, wrong_key_lengths,
};

/// The IV the CFB128 and CFB8 vectors share -- the same one the CBC vectors use.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The 160-byte plaintext shared by all nine KISA mode vectors.
const PLAINTEXT: &str = "11111111aaaaaaaa11111111bbbbbbbb11111111cccccccc11111111dddddddd22222222aaaaaaaa22222222bbbbbbbb22222222cccccccc22222222dddddddd33333333aaaaaaaa33333333bbbbbbbb33333333cccccccc33333333dddddddd44444444aaaaaaaa44444444bbbbbbbb44444444cccccccc44444444dddddddd55555555aaaaaaaa55555555bbbbbbbb55555555cccccccc55555555dddddddd";

const KEY_128: &str = "00112233445566778899aabbccddeeff";
const KEY_192: &str = "00112233445566778899aabbccddeeff0011223344556677";
const KEY_256: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// `ARIA-128-CFB8` ciphertext (CFB8).
const CT_128: &str = concat!(
    "373c8f6a965599ec785cc8f8149f6c81",
    "b632ccb8e0c6eb6a9707ae52c59257a4",
    "1f94701c1096933127a90195ed0c8e98",
    "690547572423bb45c3d70e4a18ee56b9",
    "67c10e000ba4df5fba7c404134a343d8",
    "375d04b151d161ef83417fe1748447d3",
    "0a6723c406733df7d18aa39a20752d23",
    "81942e244811bb97f72eae446b1815aa",
    "690cd1b1adcbd007c0088ecdc91cb2e2",
    "caf0e11e72459878137eea64ac62a9a1",
);

/// `ARIA-192-CFB8` ciphertext (CFB8).
const CT_192: &str = concat!(
    "411d3b4f57f705aa4d13c46e2cf426af",
    "7c8c916ed7923d889f0047bbf11471b6",
    "d54f8757ef519339105be3cb69babb97",
    "6a57d5631fc23cc3051fe9d36e8b8e27",
    "a2b2c0c4d31928ccbf30ea8239b46ba1",
    "b77f6198e7ecd2ce27b35958148e826f",
    "06aaf385bd30362ff141583e7c1d8924",
    "d44d36a1133094074631e18adafa9d2e",
    "55de98f6895c89d4266ebd33f3d4be51",
    "53a96fa12132ece2e81e66e55baa7ade",
);

/// `ARIA-256-CFB8` ciphertext (CFB8).
const CT_256: &str = concat!(
    "26baa33651e1f66434fec88ef27fd2b9",
    "a79e246dd89a3ffa00e8bdb37155433e",
    "6c24bd0b87d9a85baa9f485ccb984f5e",
    "c24d6a3ef5e3c81396177f039cf580df",
    "db55d6e1c47a28921dfe369e12fd357b",
    "289ad3a5544e1c1bd616d454db9c5f91",
    "f603373f29d5b2ed1b4b51de80f28537",
    "bbd43d5e3b5dd071dc91153cbbe732df",
    "c325821b06ed8acaae656dcf2da9f13e",
    "4f29db671476f1e644ff06d9b67d6bd4",
);

const VARIANTS: [(&str, &str, &str); 3] = [
    ("aria128-cfb8", KEY_128, CT_128),
    ("aria192-cfb8", KEY_192, CT_192),
    ("aria256-cfb8", KEY_256, CT_256),
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
    let out = run_ok(&["aria256-cfb8", "-d", "decrypt", "--key", KEY_256, "-x"], &input);
    assert_eq!(String::from_utf8_lossy(&out), format!("{PLAINTEXT}\n"));
}

/// CFB8 and CFB128 are different modes, and `aria128-cfb8` must not be a second name for
/// `aria128-cfb`: handed the same IV and ciphertext, the two commands disagree past the first
/// byte.
#[test]
fn cfb8_is_not_cfb() {
    let input = unhex(&format!("{IV}{}", &CT_128[..64]));

    let as_cfb8 = run_ok(&["aria128-cfb8", "-d", "decrypt", "--key", KEY_128], &input);
    let as_cfb = run_ok(&["aria128-cfb", "-d", "decrypt", "--key", KEY_128], &input);

    assert_eq!(
        as_cfb8[0], as_cfb[0],
        "both XOR the first byte with MSB_8 of the same output block"
    );
    assert_ne!(as_cfb8[1..], as_cfb[1..], "and they diverge from the second byte on");
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("aria128-cfb8", KEY16), ("aria192-cfb8", KEY24), ("aria256-cfb8", KEY32)],
        &[],
        Framing { prefix: 16, suffix: 0, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length("aria128-cfb8", KEY16, &[], Framing { prefix: 16, suffix: 0, pads: false });
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("aria128-cfb8", KEY32, "ARIA-128 needs a 16-byte key, got 32 bytes"),
            ("aria192-cfb8", KEY32, "ARIA-192 needs a 24-byte key, got 32 bytes"),
            ("aria256-cfb8", KEY24, "ARIA-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn a_large_payload_on_an_error_path_does_not_break_the_harness() {
    large_payload_on_an_error_path("aria128-cfb8", KEY32, "ARIA-128 needs a 16-byte key");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["aria128-cfb8", "aria192-cfb8", "aria256-cfb8"]);
}
