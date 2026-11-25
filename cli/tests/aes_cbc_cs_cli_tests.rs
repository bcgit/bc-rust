//! Tests for the `aes{128,192,256}-cbc-cs{1,2,3}` subcommands and their `aes*-cts` aliases.
//!
//! They share their key and IV loaders and streaming loops with the `aes*-cbc` commands
//! (`cli/src/helpers/block_mode_helpers.rs`), which `test_aes_cbc.sh` covers. This file pins what is
//! CBC-CS's: the known answers in both directions, CTS as CBC-CS3, the unpadded framing at lengths
//! across the loops' 1 KiB reads, the refusal of input shorter than a block, and that the commands
//! exist and round-trip at every key length.
//!
//! The known answers are RFC 3962 Appendix B's AES-128 vectors, which are CBC-CS3's and so CTS's,
//! and, for each command, the library's ciphertext under the same supplied IV, which the
//! `crypto/symmetric/tests/aes_cbc_cs_*` suites pin to the NIST ACVP vectors and to bc-fips.

mod common;
use bouncycastle::core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
use bouncycastle::symmetric::aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle::symmetric::modes::{CBC_CS_FINAL_LEN, CBC_CS1, CBC_CS2, CBC_CS3};
use common::{
    Framing, KEY16, KEY24, KEY32, key_object, listed_in_help, pseudo_random, round_trips, run,
    run_ok, tohex, unhex, wrong_key_lengths,
};

/// The IV of every RFC 3962 vector.
const ZERO_IV: &str = "00000000000000000000000000000000";

/// The AES-128 key of every RFC 3962 vector, "chicken teriyaki".
const RFC_KEY: &str = "636869636b656e207465726979616b69";

/// (Input, Output), RFC 3962 Appendix B.
const RFC3962: [(&str, &str); 6] = [
    ("4920776f756c64206c696b652074686520", "c6353568f2bf8cb4d8a580362da7ff7f97"),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320",
        "fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c2047617527732043",
        "39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c",
        "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20",
        "97687268d6ecccc0c07b25e25ecfe5849dad8bbb96c4cdc03bc103e1a194bbd839312523a78662d5be7fcbcc98ebf5a8",
    ),
    (
        "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e",
        "97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8",
    ),
];

/// Every command with a key of its length.
const COMMANDS: [(&str, &str); 12] = [
    ("aes128-cbc-cs1", KEY16),
    ("aes128-cbc-cs2", KEY16),
    ("aes128-cbc-cs3", KEY16),
    ("aes128-cts", KEY16),
    ("aes192-cbc-cs1", KEY24),
    ("aes192-cbc-cs2", KEY24),
    ("aes192-cbc-cs3", KEY24),
    ("aes192-cts", KEY24),
    ("aes256-cbc-cs1", KEY32),
    ("aes256-cbc-cs2", KEY32),
    ("aes256-cbc-cs3", KEY32),
    ("aes256-cts", KEY32),
];

/// The IV the supplied-IV checks run under.
const IV: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f0";

/// The unpadded framing: a drawn IV ahead of a body exactly as long as the plaintext.
const FRAMING: Framing = Framing { prefix: 16, suffix: 0, pads: false };

fn encrypt_with_iv(cmd: &str, key: &str, iv: &str, plaintext: &[u8]) -> Vec<u8> {
    run_ok(&[cmd, "-d", "encrypt", "--key", key, "--iv", iv], plaintext)
}

fn decrypt_with_iv(cmd: &str, key: &str, iv: &str, ciphertext: &[u8]) -> Vec<u8> {
    run_ok(&[cmd, "-d", "decrypt", "--key", key, "--iv", iv], ciphertext)
}

/// The library's ciphertext of `plaintext` under the key type `K`, the hex key and [`IV`].
fn library<K, const KEY_LEN: usize>(key: &str, plaintext: &[u8]) -> Vec<u8>
where
    K: FromKeyMaterial<KEY_LEN> + SymmetricEncryptionKey<KEY_LEN, 16, CBC_CS_FINAL_LEN>,
{
    let iv: [u8; 16] = unhex(IV).try_into().unwrap();
    key_object::<KEY_LEN, K>(key).encrypt_nonce(&iv, plaintext).unwrap()
}

/// `aes128-cts` and `aes128-cbc-cs3` reproduce RFC 3962 Appendix B with `--iv`, and take each
/// ciphertext back to its plaintext.
#[test]
fn cts_matches_rfc_3962() {
    for cmd in ["aes128-cts", "aes128-cbc-cs3"] {
        for (pt, ct) in RFC3962 {
            let (pt, ct) = (unhex(pt), unhex(ct));
            assert_eq!(tohex(&encrypt_with_iv(cmd, RFC_KEY, ZERO_IV, &pt)), tohex(&ct), "{cmd}");
            assert_eq!(decrypt_with_iv(cmd, RFC_KEY, ZERO_IV, &ct), pt, "{cmd}");
        }
    }
}

/// Each command gives the library's ciphertext for its variant and key length under a supplied
/// IV, and the CTS commands CBC-CS3's.
#[test]
fn each_command_matches_the_library() {
    let pt = pseudo_random(100, 7);
    let expected = [
        library::<AES128Key<CBC_CS1>, 16>(KEY16, &pt),
        library::<AES128Key<CBC_CS2>, 16>(KEY16, &pt),
        library::<AES128Key<CBC_CS3>, 16>(KEY16, &pt),
        library::<AES128Key<CBC_CS3>, 16>(KEY16, &pt),
        library::<AES192Key<CBC_CS1>, 24>(KEY24, &pt),
        library::<AES192Key<CBC_CS2>, 24>(KEY24, &pt),
        library::<AES192Key<CBC_CS3>, 24>(KEY24, &pt),
        library::<AES192Key<CBC_CS3>, 24>(KEY24, &pt),
        library::<AES256Key<CBC_CS1>, 32>(KEY32, &pt),
        library::<AES256Key<CBC_CS2>, 32>(KEY32, &pt),
        library::<AES256Key<CBC_CS3>, 32>(KEY32, &pt),
        library::<AES256Key<CBC_CS3>, 32>(KEY32, &pt),
    ];
    for ((cmd, key), expected) in COMMANDS.iter().zip(expected) {
        let ct = encrypt_with_iv(cmd, key, IV, &pt);
        assert_eq!(tohex(&ct), tohex(&expected), "{cmd}");
        assert_eq!(decrypt_with_iv(cmd, key, IV, &ct), pt, "{cmd}");
    }
}

/// With the IV drawn, every command composes `encrypt | decrypt`, writes the IV and a body as long
/// as the plaintext, and draws a fresh IV each time.
#[test]
fn every_command_round_trips() {
    round_trips(&COMMANDS, &[], FRAMING);
}

/// From one block up, every length round-trips unpadded, including lengths either side of the
/// 1 KiB the commands read at a time.
#[test]
fn every_length_from_one_block_round_trips_unpadded() {
    for (cmd, key) in [("aes128-cbc-cs1", KEY16), ("aes192-cbc-cs2", KEY24), ("aes256-cts", KEY32)]
    {
        for len in [16usize, 17, 31, 32, 33, 47, 48, 49, 1023, 1024, 1025, 1040, 1041, 2049] {
            let pt = pseudo_random(len, len as u32);
            let ct = run_ok(&[cmd, "-d", "encrypt", "--key", key], &pt);
            assert_eq!(ct.len(), FRAMING.output_len(len), "{cmd}, {len} bytes: framing");
            assert_eq!(run_ok(&[cmd, "-d", "decrypt", "--key", key], &ct), pt, "{cmd}, {len}");
        }
    }
}

/// Less than one block is refused in both directions, with an error exit and the library's error.
#[test]
fn less_than_one_block_is_refused() {
    for (cmd, key) in [("aes128-cbc-cs1", KEY16), ("aes192-cbc-cs2", KEY24), ("aes256-cts", KEY32)]
    {
        for len in [0usize, 1, 15] {
            let short = pseudo_random(len, 3);
            for (direction, input) in [("encrypt", short.clone()), ("decrypt", short.clone())] {
                let out = run(&[cmd, "-d", direction, "--key", key, "--iv", IV], &input);
                let stderr = String::from_utf8_lossy(&out.stderr);
                assert!(!out.status.success(), "{cmd} {direction}, {len} bytes must fail");
                assert!(stderr.contains("InvalidInputLength"), "{cmd} {direction}: {stderr}");
            }
        }
    }
}

#[test]
fn wrong_key_lengths_are_refused() {
    wrong_key_lengths(
        &[
            ("aes128-cbc-cs1", KEY24, "AES-128 needs a 16-byte key"),
            ("aes192-cbc-cs2", KEY16, "AES-192 needs a 24-byte key"),
            ("aes256-cbc-cs3", KEY16, "AES-256 needs a 32-byte key"),
            ("aes256-cts", KEY24, "AES-256 needs a 32-byte key"),
        ],
        &[],
    );
}

#[test]
fn the_commands_are_listed_in_help() {
    listed_in_help(&COMMANDS.map(|(cmd, _)| cmd));
}
