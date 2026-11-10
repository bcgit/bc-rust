//! Tests for the `camellia128-gcm`, `camellia192-gcm` and `camellia256-gcm` subcommands.
//!
//! They share their key, IV and AAD loaders, streaming loops and error paths with the `aes*-gcm`
//! commands (`cli/src/helpers/aead_cipher_helpers.rs`), and `test_aes_gcm.sh` covers those
//! exhaustively. This file pins what is specific to Camellia: a known answer in both directions
//! at each key length, the three key lengths, the tag check, and that the commands exist and
//! round-trip.
//!
//! No standard or vector suite publishes a Camellia-GCM answer (the crate's `gcm_authors_tests.rs`
//! has the Camellia authors' cases, at 128 and 256 bits), so the known answers here, at all three
//! key lengths, are Bouncy Castle Java's, produced as `gcm_bc_java_tests.rs` describes (bc-java 1.87's
//! `GCMBlockCipher` over `CamelliaEngine`, the RFC 3713 keys, a counting nonce, AAD and message);
//! the generated-nonce output is held to the library's own `Camellia128Key<GCM>` as well.

mod common;
use bouncycastle::camellia::hazmat::Camellia128Internal;
use common::{
    Framing, KEY16, KEY24, KEY32, any_input_length, library_gcm_decrypt, listed_in_help,
    pseudo_random, round_trips, run_err, run_ok, unhex, wrong_key_lengths,
};

const KEY: &str = "28ff3def08179311e2734c6d1c4e2871";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// (command, key, ct, tag) over the shared nonce, AAD and message below, from bc-java 1.87.
const VECTORS: [(&str, &str, &str, &str); 3] = [
    (
        "camellia128-gcm",
        "0123456789abcdeffedcba9876543210",
        "7a49673f1fc95a61bdbd4fd9991e69ce66e11221900db3fe0477c8db0fde7c3f86f9fb95ddcfd29d32fba91dc8",
        "254bc51b6e3af975424eab7b4cf3bd25",
    ),
    (
        "camellia192-gcm",
        "0123456789abcdeffedcba98765432100011223344556677",
        "ed112533b2cfe17a9db68a9c230c10a83cc3abef4991ee76baf0faf8d14bd0c87091ad693bd85a062f022c3fc2",
        "157cb0bc12aed1c6a327cc7d0d7d93ca",
    ),
    (
        "camellia256-gcm",
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "a8f62afcade453f94e2773f6d2318693ea4d48319cd2ee0268ba9bd4c5c88f57b78226b445b5440e3006df2118",
        "e66a02576a8bad35da49a0c073cae837",
    ),
];
const VECTOR_NONCE: &str = "101112131415161718191a1b";
const VECTOR_AAD: &str = "202122232425262728292a2b2c2d2e2f30313233";
const VECTOR_MSG: &str =
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c";

/// `encrypt` under `--iv` reproduces bc-java's ciphertext and tag, as `ciphertext || tag`, and
/// `decrypt` takes them back to the message, at each key length.
#[test]
fn encrypt_and_decrypt_match_the_bc_java_vectors() {
    for (cmd, key, ct, tag) in VECTORS {
        let args = [cmd, "--key", key, "--iv", VECTOR_NONCE, "--aad", VECTOR_AAD];
        let expected = unhex(&format!("{ct}{tag}"));
        let out = run_ok(&[&args[..], &["-d", "encrypt"]].concat(), &unhex(VECTOR_MSG));
        assert_eq!(out, expected, "{cmd}: ciphertext || tag");
        let back = run_ok(&[&args[..], &["-d", "decrypt"]].concat(), &expected);
        assert_eq!(back, unhex(VECTOR_MSG), "{cmd}: decrypt");
    }
}

/// What the command emits must be exactly what the library's `GCM` key produces: the generated
/// nonce leads, the body is as long as the input, and the tag follows.
#[test]
fn the_command_is_gcm_over_camellia() {
    for len in [0usize, 1, 5, 16, 17, 64, 1000] {
        let plaintext = pseudo_random(len, len as u32);
        let out = run_ok(
            &["camellia128-gcm", "-d", "encrypt", "--key", KEY, "--aad", "deadbeef"],
            &plaintext,
        );
        assert_eq!(out.len(), NONCE_LEN + len + TAG_LEN, "len {len}: nonce, body and tag");
        let (nonce, body) = out.split_at(NONCE_LEN);
        let recovered =
            library_gcm_decrypt::<Camellia128Internal, 16>(KEY, nonce, &unhex("deadbeef"), body);
        assert_eq!(recovered, plaintext, "len {len}: the CLI should agree with the library");
        let back =
            run_ok(&["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--aad", "deadbeef"], &out);
        assert_eq!(back, plaintext, "len {len}: round trip");
    }
}

/// A flipped ciphertext bit, a flipped tag bit, other AAD or another key fails the tag check.
#[test]
fn tampering_fails_the_tag_check() {
    let plaintext = pseudo_random(69, 9);
    let iv = "32bcb9b569e3b852d37c766a";
    let args = ["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--iv", iv, "--aad", "c3"];
    let mut ct = run_ok(
        &["camellia128-gcm", "-d", "encrypt", "--key", KEY, "--iv", iv, "--aad", "c3"],
        &plaintext,
    );
    assert_eq!(run_ok(&args, &ct), plaintext);
    ct[0] ^= 1;
    assert!(run_err(&args, &ct).contains("authentication failed"));
    ct[0] ^= 1;
    let last = ct.len() - 1;
    ct[last] ^= 1;
    assert!(run_err(&args, &ct).contains("authentication failed"));
    ct[last] ^= 1;
    let other_aad = ["camellia128-gcm", "-d", "decrypt", "--key", KEY, "--iv", iv, "--aad", "c4"];
    assert!(run_err(&other_aad, &ct).contains("authentication failed"));
    let other_key = [
        "camellia128-gcm",
        "-d",
        "decrypt",
        "--key",
        "28ff3def08179311e2734c6d1c4e2870",
        "--iv",
        iv,
        "--aad",
        "c3",
    ];
    assert!(run_err(&other_key, &ct).contains("authentication failed"));
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    round_trips(
        &[("camellia128-gcm", KEY16), ("camellia192-gcm", KEY24), ("camellia256-gcm", KEY32)],
        &[],
        Framing { prefix: 12, suffix: 16, pads: false },
    );
}

#[test]
fn any_input_length_is_accepted() {
    any_input_length(
        "camellia128-gcm",
        KEY16,
        &[],
        Framing { prefix: 12, suffix: 16, pads: false },
    );
}

#[test]
fn a_key_of_the_wrong_length_is_rejected() {
    wrong_key_lengths(
        &[
            ("camellia128-gcm", KEY32, "Camellia-128 needs a 16-byte key, got 32 bytes"),
            ("camellia192-gcm", KEY32, "Camellia-192 needs a 24-byte key, got 32 bytes"),
            ("camellia256-gcm", KEY24, "Camellia-256 needs a 32-byte key, got 24 bytes"),
        ],
        &[],
    );
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["camellia128-gcm", "camellia192-gcm", "camellia256-gcm"]);
}
