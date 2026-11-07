//! Tests for the `camellia{128,192,256}-kw` subcommands.
//!
//! They share everything but the key type with the `aes*-kw` commands, whose `test_aes_kw.sh`
//! covers the command-line contract exhaustively. This file pins what is specific to Camellia:
//! a known answer at each key length in both directions, and that the commands exist, fail closed
//! and are listed.
//!
//! The known answers are the first pseudorandom (`Normal`) 32-byte case at each key length of
//! Wycheproof's `camellia_wrap_test.json` (tcId 7, 48, 101); the full set runs in
//! `crypto/camellia/tests/kw_wycheproof.rs`.

mod common;
use common::{listed_in_help, run_err_silent, run_ok, tohex, unhex};

/// `(subcommand, kek, plaintext, ciphertext)`.
const VECTORS: [(&str, &str, &str, &str); 3] = [
    (
        "camellia128-kw",
        "c2b9d23f2831ddcdeb456853d4014db9",
        "f4cfea98e58b939cc859554385cf3a6c7f8217f728efb431c964786de8274907",
        "b66e781a42e0f1ac440d9a9c6ee726cd5303ab52e3aa48f3b970069ed13b43eca328d0abae9cc8c3",
    ),
    (
        "camellia192-kw",
        "1639f9f81e53e2eeb677a249e5eced3af108971301601a7b",
        "ec3c6a1f1a9585327fe658490c74635e5300876da5846a629398984fb551d691",
        "f9b7811aed1727dbb386efdd6a1268239f3034d6a5c219970ca814b8100e418ce62a31f4770c0c2a",
    ),
    (
        "camellia256-kw",
        "38e1b1d075d9d852b9a6c01c8ff6965af01bac457a4e339ae3e1d7b2ffacc0cd",
        "80ad6820f1c90981e2ca42b817a345c1179d0a11d8e23a8adc0505e13d87295a",
        "ce84390d0920ec3d0d15ab8f4c5b3a75253b2403539da6d94fddd2c26d0fb1abe296c188b62b9c15",
    ),
];

#[test]
fn the_wycheproof_answers_in_both_directions() {
    for (cmd, kek, pt, ct) in VECTORS {
        let wrapped = run_ok(&[cmd, "-d", "encrypt", "--key", kek], &unhex(pt));
        assert_eq!(tohex(&wrapped), ct, "{cmd} wrap");
        let hex = run_ok(&[cmd, "-d", "encrypt", "--key", kek, "-x"], &unhex(pt));
        assert_eq!(String::from_utf8_lossy(&hex).trim(), ct, "{cmd} wrap -x");
        let unwrapped = run_ok(&[cmd, "-d", "decrypt", "--key", kek], &unhex(ct));
        assert_eq!(tohex(&unwrapped), pt, "{cmd} unwrap");
    }
}

#[test]
fn a_tampered_ciphertext_and_the_wrong_kek_are_rejected() {
    for (cmd, kek, _, ct) in VECTORS {
        let mut bad = unhex(ct);
        bad[13] ^= 0x01;
        let err = run_err_silent(&[cmd, "-d", "decrypt", "--key", kek], &bad);
        assert!(err.contains("not an authentic"), "{cmd}: {err}");
        let mut wrong = unhex(kek);
        wrong[0] ^= 0x01;
        let err = run_err_silent(&[cmd, "-d", "decrypt", "--key", &tohex(&wrong)], &unhex(ct));
        assert!(err.contains("not an authentic"), "{cmd}: {err}");
    }
}

#[test]
fn unaligned_input_is_refused() {
    let (cmd, kek, _, _) = VECTORS[0];
    let err = run_err_silent(&[cmd, "-d", "encrypt", "--key", kek], &[0x5Au8; 20]);
    assert!(err.contains("20 bytes rejected"), "{err}");
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&["camellia128-kw", "camellia192-kw", "camellia256-kw"]);
}
