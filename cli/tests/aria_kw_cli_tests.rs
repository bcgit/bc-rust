//! Tests for the `aria{128,192,256}-kw` and `aria{128,192,256}-kwp` subcommands.
//!
//! They share everything but the key type with the `aes*-kw` / `aes*-kwp` commands, whose
//! `test_aes_kw.sh` covers the command-line contract exhaustively. This file pins what is
//! specific to ARIA: a known answer at each key length in both directions, for both algorithms,
//! and that the commands exist, fail closed and are listed.
//!
//! The known answers are the first pseudorandom (`Normal`) 32-byte case at each key length of
//! Wycheproof's `aria_wrap_test.json` (tcId 7, 48, 101) and `aria_kwp_test.json` (tcId 7, 82,
//! 165); the full sets run in `crypto/aria/tests/kw_wycheproof.rs`.

mod common;
use common::{listed_in_help, run_err_silent, run_ok, tohex, unhex};

const KEY_128: &str = "c2b9d23f2831ddcdeb456853d4014db9";
const KEY_192: &str = "1639f9f81e53e2eeb677a249e5eced3af108971301601a7b";
const KEY_256: &str = "38e1b1d075d9d852b9a6c01c8ff6965af01bac457a4e339ae3e1d7b2ffacc0cd";
const MSG_128: &str = "f4cfea98e58b939cc859554385cf3a6c7f8217f728efb431c964786de8274907";
const MSG_192: &str = "ec3c6a1f1a9585327fe658490c74635e5300876da5846a629398984fb551d691";
const MSG_256: &str = "80ad6820f1c90981e2ca42b817a345c1179d0a11d8e23a8adc0505e13d87295a";

/// `(subcommand, kek, plaintext, ciphertext)`.
const VECTORS: [(&str, &str, &str, &str); 6] = [
    (
        "aria128-kw",
        KEY_128,
        MSG_128,
        "0f6517209edd77d35c20f76c9399ecd513f3035a395242d65cfa2d2995b1ab0fe1e91de9bd09c6f2",
    ),
    (
        "aria192-kw",
        KEY_192,
        MSG_192,
        "b1a39a86478283b68f7205e6e90602b42b04b3c9cb57e2b3ea59383264b5261386bfdcd6b3c7507c",
    ),
    (
        "aria256-kw",
        KEY_256,
        MSG_256,
        "8decaec941b1711acb9600fa29adb58fb876e3f26b0aa2e2d34dc11ef6bd1573dd8c220eb6c32152",
    ),
    (
        "aria128-kwp",
        KEY_128,
        MSG_128,
        "e3c652b63f6ec63aad4fc55d8ead0ed8ba8fb37fad06078c1b3b1150868c3ea5bfba22ee0b225b8f",
    ),
    (
        "aria192-kwp",
        KEY_192,
        MSG_192,
        "a08ade7a8a922c0fe47df7ec6649365461c69e188b54f801f2446d67b553084235cee692de62bc2f",
    ),
    (
        "aria256-kwp",
        KEY_256,
        MSG_256,
        "794e363ca9295a23ce5a79bd4759e7956d558386d3c6c5808017f015ecb3ea34b4441da22c35a44b",
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
fn kw_refuses_what_kwp_takes() {
    let unaligned = [0x5Au8; 20];
    let err = run_err_silent(&["aria128-kw", "-d", "encrypt", "--key", KEY_128], &unaligned);
    assert!(err.contains("20 bytes rejected"), "{err}");
    let wrapped = run_ok(&["aria128-kwp", "-d", "encrypt", "--key", KEY_128], &unaligned);
    assert_eq!(wrapped.len(), 32, "20 bytes pad to 24, plus the header");
    let back = run_ok(&["aria128-kwp", "-d", "decrypt", "--key", KEY_128], &wrapped);
    assert_eq!(back, unaligned);
}

#[test]
fn the_subcommands_are_listed_in_help() {
    listed_in_help(&[
        "aria128-kw", "aria192-kw", "aria256-kw", "aria128-kwp", "aria192-kwp", "aria256-kwp",
    ]);
}
