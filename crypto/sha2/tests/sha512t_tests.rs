//! SHA-512/t (FIPS 180-4 s. 5.3.6) across the whole range of `t`, not just the two approved
//! truncations.
//!
//! `SHA512t<T>` is instantiable for every `t` the standard defines a hash for -- any positive
//! multiple of 8 below 512 other than 384 -- so the IV Generation Function's decimal formatting of
//! `t` now has three reachable branches ("SHA-512/8", "SHA-512/96", "SHA-512/224") where it
//! previously only ever saw three-digit values. These tests cover all three.
//!
//! # Where the expected values come from
//!
//! FIPS 180-4 publishes H(0) for t = 224 and t = 256 only (s. 5.3.6.1 / s. 5.3.6.2, pinned by
//! `sha512t_h0_tests.rs`) and no digests at all for any other truncation. The known-answer
//! values below were therefore generated with BC Java's `org.bouncycastle.crypto.digests
//! .SHA512tDigest`, an independent implementation of the same section, over the FIPS 180-4
//! Appendix C sample messages. The two approved truncations are in the table as well, so a change
//! that broke the cross-check would have to break it consistently with the NIST-published values
//! for t = 224 and t = 256 to go unnoticed.
//!
//! A wrong H(0) for a given t changes every digest for that t, so these digests pin the IV
//! Generation Function -- including which decimal branch it took -- as well as the truncation.

use bouncycastle_core::traits::{Algorithm, Hash, HashAlgParams, SecurityStrength};
use bouncycastle_sha2::{SHA512_224, SHA512_224_NAME, SHA512_256, SHA512_256_NAME, SHA512t};

// The generic name and output length must keep reproducing exactly what the two approved
// truncations had when they were spelled out by hand. These hold at compile time, so a regression
// fails the build of this test crate rather than a test in it; `alg_name_spells_t_in_decimal` and
// `output_len_is_t_over_eight` below are the runtime half that `cargo mutants` can see fail.
const _: () = assert!(matches!(<SHA512_224 as Algorithm>::ALG_NAME.as_bytes(), b"SHA512/224"));
const _: () = assert!(matches!(<SHA512_256 as Algorithm>::ALG_NAME.as_bytes(), b"SHA512/256"));
const _: () = assert!(matches!(SHA512_224_NAME.as_bytes(), b"SHA512/224"));
const _: () = assert!(matches!(SHA512_256_NAME.as_bytes(), b"SHA512/256"));
const _: () = assert!(<SHA512_224 as HashAlgParams>::OUTPUT_LEN == 28);
const _: () = assert!(<SHA512_256 as HashAlgParams>::OUTPUT_LEN == 32);

/// FIPS 180-4 Appendix C.1 / C.2 sample message.
const ABC: &[u8] = b"abc";
/// FIPS 180-4 Appendix C.3 sample message (two-block).
const TWO_BLOCK: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

fn from_hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "hex string must have an even length");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// Drives one `SHA512t<T>` through the whole [`Hash`] surface and checks every route agrees with
/// `expected_hex`. `construct` builds a fresh instance for each route.
fn check<H: Hash + HashAlgParams + Algorithm>(
    construct: impl Fn() -> H,
    input: &[u8],
    expected_hex: &str,
) {
    let expected = from_hex(expected_hex);
    assert_eq!(
        expected.len(),
        H::OUTPUT_LEN,
        "{}: the expected value is {} bytes but OUTPUT_LEN is {}",
        H::ALG_NAME,
        expected.len(),
        H::OUTPUT_LEN
    );

    /*** fn hash(self, data: &[u8]) -> Vec<u8> ***/
    assert_eq!(construct().hash(input), expected, "{}: hash()", H::ALG_NAME);

    /*** fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize ***/
    let mut out = vec![0u8; H::OUTPUT_LEN];
    assert_eq!(construct().hash_out(input, &mut out), H::OUTPUT_LEN, "{}: hash_out()", H::ALG_NAME);
    assert_eq!(out, expected, "{}: hash_out()", H::ALG_NAME);

    /*** streaming in one do_update, then do_final() ***/
    let mut h = construct();
    h.do_update(input);
    assert_eq!(h.do_final(), expected, "{}: do_update + do_final", H::ALG_NAME);

    /*** streaming in one do_update, then do_final_out() ***/
    let mut h = construct();
    h.do_update(input);
    let mut out = vec![0u8; H::OUTPUT_LEN];
    assert_eq!(h.do_final_out(&mut out), H::OUTPUT_LEN, "{}: do_final_out", H::ALG_NAME);
    assert_eq!(out, expected, "{}: do_final_out", H::ALG_NAME);

    /*** chunked absorb must equal one-shot, at chunk sizes either side of the 128-byte block ***/
    for chunk_len in [1usize, 7, 64, 127, 128, 129] {
        let mut h = construct();
        for chunk in input.chunks(chunk_len) {
            h.do_update(chunk);
        }
        assert_eq!(
            h.do_final(),
            expected,
            "{}: absorbing in {chunk_len}-byte chunks must equal the one-shot",
            H::ALG_NAME
        );
    }
}

/// BC Java `SHA512tDigest` cross-check, for the truncations FIPS 180-4 publishes no values for.
///
/// The `t` values span all three decimal branches of the IV Generation Function's "SHA-512/t"
/// string: one digit (8), two digits (16, 24, 88, 96) and three (104, 264, 504).
macro_rules! sha512t_kat {
    ($name:ident, $t:literal, $empty:literal, $abc:literal, $two_block:literal) => {
        #[test]
        fn $name() {
            check(SHA512t::<$t>::new, b"", $empty);
            check(SHA512t::<$t>::new, ABC, $abc);
            check(SHA512t::<$t>::new, TWO_BLOCK, $two_block);
        }
    };
}

sha512t_kat!(sha512_t8, 8, "79", "c5", "8d");
sha512t_kat!(sha512_t16, 16, "b44e", "1768", "e8d7");
sha512t_kat!(sha512_t24, 24, "2f8a89", "1e17ce", "765639");
sha512t_kat!(
    sha512_t88, 88, "f0a49fbe063fd7fba2bf3b", "8194668ea596265aef4ef5", "c040324022ed56c0badf79"
);
sha512t_kat!(
    sha512_t96,
    96,
    "44ab9c7c3eb2da370d2c0ed7",
    "67246fd8d90dca7009449ad5",
    "c75100023425182c76253d0a"
);
sha512t_kat!(
    sha512_t104,
    104,
    "47f922a2d2508feb288af79a30",
    "456045a75a5d7e0ea4af09dfce",
    "64fc045733525b8c29376fc6be"
);
sha512t_kat!(
    sha512_t264,
    264,
    "78180c9a54d1c1f5bd3b941cfec4ee2cded5663ed7bf535ecd964518515174db49",
    "888cfb35a25f524f8d17a1bb97134a9a6850b0ff269f1eb26ae038c22cd47f4c58",
    "873b4bd852e7e441c406e49b1caa88f76bfc4b95d373f783350398db4b4a3e5909"
);
sha512t_kat!(
    sha512_t504,
    504,
    "6c46fed4cb277417c5f2d88b19a88a9a010e9e81a24d4a38d818c84a1aa3b88dd115f9550869eb097001fe0e8315b1d6f04124215f095e0be7ca94f99cdc6a",
    "8c43e4bf1cad93067af1ad632ba38bba0b5673bf0129f01a469224c2d981b8ecaa301facf8e392f97efc5997885a1c90cefba70d81892f40267df4fd6fef9a",
    "9f4bd94b6620e1ec80a9d4cfa315ee73f6228ee7f8fc8f58f232cc117c58633936b2df04f2cef341aae4f92f68c53223c1a631f5b6eb597c6933e0fc5f3f1a"
);

/// The two approved truncations must keep producing exactly what they did before `SHA512t` became
/// generic. These are the published SHA-512/224 and SHA-512/256 values, and they agree with the
/// same BC Java run that produced the table above.
#[test]
fn approved_truncations_are_unchanged() {
    check(SHA512_224::new, b"", "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    check(SHA512_224::new, ABC, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    check(SHA512_224::new, TWO_BLOCK, "e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174");

    check(SHA512_256::new, b"", "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
    check(SHA512_256::new, ABC, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    check(
        SHA512_256::new,
        TWO_BLOCK,
        "bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461",
    );
}

/// `SHA512t<224>` / `SHA512t<256>` and the named aliases are the same type, so the alias cannot
/// drift away from the generic parameter set.
#[test]
fn the_named_aliases_are_the_generic_type() {
    fn same_type<T>(_: &T, _: &T) {}
    same_type(&SHA512_224::new(), &SHA512t::<224>::new());
    same_type(&SHA512_256::new(), &SHA512t::<256>::new());
}

/// A message spanning many blocks, to catch a `t` whose IV is right but whose multi-block path is
/// not. FIPS 180-4 Appendix C uses one million 'a' for exactly this.
#[test]
fn one_million_a() {
    let million = vec![b'a'; 1_000_000];
    check(SHA512t::<8>::new, &million, "32");
    check(SHA512t::<96>::new, &million, "0e1f626963a870088bab77da");
    check(SHA512_224::new, &million, "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287");
    check(
        SHA512_256::new,
        &million,
        "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21",
    );
    check(
        SHA512t::<504>::new,
        &million,
        "f94e0eb099411d073274d87a908531ce7faa8591b28f56d86694e056ab0477f03af082453f5f44ec75c67ac58843fedd44429b0aa3322277b32b04e8a0586c",
    );
}

/// The algorithm name is built from `T` at compile time; check every digit count, and that the two
/// approved truncations still spell themselves the way the crate's name constants do.
#[test]
fn alg_name_spells_t_in_decimal() {
    assert_eq!(<SHA512t<8> as Algorithm>::ALG_NAME, "SHA512/8");
    assert_eq!(<SHA512t<16> as Algorithm>::ALG_NAME, "SHA512/16");
    assert_eq!(<SHA512t<96> as Algorithm>::ALG_NAME, "SHA512/96");
    assert_eq!(<SHA512t<104> as Algorithm>::ALG_NAME, "SHA512/104");
    assert_eq!(<SHA512t<224> as Algorithm>::ALG_NAME, "SHA512/224");
    assert_eq!(<SHA512t<256> as Algorithm>::ALG_NAME, "SHA512/256");
    assert_eq!(<SHA512t<504> as Algorithm>::ALG_NAME, "SHA512/504");

    assert_eq!(<SHA512t<224> as Algorithm>::ALG_NAME, bouncycastle_sha2::SHA512_224_NAME);
    assert_eq!(<SHA512t<256> as Algorithm>::ALG_NAME, bouncycastle_sha2::SHA512_256_NAME);

    // No leading zero and no trailing NUL from the fixed-size buffer the name is built in.
    for name in [
        <SHA512t<8> as Algorithm>::ALG_NAME,
        <SHA512t<16> as Algorithm>::ALG_NAME,
        <SHA512t<504> as Algorithm>::ALG_NAME,
    ] {
        let digits = name.strip_prefix("SHA512/").expect("name starts with SHA512/");
        assert!(digits.bytes().all(|b| b.is_ascii_digit()), "{name}: digits only");
        assert!(!digits.starts_with('0'), "{name}: FIPS 180-4 s. 5.3.6 forbids a leading zero");
    }
}

/// `OUTPUT_LEN` is `T / 8`, exactly, for every accepted `T`.
#[test]
fn output_len_is_t_over_eight() {
    assert_eq!(<SHA512t<8> as HashAlgParams>::OUTPUT_LEN, 1);
    assert_eq!(<SHA512t<96> as HashAlgParams>::OUTPUT_LEN, 12);
    assert_eq!(<SHA512t<224> as HashAlgParams>::OUTPUT_LEN, 28);
    assert_eq!(<SHA512t<256> as HashAlgParams>::OUTPUT_LEN, 32);
    assert_eq!(<SHA512t<504> as HashAlgParams>::OUTPUT_LEN, 63);

    // BLOCK_LEN does not vary with t: FIPS 180-4 Figure 1, block size 1024 bits.
    assert_eq!(<SHA512t<8> as HashAlgParams>::BLOCK_LEN, 128);
    assert_eq!(<SHA512t<504> as HashAlgParams>::BLOCK_LEN, 128);
    assert_eq!(SHA512t::<8>::new().block_bitlen(), 1024);
}

/// Collision resistance is t/2 bits, rounded down to a modelled level, and the two approved
/// truncations keep the strengths they were given by hand.
#[test]
fn security_strength_is_half_of_t() {
    assert_eq!(<SHA512t<8> as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(<SHA512t<216> as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(<SHA512t<224> as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(<SHA512t<248> as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(<SHA512t<256> as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(<SHA512t<376> as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(<SHA512t<392> as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
    assert_eq!(<SHA512t<504> as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);

    // and the instance method agrees with the associated const
    assert_eq!(
        SHA512_224::new().max_security_strength(),
        <SHA512t<224> as Algorithm>::MAX_SECURITY_STRENGTH
    );
    assert_eq!(
        SHA512t::<504>::new().max_security_strength(),
        <SHA512t<504> as Algorithm>::MAX_SECURITY_STRENGTH
    );
}

/// A shorter output buffer truncates and a longer one is zero-filled past the digest, for a
/// generic `t` as much as for the approved ones.
#[test]
fn output_buffer_shorter_and_longer_than_the_digest() {
    let full = from_hex("44ab9c7c3eb2da370d2c0ed7"); // SHA512/96("")

    let mut short = [0u8; 5];
    assert_eq!(SHA512t::<96>::new().hash_out(b"", &mut short), 5);
    assert_eq!(short, full[..5]);

    let mut long = [0xAAu8; 20];
    assert_eq!(SHA512t::<96>::new().hash_out(b"", &mut long), 12);
    assert_eq!(&long[..12], &full[..]);
    assert_eq!(&long[12..], &[0u8; 8], "past the digest the buffer is zero-filled");
}
