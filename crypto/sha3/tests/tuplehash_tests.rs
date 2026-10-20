//! TupleHash and TupleHashXOF behaviour tests. The SP 800-185 sample values are in
//! `tuplehash_bc-test-data.rs`.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::hash::TestFrameworkHash;
use bouncycastle_sha3::tuplehash::{TupleHash128, TupleHash256, TupleHashXOF128, TupleHashXOF256};

/// Sec 5.1, the reason TupleHash exists: the boundaries between elements are part of the hash, so
/// re-splitting the same bytes gives an unrelated result. Every other hash in this library has the
/// opposite property, which is why it is worth pinning explicitly.
#[test]
fn the_tuple_boundaries_are_part_of_the_hash() {
    let a = TupleHash128::new(b"", 32).hash_tuple(&[b"abc", b"d"]);
    let b = TupleHash128::new(b"", 32).hash_tuple(&[b"ab", b"cd"]);
    let c = TupleHash128::new(b"", 32).hash_tuple(&[b"abcd"]);
    assert_ne!(a, b, "the same bytes split differently must hash differently");
    assert_ne!(a, c, "... and differently again from a single element");
    assert_ne!(b, c);

    // An empty element is an element: dropping it changes the answer.
    let with = TupleHash128::new(b"", 32).hash_tuple(&[b"a", b"", b"b"]);
    let without = TupleHash128::new(b"", 32).hash_tuple(&[b"a", b"b"]);
    assert_ne!(with, without, "an empty tuple element must still count");
}

/// `hash_tuple` and successive `do_update` calls must agree, since each update is one element.
#[test]
fn hash_tuple_matches_successive_updates() {
    let tuple: [&[u8]; 3] = [b"first", b"second", b"third"];
    let one = TupleHash128::new(b"S", 32).hash_tuple(&tuple);

    let mut t = TupleHash128::new(b"S", 32);
    for element in tuple {
        t.do_update(element);
    }
    assert_eq!(t.do_final(), one, "do_update per element must equal hash_tuple");
}

/// The output length is bound for the fixed-length function and not for the XOF, so they have
/// opposite behaviour when the length changes -- the same split as KMAC.
#[test]
fn length_binding_differs_between_the_two() {
    let t: [&[u8]; 2] = [b"x", b"y"];

    let short = TupleHash128::new(b"", 16).hash_tuple(&t);
    let long = TupleHash128::new(b"", 32).hash_tuple(&t);
    assert_ne!(&long[..16], &short[..], "TupleHash: a different length is a different function");

    let short = TupleHashXOF128::new(b"").output_for(&t).do_output(16);
    let long = TupleHashXOF128::new(b"").output_for(&t).do_output(32);
    assert_eq!(&long[..16], &short[..], "TupleHashXOF: one stream, so shorter is a prefix");
}

/// The customization string separates one use from another (Sec 5.2).
#[test]
fn customization_separates_the_functions() {
    let t: [&[u8]; 2] = [b"x", b"y"];
    assert_ne!(
        TupleHash128::new(b"", 32).hash_tuple(&t),
        TupleHash128::new(b"My Application", 32).hash_tuple(&t),
    );
}

/// A partial final byte cannot be expressed: the length encoding has to follow the tuple.
#[test]
fn partial_final_byte_is_refused() {
    let mut t = TupleHash128::new(b"", 32);
    t.do_update(b"abc");
    assert!(matches!(t.do_final_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));

    let mut t = TupleHashXOF128::new(b"");
    t.do_update(b"abc");
    assert!(matches!(t.into_squeezer_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));
}

#[test]
fn algorithm_names() {
    assert_eq!(TupleHash128::ALG_NAME, "TupleHash128");
    assert_eq!(TupleHash256::ALG_NAME, "TupleHash256");
    assert_eq!(TupleHashXOF128::ALG_NAME, "TupleHashXOF128");
    assert_eq!(TupleHashXOF256::ALG_NAME, "TupleHashXOF256");
}

/// Sponge rates from FIPS 202 Table 3, the nominal lengths of the XOF forms, and the constructed
/// length of the fixed forms. The generic checks elsewhere only require these to be positive.
#[test]
fn metadata() {
    assert_eq!(TupleHash128::new(b"", 32).block_bitlen(), 1344, "cSHAKE128 rate");
    assert_eq!(TupleHash256::new(b"", 64).block_bitlen(), 1088, "cSHAKE256 rate");
    assert_eq!(TupleHashXOF128::new(b"").block_bitlen(), 1344);
    assert_eq!(TupleHashXOF256::new(b"").block_bitlen(), 1088);

    assert_eq!(TupleHash128::new(b"", 17).output_len(), 17, "whatever was asked for");
    assert_eq!(TupleHash256::new(b"", 100).output_len(), 100);
    assert_eq!(TupleHashXOF128::new(b"").output_len(), 32, "the nominal length");
    assert_eq!(TupleHashXOF256::new(b"").output_len(), 64);
}

/// Every output-buffer length, at both strengths and a non-default output length.
///
/// `output_len` is bound into the computation, so a short buffer must truncate this TupleHash
/// rather than compute the TupleHash of a shorter length -- and must not panic, which it did
/// before this test existed.
#[test]
fn output_buffers_of_every_length() {
    let framework = TestFrameworkHash::new();
    let input = b"the quick brown fox";

    framework.test_hash_output_buffers(|| TupleHash128::new(b"", 32), input);
    framework.test_hash_output_buffers(|| TupleHash256::new(b"", 64), input);

    // Non-default lengths, and a customization string.
    framework.test_hash_output_buffers(|| TupleHash128::new(b"My Tuple App", 17), input);
    framework.test_hash_output_buffers(|| TupleHash256::new(b"My Tuple App", 5), input);
}
