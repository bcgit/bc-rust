//! TupleHash and TupleHashXOF behaviour tests. The SP 800-185 sample values are in
//! `tuplehash_bc-test-data.rs`.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::hash::TestFrameworkHash;
use bouncycastle_sha3::CSHAKE128;
use bouncycastle_sha3::tuplehash::{
    TUPLEHASH_MAX_OUTPUT_LEN, TupleHash128, TupleHash256, TupleHashXOF128, TupleHashXOF256,
};

/// Sec 5.1, the reason TupleHash exists: the boundaries between elements are part of the hash, so
/// re-splitting the same bytes gives an unrelated result. Every other hash in this library has the
/// opposite property, which is why it is worth pinning explicitly.
#[test]
fn the_tuple_boundaries_are_part_of_the_hash() {
    let a = TupleHash128::new(b"", 32).unwrap().hash_tuple(&[b"abc", b"d"]);
    let b = TupleHash128::new(b"", 32).unwrap().hash_tuple(&[b"ab", b"cd"]);
    let c = TupleHash128::new(b"", 32).unwrap().hash_tuple(&[b"abcd"]);
    assert_ne!(a, b, "the same bytes split differently must hash differently");
    assert_ne!(a, c, "... and differently again from a single element");
    assert_ne!(b, c);

    // An empty element is an element: dropping it changes the answer.
    let with = TupleHash128::new(b"", 32).unwrap().hash_tuple(&[b"a", b"", b"b"]);
    let without = TupleHash128::new(b"", 32).unwrap().hash_tuple(&[b"a", b"b"]);
    assert_ne!(with, without, "an empty tuple element must still count");
}

/// `hash_tuple` and successive `do_update` calls must agree, since each update is one element.
#[test]
fn hash_tuple_matches_successive_updates() {
    let tuple: [&[u8]; 3] = [b"first", b"second", b"third"];
    let one = TupleHash128::new(b"S", 32).unwrap().hash_tuple(&tuple);

    let mut t = TupleHash128::new(b"S", 32).unwrap();
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

    let short = TupleHash128::new(b"", 16).unwrap().hash_tuple(&t);
    let long = TupleHash128::new(b"", 32).unwrap().hash_tuple(&t);
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
        TupleHash128::new(b"", 32).unwrap().hash_tuple(&t),
        TupleHash128::new(b"My Application", 32).unwrap().hash_tuple(&t),
    );
}

/// A partial final byte cannot be expressed: the length encoding has to follow the tuple.
#[test]
fn partial_final_byte_is_refused() {
    let mut t = TupleHash128::new(b"", 32).unwrap();
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
    assert_eq!(TupleHash128::new(b"", 32).unwrap().block_bitlen(), 1344, "cSHAKE128 rate");
    assert_eq!(TupleHash256::new(b"", 64).unwrap().block_bitlen(), 1088, "cSHAKE256 rate");
    assert_eq!(TupleHashXOF128::new(b"").block_bitlen(), 1344);
    assert_eq!(TupleHashXOF256::new(b"").block_bitlen(), 1088);

    assert_eq!(TupleHash128::new(b"", 17).unwrap().output_len(), 17, "whatever was asked for");
    assert_eq!(TupleHash256::new(b"", 100).unwrap().output_len(), 100);
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

    framework.test_hash_output_buffers(|| TupleHash128::new(b"", 32).unwrap(), input);
    framework.test_hash_output_buffers(|| TupleHash256::new(b"", 64).unwrap(), input);

    // Non-default lengths, and a customization string.
    framework.test_hash_output_buffers(|| TupleHash128::new(b"My Tuple App", 17).unwrap(), input);
    framework.test_hash_output_buffers(|| TupleHash256::new(b"My Tuple App", 5).unwrap(), input);
}

/// `L` is bound into the computation as a bit count in a `u64` (Sec 5.3.1 step 3): a byte length
/// whose bit count does not fit is refused by `new` rather than wrapped into a different
/// function.
#[test]
fn an_output_length_past_the_cap_is_refused() {
    assert!(matches!(
        TupleHash128::new(b"", TUPLEHASH_MAX_OUTPUT_LEN + 1),
        Err(HashError::InvalidLength(_))
    ));
    assert!(TupleHash256::new(b"", TUPLEHASH_MAX_OUTPUT_LEN).is_ok(), "the cap itself is valid");
}

/// Sec 5.3 written out by hand over the public cSHAKE: `TupleHash128(X, L, S) =
/// cSHAKE128(encode_string(X[1]) || ... || encode_string(X[n]) || right_encode(L), L,
/// "TupleHash", S)`, with `left_encode` / `right_encode` / `encode_string` from Sec 2.3.1-2.3.3.
/// `L = 264` bits is chosen so that `right_encode(L)` is `01 08 02`, a two-byte value whose low
/// byte is non-zero; the SP 800-185 sample values only ever encode 256 and 512, whose low byte
/// is zero, and so cannot tell the digits' order apart.
#[test]
fn matches_the_cshake_definition_at_a_length_with_a_non_zero_low_encoding_byte() {
    fn encode_string(s: &[u8]) -> Vec<u8> {
        // left_encode(len(s) in bits): the digit count, then the big-endian digits.
        let bits = (s.len() * 8) as u64;
        let digits: Vec<u8> = bits.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
        let digits = if digits.is_empty() { vec![0] } else { digits };
        let mut out = vec![digits.len() as u8];
        out.extend_from_slice(&digits);
        out.extend_from_slice(s);
        out
    }
    fn right_encode(x: u64) -> Vec<u8> {
        let mut digits: Vec<u8> = x.to_be_bytes().iter().copied().skip_while(|&b| b == 0).collect();
        if digits.is_empty() {
            digits.push(0);
        }
        let n = digits.len() as u8;
        digits.push(n);
        digits
    }
    let (x1, x2, s, l_bytes) = (b"abc".as_slice(), b"de".as_slice(), b"S".as_slice(), 33usize);

    let mut z = encode_string(x1);
    z.extend_from_slice(&encode_string(x2));
    z.extend_from_slice(&right_encode((l_bytes * 8) as u64));
    assert_eq!(&z[z.len() - 3..], &[0x01, 0x08, 0x02], "right_encode(264)");
    let mut c = CSHAKE128::new(b"TupleHash", s);
    c.do_update(&z);
    let by_definition = c.into_squeezer().do_output(l_bytes);

    assert_eq!(TupleHash128::new(s, l_bytes).unwrap().hash_tuple(&[x1, x2]), by_definition);
}

/// Sponge rates from FIPS 202 Table 3, the nominal lengths of the XOF forms, and the constructed
/// length of the fixed forms. The generic checks elsewhere only require these to be positive.
#[test]
fn metadata() {
    assert_eq!(TUPLEHASH128::new(b"", 32).block_bitlen(), 1344, "cSHAKE128 rate");
    assert_eq!(TUPLEHASH256::new(b"", 64).block_bitlen(), 1088, "cSHAKE256 rate");
    assert_eq!(TUPLEHASHXOF128::new(b"").block_bitlen(), 1344);
    assert_eq!(TUPLEHASHXOF256::new(b"").block_bitlen(), 1088);

    assert_eq!(TUPLEHASH128::new(b"", 17).output_len(), 17, "whatever was asked for");
    assert_eq!(TUPLEHASH256::new(b"", 100).output_len(), 100);
    assert_eq!(TUPLEHASHXOF128::new(b"").output_len(), 32, "the nominal length");
    assert_eq!(TUPLEHASHXOF256::new(b"").output_len(), 64);
}

/// Every `Hash` entry point of the fixed-length form, against one sample value.
///
/// The sample-value test above goes through `hash_tuple` only, which left `hash`, `hash_out` and
/// `do_final_out` unexercised: `cargo mutants` could replace each with a constant, and change the
/// `* 8` in the `right_encode(L)` that `do_final_out` absorbs, without a test noticing.
fn check_fixed_view<H: Hash>(make: impl Fn() -> H, tuple: &[&[u8]], expected: &[u8], ctx: &str) {
    let n = expected.len();
    assert_eq!(make().output_len(), n, "{ctx}: output_len");

    // do_final_out into an exact buffer
    let mut h = make();
    tuple.iter().for_each(|e| h.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(h.do_final_out(&mut out), n, "{ctx}: do_final_out returns the length");
    assert_eq!(out, expected, "{ctx}: do_final_out");

    // ... and into a longer one, which is only written up to the output length
    let mut h = make();
    tuple.iter().for_each(|e| h.do_update(e));
    let mut out = vec![0xFFu8; n + 7];
    assert_eq!(h.do_final_out(&mut out), n);
    assert_eq!(&out[..n], expected, "{ctx}: do_final_out, oversized buffer");
    assert_eq!(&out[n..], &[0xFFu8; 7], "{ctx}: bytes past the output length are untouched");

    // hash and hash_out take one element: the last, after the rest have been fed in
    let Some((last, rest)) = tuple.split_last() else { return };
    let mut h = make();
    rest.iter().for_each(|e| h.do_update(e));
    assert_eq!(h.hash(last), expected, "{ctx}: hash as the final element");

    let mut h = make();
    rest.iter().for_each(|e| h.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(h.hash_out(last, &mut out), n, "{ctx}: hash_out returns the length");
    assert_eq!(out, expected, "{ctx}: hash_out");
}

/// Every `Hash` and `XOF` entry point of the XOF form, against one sample value. The samples ask
/// for the nominal length, so `do_final` and `hash` must reproduce them exactly.
fn check_xof_view<X: XOF>(make: impl Fn() -> X, tuple: &[&[u8]], expected: &[u8], ctx: &str) {
    let n = expected.len();
    assert_eq!(make().output_len(), n, "{ctx}: the samples ask for the nominal length");

    let mut x = make();
    tuple.iter().for_each(|e| x.do_update(e));
    assert_eq!(x.do_final(), expected, "{ctx}: do_final");

    let mut x = make();
    tuple.iter().for_each(|e| x.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(x.do_final_out(&mut out), n, "{ctx}: do_final_out returns the length");
    assert_eq!(out, expected, "{ctx}: do_final_out");

    // zero partial bits is the byte-aligned case and must be accepted; any other count refused
    let mut x = make();
    tuple.iter().for_each(|e| x.do_update(e));
    assert_eq!(x.do_final_partial_bits(0, 0).unwrap(), expected, "{ctx}: do_final_partial_bits(0)");

    let mut x = make();
    tuple.iter().for_each(|e| x.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(x.do_final_partial_bits_out(0, 0, &mut out).unwrap(), n, "{ctx}: ..._out length");
    assert_eq!(out, expected, "{ctx}: do_final_partial_bits_out(0)");

    assert!(matches!(make().do_final_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));
    let mut out = vec![0u8; n];
    assert!(matches!(
        make().do_final_partial_bits_out(0xF0, 4, &mut out),
        Err(HashError::InvalidLength(_))
    ));

    // the one-shots take one element: the last, after the rest have been fed in
    let Some((last, rest)) = tuple.split_last() else { return };
    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    assert_eq!(x.hash(last), expected, "{ctx}: hash");

    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(x.hash_out(last, &mut out), n, "{ctx}: hash_out returns the length");
    assert_eq!(out, expected, "{ctx}: hash_out");

    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    assert_eq!(x.hash_xof(last, n), expected, "{ctx}: hash_xof");

    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    assert_eq!(x.hash_xof(last, n / 2), &expected[..n / 2], "{ctx}: hash_xof, shorter");

    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(x.hash_xof_out(last, &mut out), n, "{ctx}: hash_xof_out returns the length");
    assert_eq!(out, expected, "{ctx}: hash_xof_out");
}

#[test]
fn hash_trait_view_agrees_with_the_sample_values() {
    let Some(vectors) = read_vectors("TupleHash.rsp") else { return };
    for (i, v) in vectors.iter().enumerate() {
        let n = v.output_len / 8;
        let t = as_slices(&v.tuple);
        let ctx = format!("COUNT {i}: TupleHash{}", v.strength);
        match v.strength {
            128 => check_fixed_view(|| TUPLEHASH128::new(v.s.as_bytes(), n), &t, &v.output, &ctx),
            256 => check_fixed_view(|| TUPLEHASH256::new(v.s.as_bytes(), n), &t, &v.output, &ctx),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
}

#[test]
fn xof_trait_view_agrees_with_the_sample_values() {
    let Some(vectors) = read_vectors("TupleHashXOF.rsp") else { return };
    for (i, v) in vectors.iter().enumerate() {
        let t = as_slices(&v.tuple);
        let ctx = format!("COUNT {i}: TupleHashXOF{}", v.strength);
        match v.strength {
            128 => check_xof_view(|| TUPLEHASHXOF128::new(v.s.as_bytes()), &t, &v.output, &ctx),
            256 => check_xof_view(|| TUPLEHASHXOF256::new(v.s.as_bytes()), &t, &v.output, &ctx),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
}
