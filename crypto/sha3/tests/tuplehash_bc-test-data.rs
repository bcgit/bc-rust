//! NIST SP 800-185 sample values for TupleHash128/256 and TupleHashXOF128/256.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data" (same convention as the sha2/sha3 crates), under
//! `crypto/sp800-185/`. If it is not present the tests print a warning and pass vacuously.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_sha3::tuplehash::{TupleHash128, TupleHash256, TupleHashXOF128, TupleHashXOF256};

const TEST_DATA_DIR: &str = "crypto/sp800-185";

/// One `COUNT` block of a `.rsp` file.
struct Vector {
    strength: usize,
    s: String,
    output_len: usize,
    tuple: Vec<Vec<u8>>,
    output: Vec<u8>,
}

/// Parses an SP 800-185 TupleHash `.rsp` file into its `COUNT` blocks.
fn parse_rsp_file(content: &str) -> Vec<Vector> {
    let mut out = Vec::new();
    let mut cur: Vec<(String, String)> = Vec::new();
    let finish = |cur: &mut Vec<(String, String)>, out: &mut Vec<Vector>| {
        if cur.is_empty() {
            return;
        }
        let get = |k: &str| cur.iter().find(|(a, _)| a == k).map(|(_, b)| b.clone());
        let count: usize = get("Count").expect("Count").parse().expect("a number");
        let tuple = (1..=count)
            .map(|i| hex::decode(get(&format!("Tuple{i}")).expect("a tuple element")).expect("hex"))
            .collect();
        out.push(Vector {
            strength: get("Strength").expect("Strength").parse().expect("a number"),
            s: get("S").unwrap_or_default(),
            output_len: get("Outputlen").expect("Outputlen").parse().expect("a number"),
            tuple,
            output: hex::decode(get("Output").expect("Output")).expect("hex"),
        });
        cur.clear();
    };
    for line in content.lines() {
        let line = line.trim_end();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(" = ") else { continue };
        if k == "COUNT" {
            finish(&mut cur, &mut out);
        } else {
            cur.push((k.to_string(), v.to_string()));
        }
    }
    finish(&mut cur, &mut out);
    out
}

fn read_vectors(filename: &str) -> Option<Vec<Vector>> {
    Some(parse_rsp_file(&bc_test_data(TEST_DATA_DIR, filename)?))
}

fn as_slices(tuple: &[Vec<u8>]) -> Vec<&[u8]> {
    tuple.iter().map(|v| v.as_slice()).collect()
}

/// TupleHash (Sec 5.3): the output length is bound into the input.
#[test]
fn nist_sp800_185_tuplehash_sample_values() {
    let Some(vectors) = read_vectors("TupleHash.rsp") else { return };
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        let want = v.output_len / 8;
        let t = as_slices(&v.tuple);
        let got = match v.strength {
            128 => TupleHash128::new(v.s.as_bytes(), want).hash_tuple(&t),
            256 => TupleHash256::new(v.s.as_bytes(), want).hash_tuple(&t),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(
            got,
            v.output,
            "COUNT {i}: TupleHash{} with {} elements, S={:?}",
            v.strength,
            v.tuple.len(),
            v.s
        );
    }
    println!("TupleHash: {} sample values", vectors.len());
}

/// TupleHashXOF (Sec 5.3.1): `right_encode(0)` in place of the length.
#[test]
fn nist_sp800_185_tuplehashxof_sample_values() {
    let Some(vectors) = read_vectors("TupleHashXOF.rsp") else { return };
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        let want = v.output_len / 8;
        let t = as_slices(&v.tuple);
        // do_output is the XOF reading of the stream; do_final and the one-shots bind the length
        // they are given, and are checked against the fixed-length samples elsewhere.
        let got = match v.strength {
            128 => TupleHashXOF128::new(v.s.as_bytes()).output_for(&t).do_output(want),
            256 => TupleHashXOF256::new(v.s.as_bytes()).output_for(&t).do_output(want),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(got, v.output, "COUNT {i}: TupleHashXOF{} S={:?}", v.strength, v.s);
    }
    println!("TupleHashXOF: {} sample values", vectors.len());
}

/// `do_final` as the first read binds `right_encode(L)`, so it computes fixed-length TupleHash.
///
/// SP 800-185 s. 5.3 and s. 5.3.1 differ in one field: step 4 is `newX = z || right_encode(L)` for
/// TupleHash and `newX = z || right_encode(0)` for TupleHashXOF. The encoding therefore need not
/// be chosen until the caller says how it wants to read, and `do_final` as the first read says
/// both how many bytes it wants and that it will not be back -- which is exactly `L`.
///
/// `TupleHash.rsp` and `TupleHashXOF.rsp` publish the same tuples, customization and lengths, so
/// the fixed-length file is what `do_final` has to match, byte for byte.
#[test]
fn do_final_binds_the_length_when_nothing_has_been_read() {
    let (Some(fixed), Some(xof)) =
        (read_vectors("TupleHash.rsp"), read_vectors("TupleHashXOF.rsp"))
    else {
        return;
    };
    assert_eq!(fixed.len(), xof.len(), "the two sample files pair up");

    for (i, (f, x)) in fixed.iter().zip(xof.iter()).enumerate() {
        let t = as_slices(&f.tuple);
        let ctx = format!("COUNT {i}: TupleHashXOF{} S={:?}", f.strength, f.s);
        let s = f.s.as_bytes();
        match f.strength {
            128 => check_do_final_binds_length(
                || TupleHashXOF128::new(s),
                |n| TupleHash128::new(s, n).hash_tuple(&t),
                &t,
                &f.output,
                &x.output,
                &ctx,
            ),
            256 => check_do_final_binds_length(
                || TupleHashXOF256::new(s),
                |n| TupleHash256::new(s, n).hash_tuple(&t),
                &t,
                &f.output,
                &x.output,
                &ctx,
            ),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }

        // `output_for` hands back the squeezer directly, so `do_final` on it is the first read by
        // construction -- the shortest way to spell fixed-length TupleHash through the XOF type.
        let n = f.output.len();
        let got = match f.strength {
            128 => TupleHashXOF128::new(s).output_for(&t).do_output_final(n),
            256 => TupleHashXOF256::new(s).output_for(&t).do_output_final(n),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(got, f.output, "{ctx}: output_for().do_final()");
    }
    println!("TupleHashXOF do_final: {} sample values", fixed.len());
}

/// One paired sample through `do_final`. `fixed_expected` is the published fixed-length value,
/// `xof_expected` the published XOF value over the same tuple, and `fixed_of` computes the
/// fixed-length function at a length no vector covers.
fn check_do_final_binds_length<X: XOF>(
    make: impl Fn() -> X,
    fixed_of: impl Fn(usize) -> Vec<u8>,
    tuple: &[&[u8]],
    fixed_expected: &[u8],
    xof_expected: &[u8],
    ctx: &str,
) {
    let n = fixed_expected.len();
    assert_ne!(fixed_expected, xof_expected, "{ctx}: the two sample values must differ at all");
    let absorbed = || {
        let mut x = make();
        tuple.iter().for_each(|element| x.do_update(element));
        x.into_squeezer()
    };

    // The first read, with no do_output before it: right_encode(8n), so the fixed-length function.
    assert_eq!(absorbed().do_output_final(n), fixed_expected, "{ctx}: do_final binds the length");

    // Pre-filled, so the documented zeroization is observable.
    let mut buf = vec![0xFFu8; n];
    assert_eq!(
        absorbed().do_output_final_out(&mut buf),
        n,
        "{ctx}: do_final_out returns the length"
    );
    assert_eq!(buf, fixed_expected, "{ctx}: do_final_out binds the length");

    // The `L` bound is the length actually asked for, not a fixed one. No sample value covers
    // these lengths, so the comparison is against this library's own fixed-length function.
    for shorter in [n / 2, n - 1] {
        assert_eq!(absorbed().do_output_final(shorter), fixed_of(shorter), "{ctx}: L = {shorter}");
    }

    // The one-shots name their length and never come back, so they bind it too. They take one
    // tuple element, the last, after the rest have been fed in.
    if let Some((last, rest)) = tuple.split_last() {
        let mut x = make();
        rest.iter().for_each(|element| x.do_update(element));
        assert_eq!(x.xof(last, n), fixed_expected, "{ctx}: xof binds the length");

        let mut buf = vec![0xFFu8; n];
        let mut x = make();
        rest.iter().for_each(|element| x.do_update(element));
        assert_eq!(x.xof_out(last, &mut buf), n, "{ctx}: xof_out returns the length");
        assert_eq!(buf, fixed_expected, "{ctx}: xof_out binds the length");
    }

    // Once a read has happened right_encode(0) is in the sponge and cannot be revised, so do_final
    // after a do_output is the XOF stream continuing, not the fixed-length function.
    let split = n / 2;
    let mut squeezer = absorbed();
    let head = squeezer.do_output(split);
    let tail = squeezer.do_output_final(n - split);
    assert_eq!([head, tail].concat(), xof_expected, "{ctx}: do_final after a read stays the XOF");
}

/// The two are different functions on identical inputs, as for KMAC.
#[test]
fn tuplehashxof_is_not_tuplehash_truncated() {
    let (Some(fixed), Some(xof)) =
        (read_vectors("TupleHash.rsp"), read_vectors("TupleHashXOF.rsp"))
    else {
        return;
    };
    assert_eq!(fixed.len(), xof.len());
    for (i, (f, x)) in fixed.iter().zip(xof.iter()).enumerate() {
        assert_eq!(f.tuple, x.tuple, "COUNT {i}: the sample pairs share a tuple");
        assert_eq!(f.output_len, x.output_len, "COUNT {i}: ... and an output length");
        assert_ne!(f.output, x.output, "COUNT {i}: the two functions must differ");
    }
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
    // Hash::do_final_out zeroizes the whole buffer, so the tail is 0 rather than what the caller
    // left there -- the same as SHA3, which is the contract these fixed-length types share.
    assert_eq!(&out[n..], &[0u8; 7], "{ctx}: bytes past the output length are zeroized");

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

/// Every `Hash` and `XOF` entry point of the XOF form, against one paired sample value.
///
/// The samples ask for the nominal length, and the `Hash` view is a final read at that length, so
/// it binds `L` and must reproduce the *fixed-length* sample; reading the stream with `do_output`
/// must reproduce the XOF one.
fn check_xof_view<X: XOF>(
    make: impl Fn() -> X,
    tuple: &[&[u8]],
    expected: &[u8],
    fixed_expected: &[u8],
    ctx: &str,
) {
    let n = expected.len();
    assert_eq!(make().output_len(), n, "{ctx}: the samples ask for the nominal length");
    assert_eq!(fixed_expected.len(), n, "{ctx}: ... and the paired samples share it");

    let mut x = make();
    tuple.iter().for_each(|e| x.do_update(e));
    assert_eq!(x.do_final(), fixed_expected, "{ctx}: do_final");

    let mut x = make();
    tuple.iter().for_each(|e| x.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(x.do_final_out(&mut out), n, "{ctx}: do_final_out returns the length");
    assert_eq!(out, fixed_expected, "{ctx}: do_final_out");

    // zero partial bits is the byte-aligned case and must be accepted; any other count refused
    let mut x = make();
    tuple.iter().for_each(|e| x.do_update(e));
    assert_eq!(
        x.do_final_partial_bits(0, 0).unwrap(),
        fixed_expected,
        "{ctx}: do_final_partial_bits(0)"
    );

    let mut x = make();
    tuple.iter().for_each(|e| x.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(x.do_final_partial_bits_out(0, 0, &mut out).unwrap(), n, "{ctx}: ..._out length");
    assert_eq!(out, fixed_expected, "{ctx}: do_final_partial_bits_out(0)");

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
    assert_eq!(x.hash(last), fixed_expected, "{ctx}: hash");

    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    let mut out = vec![0u8; n];
    assert_eq!(x.hash_out(last, &mut out), n, "{ctx}: hash_out returns the length");
    assert_eq!(out, fixed_expected, "{ctx}: hash_out");

    // The XOF reading of the stream is do_output; the one-shots bind the length they are given,
    // so they belong to `do_final_binds_the_length_when_nothing_has_been_read` instead.
    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    x.do_update(last);
    assert_eq!(x.into_squeezer().do_output(n), expected, "{ctx}: do_output");

    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    x.do_update(last);
    assert_eq!(x.into_squeezer().do_output(n / 2), &expected[..n / 2], "{ctx}: do_output, shorter");

    let mut x = make();
    rest.iter().for_each(|e| x.do_update(e));
    x.do_update(last);
    let mut out = vec![0u8; n];
    assert_eq!(x.into_squeezer().do_output_out(&mut out), n, "{ctx}: do_output_out length");
    assert_eq!(out, expected, "{ctx}: do_output_out");
}

#[test]
fn hash_trait_view_agrees_with_the_sample_values() {
    let Some(vectors) = read_vectors("TupleHash.rsp") else { return };
    for (i, v) in vectors.iter().enumerate() {
        let n = v.output_len / 8;
        let t = as_slices(&v.tuple);
        let ctx = format!("COUNT {i}: TupleHash{}", v.strength);
        match v.strength {
            128 => check_fixed_view(|| TupleHash128::new(v.s.as_bytes(), n), &t, &v.output, &ctx),
            256 => check_fixed_view(|| TupleHash256::new(v.s.as_bytes(), n), &t, &v.output, &ctx),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
}

#[test]
fn xof_trait_view_agrees_with_the_sample_values() {
    let (Some(fixed), Some(xof)) =
        (read_vectors("TupleHash.rsp"), read_vectors("TupleHashXOF.rsp"))
    else {
        return;
    };
    assert_eq!(fixed.len(), xof.len(), "the two sample files pair up");

    for (i, (f, v)) in fixed.iter().zip(xof.iter()).enumerate() {
        let t = as_slices(&v.tuple);
        let ctx = format!("COUNT {i}: TupleHashXOF{}", v.strength);
        let s = v.s.as_bytes();
        match v.strength {
            128 => check_xof_view(|| TupleHashXOF128::new(s), &t, &v.output, &f.output, &ctx),
            256 => check_xof_view(|| TupleHashXOF256::new(s), &t, &v.output, &f.output, &ctx),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
}
