//! NIST SP 800-185 sample values for ParallelHash128/256 and ParallelHashXOF128/256.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data" (same convention as the sha2/sha3 crates), under
//! `crypto/sp800-185/`. If it is not present the tests print a warning and pass vacuously.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_sha3::parallelhash::{
    ParallelHash128, ParallelHash256, ParallelHashXOF128, ParallelHashXOF256,
};

const TEST_DATA_DIR: &str = "crypto/sp800-185";

/// One `COUNT` block of a `.rsp` file.
struct Vector {
    strength: usize,
    block_size: usize,
    s: String,
    output_len: usize,
    msg: Vec<u8>,
    output: Vec<u8>,
}

/// Parses an SP 800-185 ParallelHash `.rsp` file into its `COUNT` blocks.
fn parse_rsp_file(content: &str) -> Vec<Vector> {
    let mut out = Vec::new();
    let mut cur: Vec<(String, String)> = Vec::new();
    let finish = |cur: &mut Vec<(String, String)>, out: &mut Vec<Vector>| {
        if cur.is_empty() {
            return;
        }
        let get = |k: &str| cur.iter().find(|(a, _)| a == k).map(|(_, b)| b.clone());
        out.push(Vector {
            strength: get("Strength").expect("Strength").parse().expect("a number"),
            block_size: get("B").expect("B").parse().expect("a number"),
            s: get("S").unwrap_or_default(),
            output_len: get("Outputlen").expect("Outputlen").parse().expect("a number"),
            msg: hex::decode(get("Msg").expect("Msg")).expect("hex"),
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

/// ParallelHash (Sec 6.3): the output length is bound into the input.
#[test]
fn nist_sp800_185_parallelhash_sample_values() {
    let Some(vectors) = read_vectors("ParallelHash.rsp") else { return };
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        let want = v.output_len / 8;
        let got = match v.strength {
            128 => ParallelHash128::new(v.block_size, v.s.as_bytes(), want).hash(&v.msg),
            256 => ParallelHash256::new(v.block_size, v.s.as_bytes(), want).hash(&v.msg),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(
            got, v.output,
            "COUNT {i}: ParallelHash{} B={} S={:?}",
            v.strength, v.block_size, v.s
        );
    }
    println!("ParallelHash: {} sample values", vectors.len());
}

/// ParallelHashXOF (Sec 6.3.1): `right_encode(0)` in place of the length.
#[test]
fn nist_sp800_185_parallelhashxof_sample_values() {
    let Some(vectors) = read_vectors("ParallelHashXOF.rsp") else { return };
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        let want = v.output_len / 8;
        // Read with do_output, which is the XOF reading of the stream: the one-shots bind the
        // length they are given, and are checked against the fixed-length samples elsewhere.
        let got = match v.strength {
            128 => {
                let mut p = ParallelHashXOF128::new(v.block_size, v.s.as_bytes());
                p.do_update(&v.msg);
                p.into_squeezer().do_output(want)
            }
            256 => {
                let mut p = ParallelHashXOF256::new(v.block_size, v.s.as_bytes());
                p.do_update(&v.msg);
                p.into_squeezer().do_output(want)
            }
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(
            got, v.output,
            "COUNT {i}: ParallelHashXOF{} B={} S={:?}",
            v.strength, v.block_size, v.s
        );
    }
    println!("ParallelHashXOF: {} sample values", vectors.len());
}

/// `do_final` as the first read binds `right_encode(L)`, so it computes fixed-length ParallelHash.
///
/// SP 800-185 s. 6.3 and s. 6.3.1 differ in one field: step 4 is `z = z || right_encode(n) ||
/// right_encode(L)` for ParallelHash and `right_encode(0)` in that second slot for
/// ParallelHashXOF. The block count is settled when the input ends, but the length is not -- so it
/// waits for the first read, and `do_final` there says both how many bytes are wanted and that
/// there will be no more, which is exactly `L`.
///
/// `ParallelHash.rsp` and `ParallelHashXOF.rsp` publish the same messages, block sizes,
/// customization and lengths, so the fixed-length file is what `do_final` has to match.
#[test]
fn do_final_binds_the_length_when_nothing_has_been_read() {
    let (Some(fixed), Some(xof)) =
        (read_vectors("ParallelHash.rsp"), read_vectors("ParallelHashXOF.rsp"))
    else {
        return;
    };
    assert_eq!(fixed.len(), xof.len(), "the two sample files pair up");

    for (i, (f, x)) in fixed.iter().zip(xof.iter()).enumerate() {
        let ctx =
            format!("COUNT {i}: ParallelHashXOF{} B={} S={:?}", f.strength, f.block_size, f.s);
        let (b, s) = (f.block_size, f.s.as_bytes());
        match f.strength {
            128 => check_do_final_binds_length(
                || ParallelHashXOF128::new(b, s),
                |n| ParallelHash128::new(b, s, n).hash(&f.msg),
                &f.msg,
                &f.output,
                &x.output,
                &ctx,
            ),
            256 => check_do_final_binds_length(
                || ParallelHashXOF256::new(b, s),
                |n| ParallelHash256::new(b, s, n).hash(&f.msg),
                &f.msg,
                &f.output,
                &x.output,
                &ctx,
            ),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
    println!("ParallelHashXOF do_final: {} sample values", fixed.len());
}

/// One paired sample through `do_final`. `fixed_expected` is the published fixed-length value,
/// `xof_expected` the published XOF value over the same message, and `fixed_of` computes the
/// fixed-length function at a length no vector covers.
fn check_do_final_binds_length<X: XOF>(
    make: impl Fn() -> X,
    fixed_of: impl Fn(usize) -> Vec<u8>,
    msg: &[u8],
    fixed_expected: &[u8],
    xof_expected: &[u8],
    ctx: &str,
) {
    let n = fixed_expected.len();
    assert_ne!(fixed_expected, xof_expected, "{ctx}: the two sample values must differ at all");
    let absorbed = || {
        let mut x = make();
        x.do_update(msg);
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

    // The one-shots name their length and never come back, so they bind it too.
    assert_eq!(make().xof(msg, n), fixed_expected, "{ctx}: xof binds the length");

    let mut buf = vec![0xFFu8; n];
    assert_eq!(make().xof_out(msg, &mut buf), n, "{ctx}: xof_out returns the length");
    assert_eq!(buf, fixed_expected, "{ctx}: xof_out binds the length");

    // Once a read has happened right_encode(0) is in the sponge and cannot be revised, so do_final
    // after a do_output is the XOF stream continuing, not the fixed-length function.
    let split = n / 2;
    let mut squeezer = absorbed();
    let head = squeezer.do_output(split);
    let tail = squeezer.do_output_final(n - split);
    assert_eq!([head, tail].concat(), xof_expected, "{ctx}: do_final after a read stays the XOF");
}

/// The two are different functions on identical inputs.
#[test]
fn parallelhashxof_is_not_parallelhash_truncated() {
    let (Some(fixed), Some(xof)) =
        (read_vectors("ParallelHash.rsp"), read_vectors("ParallelHashXOF.rsp"))
    else {
        return;
    };
    assert_eq!(fixed.len(), xof.len());
    for (i, (f, x)) in fixed.iter().zip(xof.iter()).enumerate() {
        assert_eq!(f.msg, x.msg, "COUNT {i}: the sample pairs share a message");
        assert_eq!(f.block_size, x.block_size, "COUNT {i}: ... and a block size");
        assert_ne!(f.output, x.output, "COUNT {i}: the two functions must differ");
    }
}

/// Every `Hash` entry point of the fixed-length form, against one sample value.
///
/// The sample-value test above goes through `hash` only, which left `hash_out` and
/// `do_final_out` unexercised: `cargo mutants` could replace each with a constant, and change the
/// `* 8` in the `right_encode(L)` that `do_final_out` binds, without a test noticing.
fn check_fixed_view<H: Hash>(make: impl Fn() -> H, msg: &[u8], expected: &[u8], ctx: &str) {
    let n = expected.len();
    assert_eq!(make().output_len(), n, "{ctx}: output_len");

    let mut out = vec![0u8; n];
    assert_eq!(make().hash_out(msg, &mut out), n, "{ctx}: hash_out returns the length");
    assert_eq!(out, expected, "{ctx}: hash_out");

    let mut h = make();
    msg.chunks(5).for_each(|c| h.do_update(c));
    let mut out = vec![0u8; n];
    assert_eq!(h.do_final_out(&mut out), n, "{ctx}: do_final_out returns the length");
    assert_eq!(out, expected, "{ctx}: do_final_out");

    // a longer buffer is only written up to the output length
    let mut h = make();
    h.do_update(msg);
    let mut out = vec![0xFFu8; n + 7];
    assert_eq!(h.do_final_out(&mut out), n);
    assert_eq!(&out[..n], expected, "{ctx}: do_final_out, oversized buffer");
    // Hash::do_final_out zeroizes the whole buffer, so the tail is 0 rather than what the caller
    // left there -- the same as SHA3, which is the contract these fixed-length types share.
    assert_eq!(&out[n..], &[0u8; 7], "{ctx}: bytes past the output length are zeroized");
}

/// Every `Hash` and `XOF` entry point of the XOF form, against one paired sample value.
///
/// The samples ask for the nominal length, and the `Hash` view is a final read at that length, so
/// it binds `L` and must reproduce the *fixed-length* sample; reading the stream with `do_output`
/// must reproduce the XOF one.
fn check_xof_view<X: XOF>(
    make: impl Fn() -> X,
    msg: &[u8],
    expected: &[u8],
    fixed_expected: &[u8],
    ctx: &str,
) {
    let n = expected.len();
    assert_eq!(make().output_len(), n, "{ctx}: the samples ask for the nominal length");
    assert_eq!(fixed_expected.len(), n, "{ctx}: ... and the paired samples share it");

    assert_eq!(make().hash(msg), fixed_expected, "{ctx}: hash");

    let mut out = vec![0u8; n];
    assert_eq!(make().hash_out(msg, &mut out), n, "{ctx}: hash_out returns the length");
    assert_eq!(out, fixed_expected, "{ctx}: hash_out");

    let mut x = make();
    msg.chunks(5).for_each(|c| x.do_update(c));
    assert_eq!(x.do_final(), fixed_expected, "{ctx}: do_final");

    let mut x = make();
    x.do_update(msg);
    let mut out = vec![0u8; n];
    assert_eq!(x.do_final_out(&mut out), n, "{ctx}: do_final_out returns the length");
    assert_eq!(out, fixed_expected, "{ctx}: do_final_out");

    // zero partial bits is the byte-aligned case and must be accepted; any other count refused
    let mut x = make();
    x.do_update(msg);
    assert_eq!(
        x.do_final_partial_bits(0, 0).unwrap(),
        fixed_expected,
        "{ctx}: do_final_partial_bits(0)"
    );

    let mut x = make();
    x.do_update(msg);
    let mut out = vec![0u8; n];
    assert_eq!(x.do_final_partial_bits_out(0, 0, &mut out).unwrap(), n, "{ctx}: ..._out length");
    assert_eq!(out, fixed_expected, "{ctx}: do_final_partial_bits_out(0)");

    assert!(matches!(make().do_final_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));
    let mut out = vec![0u8; n];
    assert!(matches!(
        make().do_final_partial_bits_out(0xF0, 4, &mut out),
        Err(HashError::InvalidLength(_))
    ));

    // The XOF reading of the stream is do_output; the one-shots bind the length they are given,
    // so they belong to `do_final_binds_the_length_when_nothing_has_been_read` instead.
    let mut x = make();
    x.do_update(msg);
    assert_eq!(x.into_squeezer().do_output(n / 2), &expected[..n / 2], "{ctx}: do_output, shorter");

    let mut out = vec![0u8; n];
    let mut x = make();
    x.do_update(msg);
    assert_eq!(x.into_squeezer().do_output_out(&mut out), n, "{ctx}: do_output_out length");
    assert_eq!(out, expected, "{ctx}: do_output_out");
}

#[test]
fn hash_trait_view_agrees_with_the_sample_values() {
    let Some(vectors) = read_vectors("ParallelHash.rsp") else { return };
    for (i, v) in vectors.iter().enumerate() {
        let n = v.output_len / 8;
        let (b, s) = (v.block_size, v.s.as_bytes());
        let ctx = format!("COUNT {i}: ParallelHash{} B={b}", v.strength);
        match v.strength {
            128 => check_fixed_view(|| ParallelHash128::new(b, s, n), &v.msg, &v.output, &ctx),
            256 => check_fixed_view(|| ParallelHash256::new(b, s, n), &v.msg, &v.output, &ctx),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
}

#[test]
fn xof_trait_view_agrees_with_the_sample_values() {
    let (Some(fixed), Some(xof)) =
        (read_vectors("ParallelHash.rsp"), read_vectors("ParallelHashXOF.rsp"))
    else {
        return;
    };
    assert_eq!(fixed.len(), xof.len(), "the two sample files pair up");

    for (i, (f, v)) in fixed.iter().zip(xof.iter()).enumerate() {
        let (b, s) = (v.block_size, v.s.as_bytes());
        let ctx = format!("COUNT {i}: ParallelHashXOF{} B={b}", v.strength);
        match v.strength {
            128 => {
                check_xof_view(|| ParallelHashXOF128::new(b, s), &v.msg, &v.output, &f.output, &ctx)
            }
            256 => {
                check_xof_view(|| ParallelHashXOF256::new(b, s), &v.msg, &v.output, &f.output, &ctx)
            }
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
}
