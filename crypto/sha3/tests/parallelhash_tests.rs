//! ParallelHash against the NIST SP 800-185 sample values.
//!
//! Vectors come from the `bc-test-data` repo cloned alongside this one; see `cshake_tests.rs`.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::hash::TestFrameworkHash;
use bouncycastle_hex as hex;
use bouncycastle_sha3::{PARALLELHASH128, PARALLELHASH256, PARALLELHASHXOF128, PARALLELHASHXOF256};
use std::fs;
use std::path::Path;

const DATA_DIRS: [&str; 2] =
    ["../../../bc-test-data/crypto/sp800-185", "../bc-test-data/crypto/sp800-185"];

struct Vector {
    strength: usize,
    block_size: usize,
    s: String,
    output_len: usize,
    msg: Vec<u8>,
    output: Vec<u8>,
}

fn read_vectors(filename: &str) -> Option<Vec<Vector>> {
    let Some(dir) = DATA_DIRS.into_iter().find(|d| Path::new(d).exists()) else {
        println!("WARNING: bc-test-data not found; ParallelHash sample-value tests skipped");
        return None;
    };
    let path = Path::new(dir).join(filename);
    let content = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("bc-test-data is present but {} is unreadable: {e}", path.display())
    });

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
    Some(out)
}

/// ParallelHash (Sec 6.3): the output length is bound into the input.
#[test]
fn nist_sp800_185_parallelhash_sample_values() {
    let Some(vectors) = read_vectors("ParallelHash.rsp") else { return };
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        let want = v.output_len / 8;
        let got = match v.strength {
            128 => PARALLELHASH128::new(v.block_size, v.s.as_bytes(), want).hash(&v.msg),
            256 => PARALLELHASH256::new(v.block_size, v.s.as_bytes(), want).hash(&v.msg),
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
                let mut p = PARALLELHASHXOF128::new(v.block_size, v.s.as_bytes());
                p.do_update(&v.msg);
                p.into_squeezer().do_output(want)
            }
            256 => {
                let mut p = PARALLELHASHXOF256::new(v.block_size, v.s.as_bytes());
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
                || PARALLELHASHXOF128::new(b, s),
                |n| PARALLELHASH128::new(b, s, n).hash(&f.msg),
                &f.msg,
                &f.output,
                &x.output,
                &ctx,
            ),
            256 => check_do_final_binds_length(
                || PARALLELHASHXOF256::new(b, s),
                |n| PARALLELHASH256::new(b, s, n).hash(&f.msg),
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
    assert_eq!(absorbed().do_final(n), fixed_expected, "{ctx}: do_final binds the length");

    // Pre-filled, so the documented zeroization is observable.
    let mut buf = vec![0xFFu8; n];
    assert_eq!(absorbed().do_final_out(&mut buf), n, "{ctx}: do_final_out returns the length");
    assert_eq!(buf, fixed_expected, "{ctx}: do_final_out binds the length");

    // The `L` bound is the length actually asked for, not a fixed one. No sample value covers
    // these lengths, so the comparison is against this library's own fixed-length function.
    for shorter in [n / 2, n - 1] {
        assert_eq!(absorbed().do_final(shorter), fixed_of(shorter), "{ctx}: L = {shorter}");
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
    let tail = squeezer.do_final(n - split);
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

/// Unlike TupleHash, ParallelHash *is* ordinary byte-wise streaming: the blocks come from `B`, not
/// from how the caller chunks its `do_update` calls. Chunkings that straddle block boundaries are
/// the interesting ones, so this walks a range of chunk sizes against a block size of 8.
#[test]
fn chunking_does_not_change_the_result() {
    let msg: Vec<u8> = (0..=200u8).collect();
    let one = PARALLELHASH128::new(8, b"S", 32).hash(&msg);

    for chunk in [1usize, 3, 7, 8, 9, 16, 64, 201] {
        let mut p = PARALLELHASH128::new(8, b"S", 32);
        for piece in msg.chunks(chunk) {
            p.do_update(piece);
        }
        assert_eq!(p.do_final(), one, "chunk size {chunk} must not change the result");
    }
}

/// Sec 6.2: `B` is a parameter of the function. The same message under a different block size is a
/// different hash, not a re-arrangement of the same work.
#[test]
fn the_block_size_is_part_of_the_hash() {
    let msg: Vec<u8> = (0..=100u8).collect();
    let b8 = PARALLELHASH128::new(8, b"", 32).hash(&msg);
    let b12 = PARALLELHASH128::new(12, b"", 32).hash(&msg);
    let b16 = PARALLELHASH128::new(16, b"", 32).hash(&msg);
    assert_ne!(b8, b12);
    assert_ne!(b8, b16);
    assert_ne!(b12, b16);
}

/// A short final block, an exactly-full final block, and an empty message are the boundary cases
/// of the block loop.
///
/// This test matters more than it looks: **every published ParallelHash sample value has a
/// block-aligned message** (24 bytes at B = 8, 72 at B = 12), so the NIST vectors never exercise a
/// short final block at all. Deleting the flush of the partial buffer passes all twelve of them
/// and fails only here.
#[test]
fn block_boundary_cases() {
    // exactly one full block, versus one full block plus one byte
    let full = PARALLELHASH128::new(8, b"", 32).hash(&[0xAAu8; 8]);
    let plus = PARALLELHASH128::new(8, b"", 32).hash(&[0xAAu8; 9]);
    assert_ne!(full, plus);

    // two full blocks versus one short block: different block counts, so different output
    let two = PARALLELHASH128::new(8, b"", 32).hash(&[0xAAu8; 16]);
    assert_ne!(two, full);

    // an empty message is zero blocks, and must still produce a hash
    let empty = PARALLELHASH128::new(8, b"", 32).hash(b"");
    assert_eq!(empty.len(), 32);
    assert_ne!(empty, full);
}

/// The XOF's output at one length is a prefix of its output at a longer one; the fixed-length
/// function's is not.
#[test]
fn length_binding_differs_between_the_two() {
    let msg = b"parallel";
    let short = PARALLELHASH128::new(4, b"", 16).hash(msg);
    let long = PARALLELHASH128::new(4, b"", 32).hash(msg);
    assert_ne!(&long[..16], &short[..], "ParallelHash: a different length is a different function");

    let squeeze = |n| {
        let mut p = PARALLELHASHXOF128::new(4, b"");
        p.do_update(msg);
        p.into_squeezer().do_output(n)
    };
    let short = squeeze(16);
    let long = squeeze(32);
    assert_eq!(&long[..16], &short[..], "ParallelHashXOF: one stream, so shorter is a prefix");
}

/// A partial final byte cannot be expressed: the block count and length encodings must follow.
#[test]
fn partial_final_byte_is_refused() {
    let mut p = PARALLELHASH128::new(8, b"", 32);
    p.do_update(b"abc");
    assert!(matches!(p.do_final_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));

    let mut p = PARALLELHASHXOF128::new(8, b"");
    p.do_update(b"abc");
    assert!(matches!(p.into_squeezer_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));
}

/// Sec 6.2 forbids a zero block size.
#[test]
#[should_panic(expected = "block size B must be positive")]
fn zero_block_size_is_rejected() {
    let _ = PARALLELHASH128::new(0, b"", 32);
}

#[test]
fn algorithm_names() {
    assert_eq!(PARALLELHASH128::ALG_NAME, "ParallelHash128");
    assert_eq!(PARALLELHASH256::ALG_NAME, "ParallelHash256");
    assert_eq!(PARALLELHASHXOF128::ALG_NAME, "ParallelHashXOF128");
    assert_eq!(PARALLELHASHXOF256::ALG_NAME, "ParallelHashXOF256");
}

/// Sponge rates from FIPS 202 Table 3, the nominal lengths of the XOF forms, and the constructed
/// length of the fixed forms. The generic checks elsewhere only require these to be positive.
#[test]
fn metadata() {
    assert_eq!(PARALLELHASH128::new(8, b"", 32).block_bitlen(), 1344, "cSHAKE128 rate");
    assert_eq!(PARALLELHASH256::new(8, b"", 64).block_bitlen(), 1088, "cSHAKE256 rate");
    assert_eq!(PARALLELHASHXOF128::new(8, b"").block_bitlen(), 1344);
    assert_eq!(PARALLELHASHXOF256::new(8, b"").block_bitlen(), 1088);

    assert_eq!(PARALLELHASH128::new(8, b"", 17).output_len(), 17, "whatever was asked for");
    assert_eq!(PARALLELHASH256::new(8, b"", 100).output_len(), 100);
    assert_eq!(PARALLELHASHXOF128::new(8, b"").output_len(), 32, "the nominal length");
    assert_eq!(PARALLELHASHXOF256::new(8, b"").output_len(), 64);
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
            128 => check_fixed_view(|| PARALLELHASH128::new(b, s, n), &v.msg, &v.output, &ctx),
            256 => check_fixed_view(|| PARALLELHASH256::new(b, s, n), &v.msg, &v.output, &ctx),
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
                check_xof_view(|| PARALLELHASHXOF128::new(b, s), &v.msg, &v.output, &f.output, &ctx)
            }
            256 => {
                check_xof_view(|| PARALLELHASHXOF256::new(b, s), &v.msg, &v.output, &f.output, &ctx)
            }
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
}

/// Every output-buffer length, at both strengths and a non-default output length.
///
/// As for TupleHash: `output_len` is bound into the computation, so a short buffer truncates this
/// ParallelHash rather than computing a shorter one, and must not panic.
#[test]
fn output_buffers_of_every_length() {
    let framework = TestFrameworkHash::new();
    let input = b"the quick brown fox jumps over the lazy dog";

    framework.test_hash_output_buffers(|| PARALLELHASH128::new(8, b"", 32), input);
    framework.test_hash_output_buffers(|| PARALLELHASH256::new(8, b"", 64), input);

    // A block size that does not divide the input, a customization string, odd output lengths.
    framework.test_hash_output_buffers(|| PARALLELHASH128::new(12, b"Parallel Data", 17), input);
    framework.test_hash_output_buffers(|| PARALLELHASH256::new(5, b"Parallel Data", 5), input);
}
