//! NIST SP 800-185 sample values for KMAC128/256 and KMACXOF128/256.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data" (same convention as the sha2/sha3 crates), under
//! `crypto/sp800-185/`. If it is not present the tests print a warning and pass vacuously.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::MacGenerationKey;
use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
use bouncycastle_hex as hex;
use bouncycastle_sha3::kmac::{KMAC128Key, KMAC256Key, KMACXOF128, KMACXOF256};

const TEST_DATA_DIR: &str = "crypto/sp800-185";

/// One `COUNT` block of a `.rsp` file.
struct Vector {
    strength: usize,
    key: Vec<u8>,
    s: String,
    output_len: usize,
    msg: Vec<u8>,
    output: Vec<u8>,
}

/// Parses an SP 800-185 KMAC `.rsp` file into its `COUNT` blocks.
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
            key: hex::decode(get("Key").expect("Key")).expect("hex"),
            s: get("S").unwrap_or_default(),
            output_len: get("Outputlen").expect("Outputlen").parse().expect("a number"),
            msg: hex::decode(get("Msg").unwrap_or_default()).expect("hex"),
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

/// Every published sample key is 32 bytes, which carries a 256-bit strength and so satisfies both
/// KMAC128 and KMAC256 without the weak-key escape hatch.
fn key_material(bytes: &[u8]) -> KeyMaterial<32> {
    assert_eq!(bytes.len(), 32, "the sample keys are all 32 bytes");
    KeyMaterial::<32>::from_bytes_as_type(bytes, KeyType::MACKey).expect("a valid MAC key")
}

/// Fixed-length KMAC128 at the length `n` through the key type of that length, for the lengths
/// the sample values and their derived checks use: the published 32 and the shorter 16 and 31.
fn kmac128_at(key: &KeyMaterial<32>, s: &[u8], msg: &[u8], n: usize) -> Vec<u8> {
    match n {
        16 => KMAC128Key::<16>::with_params(key, s).expect("a valid key").mac(msg).to_vec(),
        31 => KMAC128Key::<31>::with_params(key, s).expect("a valid key").mac(msg).to_vec(),
        32 => KMAC128Key::<32>::with_params(key, s).expect("a valid key").mac(msg).to_vec(),
        other => panic!("no KMAC128 key type is instantiated at {other} bytes"),
    }
}

/// As [`kmac128_at`] for KMAC256: the published 64 and the shorter 32 and 63.
fn kmac256_at(key: &KeyMaterial<32>, s: &[u8], msg: &[u8], n: usize) -> Vec<u8> {
    match n {
        32 => KMAC256Key::<32>::with_params(key, s).expect("a valid key").mac(msg).to_vec(),
        63 => KMAC256Key::<63>::with_params(key, s).expect("a valid key").mac(msg).to_vec(),
        64 => KMAC256Key::<64>::with_params(key, s).expect("a valid key").mac(msg).to_vec(),
        other => panic!("no KMAC256 key type is instantiated at {other} bytes"),
    }
}

/// KMAC (Sec 4.3): the requested output length is bound into the input. Each sample value runs
/// through the shared MAC key suite as well, which pins the `_out` forms, the streaming workers
/// and verification against it.
#[test]
fn nist_sp800_185_kmac_sample_values() {
    let Some(vectors) = read_vectors("KMAC.rsp") else { return };
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        assert!(v.output_len.is_multiple_of(8), "COUNT {i}: byte-aligned outputs only");
        let want = v.output_len / 8;
        let key = key_material(&v.key);
        let s = v.s.as_bytes();
        let ctx = format!("COUNT {i}: KMAC{} S={:?}", v.strength, v.s);

        match (v.strength, want) {
            (128, 32) => {
                let k = KMAC128Key::<32>::with_params(&key, s).expect("a valid key");
                let expected: [u8; 32] = v.output.as_slice().try_into().expect("32 bytes");
                assert_eq!(k.mac(&v.msg), expected, "{ctx}");
                TestFrameworkMAC::new().test_mac_key(&k, &v.msg, &expected);
            }
            (256, 64) => {
                let k = KMAC256Key::<64>::with_params(&key, s).expect("a valid key");
                let expected: [u8; 64] = v.output.as_slice().try_into().expect("64 bytes");
                assert_eq!(k.mac(&v.msg), expected, "{ctx}");
                TestFrameworkMAC::new().test_mac_key(&k, &v.msg, &expected);
            }
            other => panic!("{ctx}: unexpected (strength, length) {other:?}"),
        }
    }
    println!("KMAC: {} sample values", vectors.len());
}

/// KMACXOF (Sec 4.3.1): `right_encode(0)` in place of the length, then arbitrary output.
#[test]
fn nist_sp800_185_kmacxof_sample_values() {
    let Some(vectors) = read_vectors("KMACXOF.rsp") else { return };
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        let want = v.output_len / 8;
        let key = key_material(&v.key);

        // Read with do_output, which is the XOF reading of the stream: the one-shots bind the
        // length they are given, and are checked against the fixed-length samples elsewhere.
        let got = match v.strength {
            128 => {
                let mut k = KMACXOF128::new(&key, v.s.as_bytes(), false).expect("a valid key");
                k.do_update(&v.msg);
                k.into_squeezer().do_output(want)
            }
            256 => {
                let mut k = KMACXOF256::new(&key, v.s.as_bytes(), false).expect("a valid key");
                k.do_update(&v.msg);
                k.into_squeezer().do_output(want)
            }
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(got, v.output, "COUNT {i}: KMACXOF{} S={:?}", v.strength, v.s);
    }
    println!("KMACXOF: {} sample values", vectors.len());
}

/// Sec 4.3.1 versus Sec 4.3: with identical key, message, customization *and* length, KMAC and
/// KMACXOF are different functions, because one binds `right_encode(L)` and the other
/// `right_encode(0)`. The published samples use the same inputs for both, so this is checkable
/// directly against them -- and it is the property that would break if `into_squeezer` bound the
/// length by mistake.
#[test]
fn kmacxof_is_not_kmac_truncated() {
    let (Some(fixed), Some(xof)) = (read_vectors("KMAC.rsp"), read_vectors("KMACXOF.rsp")) else {
        return;
    };
    assert_eq!(fixed.len(), xof.len(), "the two sample files pair up");

    for (i, (f, x)) in fixed.iter().zip(xof.iter()).enumerate() {
        assert_eq!(f.key, x.key, "COUNT {i}: the sample pairs share a key");
        assert_eq!(f.msg, x.msg, "COUNT {i}: ... and a message");
        assert_eq!(f.output_len, x.output_len, "COUNT {i}: ... and an output length");
        assert_ne!(
            f.output, x.output,
            "COUNT {i}: KMAC and KMACXOF must not agree on the same inputs"
        );
    }
}

/// `do_final` as the first read binds `right_encode(L)`, so it computes fixed-length KMAC.
///
/// SP 800-185 s. 4.3 and s. 4.3.1 are the same function but for one field: step 1 absorbs
/// `bytepad(encode_string(K), 168) || X || right_encode(L)` for KMAC and `right_encode(0)` for
/// KMACXOF. Nothing else separates them, so the encoding need not be chosen until the caller says
/// how it wants to read -- and `do_final` as the first read says both how many bytes it wants and
/// that it will not be back, which is exactly `L`.
///
/// So `KMACXOF128::into_squeezer().do_final(n)` must be `KMAC128(K, X, 8n, S)` to the byte, which
/// the paired sample files check directly: `KMAC.rsp` and `KMACXOF.rsp` publish the same key,
/// message, customization and length, and the fixed-length file is what `do_final` has to match.
#[test]
fn do_final_binds_the_length_when_nothing_has_been_read() {
    let (Some(fixed), Some(xof)) = (read_vectors("KMAC.rsp"), read_vectors("KMACXOF.rsp")) else {
        return;
    };
    assert_eq!(fixed.len(), xof.len(), "the two sample files pair up");

    for (i, (f, x)) in fixed.iter().zip(xof.iter()).enumerate() {
        let key = key_material(&f.key);
        let ctx = format!("COUNT {i}: KMACXOF{} S={:?}", f.strength, f.s);
        let s = f.s.as_bytes();
        match f.strength {
            128 => check_do_final_binds_length(
                || KMACXOF128::new(&key, s, false).expect("a valid key"),
                |n| kmac128_at(&key, s, &f.msg, n),
                &f.msg,
                &f.output,
                &x.output,
                &ctx,
            ),
            256 => check_do_final_binds_length(
                || KMACXOF256::new(&key, s, false).expect("a valid key"),
                |n| kmac256_at(&key, s, &f.msg, n),
                &f.msg,
                &f.output,
                &x.output,
                &ctx,
            ),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
    println!("KMACXOF do_final: {} sample values", fixed.len());
}

/// One paired sample through `do_final`. `fixed_expected` is the published fixed-length value,
/// `xof_expected` the published XOF value over the same inputs, and `fixed_of` computes the
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

    // The first read, with no do_output before it: right_encode(8n), so the fixed-length function.
    let mut x = make();
    x.do_update(msg);
    assert_eq!(
        x.into_squeezer().do_output_final(n),
        fixed_expected,
        "{ctx}: do_final binds the length"
    );

    // Pre-filled, so the documented zeroization is observable.
    let mut buf = vec![0xFFu8; n];
    let mut x = make();
    x.do_update(msg);
    assert_eq!(
        x.into_squeezer().do_output_final_out(&mut buf),
        n,
        "{ctx}: do_final_out returns the len"
    );
    assert_eq!(buf, fixed_expected, "{ctx}: do_final_out binds the length");

    // The `L` bound is the length actually asked for, not a fixed one. No sample value covers
    // these lengths, so the comparison is against this library's own fixed-length function.
    for shorter in [n / 2, n - 1] {
        let mut x = make();
        x.do_update(msg);
        assert_eq!(
            x.into_squeezer().do_output_final(shorter),
            fixed_of(shorter),
            "{ctx}: L = {shorter}"
        );
    }

    // The one-shots name their length and never come back, so they bind it too.
    assert_eq!(make().xof(msg, n), fixed_expected, "{ctx}: xof binds the length");

    let mut buf = vec![0xFFu8; n];
    assert_eq!(make().xof_out(msg, &mut buf), n, "{ctx}: xof_out returns the length");
    assert_eq!(buf, fixed_expected, "{ctx}: xof_out binds the length");

    // Once a read has happened right_encode(0) is in the sponge and cannot be revised, so do_final
    // after a do_output is the XOF stream continuing, not the fixed-length function.
    let split = n / 2;
    let mut x = make();
    x.do_update(msg);
    let mut squeezer = x.into_squeezer();
    let head = squeezer.do_output(split);
    let tail = squeezer.do_output_final(n - split);
    assert_eq!([head, tail].concat(), xof_expected, "{ctx}: do_final after a read stays the XOF");
}

/// KMACXOF through the shared `XOF` conformance suite.
///
/// This is what the constructor-closure form of the framework buys: a keyed XOF has no `Default`,
/// so before it the suite could only be pointed at unkeyed functions. The expected output is taken
/// from a published sample value, so this checks conformance and a NIST vector at once.
#[test]
fn test_framework_xof() {
    let Some(vectors) = read_vectors("KMACXOF.rsp") else { return };
    let v = vectors.first().expect("at least one sample");
    let key = key_material(&v.key);

    // Partial-byte input is not expressible for KMACXOF -- right_encode(0) has to follow the
    // message -- so that part of the suite is switched off.
    let mut framework = TestFrameworkXOF::new();
    framework.enable_partial_byte_tests = false;
    // Sec 4.3.1: do_final as the first read binds right_encode(L), which is fixed-length KMAC
    // rather than this stream. Checked against the paired sample files elsewhere in this file.
    framework.do_final_binds_output_length = true;
    framework.test_xof(
        || KMACXOF128::new(&key, v.s.as_bytes(), false).expect("a valid key"),
        &v.msg,
        &v.output,
    );
}
