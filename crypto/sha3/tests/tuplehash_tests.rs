//! TupleHash against the NIST SP 800-185 sample values.
//!
//! Vectors come from the `bc-test-data` repo cloned alongside this one; see `cshake_tests.rs`.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, XOF, XofOutput};
use bouncycastle_hex as hex;
use bouncycastle_sha3::{TUPLEHASH128, TUPLEHASH256, TUPLEHASHXOF128, TUPLEHASHXOF256};
use std::fs;
use std::path::Path;

const DATA_DIRS: [&str; 2] =
    ["../../../bc-test-data/crypto/sp800-185", "../bc-test-data/crypto/sp800-185"];

/// One `COUNT` block of a `.rsp` file.
struct Vector {
    strength: usize,
    s: String,
    output_len: usize,
    tuple: Vec<Vec<u8>>,
    output: Vec<u8>,
}

fn read_vectors(filename: &str) -> Option<Vec<Vector>> {
    let Some(dir) = DATA_DIRS.into_iter().find(|d| Path::new(d).exists()) else {
        println!("WARNING: bc-test-data not found; TupleHash sample-value tests skipped");
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
    Some(out)
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
            128 => TUPLEHASH128::new(v.s.as_bytes(), want).hash_tuple(&t),
            256 => TUPLEHASH256::new(v.s.as_bytes(), want).hash_tuple(&t),
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
        let got = match v.strength {
            128 => TUPLEHASHXOF128::new(v.s.as_bytes()).output_for(&t).do_output(want),
            256 => TUPLEHASHXOF256::new(v.s.as_bytes()).output_for(&t).do_output(want),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(got, v.output, "COUNT {i}: TupleHashXOF{} S={:?}", v.strength, v.s);
    }
    println!("TupleHashXOF: {} sample values", vectors.len());
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

/// Sec 5.1, the reason TupleHash exists: the boundaries between elements are part of the hash, so
/// re-splitting the same bytes gives an unrelated result. Every other hash in this library has the
/// opposite property, which is why it is worth pinning explicitly.
#[test]
fn the_tuple_boundaries_are_part_of_the_hash() {
    let a = TUPLEHASH128::new(b"", 32).hash_tuple(&[b"abc", b"d"]);
    let b = TUPLEHASH128::new(b"", 32).hash_tuple(&[b"ab", b"cd"]);
    let c = TUPLEHASH128::new(b"", 32).hash_tuple(&[b"abcd"]);
    assert_ne!(a, b, "the same bytes split differently must hash differently");
    assert_ne!(a, c, "... and differently again from a single element");
    assert_ne!(b, c);

    // An empty element is an element: dropping it changes the answer.
    let with = TUPLEHASH128::new(b"", 32).hash_tuple(&[b"a", b"", b"b"]);
    let without = TUPLEHASH128::new(b"", 32).hash_tuple(&[b"a", b"b"]);
    assert_ne!(with, without, "an empty tuple element must still count");
}

/// `hash_tuple` and successive `do_update` calls must agree, since each update is one element.
#[test]
fn hash_tuple_matches_successive_updates() {
    let tuple: [&[u8]; 3] = [b"first", b"second", b"third"];
    let one = TUPLEHASH128::new(b"S", 32).hash_tuple(&tuple);

    let mut t = TUPLEHASH128::new(b"S", 32);
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

    let short = TUPLEHASH128::new(b"", 16).hash_tuple(&t);
    let long = TUPLEHASH128::new(b"", 32).hash_tuple(&t);
    assert_ne!(&long[..16], &short[..], "TupleHash: a different length is a different function");

    let short = TUPLEHASHXOF128::new(b"").output_for(&t).do_output(16);
    let long = TUPLEHASHXOF128::new(b"").output_for(&t).do_output(32);
    assert_eq!(&long[..16], &short[..], "TupleHashXOF: one stream, so shorter is a prefix");
}

/// The customization string separates one use from another (Sec 5.2).
#[test]
fn customization_separates_the_functions() {
    let t: [&[u8]; 2] = [b"x", b"y"];
    assert_ne!(
        TUPLEHASH128::new(b"", 32).hash_tuple(&t),
        TUPLEHASH128::new(b"My Application", 32).hash_tuple(&t),
    );
}

/// A partial final byte cannot be expressed: the length encoding has to follow the tuple.
#[test]
fn partial_final_byte_is_refused() {
    let mut t = TUPLEHASH128::new(b"", 32);
    t.do_update(b"abc");
    assert!(matches!(t.do_final_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));

    let mut t = TUPLEHASHXOF128::new(b"");
    t.do_update(b"abc");
    assert!(matches!(t.into_output_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));
}

#[test]
fn algorithm_names() {
    assert_eq!(TUPLEHASH128::ALG_NAME, "TupleHash128");
    assert_eq!(TUPLEHASH256::ALG_NAME, "TupleHash256");
    assert_eq!(TUPLEHASHXOF128::ALG_NAME, "TupleHashXOF128");
    assert_eq!(TUPLEHASHXOF256::ALG_NAME, "TupleHashXOF256");
}
