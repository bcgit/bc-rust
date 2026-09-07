//! ParallelHash against the NIST SP 800-185 sample values.
//!
//! Vectors come from the `bc-test-data` repo cloned alongside this one; see `cshake_tests.rs`.

use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, XOF};
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
        let got = match v.strength {
            128 => PARALLELHASHXOF128::new(v.block_size, v.s.as_bytes()).hash_xof(&v.msg, want),
            256 => PARALLELHASHXOF256::new(v.block_size, v.s.as_bytes()).hash_xof(&v.msg, want),
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

    let short = PARALLELHASHXOF128::new(4, b"").hash_xof(msg, 16);
    let long = PARALLELHASHXOF128::new(4, b"").hash_xof(msg, 32);
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
    assert!(matches!(p.into_output_partial_bits(0xF0, 4), Err(HashError::InvalidLength(_))));
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
