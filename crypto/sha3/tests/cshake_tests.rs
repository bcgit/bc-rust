//! cSHAKE against the NIST SP 800-185 sample values.
//!
//! The vectors live in the `bc-test-data` repo, which must be cloned alongside this one at
//! `../bc-test-data` (the same convention as the ML-KEM, ML-DSA and SHA-3 suites). If it is not
//! present these tests print a warning and pass vacuously.

use bouncycastle_core::traits::{Algorithm, Hash, XOF, XofOutput};
use bouncycastle_hex as hex;
use bouncycastle_sha3::{CSHAKE128, CSHAKE256, SHAKE128, SHAKE256};
use std::fs;
use std::path::Path;

/// One `COUNT` block of a `.rsp` file.
struct Vector {
    strength: usize,
    n: String,
    s: String,
    output_len: usize,
    msg: Vec<u8>,
    output: Vec<u8>,
}

/// Two candidates, as in `cavp_tests.rs`: the first is relative to the crate directory (where cargo
/// runs an integration test), the second to the workspace root.
const DATA_DIRS: [&str; 2] =
    ["../../../bc-test-data/crypto/sp800-185", "../bc-test-data/crypto/sp800-185"];

fn read_vectors(filename: &str) -> Option<Vec<Vector>> {
    let Some(dir) = DATA_DIRS.into_iter().find(|d| Path::new(d).exists()) else {
        println!("WARNING: bc-test-data not found; cSHAKE sample-value tests skipped");
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
            n: get("N").unwrap_or_default(),
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
    Some(out)
}

/// Every published cSHAKE sample value, at both strengths.
#[test]
fn nist_sp800_185_sample_values() {
    let Some(vectors) = read_vectors("cSHAKE.rsp") else { return };
    assert!(!vectors.is_empty(), "the vector file must not be empty");

    for (i, v) in vectors.iter().enumerate() {
        assert!(v.output_len.is_multiple_of(8), "COUNT {i}: byte-aligned outputs only");
        let want = v.output_len / 8;

        let got = match v.strength {
            128 => {
                let mut c = CSHAKE128::new(v.n.as_bytes(), v.s.as_bytes());
                c.do_update(&v.msg);
                c.into_output().do_output(want)
            }
            256 => {
                let mut c = CSHAKE256::new(v.n.as_bytes(), v.s.as_bytes());
                c.do_update(&v.msg);
                c.into_output().do_output(want)
            }
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(got, v.output, "COUNT {i}: cSHAKE{} S={:?}", v.strength, v.s);
    }
    println!("cSHAKE: {} sample values", vectors.len());
}

/// SP 800-185 Sec 3.3 step 1: with `N` and `S` both empty, cSHAKE *is* SHAKE.
///
/// This is a special case in the definition rather than a consequence of the general construction:
/// the customized branch absorbs a `bytepad` prefix and uses the `00` domain separator, where SHAKE
/// absorbs nothing and uses `1111`. Getting it wrong would leave cSHAKE self-consistent but
/// incompatible with SHAKE, which no sample value would catch, since every published sample has a
/// non-empty `S`.
#[test]
fn empty_name_and_customization_is_plain_shake() {
    for msg in [b"".as_slice(), b"abc", &[0u8; 200], b"Hello, world!"] {
        for len in [1usize, 16, 32, 168, 200] {
            assert_eq!(
                CSHAKE128::new(b"", b"").hash_xof(msg, len),
                SHAKE128::new().hash_xof(msg, len),
                "cSHAKE128 with no N or S must equal SHAKE128 / len {len}"
            );
            assert_eq!(
                CSHAKE256::new(b"", b"").hash_xof(msg, len),
                SHAKE256::new().hash_xof(msg, len),
                "cSHAKE256 with no N or S must equal SHAKE256 / len {len}"
            );
        }
    }
}

/// Sec 3.1: two instances with different `N` or `S` must produce unrelated output. That is the
/// whole point of customization, so a customized instance must also differ from plain SHAKE.
#[test]
fn customization_separates_the_functions() {
    let msg = b"the same message";
    let plain = SHAKE128::new().hash_xof(msg, 32);
    let email = CSHAKE128::new(b"", b"Email Signature").hash_xof(msg, 32);
    let finger = CSHAKE128::new(b"", b"key fingerprint").hash_xof(msg, 32);
    let named = CSHAKE128::new(b"KMAC", b"").hash_xof(msg, 32);

    assert_ne!(plain, email, "a customized cSHAKE must differ from SHAKE");
    assert_ne!(email, finger, "different S must give unrelated output");
    assert_ne!(plain, named, "a function name alone must customize");
    assert_ne!(email, named, "N and S must not be interchangeable");
}

/// `N` and `S` are separate inputs, and `encode_string` length-prefixes each, so moving bytes from
/// one to the other must change the result. Without the prefixes, ("AB", "") and ("A", "B") would
/// collide -- the ambiguity Sec 2.3.2 exists to prevent.
#[test]
fn the_boundary_between_n_and_s_is_unambiguous() {
    let msg = b"x";
    assert_ne!(
        CSHAKE128::new(b"AB", b"").hash_xof(msg, 32),
        CSHAKE128::new(b"A", b"B").hash_xof(msg, 32),
        "the split between N and S must be part of the computation"
    );
}

/// Chunked input must equal a single update, and the output must be one continuous stream.
#[test]
fn streaming_matches_one_shot() {
    let msg: Vec<u8> = (0..=255u8).collect();
    let one = CSHAKE128::new(b"", b"Email Signature").hash_xof(&msg, 64);

    let mut c = CSHAKE128::new(b"", b"Email Signature");
    for chunk in msg.chunks(7) {
        c.do_update(chunk);
    }
    let mut out = c.into_output();
    let head = out.do_output(20);
    let tail = out.do_final(44);
    assert_eq!([head, tail].concat(), one, "chunked in, split out, must equal the one-shot");
}

/// cSHAKE is a `Hash`, so `do_final` gives the nominal digest size and is a prefix of the stream.
#[test]
fn cshake_is_a_hash() {
    let mut c = CSHAKE128::new(b"", b"Email Signature");
    c.do_update(b"abc");
    let digest = c.do_final();
    assert_eq!(digest.len(), 32, "cSHAKE128's nominal output length");
    assert_eq!(CSHAKE128::new(b"", b"Email Signature").hash(b"abc"), digest);

    let long = CSHAKE128::new(b"", b"Email Signature").hash_xof(b"abc", 64);
    assert_eq!(&long[..32], &digest[..], "do_final must be a prefix of the longer output");

    let mut c = CSHAKE256::new(b"", b"Email Signature");
    c.do_update(b"abc");
    assert_eq!(c.do_final().len(), 64, "cSHAKE256's nominal output length");
}

/// The algorithm names, so the factory and any registry agree with the specification's spelling.
#[test]
fn algorithm_names() {
    assert_eq!(CSHAKE128::ALG_NAME, "CSHAKE128");
    assert_eq!(CSHAKE256::ALG_NAME, "CSHAKE256");
}
