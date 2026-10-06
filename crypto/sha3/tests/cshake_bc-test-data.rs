//! NIST SP 800-185 sample values for cSHAKE128/256.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data" (same convention as the sha2/sha3 crates), under
//! `crypto/sp800-185/`. If it is not present the tests print a warning and pass vacuously.

use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
use bouncycastle_hex as hex;
use bouncycastle_sha3::{CSHAKE128, CSHAKE256};

const TEST_DATA_DIR: &str = "crypto/sp800-185";

/// One `COUNT` block of a `.rsp` file.
struct Vector {
    strength: usize,
    n: String,
    s: String,
    output_len: usize,
    msg: Vec<u8>,
    output: Vec<u8>,
}

/// Parses an SP 800-185 cSHAKE `.rsp` file into its `COUNT` blocks.
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
    out
}

fn read_vectors(filename: &str) -> Option<Vec<Vector>> {
    Some(parse_rsp_file(&bc_test_data(TEST_DATA_DIR, filename)?))
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
                c.into_squeezer().do_output(want)
            }
            256 => {
                let mut c = CSHAKE256::new(v.n.as_bytes(), v.s.as_bytes());
                c.do_update(&v.msg);
                c.into_squeezer().do_output(want)
            }
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(got, v.output, "COUNT {i}: cSHAKE{} S={:?}", v.strength, v.s);
    }
    println!("cSHAKE: {} sample values", vectors.len());
}

/// cSHAKE through the shared `XOF` conformance suite, with a published sample value as the
/// expected output -- conformance and a NIST vector in one.
#[test]
fn test_framework_xof() {
    let Some(vectors) = read_vectors("cSHAKE.rsp") else { return };
    let v = vectors.first().expect("at least one sample");
    // The partial-byte input path is cSHAKE's own (it inherits SHAKE's), so leave it enabled.
    TestFrameworkXOF::new().test_xof(
        || CSHAKE128::new(v.n.as_bytes(), v.s.as_bytes()),
        &v.msg,
        &v.output,
    );
}
