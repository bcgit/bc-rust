//! KMAC against the NIST SP 800-185 sample values.
//!
//! Vectors come from the `bc-test-data` repo cloned alongside this one; see `cshake_tests.rs`.

use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, MAC, XofOutput};
use bouncycastle_hex as hex;
use bouncycastle_sha3::{KMAC128, KMAC256};
use std::fs;
use std::path::Path;

const DATA_DIRS: [&str; 2] =
    ["../../../bc-test-data/crypto/sp800-185", "../bc-test-data/crypto/sp800-185"];

/// One `COUNT` block of a `.rsp` file.
struct Vector {
    strength: usize,
    key: Vec<u8>,
    s: String,
    output_len: usize,
    msg: Vec<u8>,
    output: Vec<u8>,
}

fn read_vectors(filename: &str) -> Option<Vec<Vector>> {
    let Some(dir) = DATA_DIRS.into_iter().find(|d| Path::new(d).exists()) else {
        println!("WARNING: bc-test-data not found; KMAC sample-value tests skipped");
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
    Some(out)
}

/// Every published sample key is 32 bytes, which carries a 256-bit strength and so satisfies both
/// KMAC128 and KMAC256 without the weak-key escape hatch.
fn key_material(bytes: &[u8]) -> KeyMaterial<32> {
    assert_eq!(bytes.len(), 32, "the sample keys are all 32 bytes");
    KeyMaterial::<32>::from_bytes_as_type(bytes, KeyType::MACKey).expect("a valid MAC key")
}

/// KMAC (Sec 4.3): the requested output length is bound into the input.
#[test]
fn nist_sp800_185_kmac_sample_values() {
    let Some(vectors) = read_vectors("KMAC.rsp") else { return };
    assert!(!vectors.is_empty());

    for (i, v) in vectors.iter().enumerate() {
        assert!(v.output_len.is_multiple_of(8), "COUNT {i}: byte-aligned outputs only");
        let want = v.output_len / 8;
        let key = key_material(&v.key);

        let got = match v.strength {
            128 => KMAC128::new_with_params(&key, v.s.as_bytes(), want, false)
                .expect("a valid key")
                .mac(&v.msg),
            256 => KMAC256::new_with_params(&key, v.s.as_bytes(), want, false)
                .expect("a valid key")
                .mac(&v.msg),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        };
        assert_eq!(got, v.output, "COUNT {i}: KMAC{} S={:?}", v.strength, v.s);
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

        let got = match v.strength {
            128 => {
                let mut k = KMAC128::new_with_params(&key, v.s.as_bytes(), want, false)
                    .expect("a valid key");
                k.do_update(&v.msg);
                k.into_output().do_output(want)
            }
            256 => {
                let mut k = KMAC256::new_with_params(&key, v.s.as_bytes(), want, false)
                    .expect("a valid key");
                k.do_update(&v.msg);
                k.into_output().do_output(want)
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
/// directly against them -- and it is the property that would break if `into_output` bound the
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

/// The output length is absorbed, so asking for a different length is a different function -- not
/// a prefix. Sec 1: "any change in the requested output length completely changes the function".
#[test]
fn output_length_changes_the_function() {
    let key = key_material(&[0x42u8; 32]);
    let short = KMAC128::new_with_params(&key, b"", 16, false).unwrap().mac(b"abc");
    let long = KMAC128::new_with_params(&key, b"", 32, false).unwrap().mac(b"abc");

    assert_eq!(short.len(), 16);
    assert_eq!(long.len(), 32);
    assert_ne!(&long[..16], &short[..], "a longer KMAC must not extend a shorter one");
}

/// The customization string separates one use of KMAC from another (Sec 4.2).
#[test]
fn customization_separates_the_functions() {
    let key = key_material(&[0x42u8; 32]);
    let plain = KMAC128::new_with_params(&key, b"", 32, false).unwrap().mac(b"abc");
    let custom =
        KMAC128::new_with_params(&key, b"My Tagged Application", 32, false).unwrap().mac(b"abc");
    assert_ne!(plain, custom, "a customization string must change the output");
}

/// Streaming input must equal the one-shot, and `verify` must accept only the right tag.
#[test]
fn streaming_and_verification() {
    let key = key_material(&[0x11u8; 32]);
    let msg: Vec<u8> = (0..=255u8).collect();

    let one = KMAC128::new_with_params(&key, b"", 32, false).unwrap().mac(&msg);

    let mut k = KMAC128::new_with_params(&key, b"", 32, false).unwrap();
    for chunk in msg.chunks(13) {
        k.do_update(chunk);
    }
    assert_eq!(k.do_final(), one, "chunked input must equal the one-shot");

    assert!(
        KMAC128::new_with_params(&key, b"", 32, false).unwrap().verify(&msg, &one),
        "the correct tag must verify"
    );

    let mut wrong = one.clone();
    wrong[0] ^= 1;
    assert!(
        !KMAC128::new_with_params(&key, b"", 32, false).unwrap().verify(&msg, &wrong),
        "a corrupted tag must not verify"
    );
    assert!(
        !KMAC128::new_with_params(&key, b"", 32, false).unwrap().verify(&msg, &one[..16]),
        "a truncated tag must not verify"
    );
}

/// Sec 8.4.1 wants the key at least as long as the security strength; the tag on the key material
/// is how that is enforced, so a key tagged too weak must be refused unless explicitly allowed.
#[test]
fn weak_keys_are_refused_unless_allowed() {
    let weak = KeyMaterial::<16>::from_bytes_as_type(&[0x01u8; 16], KeyType::MACKey)
        .expect("a valid 16-byte MAC key");
    assert!(weak.security_strength() < bouncycastle_core::traits::SecurityStrength::_256bit);

    assert!(KMAC256::new(&weak).is_err(), "a 128-bit key must not instantiate KMAC256");
    assert!(KMAC256::new_allow_weak_key(&weak).is_ok(), "... unless explicitly allowed");
    assert!(KMAC128::new(&weak).is_ok(), "but it is enough for KMAC128");
}

/// The default constructor: no customization, nominal output length.
#[test]
fn default_constructor_uses_the_nominal_length() {
    let key = key_material(&[0x42u8; 32]);
    assert_eq!(KMAC128::new(&key).unwrap().output_len(), 32);
    assert_eq!(KMAC256::new(&key).unwrap().output_len(), 64);

    // ... and agrees with spelling the same thing out in full.
    assert_eq!(
        KMAC128::new(&key).unwrap().mac(b"abc"),
        KMAC128::new_with_params(&key, b"", 32, false).unwrap().mac(b"abc"),
    );
}

#[test]
fn algorithm_names() {
    assert_eq!(KMAC128::ALG_NAME, "KMAC128");
    assert_eq!(KMAC256::ALG_NAME, "KMAC256");
}
