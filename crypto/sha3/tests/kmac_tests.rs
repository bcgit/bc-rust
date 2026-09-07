//! KMAC against the NIST SP 800-185 sample values.
//!
//! Vectors come from the `bc-test-data` repo cloned alongside this one; see `cshake_tests.rs`.

use bouncycastle_core::errors::{KeyMaterialError, MACError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, Hash, MAC, XOF};
use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
use bouncycastle_hex as hex;
use bouncycastle_sha3::{KMAC128, KMAC256, KMACXOF128, KMACXOF256};
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
            128 => KMACXOF128::new(&key, v.s.as_bytes(), false)
                .expect("a valid key")
                .hash_xof(&v.msg, want),
            256 => KMACXOF256::new(&key, v.s.as_bytes(), false)
                .expect("a valid key")
                .hash_xof(&v.msg, want),
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

/// The counterpart to `output_length_changes_the_function`: because KMACXOF binds
/// `right_encode(0)` rather than the length, output at one length *is* a prefix of output at a
/// longer one, and `do_final` is simply the first `output_len` bytes of that same stream.
#[test]
fn kmacxof_output_is_one_stream() {
    let key = key_material(&[0x42u8; 32]);
    let long = KMACXOF128::new(&key, b"", false).unwrap().hash_xof(b"abc", 64);

    let short = KMACXOF128::new(&key, b"", false).unwrap().hash_xof(b"abc", 16);
    assert_eq!(&long[..16], &short[..], "KMACXOF at a shorter length must be a prefix");

    let mut k = KMACXOF128::new(&key, b"", false).unwrap();
    k.do_update(b"abc");
    let via_hash = k.do_final();
    assert_eq!(via_hash.len(), 32, "the nominal output length");
    assert_eq!(&long[..32], &via_hash[..], "do_final must be a prefix of the stream");
}

/// A partial final byte cannot be expressed: `right_encode(0)` has to follow the message, and the
/// sponge cannot absorb byte-aligned data after a partial byte.
#[test]
fn kmacxof_rejects_a_partial_final_byte() {
    let key = key_material(&[0x42u8; 32]);
    let mut k = KMACXOF128::new(&key, b"", false).unwrap();
    k.do_update(b"abc");
    assert!(matches!(
        k.into_output_partial_bits(0xF0, 4),
        Err(bouncycastle_core::errors::HashError::InvalidLength(_))
    ));

    // ... but zero bits means the message ended on a byte boundary, which is fine.
    let mut k = KMACXOF128::new(&key, b"", false).unwrap();
    k.do_update(b"abc");
    assert!(k.into_output_partial_bits(0, 0).is_ok());
}

#[test]
fn kmacxof_algorithm_names() {
    assert_eq!(KMACXOF128::ALG_NAME, "KMACXOF128");
    assert_eq!(KMACXOF256::ALG_NAME, "KMACXOF256");
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
    framework.test_xof(
        || KMACXOF128::new(&key, v.s.as_bytes(), false).expect("a valid key"),
        &v.msg,
        &v.output,
    );
}

/// `mac_out` and `do_final_out` against one sample value. The sample-value test above goes through
/// `mac` only, so these two, their returned lengths, and the buffer-length check in `do_final_out`
/// were all invisible to `cargo mutants`.
fn check_out_variants<M: MAC>(make: impl Fn() -> M, msg: &[u8], expected: &[u8], ctx: &str) {
    let n = expected.len();

    let mut out = vec![0xFFu8; n];
    assert_eq!(make().mac_out(msg, &mut out).unwrap(), n, "{ctx}: mac_out returns the length");
    assert_eq!(out, expected, "{ctx}: mac_out");

    // mac_out zero-fills the whole buffer first, so a longer one ends in zeros
    let mut out = vec![0xFFu8; n + 5];
    assert_eq!(make().mac_out(msg, &mut out).unwrap(), n);
    assert_eq!(&out[..n], expected, "{ctx}: mac_out, oversized buffer");
    assert_eq!(&out[n..], &[0u8; 5], "{ctx}: mac_out zeroizes past the tag");

    let mut m = make();
    msg.chunks(7).for_each(|c| m.do_update(c));
    let mut out = vec![0xFFu8; n];
    assert_eq!(m.do_final_out(&mut out).unwrap(), n, "{ctx}: do_final_out returns the length");
    assert_eq!(out, expected, "{ctx}: do_final_out");

    // do_final_out writes exactly output_len bytes and leaves the rest alone
    let mut m = make();
    m.do_update(msg);
    let mut out = vec![0xFFu8; n + 5];
    assert_eq!(m.do_final_out(&mut out).unwrap(), n);
    assert_eq!(&out[..n], expected, "{ctx}: do_final_out, oversized buffer");
    assert_eq!(&out[n..], &[0xFFu8; 5], "{ctx}: do_final_out leaves bytes past the tag");

    // a buffer one byte short is refused, by both
    let mut out = vec![0u8; n - 1];
    assert!(
        matches!(make().do_final_out(&mut out), Err(MACError::InvalidLength(_))),
        "{ctx}: do_final_out must refuse a short buffer"
    );
    assert!(
        matches!(make().mac_out(msg, &mut out), Err(MACError::InvalidLength(_))),
        "{ctx}: mac_out must refuse a short buffer"
    );
}

#[test]
fn mac_out_and_do_final_out_agree_with_the_sample_values() {
    let Some(vectors) = read_vectors("KMAC.rsp") else { return };
    for (i, v) in vectors.iter().enumerate() {
        let n = v.output_len / 8;
        let key = key_material(&v.key);
        let s = v.s.as_bytes();
        let ctx = format!("COUNT {i}: KMAC{} S={:?}", v.strength, v.s);
        match v.strength {
            128 => check_out_variants(
                || KMAC128::new_with_params(&key, s, n, false).unwrap(),
                &v.msg,
                &v.output,
                &ctx,
            ),
            256 => check_out_variants(
                || KMAC256::new_with_params(&key, s, n, false).unwrap(),
                &v.msg,
                &v.output,
                &ctx,
            ),
            other => panic!("COUNT {i}: unexpected strength {other}"),
        }
    }
}

/// `new_allow_weak_key` is `new` without the strength check: same customization, same nominal
/// length, same tag.
#[test]
fn new_allow_weak_key_uses_the_nominal_length() {
    let key = key_material(&[0x42u8; 32]);

    let k = KMAC128::new_allow_weak_key(&key).unwrap();
    assert_eq!(k.output_len(), 32);
    assert_eq!(k.mac(b"abc"), KMAC128::new(&key).unwrap().mac(b"abc"));

    let k = KMAC256::new_allow_weak_key(&key).unwrap();
    assert_eq!(k.output_len(), 64);
    assert_eq!(k.mac(b"abc"), KMAC256::new(&key).unwrap().mac(b"abc"));
}

/// The same stance as HMAC: a key tagged `MACKey` or `Zeroized` is accepted, anything else is
/// refused as the wrong type. A zeroized key carries no security strength, so it also needs
/// `allow_weak_key`.
#[test]
fn key_type_is_checked() {
    let cipher_key =
        KeyMaterial::<32>::from_bytes_as_type(&[0x42u8; 32], KeyType::SymmetricCipherKey).unwrap();
    assert!(matches!(
        KMAC128::new(&cipher_key),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(matches!(
        KMAC128::new_with_params(&cipher_key, b"", 32, true),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(matches!(
        KMACXOF128::new(&cipher_key, b"", true),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));

    let zero = KeyMaterial::<32>::new();
    assert_eq!(zero.key_type(), KeyType::Zeroized);
    assert!(KMAC128::new(&zero).is_err(), "a zeroized key has no security strength");
    assert!(KMAC128::new_with_params(&zero, b"", 32, true).is_ok(), "... but is the right type");
    assert!(KMAC128::new_allow_weak_key(&zero).is_ok());
    assert!(KMACXOF128::new(&zero, b"", true).is_ok());
}

/// The `Hash` view of the partial-byte entry points on KMACXOF: zero bits is the byte-aligned case
/// and yields the same bytes as `do_final`; anything else is refused. The test above only covers
/// the `XOF` entry point, `into_output_partial_bits`.
#[test]
fn kmacxof_hash_view_partial_bits() {
    let key = key_material(&[0x42u8; 32]);
    let fresh = || {
        let mut k = KMACXOF128::new(&key, b"", false).unwrap();
        k.do_update(b"abc");
        k
    };
    let expected = fresh().do_final();
    assert_eq!(expected.len(), 32);

    assert_eq!(fresh().do_final_partial_bits(0, 0).unwrap(), expected);
    let mut out = vec![0u8; 32];
    assert_eq!(fresh().do_final_partial_bits_out(0, 0, &mut out).unwrap(), 32);
    assert_eq!(out, expected);

    assert!(matches!(
        fresh().do_final_partial_bits(0xF0, 4),
        Err(bouncycastle_core::errors::HashError::InvalidLength(_))
    ));
    assert!(matches!(
        fresh().do_final_partial_bits_out(0xF0, 4, &mut out),
        Err(bouncycastle_core::errors::HashError::InvalidLength(_))
    ));
}
