//! NIST SP 800-232 known-answer test (KAT) vectors for Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128
//! and Ascon-CXOF128.
//!
//! Vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data), which must be
//! cloned alongside this repo at "../bc-test-data", under `crypto/ascon/<variant>/`. If it is not
//! present the tests print a warning and pass vacuously.
//!
//! These full sweeps (1025–1089 cases each) complement the small embedded vector sets in the
//! per-primitive test files.

use bouncycastle_ascon::AsconAead128;
use bouncycastle_ascon::AsconCXof128;
use bouncycastle_ascon::AsconHash256;
use bouncycastle_ascon::AsconXof128;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Hash, XOF};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use std::collections::BTreeMap;

const TEST_DATA_DIR: &str = "crypto/ascon";

fn decode_hex(value: &str) -> Vec<u8> {
    let clean = value.trim();

    if clean.is_empty() { Vec::new() } else { hex::decode(clean).expect("valid hex") }
}

/// Parse a NIST LWC KAT file: blank-line-delimited `Tag = Value` cases.
fn parse_kat(contents: &str) -> Vec<BTreeMap<String, String>> {
    let mut cases = Vec::new();
    let mut current = BTreeMap::new();

    for raw in contents.lines() {
        let line = raw.trim();

        if line.is_empty() {
            if !current.is_empty() {
                cases.push(std::mem::take(&mut current));
            }
            continue;
        }

        if line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();

            if key == "Count" && !current.is_empty() {
                cases.push(std::mem::take(&mut current));
            }

            current.insert(key, value);
        }
    }

    if !current.is_empty() {
        cases.push(current);
    }

    cases
}

fn field<'a>(case: &'a BTreeMap<String, String>, names: &[&str]) -> &'a str {
    for name in names {
        if let Some(v) = case.get(*name) {
            return v.as_str();
        }
    }

    panic!("missing field {names:?}; case had {:?}", case.keys().collect::<Vec<_>>());
}

fn to_16(bytes: &[u8], what: &str) -> [u8; 16] {
    bytes.try_into().unwrap_or_else(|_| panic!("{what} must be 16 bytes, got {}", bytes.len()))
}

/// Build a `KeyMaterial<16>` for a KAT key. The NIST LWC vectors include an all-zero key
/// (Count=1), which `KeyMaterial::from_bytes_as_type` would otherwise tag
/// `KeyType::Zeroized` / `SecurityStrength::None`; force the type/strength the way a caller
/// who knows the provenance of the key would (see `cli/src/helpers.rs::parse_seed`).
fn key_material(key: &[u8; 16]) -> KeyMaterial<16> {
    let mut km = KeyMaterial::<16>::from_bytes_as_type(key, KeyType::SymmetricCipherKey).unwrap();

    do_hazardous_operations(&mut km, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(SecurityStrength::_128bit)
    })
    .unwrap();

    km
}

#[test]
fn ascon_aead128_kat() {
    let Some(contents) = bc_test_data(TEST_DATA_DIR, "asconaead128/LWC_AEAD_KAT_128_128.txt")
    else {
        return;
    };

    let cases = parse_kat(&contents);
    assert!(!cases.is_empty(), "no AEAD cases parsed");

    for case in &cases {
        let key = key_material(&to_16(&decode_hex(field(case, &["Key", "K"])), "key"));
        let nonce = to_16(&decode_hex(field(case, &["Nonce", "N"])), "nonce");
        let ad = decode_hex(field(case, &["AD", "A"]));
        let pt = decode_hex(field(case, &["PT", "P"]));
        let expected_ct = decode_hex(field(case, &["CT", "C"]));

        let ad_opt = if ad.is_empty() { None } else { Some(ad.as_slice()) };

        // One-shot encrypt.
        let mut ct = vec![0u8; pt.len() + 16];
        let n = AsconAead128::encrypt(&key, &nonce, ad_opt, &pt, &mut ct).unwrap();
        ct.truncate(n);

        assert_eq!(ct, expected_ct, "encrypt mismatch (Count {})", field(case, &["Count"]));

        // One-shot decrypt round-trip.
        let mut pt_out = vec![0u8; expected_ct.len()];
        let m = AsconAead128::decrypt(&key, &nonce, ad_opt, &expected_ct, &mut pt_out)
            .expect("decrypt should authenticate");

        pt_out.truncate(m);

        assert_eq!(pt_out, pt, "decrypt mismatch (Count {})", field(case, &["Count"]));

        // Byte-at-a-time streaming encrypt/decrypt, through the inherent API.
        let mut enc = AsconAead128::new_encrypting(&key, &nonce, ad_opt).unwrap();
        let mut stream_ct = pt.clone();

        for byte in stream_ct.iter_mut() {
            enc.do_encrypt_update(core::slice::from_mut(byte));
        }

        let tag = enc.do_encrypt_final();
        stream_ct.extend_from_slice(&tag);

        assert_eq!(
            stream_ct,
            expected_ct,
            "streaming encrypt mismatch (Count {})",
            field(case, &["Count"])
        );

        let mut dec = AsconAead128::new_decrypting(&key, &nonce, ad_opt).unwrap();
        let mut stream_pt = expected_ct[..pt.len()].to_vec();

        for byte in stream_pt.iter_mut() {
            dec.do_decrypt_update(core::slice::from_mut(byte));
        }

        dec.do_decrypt_final(&tag).expect("streaming decrypt should authenticate");

        assert_eq!(stream_pt, pt, "streaming decrypt mismatch (Count {})", field(case, &["Count"]));
    }

    println!("Ascon-AEAD128: {} KAT cases passed", cases.len());
}

#[test]
fn ascon_hash256_kat() {
    let Some(contents) = bc_test_data(TEST_DATA_DIR, "asconhash256/LWC_HASH_KAT_256.txt") else {
        return;
    };

    let cases = parse_kat(&contents);
    assert!(!cases.is_empty(), "no Hash256 cases parsed");

    for case in &cases {
        let msg = decode_hex(field(case, &["Msg"]));
        let expected = decode_hex(field(case, &["MD"]));

        assert_eq!(
            AsconHash256::new().hash(&msg),
            expected,
            "Hash256 mismatch (Count {})",
            field(case, &["Count"])
        );
    }

    println!("Ascon-Hash256: {} KAT cases passed", cases.len());
}

#[test]
fn ascon_xof128_kat() {
    let Some(contents) = bc_test_data(TEST_DATA_DIR, "asconxof128/LWC_XOF_KAT_128_512.txt") else {
        return;
    };

    let cases = parse_kat(&contents);
    assert!(!cases.is_empty(), "no XOF128 cases parsed");

    for case in &cases {
        let msg = decode_hex(field(case, &["Msg"]));
        let expected = decode_hex(field(case, &["MD", "Output"]));

        let got = AsconXof128::new().xof(&msg, expected.len());

        assert_eq!(got, expected, "XOF128 mismatch (Count {})", field(case, &["Count"]));
    }

    println!("Ascon-XOF128: {} KAT cases passed", cases.len());
}

#[test]
fn ascon_cxof128_kat() {
    let Some(contents) = bc_test_data(TEST_DATA_DIR, "asconcxof128/LWC_CXOF_KAT_128_512.txt")
    else {
        return;
    };

    let cases = parse_kat(&contents);
    assert!(!cases.is_empty(), "no CXOF128 cases parsed");

    for case in &cases {
        let msg = decode_hex(field(case, &["Msg"]));
        let z = decode_hex(field(case, &["Z", "Customization"]));
        let expected = decode_hex(field(case, &["MD", "Output"]));

        let got = AsconCXof128::with_customization(&z).unwrap().xof(&msg, expected.len());

        assert_eq!(got, expected, "CXOF128 mismatch (Count {})", field(case, &["Count"]));
    }

    println!("Ascon-CXOF128: {} KAT cases passed", cases.len());
}
