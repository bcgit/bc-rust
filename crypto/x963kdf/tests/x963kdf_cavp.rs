//! NIST CAVP "ANS X9.63-2001" KDF component vectors (SP 800-135 test vectors, `ansx963_2001.rsp`
//! in `bc-test-data/crypto/cavp/`): every `[SHA-224]`, `[SHA-256]`, `[SHA-384]` and `[SHA-512]`
//! record, with `Z` as the shared secret, `SharedInfo` as the shared info and `key_data` the
//! expected keying data at the section's length. The `[SHA-1]` sections are not read: the library
//! has no SHA-1. A missing `bc-test-data` checkout fails the test rather than skipping it.

use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_x963kdf::{X963KDF_SHA224, X963KDF_SHA256, X963KDF_SHA384, X963KDF_SHA512};

fn get_test_data(filename: &str) -> String {
    bc_test_data("crypto/cavp", filename).unwrap_or_else(|| {
        panic!("bc-test-data not found beside this repository; the X9.63 KDF CAVP suite requires it rather than skipping")
    })
}

struct Record {
    hash: String,
    count: String,
    z: Vec<u8>,
    shared_info: Vec<u8>,
    key_data: Vec<u8>,
}

/// The records, each under the most recent `[SHA-*]` header; the length headers are implied by
/// the values and only checked against them.
fn parse(content: &str) -> Vec<Record> {
    let mut out = Vec::new();
    let mut hash = String::new();
    let (mut count, mut z, mut info) = (None, None, None);
    for raw in content.lines() {
        let line = raw.trim();
        if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if inner.starts_with("SHA-") {
                hash = inner.to_string();
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "COUNT" => count = Some(v.to_string()),
            "Z" => z = Some(bouncycastle_hex::decode(v).unwrap()),
            "SharedInfo" => {
                info = Some(if v.is_empty() {
                    Vec::new()
                } else {
                    bouncycastle_hex::decode(v).unwrap()
                })
            }
            "key_data" => out.push(Record {
                hash: hash.clone(),
                count: count.take().unwrap(),
                z: z.take().unwrap(),
                shared_info: info.take().unwrap(),
                key_data: bouncycastle_hex::decode(v).unwrap(),
            }),
            _ => {}
        }
    }
    out
}

#[test]
fn cavp_ansx963_2001() {
    let records = parse(&get_test_data("ansx963_2001.rsp"));
    let mut checked = 0usize;
    for r in &records {
        // Z is 192 or 521 bits; typed as the shared secret of a key agreement.
        let z = KeyMaterial::<128>::from_bytes_as_type(&r.z, KeyType::SharedSecret).unwrap();
        let len = r.key_data.len();
        let mut out = KeyMaterial::<128>::new();
        let written = match r.hash.as_str() {
            "SHA-1" => continue,
            "SHA-224" => X963KDF_SHA224::derive_out(&z, &r.shared_info, len, &mut out),
            "SHA-256" => X963KDF_SHA256::derive_out(&z, &r.shared_info, len, &mut out),
            "SHA-384" => X963KDF_SHA384::derive_out(&z, &r.shared_info, len, &mut out),
            "SHA-512" => X963KDF_SHA512::derive_out(&z, &r.shared_info, len, &mut out),
            other => panic!("unexpected hash section {other}"),
        }
        .unwrap_or_else(|e| panic!("{} COUNT {}: {e:?}", r.hash, r.count));
        assert_eq!(written, len);
        assert_eq!(out.ref_to_bytes(), r.key_data.as_slice(), "{} COUNT {}", r.hash, r.count);
        checked += 1;
    }
    assert_eq!(checked, 80, "four hashes, two sections of ten records each");
}
