//! Known-answer tests against Project Wycheproof's `testvectors_v1/hmac_*_test.json` for every
//! HMAC this library instantiates: SHA-224/256/384/512, SHA-512/224, SHA-512/256,
//! SHA3-224/256/384/512 and SM3. (`hmac_sha1_test.json` has no counterpart here.)
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the tests print a warning and pass, matching the convention used by the other vector
//! suites.
//!
//! Each file has a full-length-tag group and a truncated-tag group (half the output length). A
//! full-length tag is checked through `verify`. A truncated tag is checked through `mac_out` into a
//! buffer of the tag's length, and `verify` must reject it: it requires the full output length.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::MAC;
use bouncycastle_core_test_framework::test_data_loaders::wycheproof;
use bouncycastle_hex as hex;
use bouncycastle_sha2::hmac::{
    HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512, HMAC_SHA512_224, HMAC_SHA512_256,
};
use bouncycastle_sha3::hmac::{HMAC_SHA3_224, HMAC_SHA3_256, HMAC_SHA3_384, HMAC_SHA3_512};
use bouncycastle_sm3::hmac::HMAC_SM3;
use serde_json::Value;

/// The longest key in any of the files is 65 bytes.
const MAX_KEY_LEN: usize = 128;

fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

/// Runs every case in one `hmac_*_test.json` file through `M`.
fn run<M: MAC>(filename: &str, algorithm: &str) {
    let Some(contents) = wycheproof(filename) else { return };

    let doc: Value = serde_json::from_str(&contents).expect("valid wycheproof JSON");
    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some(algorithm), "{filename}");

    let (mut full, mut truncated, mut invalid) = (0usize, 0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        let tag_len = group.get("tagSize").and_then(Value::as_u64).expect("tagSize") as usize / 8;

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let msg = decode(test, "msg", tc_id);
            let tag = decode(test, "tag", tc_id);
            let valid = match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => true,
                "invalid" => false,
                other => panic!("{filename} tcId {tc_id}: unexpected result {other}"),
            };
            // Some keys are shorter than the hash's security strength (128-bit keys for
            // HMAC-SHA-512, say); the key-strength policy is tested in `hmac_tests.rs`.
            let key = KeyMaterial::<MAX_KEY_LEN>::from_bytes_as_type(
                &decode(test, "key", tc_id),
                KeyType::MACKey,
            )
            .expect("a MAC key");
            let mac = || M::new_allow_weak_key(&key).expect("an HMAC instance");

            let ctx = format!("{filename} tcId {tc_id}");
            if tag_len == mac().output_len() {
                assert_eq!(mac().verify(&msg, &tag), valid, "{ctx}: verify");
                if valid {
                    assert_eq!(mac().mac(&msg), tag, "{ctx}: mac");
                }
                full += 1;
            } else {
                let mut out = vec![0u8; tag_len];
                assert_eq!(mac().mac_out(&msg, &mut out).expect("mac_out"), tag_len, "{ctx}");
                assert_eq!(out == tag, valid, "{ctx}: truncated mac_out");
                assert!(!mac().verify(&msg, &tag), "{ctx}: verify takes only a full-length tag");
                truncated += 1;
            }
            invalid += usize::from(!valid);
        }
    }

    println!(
        "Wycheproof {algorithm}: {} cases ({full} full-length, {truncated} truncated; \
         {invalid} invalid)",
        full + truncated
    );
    assert!(full > 0 && truncated > 0 && invalid > 0, "{filename}: expected every kind of case");
}

#[test]
fn wycheproof_hmac_sha224() {
    run::<HMAC_SHA224>("hmac_sha224_test.json", "HMACSHA224");
}

#[test]
fn wycheproof_hmac_sha256() {
    run::<HMAC_SHA256>("hmac_sha256_test.json", "HMACSHA256");
}

#[test]
fn wycheproof_hmac_sha384() {
    run::<HMAC_SHA384>("hmac_sha384_test.json", "HMACSHA384");
}

#[test]
fn wycheproof_hmac_sha512() {
    run::<HMAC_SHA512>("hmac_sha512_test.json", "HMACSHA512");
}

#[test]
fn wycheproof_hmac_sha512_224() {
    run::<HMAC_SHA512_224>("hmac_sha512_224_test.json", "HMACSHA512/224");
}

#[test]
fn wycheproof_hmac_sha512_256() {
    run::<HMAC_SHA512_256>("hmac_sha512_256_test.json", "HMACSHA512/256");
}

#[test]
fn wycheproof_hmac_sha3_224() {
    run::<HMAC_SHA3_224>("hmac_sha3_224_test.json", "HMACSHA3-224");
}

#[test]
fn wycheproof_hmac_sha3_256() {
    run::<HMAC_SHA3_256>("hmac_sha3_256_test.json", "HMACSHA3-256");
}

#[test]
fn wycheproof_hmac_sha3_384() {
    run::<HMAC_SHA3_384>("hmac_sha3_384_test.json", "HMACSHA3-384");
}

#[test]
fn wycheproof_hmac_sha3_512() {
    run::<HMAC_SHA3_512>("hmac_sha3_512_test.json", "HMACSHA3-512");
}

#[test]
fn wycheproof_hmac_sm3() {
    run::<HMAC_SM3>("hmac_sm3_test.json", "HMACSM3");
}
