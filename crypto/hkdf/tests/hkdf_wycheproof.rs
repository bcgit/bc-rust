//! Known-answer tests against Project Wycheproof's
//! `testvectors_v1/hkdf_sha{256,384,512}_test.json`. (`hkdf_sha1_test.json` has no counterpart
//! here.)
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the tests print a warning and pass, matching the convention used by the other vector
//! suites.
//!
//! A `valid` case must produce exactly `okm`. The only `invalid` cases ask for one byte more than
//! RFC 5869 Sec 2.3's limit of 255 * HashLen, which must be refused with `KDFError::InvalidLength`.

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Hash, HashAlgParams};
use bouncycastle_core_test_framework::test_data_loaders::wycheproof;
use bouncycastle_hex as hex;
use bouncycastle_hkdf::HKDF;
use bouncycastle_sha2::hkdf::{
    SUSPENDED_HKDF_SHA256_STATE_LEN, SUSPENDED_HKDF_SHA384_STATE_LEN,
    SUSPENDED_HKDF_SHA512_STATE_LEN,
};
use bouncycastle_sha2::{
    SHA256, SHA384, SHA512, SUSPENDED_SHA256_STATE_LEN, SUSPENDED_SHA512_STATE_LEN,
};
use serde_json::Value;

/// The longest IKM or salt in any of the files is 80 bytes.
const MAX_INPUT_LEN: usize = 80;
/// 255 * 64, the most HKDF-SHA-512 can produce.
const MAX_OKM_LEN: usize = 255 * 64;

fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

/// Runs every case in one `hkdf_*_test.json` file through `HKDF<H, ..>`. The state lengths are
/// those of `bouncycastle_sha2::hkdf`'s aliases, which cannot be passed as a type here.
fn run<
    H: Hash + HashAlgParams + Default,
    const HASH_STATE_LEN: usize,
    const HKDF_STATE_LEN: usize,
>(
    filename: &str,
    algorithm: &str,
) {
    let Some(contents) = wycheproof(filename) else { return };

    let doc: Value = serde_json::from_str(&contents).expect("valid wycheproof JSON");
    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some(algorithm), "{filename}");

    let (mut valid_count, mut invalid_count) = (0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let ctx = format!("{filename} tcId {tc_id}");
            let ikm = KeyMaterial::<MAX_INPUT_LEN>::from_bytes_as_type(
                &decode(test, "ikm", tc_id),
                KeyType::Seed,
            )
            .expect("ikm fits");
            // An empty salt is an absent one: a zero-length KeyMaterial.
            let salt = KeyMaterial::<MAX_INPUT_LEN>::from_bytes_as_type(
                &decode(test, "salt", tc_id),
                KeyType::MACKey,
            )
            .expect("salt fits");
            let info = decode(test, "info", tc_id);
            let size = test.get("size").and_then(Value::as_u64).expect("size") as usize;

            let mut okm = KeyMaterial::<MAX_OKM_LEN>::new();
            let result = HKDF::<H, HASH_STATE_LEN, HKDF_STATE_LEN>::extract_and_expand_out(
                &salt, &ikm, &info, size, &mut okm,
            );

            match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => {
                    let written = result.unwrap_or_else(|e| panic!("{ctx}: {e:?}"));
                    assert_eq!(written, size, "{ctx}: bytes written");
                    assert_eq!(okm.ref_to_bytes(), &decode(test, "okm", tc_id)[..], "{ctx}: okm");
                    valid_count += 1;
                }
                "invalid" => {
                    assert!(
                        matches!(result, Err(KDFError::InvalidLength(_))),
                        "{ctx}: expected InvalidLength, got {result:?}"
                    );
                    invalid_count += 1;
                }
                other => panic!("{ctx}: unexpected result {other}"),
            }
        }
    }

    println!("Wycheproof {algorithm}: {valid_count} valid and {invalid_count} invalid cases run");
    assert!(valid_count > 0 && invalid_count > 0, "{filename}: expected both valid and invalid");
}

#[test]
fn wycheproof_hkdf_sha256() {
    run::<SHA256, SUSPENDED_SHA256_STATE_LEN, SUSPENDED_HKDF_SHA256_STATE_LEN>(
        "hkdf_sha256_test.json", "HKDF-SHA-256",
    );
}

#[test]
fn wycheproof_hkdf_sha384() {
    run::<SHA384, SUSPENDED_SHA512_STATE_LEN, SUSPENDED_HKDF_SHA384_STATE_LEN>(
        "hkdf_sha384_test.json", "HKDF-SHA-384",
    );
}

#[test]
fn wycheproof_hkdf_sha512() {
    run::<SHA512, SUSPENDED_SHA512_STATE_LEN, SUSPENDED_HKDF_SHA512_STATE_LEN>(
        "hkdf_sha512_test.json", "HKDF-SHA-512",
    );
}
