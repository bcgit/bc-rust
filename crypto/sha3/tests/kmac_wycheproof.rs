//! Known-answer tests against Project Wycheproof's
//! `testvectors_v1/kmac{128,256}_no_customization_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the tests print a warning and pass, matching the convention used by the other vector
//! suites.
//!
//! Every case uses an empty customization string and asks for the group's `tagSize` as the output
//! length. KMAC binds that length into its input (SP 800-185 Sec 4.3), so each group runs through
//! a key type of that length, and each tag goes through `verify`, as well as through `mac` for the
//! valid ones.

use bouncycastle_core::errors::MACError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{MacGenerationKey, MacVerificationKey};
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_sha3::kmac::{KMAC128Key, KMAC256Key};

/// The longest key in either file is 129 bytes.
const MAX_KEY_LEN: usize = 160;

/// Runs every case in one group of a KMAC file at the group's tag length; `new_kmac(key)` builds
/// the KMAC key under test. Returns the valid and invalid counts.
fn run_group<const N: usize, K>(
    group: &Value,
    filename: &str,
    new_kmac: impl Fn(&KeyMaterial<MAX_KEY_LEN>) -> K,
) -> (usize, usize)
where
    K: MacGenerationKey<N> + MacVerificationKey<N>,
{
    let (mut valid_count, mut invalid_count) = (0usize, 0usize);
    for test in group.get("tests").and_then(Value::as_array).expect("tests") {
        let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
        let ctx = format!("{filename} tcId {tc_id}");
        let key = KeyMaterial::<MAX_KEY_LEN>::from_bytes_as_type(
            &hex_field(test, "key", tc_id),
            KeyType::MACKey,
        )
        .expect("a MAC key");
        let msg = hex_field(test, "msg", tc_id);
        let tag = hex_field(test, "tag", tc_id);
        // A tag of another length can never verify: the length is the key type's.
        let Ok(tag) = <[u8; N]>::try_from(tag.as_slice()) else {
            assert_ne!(
                test.get("result").and_then(Value::as_str),
                Some("valid"),
                "{ctx}: a valid tag of the wrong length"
            );
            invalid_count += 1;
            continue;
        };

        match test.get("result").and_then(Value::as_str).expect("result") {
            "valid" => {
                assert_eq!(new_kmac(&key).mac(&msg), tag, "{ctx}: mac");
                assert_eq!(new_kmac(&key).verify(&msg, &tag), Ok(()), "{ctx}: verify");
                valid_count += 1;
            }
            "invalid" => {
                assert_eq!(
                    new_kmac(&key).verify(&msg, &tag),
                    Err(MACError::VerificationFailed),
                    "{ctx}: verify"
                );
                invalid_count += 1;
            }
            other => panic!("{ctx}: unexpected result {other}"),
        }
    }
    (valid_count, invalid_count)
}

/// The file's groups: a `tagSize` of 128, 256 or 512 bits, each through the key type of that
/// length.
fn run(filename: &str, algorithm: &str, strength: usize) {
    let Some(doc) = wycheproof_json(filename) else { return };

    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some(algorithm), "{filename}");

    let (mut valid_count, mut invalid_count) = (0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        let tag_len = group.get("tagSize").and_then(Value::as_u64).expect("tagSize") as usize / 8;
        // Every key in these files is at least 256 bits, so neither needs the weak-key escape
        // hatch.
        let (v, i) = match (strength, tag_len) {
            (128, 16) => run_group::<16, _>(group, filename, |k| {
                KMAC128Key::<16>::with_params(k, b"").expect("a KMAC128 key")
            }),
            (128, 32) => run_group::<32, _>(group, filename, |k| {
                KMAC128Key::<32>::with_params(k, b"").expect("a KMAC128 key")
            }),
            (256, 16) => run_group::<16, _>(group, filename, |k| {
                KMAC256Key::<16>::with_params(k, b"").expect("a KMAC256 key")
            }),
            (256, 32) => run_group::<32, _>(group, filename, |k| {
                KMAC256Key::<32>::with_params(k, b"").expect("a KMAC256 key")
            }),
            (256, 64) => run_group::<64, _>(group, filename, |k| {
                KMAC256Key::<64>::with_params(k, b"").expect("a KMAC256 key")
            }),
            other => panic!("{filename}: unexpected (strength, tagSize) {other:?}"),
        };
        valid_count += v;
        invalid_count += i;
    }

    println!("Wycheproof {algorithm}: {valid_count} valid and {invalid_count} invalid cases run");
    assert!(valid_count > 0 && invalid_count > 0, "{filename}: expected both valid and invalid");
}

#[test]
fn wycheproof_kmac128() {
    run("kmac128_no_customization_test.json", "KMAC128", 128);
}

#[test]
fn wycheproof_kmac256() {
    run("kmac256_no_customization_test.json", "KMAC256", 256);
}
