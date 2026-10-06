//! Known-answer tests against Project Wycheproof's
//! `testvectors_v1/kmac{128,256}_no_customization_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the tests print a warning and pass, matching the convention used by the other vector
//! suites.
//!
//! Every case uses an empty customization string and asks for the group's `tagSize` as the output
//! length. KMAC binds that length into its input (SP 800-185 Sec 4.3), so each tag is a full-length
//! KMAC of that size and goes through `verify`, as well as through `mac` for the valid ones.

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::MAC;
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_sha3::kmac::{KMAC128, KMAC256};

/// The longest key in either file is 129 bytes.
const MAX_KEY_LEN: usize = 160;

/// Runs every case in one KMAC file; `new_kmac(key, output_len)` builds the KMAC under test.
fn run<M: MAC>(
    filename: &str,
    algorithm: &str,
    new_kmac: impl Fn(&KeyMaterial<MAX_KEY_LEN>, usize) -> M,
) {
    let Some(doc) = wycheproof_json(filename) else { return };

    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some(algorithm), "{filename}");

    let (mut valid_count, mut invalid_count) = (0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        let tag_len = group.get("tagSize").and_then(Value::as_u64).expect("tagSize") as usize / 8;

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

            match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => {
                    assert_eq!(new_kmac(&key, tag_len).mac(&msg), tag, "{ctx}: mac");
                    assert!(new_kmac(&key, tag_len).verify(&msg, &tag), "{ctx}: verify");
                    valid_count += 1;
                }
                "invalid" => {
                    assert!(!new_kmac(&key, tag_len).verify(&msg, &tag), "{ctx}: verify");
                    invalid_count += 1;
                }
                other => panic!("{ctx}: unexpected result {other}"),
            }
        }
    }

    println!("Wycheproof {algorithm}: {valid_count} valid and {invalid_count} invalid cases run");
    assert!(valid_count > 0 && invalid_count > 0, "{filename}: expected both valid and invalid");
}

// Every key in these files is at least 256 bits, so neither needs the weak-key escape hatch.

#[test]
fn wycheproof_kmac128() {
    run("kmac128_no_customization_test.json", "KMAC128", |key, output_len| {
        KMAC128::new_with_params(key, b"", output_len, false).expect("a KMAC128 instance")
    });
}

#[test]
fn wycheproof_kmac256() {
    run("kmac256_no_customization_test.json", "KMAC256", |key, output_len| {
        KMAC256::new_with_params(key, b"", output_len, false).expect("a KMAC256 instance")
    });
}
