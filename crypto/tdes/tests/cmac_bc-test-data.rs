//! Known-answer tests against the NIST ACVP `CMAC-TDES` vectors from the `bc-test-data` repo:
//! `CMAC-TDES.4014545` (keying option 1, three-key, generate and verify) and
//! `CMAC-TDES.4014546` (keying option 2, two-key, verify only), both through the generic
//! `bouncycastle_cipher::BlockCipherKey`, the one key with a MAC role over TDEA.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is missing, the test prints a warning and
//! passes without checking anything.
//!
//! The sets include 8-, 24- and 48-bit tags. A three-key case is computed as the full tag and
//! compared on its first `macLen` bits, with the full-length ones also going through the key's
//! `verify`. Two-key TDEA cannot generate a tag here (SP 800-131A Rev 2 Table 9, a compile-time
//! refusal), so its verify cases run through the key's `verify` alone, which takes the full
//! tag: the truncated two-key groups are counted and skipped.

use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::CMAC;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json, hex_field};
use bouncycastle_tdes::BLOCK_LEN;
use bouncycastle_tdes::hazmat::{TDES2Internal, TDESInternal};
use std::collections::BTreeMap;

const TEST_DATA_DIR: &str = "crypto/aes_tdes_vectors/CMAC";
const THREE_KEY: (&str, &str) = ("CMAC-TDES.4014545.req.json", "CMAC-TDES.4014545.rsp.json");
const TWO_KEY: (&str, &str) = ("CMAC-TDES.4014546.req.json", "CMAC-TDES.4014546.rsp.json");

fn three_key(key: &[u8]) -> BlockCipherKey<TDESInternal, CMAC<BLOCK_LEN>> {
    let material = KeyMaterial::<24>::from_bytes_as_type(key, KeyType::MACKey).unwrap();
    BlockCipherKey::from_key_material(&material).unwrap()
}

/// The two-key bundle is `Key1 || Key2`; the file carries `Key3 = Key1` as well.
fn two_key(key: &[u8]) -> BlockCipherKey<TDES2Internal, CMAC<BLOCK_LEN>> {
    let material = KeyMaterial::<16>::from_bytes_as_type(&key[..16], KeyType::MACKey).unwrap();
    BlockCipherKey::from_key_material(&material).unwrap()
}

fn answers(rsp: &Value) -> BTreeMap<u64, Value> {
    let mut answers = BTreeMap::new();
    for group in rsp[1]["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            answers.insert(test["tcId"].as_u64().unwrap(), test.clone());
        }
    }
    answers
}

#[test]
fn acvp_cmac_tdes_three_key() {
    let Some(req) = bc_test_data_json(TEST_DATA_DIR, THREE_KEY.0) else { return };
    let Some(rsp) = bc_test_data_json(TEST_DATA_DIR, THREE_KEY.1) else { return };
    let answers = answers(&rsp);

    let (mut generated, mut verified, mut rejected) = (0usize, 0usize, 0usize);
    for group in req[1]["testGroups"].as_array().unwrap() {
        assert_eq!(group["keyingOption"].as_u64().unwrap(), 1);
        let mac_len = (group["macLen"].as_u64().unwrap() / 8) as usize;
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let answer = &answers[&tc_id];
            let key = three_key(&hex_field(test, "key", tc_id));
            let msg = hex_field(test, "message", tc_id);
            let full = key.mac(&msg);
            match group["direction"].as_str().unwrap() {
                "gen" => {
                    assert_eq!(
                        full[..mac_len],
                        hex_field(answer, "mac", tc_id)[..],
                        "tcId {tc_id}"
                    );
                    generated += 1;
                }
                "ver" => {
                    let passed = answer["testPassed"].as_bool().unwrap();
                    let tag = hex_field(test, "mac", tc_id);
                    assert_eq!(full[..mac_len] == tag[..], passed, "tcId {tc_id}");
                    if let Ok(tag) = <&[u8; BLOCK_LEN]>::try_from(tag.as_slice()) {
                        assert_eq!(key.verify(&msg, tag).is_ok(), passed, "tcId {tc_id}");
                    }
                    if passed { verified += 1 } else { rejected += 1 }
                }
                other => panic!("unexpected direction {other}"),
            }
        }
    }
    println!(
        "ACVP CMAC-TDES three-key: {generated} gen, {verified} ver passed, {rejected} ver rejected"
    );
    assert_eq!(generated, 72);
    assert_eq!(verified + rejected, 180);
    assert!(verified > 0 && rejected > 0);
}

#[test]
fn acvp_cmac_tdes_two_key_verifies() {
    let Some(req) = bc_test_data_json(TEST_DATA_DIR, TWO_KEY.0) else { return };
    let Some(rsp) = bc_test_data_json(TEST_DATA_DIR, TWO_KEY.1) else { return };
    let answers = answers(&rsp);

    let (mut verified, mut rejected, mut truncated) = (0usize, 0usize, 0usize);
    for group in req[1]["testGroups"].as_array().unwrap() {
        assert_eq!(group["keyingOption"].as_u64().unwrap(), 2);
        assert_eq!(group["direction"].as_str().unwrap(), "ver");
        if group["macLen"].as_u64().unwrap() != 8 * BLOCK_LEN as u64 {
            truncated += group["tests"].as_array().unwrap().len();
            continue;
        }
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let passed = answers[&tc_id]["testPassed"].as_bool().unwrap();
            let key = two_key(&hex_field(test, "key", tc_id));
            let msg = hex_field(test, "message", tc_id);
            let tag: [u8; BLOCK_LEN] = hex_field(test, "mac", tc_id).try_into().unwrap();
            assert_eq!(key.verify(&msg, &tag).is_ok(), passed, "tcId {tc_id}");
            if passed { verified += 1 } else { rejected += 1 }
        }
    }
    println!(
        "ACVP CMAC-TDES two-key: {verified} ver passed, {rejected} ver rejected, {truncated} truncated-tag cases skipped"
    );
    assert_eq!(verified + rejected, 60);
    assert_eq!(truncated, 120);
    assert!(verified > 0 && rejected > 0);
}
