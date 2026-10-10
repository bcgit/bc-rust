//! Known-answer tests against the NIST ACVP `CMAC-AES` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is missing, the test prints a warning and
//! passes without checking anything.
//!
//! The set includes 8- and 56-bit tags, below the `CMAC_MIN_TAG_LEN` that `mac_out` will truncate
//! to, so every case is computed as a full tag and compared on its first `macLen` bits.

use bouncycastle_aes::{AES_CMAC_128, AES_CMAC_192, AES_CMAC_256};
use bouncycastle_core::traits::MAC;
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json, hex_field};
use std::collections::BTreeMap;

#[path = "common/cmac_helpers.rs"]
mod cmac_helpers;
use cmac_helpers::mac_key;

const TEST_DATA_DIR: &str = "crypto/aes_tdes_vectors/CMAC";
const REQUEST_FILE: &str = "CMAC-AES.4014544.req.json";
const RESPONSE_FILE: &str = "CMAC-AES.4014544.rsp.json";

/// The full 16-byte AES-CMAC tag of `msg` under `key`, dispatched on the key length.
fn aes_cmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    match key.len() {
        16 => AES_CMAC_128::new(&mac_key::<16>(key)).unwrap().mac(msg),
        24 => AES_CMAC_192::new(&mac_key::<24>(key)).unwrap().mac(msg),
        32 => AES_CMAC_256::new(&mac_key::<32>(key)).unwrap().mac(msg),
        other => panic!("unexpected AES key length {other}"),
    }
}

/// `MAC::verify` of a full-length tag, dispatched on the key length.
fn aes_cmac_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    match key.len() {
        16 => AES_CMAC_128::new(&mac_key::<16>(key)).unwrap().verify(msg, tag),
        24 => AES_CMAC_192::new(&mac_key::<24>(key)).unwrap().verify(msg, tag),
        32 => AES_CMAC_256::new(&mac_key::<32>(key)).unwrap().verify(msg, tag),
        other => panic!("unexpected AES key length {other}"),
    }
}

#[test]
fn acvp_cmac_aes() {
    let Some(req) = bc_test_data_json(TEST_DATA_DIR, REQUEST_FILE) else { return };
    let Some(rsp) = bc_test_data_json(TEST_DATA_DIR, RESPONSE_FILE) else { return };

    let mut answers: BTreeMap<u64, Value> = BTreeMap::new();
    for group in rsp[1]["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            answers.insert(test["tcId"].as_u64().unwrap(), test.clone());
        }
    }

    let (mut generated, mut verified, mut rejected) = (0usize, 0usize, 0usize);
    for group in req[1]["testGroups"].as_array().unwrap() {
        let mac_len = (group["macLen"].as_u64().unwrap() / 8) as usize;
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let answer = &answers[&tc_id];
            let key = hex_field(test, "key", tc_id);
            let msg = hex_field(test, "message", tc_id);
            let full = aes_cmac(&key, &msg);
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
                    if mac_len == 16 {
                        assert_eq!(aes_cmac_verify(&key, &msg, &tag), passed, "tcId {tc_id}");
                    }
                    if passed { verified += 1 } else { rejected += 1 }
                }
                other => panic!("unexpected direction {other}"),
            }
        }
    }
    println!("ACVP CMAC-AES: {generated} gen, {verified} ver passed, {rejected} ver rejected");
    assert_eq!(generated + verified + rejected, 756, "expected all 756 ACVP CMAC-AES cases to run");
    assert!(verified > 0 && rejected > 0);
}
