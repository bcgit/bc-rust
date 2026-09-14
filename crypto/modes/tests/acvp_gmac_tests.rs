//! Known-answer tests against the NIST ACVP `ACVP-AES-GMAC` vectors from the `bc-test-data` repo.
//!
//! Same joiner and shape as `acvp_gcm_tests.rs` (see its module docs for the `bc-test-data`
//! requirement and what is and is not covered against `bc-test-data`), over the GMAC set
//! (`ACVP-AES-GMAC.4014543`, 270 cases): `payloadLen` is 0 throughout -- SP 800-38D Sec 5.2, GMAC is
//! GCM restricted to `P = ""` -- with AAD lengths of 128/192/256 bits, both directions, all three
//! key lengths, 96- and 128-bit tags.

// See `acvp_gcm_tests.rs` for why this is its own module path rather than `mod common;`.
#[path = "common/acvp_gcm.rs"]
mod acvp_gcm;

use acvp_gcm::{GCM_NONCE_LEN, decode, run_decrypt_case, run_encrypt_case, test_data_dir};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

const SUBDIR: &str = "aes_tdes_vectors/GCM";
const REQUEST_FILE: &str = "ACVP-AES-GMAC.4014543.req.json";
const RESPONSE_FILE: &str = "ACVP-AES-GMAC.4014543.rsp.json";

#[test]
fn acvp_aes_gmac_known_answer_tests() {
    let Some(dir) = test_data_dir(SUBDIR, REQUEST_FILE, RESPONSE_FILE) else { return };

    let req: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(REQUEST_FILE)).expect("readable request file"),
    )
    .expect("valid ACVP request JSON");
    let rsp: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(RESPONSE_FILE)).expect("readable response file"),
    )
    .expect("valid ACVP response JSON");

    let mut answers: BTreeMap<u64, Value> = BTreeMap::new();
    for group in rsp[1]["testGroups"].as_array().expect("response testGroups") {
        for test in group["tests"].as_array().expect("response tests") {
            let tc_id = test["tcId"].as_u64().expect("tcId");
            answers.insert(tc_id, test.clone());
        }
    }

    let groups = req[1]["testGroups"].as_array().expect("request testGroups");

    let mut checked = 0usize;
    let mut encrypt_checked = 0usize;
    let mut decrypt_failed_checked = 0usize;
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();

    for group in groups {
        let direction = group["direction"].as_str().expect("direction");
        let tag_len = (group["tagLen"].as_u64().expect("tagLen") / 8) as usize;
        let iv_len = group["ivLen"].as_u64().expect("ivLen");
        assert_eq!(iv_len, 96, "every group in this set has a 96-bit IV");
        let payload_len = group["payloadLen"].as_u64().expect("payloadLen");
        assert_eq!(payload_len, 0, "GMAC groups carry no plaintext");

        for test in group["tests"].as_array().expect("tests") {
            let tc_id = test["tcId"].as_u64().expect("tcId");
            let key_bytes = decode(test, "key", tc_id);
            let aad = decode(test, "aad", tc_id);
            let iv_bytes = decode(test, "iv", tc_id);
            let iv: [u8; GCM_NONCE_LEN] = iv_bytes
                .try_into()
                .unwrap_or_else(|_| panic!("tcId {tc_id}: expected a 12-byte IV"));

            match direction {
                "encrypt" => {
                    let answer =
                        answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
                    let tag = decode(answer, "tag", tc_id);
                    // A GMAC "ciphertext" is always empty.
                    run_encrypt_case(&key_bytes, iv, &aad, &[], tag_len, &[], &tag);
                    run_decrypt_case(&key_bytes, iv, &aad, &[], &tag, Some(&[]));
                    encrypt_checked += 1;
                }
                "decrypt" => {
                    let tag = decode(test, "tag", tc_id);
                    let answer =
                        answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
                    // See `acvp_gcm_tests.rs`: a forgery reports `testPassed: false`; a valid case
                    // reports success with no `testPassed` field at all (here there is no `pt` to
                    // report either, since GMAC's plaintext is always empty).
                    if answer.get("testPassed").and_then(Value::as_bool) == Some(false) {
                        run_decrypt_case(&key_bytes, iv, &aad, &[], &tag, None);
                        decrypt_failed_checked += 1;
                    } else {
                        run_decrypt_case(&key_bytes, iv, &aad, &[], &tag, Some(&[]));
                    }
                }
                other => panic!("unexpected direction {other}"),
            }

            *per_kind.entry(format!("AES-{} {direction}", key_bytes.len() * 8)).or_default() += 1;
            checked += 1;
        }
    }

    for (kind, n) in &per_kind {
        println!("ACVP AES-GMAC {kind}: {n} cases");
    }
    println!(
        "ACVP AES-GMAC: {checked} cases checked ({encrypt_checked} encrypt, also round-tripped \
         through decrypt; {decrypt_failed_checked} decrypt forgeries)"
    );

    assert_eq!(checked, 270, "expected all 270 ACVP AES-GMAC cases to run");
    assert!(encrypt_checked > 0 && decrypt_failed_checked > 0, "expected both directions covered");
}
