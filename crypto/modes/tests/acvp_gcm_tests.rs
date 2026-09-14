//! Known-answer tests against the NIST ACVP `ACVP-AES-GCM` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the other ACVP suites in this crate.
//!
//! The set (`ACVP-AES-GCM.4014542`) covers all three AES key lengths, a 96-bit IV throughout,
//! 96- and 128-bit tags, payload lengths of 64/128/192 bits and AAD lengths of 128/256 bits, in
//! both directions -- 270 cases total. Not every decrypt case in this particular set is a
//! forgery, but the ones that are all report `testPassed: false`; the valid-decrypt path is
//! additionally exercised by round-tripping every encrypt case through both the detached one-shot
//! and the inline `SimpleCipherDecryptor` streaming view (`acvp_gcm::run_decrypt_case`, below).
//!
//! **Not covered here:** `bc-test-data` has no CAVP `.rsp` GCM vector files and no Wycheproof
//! `aes_gcm_test.json` -- only `sm4_gcm_test.json` exists under `wycheproof/`, and there is no
//! `GCM/cavp/` directory. This file and `acvp_gmac_tests.rs` are therefore the full extent of the
//! vector-based coverage against `bc-test-data`. If those files are added later, `cavp_gcm_tests.rs`
//! and `wycheproof_gcm_tests.rs` should be written against them following this file's shape.

// Not `mod common;`: this crate-private helper's `serde_json::Value` usage, if pulled into the
// shared `common` module that most other test binaries in this crate include via `mod common;`,
// makes `u8: PartialEq<_>` ambiguous (`core`'s impl vs. serde_json's `impl PartialEq<Value> for
// u8`) at every bare `assert_eq!(byte_array, [])` in *those* files too -- `ecb_tests.rs` hit this
// exactly. Giving it its own module path keeps that ambiguity local to the two files that actually
// need ACVP JSON parsing.
#[path = "common/acvp_gcm.rs"]
mod acvp_gcm;

use acvp_gcm::{GCM_NONCE_LEN, decode, run_decrypt_case, run_encrypt_case, test_data_dir};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;

const SUBDIR: &str = "aes_tdes_vectors/GCM";
const REQUEST_FILE: &str = "ACVP-AES-GCM.4014542.req.json";
const RESPONSE_FILE: &str = "ACVP-AES-GCM.4014542.rsp.json";

#[test]
fn acvp_aes_gcm_known_answer_tests() {
    let Some(dir) = test_data_dir(SUBDIR, REQUEST_FILE, RESPONSE_FILE) else { return };

    let req: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(REQUEST_FILE)).expect("readable request file"),
    )
    .expect("valid ACVP request JSON");
    let rsp: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(RESPONSE_FILE)).expect("readable response file"),
    )
    .expect("valid ACVP response JSON");

    // The response file carries only the answer, against a tcId. Index it.
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
                    let pt = decode(test, "pt", tc_id);
                    let answer =
                        answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
                    let ct = decode(answer, "ct", tc_id);
                    let tag = decode(answer, "tag", tc_id);
                    run_encrypt_case(&key_bytes, iv, &aad, &pt, tag_len, &ct, &tag);

                    // Also round-trip this known-good ciphertext through decryption, since every
                    // decrypt group in this particular ACVP set is a forgery (below) and this is
                    // otherwise the only valid-decrypt coverage this file would have.
                    run_decrypt_case(&key_bytes, iv, &aad, &ct, &tag, Some(&pt));
                    encrypt_checked += 1;
                }
                "decrypt" => {
                    let ct = decode(test, "ct", tc_id);
                    let tag = decode(test, "tag", tc_id);
                    let answer =
                        answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
                    // A forgery reports `testPassed: false` and no plaintext; a valid case reports
                    // `pt` directly, with no `testPassed` field at all (ACVP's convention: the key
                    // is present only to report failure).
                    if answer.get("testPassed").and_then(Value::as_bool) == Some(false) {
                        run_decrypt_case(&key_bytes, iv, &aad, &ct, &tag, None);
                        decrypt_failed_checked += 1;
                    } else {
                        let pt = decode(answer, "pt", tc_id);
                        run_decrypt_case(&key_bytes, iv, &aad, &ct, &tag, Some(&pt));
                    }
                }
                other => panic!("unexpected direction {other}"),
            }

            *per_kind.entry(format!("AES-{} {direction}", key_bytes.len() * 8)).or_default() += 1;
            checked += 1;
        }
    }

    for (kind, n) in &per_kind {
        println!("ACVP AES-GCM {kind}: {n} cases");
    }
    println!(
        "ACVP AES-GCM: {checked} cases checked ({encrypt_checked} encrypt, also round-tripped \
         through decrypt; {decrypt_failed_checked} decrypt forgeries)"
    );

    assert_eq!(checked, 270, "expected all 270 ACVP AES-GCM cases to run");
    assert!(encrypt_checked > 0 && decrypt_failed_checked > 0, "expected both directions covered");
}
