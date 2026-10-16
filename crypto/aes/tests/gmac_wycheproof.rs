//! Known-answer tests against Project Wycheproof's `testvectors_v1/aes_gmac_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the test prints a warning and passes, matching the convention used by the other vector
//! suites in this crate.
//!
//! GMAC is GCM with an empty plaintext (SP 800-38D Sec 5.2): the vector's `msg` is the AAD, and the
//! tag is the whole output. Cases run through the same helpers as `gmac_bc-test-data.rs`. A `valid`
//! case must produce exactly `tag`, which must then verify; an `invalid` case must fail the tag
//! check.
//!
//! `Gcm` fixes the IV at 96 bits, so the file's 128-bit-IV groups are counted as not supported, as
//! in `gcm_wycheproof.rs`.

#[path = "common/acvp_gcm_helpers.rs"]
mod acvp_gcm_helpers;

use acvp_gcm_helpers::{GCM_NONCE_LEN, run_decrypt_case, run_encrypt_case};
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};

#[test]
fn wycheproof_aes_gmac() {
    let Some(doc) = wycheproof_json("aes_gmac_test.json") else { return };

    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some("AES-GMAC"));

    let (mut valid_count, mut invalid_count) = (0usize, 0usize);
    let (mut unsupported_groups, mut unsupported_cases) = (0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        let tests = group.get("tests").and_then(Value::as_array).expect("tests");
        let iv_bits = group.get("ivSize").and_then(Value::as_u64).expect("ivSize");
        if iv_bits as usize != 8 * GCM_NONCE_LEN {
            unsupported_groups += 1;
            unsupported_cases += tests.len();
            continue;
        }

        for test in tests {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let key = hex_field(test, "key", tc_id);
            let iv: [u8; GCM_NONCE_LEN] =
                hex_field(test, "iv", tc_id).try_into().expect("a 96-bit IV");
            let aad = hex_field(test, "msg", tc_id);
            let tag = hex_field(test, "tag", tc_id);

            match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => {
                    run_encrypt_case(&key, iv, &aad, &[], tag.len(), &[], &tag);
                    run_decrypt_case(&key, iv, &aad, &[], &tag, Some(&[]));
                    valid_count += 1;
                }
                "invalid" => {
                    run_decrypt_case(&key, iv, &aad, &[], &tag, None);
                    invalid_count += 1;
                }
                other => panic!("tcId {tc_id}: unexpected result {other}"),
            }
        }
    }

    println!(
        "Wycheproof AES-GMAC: {} cases run ({valid_count} valid, {invalid_count} invalid), \
         {unsupported_cases} cases in {unsupported_groups} groups not supported \
         (no 96-bit-IV instantiation)",
        valid_count + invalid_count
    );
    assert!(valid_count > 0 && invalid_count > 0, "expected both valid and invalid cases");
    assert!(unsupported_groups > 0, "expected the 128-bit-IV groups to be outside Gcm's shape");
}
