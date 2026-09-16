//! Test against the project wycheproof repo: `ecdsa_brainpoolP384r1_sha384_p1363_test.json` (raw
//! `r || s`, against [`ECDSABp384r1::verify`]) and `ecdsa_brainpoolP384r1_sha384_test.json` (DER
//! `SEQUENCE { r, s }`, RFC 3279 §2.2.3, against [`ECDSABp384r1::verify_der`]). See
//! `wycheproof.rs`'s docs for the sibling-clone convention and what wycheproof's value is here
//! (malleability/invalid-encoding coverage, not signature-generation KATs).

use bouncycastle_core::traits::{SignaturePublicKey, SignatureVerifier};
use bouncycastle_ecdsa::ecdsa_bp384r1::ECDSABp384r1;
use bouncycastle_ecdsa::keys_bp384r1::ECDSABp384r1PublicKey;
use bouncycastle_hex::decode as hex_decode;
use serde_json::Value;
use std::fs;
use std::path::Path;

const TEST_DATA_PATH_RELATIVE: &str = "../../../wycheproof/testvectors_v1";
const TEST_DATA_PATH: &str = "../wycheproof/testvectors_v1";

fn get_test_data(filename: &str) -> Option<String> {
    for dir in [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH] {
        let path = format!("{dir}/{filename}");
        if Path::new(&path).exists() {
            return Some(fs::read_to_string(path).unwrap());
        }
    }
    println!("WARNING: wycheproof directory not found; {filename} test skipped");
    None
}

#[test]
fn ecdsa_brainpool_p384r1_sha384_p1363_test() {
    let Some(contents) = get_test_data("ecdsa_brainpoolP384r1_sha384_p1363_test.json") else {
        return;
    };
    let doc: Value = serde_json::from_str(&contents).unwrap();

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], "SHA-384");
        let pk_hex = group["publicKey"]["uncompressed"].as_str().unwrap();
        let pk_bytes = hex_decode(pk_hex).unwrap();
        let pk = ECDSABp384r1PublicKey::from_bytes(&pk_bytes).ok();

        for test in group["tests"].as_array().unwrap() {
            num_tests += 1;
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig = hex_decode(test["sig"].as_str().unwrap()).unwrap();
            let expect_valid = test["result"].as_str().unwrap() == "valid";
            if expect_valid {
                num_valid += 1;
            } else {
                num_invalid += 1;
            }

            let result = pk.as_ref().and_then(|pk| ECDSABp384r1::verify(pk, &msg, None, &sig).ok());
            assert_eq!(
                result.is_some(),
                expect_valid,
                "tcId {tc_id}: expected valid={expect_valid}, comment={:?}",
                test["comment"]
            );
        }
    }

    println!(
        "ecdsa_brainpoolP384r1_sha384_p1363_test: {num_tests} test cases passed ({num_valid} valid, {num_invalid} invalid)."
    );
}

/// The DER counterpart of the above: `ecdsa_brainpoolP384r1_sha384_test.json`, against
/// [`ECDSABp384r1::verify_der`].
#[test]
fn ecdsa_brainpool_p384r1_sha384_der_test() {
    let Some(contents) = get_test_data("ecdsa_brainpoolP384r1_sha384_test.json") else {
        return;
    };
    let doc: Value = serde_json::from_str(&contents).unwrap();

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], "SHA-384");
        let pk_hex = group["publicKey"]["uncompressed"].as_str().unwrap();
        let pk_bytes = hex_decode(pk_hex).unwrap();
        let pk = ECDSABp384r1PublicKey::from_bytes(&pk_bytes).ok();

        for test in group["tests"].as_array().unwrap() {
            num_tests += 1;
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig = hex_decode(test["sig"].as_str().unwrap()).unwrap();
            let expect_valid = test["result"].as_str().unwrap() == "valid";
            if expect_valid {
                num_valid += 1;
            } else {
                num_invalid += 1;
            }

            let result =
                pk.as_ref().and_then(|pk| ECDSABp384r1::verify_der(pk, &msg, None, &sig).ok());
            assert_eq!(
                result.is_some(),
                expect_valid,
                "tcId {tc_id}: expected valid={expect_valid}, comment={:?}",
                test["comment"]
            );
        }
    }

    println!(
        "ecdsa_brainpoolP384r1_sha384_der_test: {num_tests} test cases passed ({num_valid} valid, {num_invalid} invalid)."
    );
}
