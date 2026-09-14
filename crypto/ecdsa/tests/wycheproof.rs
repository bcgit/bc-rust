//! Test against the project wycheproof repo available at:
//!     https://github.com/C2SP/wycheproof
//! Requires that the wycheproof repository is cloned and available for testing at "../wycheproof"
//! relative to the root of this git project (see `bouncycastle-mldsa`'s `tests/wycheproof.rs` for
//! the same convention).
//!
//! Exercises `ecdsa_secp256r1_sha256_p1363_test.json` -- the "P1363" (raw, fixed-width `r || s`)
//! signature encoding, which is what [`ECDSAP256`] produces and consumes (see
//! `bouncycastle_ecdsa`'s crate docs on why there is no DER `SEQUENCE` support yet). The plain
//! (non-p1363) `ecdsa_secp256r1_sha256_test.json` file is DER-encoded and out of scope for the same
//! reason.
//!
//! This is a verify-only test set (`EcdsaP1363Verify`): wycheproof's value here is the malleability,
//! invalid-encoding and edge-case `r`/`s` cases, not KATs for signature generation (RFC 6979's own
//! Appendix A.2.5 vectors, exercised in `rfc6979_vectors_tests.rs`, cover that).

use bouncycastle_core::traits::{SignaturePublicKey, SignatureVerifier};
use bouncycastle_ecdsa::ecdsa_p256::ECDSAP256;
use bouncycastle_ecdsa::keys::ECDSAP256PublicKey;
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
    println!("WARNING: wycheproof directory not found; ecdsa_secp256r1_sha256_p1363 test skipped");
    None
}

#[test]
fn ecdsa_secp256r1_sha256_p1363_test() {
    let Some(contents) = get_test_data("ecdsa_secp256r1_sha256_p1363_test.json") else {
        return;
    };
    let doc: Value = serde_json::from_str(&contents).unwrap();

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], "SHA-256");
        let pk_hex = group["publicKey"]["uncompressed"].as_str().unwrap();
        let pk_bytes = hex_decode(pk_hex).unwrap();
        // A malformed group public key (EdgeCasePublicKey groups deliberately use invalid points)
        // makes every "valid" test in that group impossible by construction -- SP 800-186 Appendix
        // D.1.1.1 validation on decode is exactly what's meant to reject those, so a decode failure
        // here counts every test in the group as correctly rejected rather than failing the test.
        let pk = match ECDSAP256PublicKey::from_bytes(&pk_bytes) {
            Ok(pk) => Some(pk),
            Err(_) => None,
        };

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

            let result = pk.as_ref().and_then(|pk| ECDSAP256::verify(pk, &msg, None, &sig).ok());
            assert_eq!(
                result.is_some(),
                expect_valid,
                "tcId {tc_id}: expected valid={expect_valid}, comment={:?}",
                test["comment"]
            );
        }
    }

    println!(
        "ecdsa_secp256r1_sha256_p1363_test: {num_tests} test cases passed ({num_valid} valid, {num_invalid} invalid)."
    );
}
