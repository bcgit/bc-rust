//! PBKDF2 against Wycheproof's `pbkdf2_hmacsha*_test.json` and NIST ACVP's `PBKDF-1.0`.
//!
//! Wycheproof: the SHA-224, SHA-256, SHA-384 and SHA-512 files, every case of which is valid;
//! the SHA-256 file includes RFC 7914's vectors. The SHA-1 file, which holds RFC 6070's, is
//! counted and not run: the library's release has no SHA-1. Without a Wycheproof checkout or a
//! copy of a file in bc-test-data the file is skipped, with the loader's warning.
//!
//! ACVP: ACVP-Server's `gen-val/json-files/PBKDF-1.0`, in `bc-test-data/crypto/acvp`, 50 cases
//! over HMAC-SHA2-224 with up to 10,000 iterations. A missing `bc-test-data` checkout fails
//! that test rather than skipping it.

use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core_test_framework::test_data_loaders::{
    Value, bc_test_data_json, wycheproof_json,
};
use bouncycastle_digest::hmac::HMACParams;
use bouncycastle_digest::pbkdf2::PBKDF2;
use bouncycastle_digest::sha2::{SHA224, SHA256, SHA384, SHA512};
use core::num::NonZeroU32;
use std::collections::HashMap;

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    if s.is_empty() { Vec::new() } else { bouncycastle_core::hex::decode(s).unwrap() }
}

fn derive<H: HMACParams>(password: &[u8], salt: &[u8], iterations: u64, len: usize) -> Vec<u8> {
    let password = KeyMaterial::<512>::from_bytes_as_type(password, KeyType::Unknown).unwrap();
    let iterations = NonZeroU32::new(u32::try_from(iterations).unwrap()).unwrap();
    let mut out = KeyMaterial::<512>::new();
    assert_eq!(PBKDF2::<H>::derive_out(&password, salt, iterations, len, &mut out), Ok(len));
    out.ref_to_bytes().to_vec()
}

/// Runs one Wycheproof file; `None` if neither Wycheproof nor a copy of the file is there.
fn wycheproof<H: HMACParams>(filename: &str) -> Option<usize> {
    let file = wycheproof_json(filename)?;
    let mut run = 0usize;
    for group in file["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            assert_eq!(test["result"], "valid", "tcId {tc_id}: these files hold valid cases only");
            let len = test["dkLen"].as_u64().unwrap() as usize;
            let got = derive::<H>(
                &hex(&test["password"]),
                &hex(&test["salt"]),
                test["iterationCount"].as_u64().unwrap(),
                len,
            );
            assert_eq!(got, hex(&test["dk"]), "{filename} tcId {tc_id}");
            run += 1;
        }
    }
    assert_eq!(run as u64, file["numberOfTests"].as_u64().unwrap(), "{filename}");
    Some(run)
}

#[test]
fn wycheproof_pbkdf2() {
    let Some(sha224) = wycheproof::<SHA224>("pbkdf2_hmacsha224_test.json") else { return };
    let sha256 = wycheproof::<SHA256>("pbkdf2_hmacsha256_test.json").unwrap();
    let sha384 = wycheproof::<SHA384>("pbkdf2_hmacsha384_test.json").unwrap();
    let sha512 = wycheproof::<SHA512>("pbkdf2_hmacsha512_test.json").unwrap();
    assert_eq!((sha224, sha256, sha384, sha512), (58, 60, 58, 58));
    // Counted, not run: no SHA-1 on the release.
    let sha1 = wycheproof_json("pbkdf2_hmacsha1_test.json").unwrap();
    assert_eq!(sha1["numberOfTests"], 64);
}

#[test]
fn acvp_pbkdf_1_0() {
    let get = |filename: &str| {
        bc_test_data_json("crypto/acvp/PBKDF-1.0", filename).unwrap_or_else(|| {
            panic!("bc-test-data not found beside this repository; the PBKDF2 ACVP suite requires it rather than skipping")
        })
    };
    let (prompt, expected) = (get("prompt.json"), get("expectedResults.json"));
    let mut answers = HashMap::new();
    for group in expected["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            answers.insert(test["tcId"].as_u64().unwrap(), hex(&test["derivedKey"]));
        }
    }
    let mut run = 0usize;
    for group in prompt["testGroups"].as_array().unwrap() {
        assert_eq!(group["testType"], "AFT");
        assert_eq!(group["hmacAlg"], "SHA2-224", "the set holds one HMAC");
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let bits = test["keyLen"].as_u64().unwrap() as usize;
            assert_eq!(bits % 8, 0, "tcId {tc_id}");
            // The password is given as text, the salt as hex.
            let got = derive::<SHA224>(
                test["password"].as_str().unwrap().as_bytes(),
                &hex(&test["salt"]),
                test["iterationCount"].as_u64().unwrap(),
                bits / 8,
            );
            assert_eq!(got, answers[&tc_id], "tcId {tc_id}");
            run += 1;
        }
    }
    assert_eq!(run, 50);
}
