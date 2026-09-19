//! RSA-1536 (verification only, see `rsa_1536.rs`'s docs) against Wycheproof's
//! `rsa_pkcs1_1536_sig_gen_test.json`, the same way `rsa_1024_tests.rs` uses its own sig-gen file:
//! each group's `(n, e)` plus its own `(msg, sig)` pairs, used directly as real "valid" verify
//! vectors, since a sig-gen file's private key fields are simultaneously valid public key
//! material and this crate never constructs an RSA-1536 private key at all.

use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rsa::rsa_1536::{
    Rsa1536PublicKey, pkcs1_v1_5_verify_sha256, pkcs1_v1_5_verify_sha384, pkcs1_v1_5_verify_sha512,
};
use serde_json::Value;
use std::fs;
use std::path::Path;

const TEST_DATA_PATH_RELATIVE: &str = "../../../wycheproof/testvectors_v1";
const TEST_DATA_PATH: &str = "../wycheproof/testvectors_v1";

fn get_test_data(filename: &str) -> String {
    for dir in [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH] {
        let path = format!("{dir}/{filename}");
        if Path::new(&path).exists() {
            return fs::read_to_string(path).unwrap();
        }
    }
    panic!(
        "wycheproof not found (looked for {filename} in {TEST_DATA_PATH_RELATIVE:?} and \
         {TEST_DATA_PATH:?}); this suite requires it rather than skipping"
    );
}

fn limbs_from_hex<const L: usize>(hex: &str) -> [u64; L] {
    let bytes_len = 8 * L;
    let mut bytes = hex_decode(hex).expect("valid hex");
    if bytes.len() == bytes_len + 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    assert_eq!(bytes.len(), bytes_len, "expected a {}-bit value", bytes_len * 8);
    let mut limbs = [0u64; L];
    for i in 0..L {
        let start = bytes_len - (i + 1) * 8;
        limbs[i] = u64::from_be_bytes(bytes[start..start + 8].try_into().unwrap());
    }
    limbs
}

fn run_sig_gen_group_as_verify_vectors(
    sha: &str,
    verify: impl Fn(&Rsa1536PublicKey, &[u8], &[u8; 192]) -> bool,
) {
    let doc: Value =
        serde_json::from_str(&get_test_data("rsa_pkcs1_1536_sig_gen_test.json")).unwrap();
    let group = doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["sha"] == sha)
        .unwrap_or_else(|| panic!("the {sha}/1536 group"));

    let n: [u64; 24] = limbs_from_hex(group["privateKey"]["modulus"].as_str().unwrap());
    let e =
        u32::from_str_radix(group["privateKey"]["publicExponent"].as_str().unwrap(), 16).unwrap();
    let pk = Rsa1536PublicKey::new(&n, e).expect("group public key must be valid");

    let mut num_tests = 0usize;
    for test in group["tests"].as_array().unwrap() {
        num_tests += 1;
        let tc_id = test["tcId"].as_u64().unwrap();
        let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
        let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();
        let sig: [u8; 192] = sig_bytes.try_into().expect("sig-gen signatures are always k octets");
        assert!(verify(&pk, &msg, &sig), "tcId {tc_id}: a genuine signature must verify");
    }
    assert_eq!(num_tests, 8);
}

#[test]
fn pkcs1_v1_5_sha256_accepts_genuine_sig_gen_signatures() {
    run_sig_gen_group_as_verify_vectors("SHA-256", |pk, msg, sig| {
        pkcs1_v1_5_verify_sha256(pk, msg, sig).is_ok()
    });
}

#[test]
fn pkcs1_v1_5_sha384_accepts_genuine_sig_gen_signatures() {
    run_sig_gen_group_as_verify_vectors("SHA-384", |pk, msg, sig| {
        pkcs1_v1_5_verify_sha384(pk, msg, sig).is_ok()
    });
}

#[test]
fn pkcs1_v1_5_sha512_accepts_genuine_sig_gen_signatures() {
    run_sig_gen_group_as_verify_vectors("SHA-512", |pk, msg, sig| {
        pkcs1_v1_5_verify_sha512(pk, msg, sig).is_ok()
    });
}

fn run_sig_gen_group_rejects_wrong_message(
    sha: &str,
    verify: impl Fn(&Rsa1536PublicKey, &[u8], &[u8; 192]) -> bool,
) {
    let doc: Value =
        serde_json::from_str(&get_test_data("rsa_pkcs1_1536_sig_gen_test.json")).unwrap();
    let group = doc["testGroups"].as_array().unwrap().iter().find(|g| g["sha"] == sha).unwrap();
    let n: [u64; 24] = limbs_from_hex(group["privateKey"]["modulus"].as_str().unwrap());
    let e =
        u32::from_str_radix(group["privateKey"]["publicExponent"].as_str().unwrap(), 16).unwrap();
    let pk = Rsa1536PublicKey::new(&n, e).unwrap();
    let test = &group["tests"][0];
    let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();
    let sig: [u8; 192] = sig_bytes.try_into().unwrap();
    assert!(!verify(&pk, b"a message this signature was not made for", &sig));
}

#[test]
fn pkcs1_v1_5_sha256_rejects_wrong_message() {
    run_sig_gen_group_rejects_wrong_message("SHA-256", |pk, msg, sig| {
        pkcs1_v1_5_verify_sha256(pk, msg, sig).is_ok()
    });
}

/// Mutation testing found that `pkcs1_v1_5_verify_sha384`/`_sha512` had no rejection-path test of
/// their own (only `verify_sha256`'s did) -- a whole-function-body mutant that always returned
/// `Ok(())` still passed the whole suite for either.
#[test]
fn pkcs1_v1_5_sha384_rejects_wrong_message() {
    run_sig_gen_group_rejects_wrong_message("SHA-384", |pk, msg, sig| {
        pkcs1_v1_5_verify_sha384(pk, msg, sig).is_ok()
    });
}

#[test]
fn pkcs1_v1_5_sha512_rejects_wrong_message() {
    run_sig_gen_group_rejects_wrong_message("SHA-512", |pk, msg, sig| {
        pkcs1_v1_5_verify_sha512(pk, msg, sig).is_ok()
    });
}
