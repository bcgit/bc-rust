//! RSA-1536 (verification only, see `rsa_1536.rs`'s docs) against Wycheproof's
//! `rsa_pkcs1_1536_sig_gen_test.json`, the same way `rsa_rsa_1024_tests.rs` uses its own sig-gen file:
//! each group's `(n, e)` plus its own `(msg, sig)` pairs, used directly as real "valid" verify
//! vectors, since a sig-gen file's private key fields are simultaneously valid public key
//! material and this module never constructs an RSA-1536 private key at all.

use bouncycastle_core::errors::{KeyDecodingError, SignatureError};
use bouncycastle_core::hex::decode as hex_decode;
use bouncycastle_core::signature_key::OneShotVerifyingKey;
use bouncycastle_core::traits::PublicKey;
use bouncycastle_modexp::rsa::RSA1536;
use bouncycastle_modexp::rsa::keys::{RsaPublicComponents, RsaPublicKey};
use bouncycastle_modexp::rsa::rsa_1536::{
    PK_LEN, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512,
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
    verify: impl Fn(&RsaPublicComponents<RSA1536>, &[u8], &[u8; 192]) -> bool,
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
        u64::from_str_radix(group["privateKey"]["publicExponent"].as_str().unwrap(), 16).unwrap();
    let pk = RsaPublicComponents::<RSA1536>::new(&n, e).expect("group public key must be valid");

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
        pk.key::<RSASSA_PKCS1_v1_5_SHA256>().verify(msg, None, sig).is_ok()
    });
}

#[test]
fn pkcs1_v1_5_sha384_accepts_genuine_sig_gen_signatures() {
    run_sig_gen_group_as_verify_vectors("SHA-384", |pk, msg, sig| {
        pk.key::<RSASSA_PKCS1_v1_5_SHA384>().verify(msg, None, sig).is_ok()
    });
}

#[test]
fn pkcs1_v1_5_sha512_accepts_genuine_sig_gen_signatures() {
    run_sig_gen_group_as_verify_vectors("SHA-512", |pk, msg, sig| {
        pk.key::<RSASSA_PKCS1_v1_5_SHA512>().verify(msg, None, sig).is_ok()
    });
}

fn run_sig_gen_group_rejects_wrong_message(
    sha: &str,
    verify: impl Fn(&RsaPublicComponents<RSA1536>, &[u8], &[u8; 192]) -> bool,
) {
    let doc: Value =
        serde_json::from_str(&get_test_data("rsa_pkcs1_1536_sig_gen_test.json")).unwrap();
    let group = doc["testGroups"].as_array().unwrap().iter().find(|g| g["sha"] == sha).unwrap();
    let n: [u64; 24] = limbs_from_hex(group["privateKey"]["modulus"].as_str().unwrap());
    let e =
        u64::from_str_radix(group["privateKey"]["publicExponent"].as_str().unwrap(), 16).unwrap();
    let pk = RsaPublicComponents::<RSA1536>::new(&n, e).unwrap();
    let test = &group["tests"][0];
    let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();
    let sig: [u8; 192] = sig_bytes.try_into().unwrap();
    assert!(!verify(&pk, b"a message this signature was not made for", &sig));
}

#[test]
fn pkcs1_v1_5_sha256_rejects_wrong_message() {
    run_sig_gen_group_rejects_wrong_message("SHA-256", |pk, msg, sig| {
        pk.key::<RSASSA_PKCS1_v1_5_SHA256>().verify(msg, None, sig).is_ok()
    });
}

/// Mutation testing found that PKCS#1 v1.5/SHA-384 and /SHA-512 verification had no rejection-path test of
/// their own (only `verify_sha256`'s did) -- a whole-function-body mutant that always returned
/// `Ok(())` still passed the whole suite for either.
#[test]
fn pkcs1_v1_5_sha384_rejects_wrong_message() {
    run_sig_gen_group_rejects_wrong_message("SHA-384", |pk, msg, sig| {
        pk.key::<RSASSA_PKCS1_v1_5_SHA384>().verify(msg, None, sig).is_ok()
    });
}

#[test]
fn pkcs1_v1_5_sha512_rejects_wrong_message() {
    run_sig_gen_group_rejects_wrong_message("SHA-512", |pk, msg, sig| {
        pk.key::<RSASSA_PKCS1_v1_5_SHA512>().verify(msg, None, sig).is_ok()
    });
}

// ---- bouncycastle_core trait conformance ------------------------------------------------------
//
// Verify-only at this size, as at RSA-1024 -- see `rsa_rsa_1024_tests.rs` for why the
// `core-test-framework` signature suite cannot run here.

#[test]
fn trait_verify_rejects_truncated_signature() {
    run_sig_gen_group_as_verify_vectors("SHA-256", |pk, msg, sig| {
        matches!(
            pk.key::<RSASSA_PKCS1_v1_5_SHA256>().verify(msg, None, &sig[..191]),
            Err(SignatureError::LengthError(_))
        )
    });
}

#[test]
fn public_key_trait_encoding_round_trips_and_rejects_wrong_lengths() {
    let doc: Value =
        serde_json::from_str(&get_test_data("rsa_pkcs1_1536_sig_gen_test.json")).unwrap();
    let group = &doc["testGroups"][0];
    let n: [u64; 24] = limbs_from_hex(group["privateKey"]["modulus"].as_str().unwrap());
    let e =
        u64::from_str_radix(group["privateKey"]["publicExponent"].as_str().unwrap(), 16).unwrap();
    let pk =
        RsaPublicComponents::<RSA1536>::new(&n, e).unwrap().into_key::<RSASSA_PKCS1_v1_5_SHA256>();

    let bytes = pk.encode();
    assert_eq!(bytes.len(), PK_LEN);
    assert_eq!(RsaPublicKey::<RSASSA_PKCS1_v1_5_SHA256>::from_bytes(&bytes).unwrap(), pk);
    assert!(matches!(
        RsaPublicKey::<RSASSA_PKCS1_v1_5_SHA256>::from_bytes(&bytes[..PK_LEN - 1]),
        Err(KeyDecodingError(_))
    ));
    let mut too_long = bytes.to_vec();
    too_long.push(0);
    assert!(matches!(
        RsaPublicKey::<RSASSA_PKCS1_v1_5_SHA256>::from_bytes(&too_long),
        Err(KeyDecodingError(_))
    ));
}

/// RFC 8017 §8.2.2 step 1 through this size's own range check: `0xff..ff` is `2^1536 - 1 >= n`
/// for any 1536-bit `n`, an out-of-range representative, reported as an invalid signature.
#[test]
fn trait_verify_reports_out_of_range_representative_as_invalid_signature() {
    run_sig_gen_group_as_verify_vectors("SHA-256", |pk, msg, _sig| {
        matches!(
            pk.key::<RSASSA_PKCS1_v1_5_SHA256>().verify(msg, None, &[0xffu8; 192]),
            Err(SignatureError::SignatureVerificationFailed)
        )
    });
}

/// A genuine RSASSA-PKCS1-v1_5/SHA-256 signature under the SHA-256 group's key of
/// `rsa_pkcs1_1536_sig_gen_test.json`, for [`SIG_PLUS_N_MSG`]: made offline (Python 3.12) with
/// the file's `privateExponent`, the encoding checked against all eight of the group's own
/// signatures first, and the message the first of a numbered series whose signature `s` has
/// `s + n < 2^1536`, which none of the file's signatures has (its `n` begins `0xeb`).
const SIG_PLUS_N_MSG: &[u8] = b"RSA-1536 signature representative plus n, 10";
const SIG_PLUS_N_SIG: &str = "139164728040a5c4ec035bf031466bf0b20c81214c302da8f9e8efdd78058aa6\
    2eb9ada000fbf7f2bfdc99ef5dd52509ae233c11db82e6eb4c89e502d52274de067e0f7ec5d863b9e3e598de96\
    44ed35a23fa7d996710a67ddc7d8435e752276e191f8120c944171474d01ce4af0d82ab7094bd83dbf507b5fa0\
    30fab629588ff9accfa7ccf41d7d7bc858abd7dbc6d71c78b10c2f3a6b169930920e9ee4c9af52a0d3422461fd\
    d9d08549c148bce32bf2bf6206b2963693deacbc8d3b2e8fe5";

/// RFC 8017 §8.2.2 step 1 on a representative that is out of range but congruent to a genuine
/// signature: `s + n`. Without the range check, RSAVP1 would compute `(s + n)^e mod n =
/// s^e mod n` and accept it, so it is the check alone that refuses it.
#[test]
fn trait_verify_refuses_a_genuine_signature_plus_the_modulus() {
    let doc: Value =
        serde_json::from_str(&get_test_data("rsa_pkcs1_1536_sig_gen_test.json")).unwrap();
    let group = doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["sha"] == "SHA-256" && g["tests"].as_array().unwrap().len() == 8)
        .unwrap();
    let n: [u64; 24] = limbs_from_hex(group["privateKey"]["modulus"].as_str().unwrap());
    let e =
        u64::from_str_radix(group["privateKey"]["publicExponent"].as_str().unwrap(), 16).unwrap();
    let pk =
        RsaPublicComponents::<RSA1536>::new(&n, e).unwrap().into_key::<RSASSA_PKCS1_v1_5_SHA256>();

    let sig: [u8; 192] = hex_decode(SIG_PLUS_N_SIG).unwrap().try_into().unwrap();
    assert_eq!(pk.verify(SIG_PLUS_N_MSG, None, &sig), Ok(()));

    // s + n, over big-endian bytes; it fits in 1536 bits by the choice of message.
    let mut n_bytes = [0u8; 192];
    for (i, limb) in n.iter().enumerate() {
        n_bytes[192 - 8 * (i + 1)..192 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
    let mut sig_plus_n = [0u8; 192];
    let mut carry = 0u16;
    for i in (0..192).rev() {
        let t = u16::from(sig[i]) + u16::from(n_bytes[i]) + carry;
        sig_plus_n[i] = t as u8;
        carry = t >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        pk.verify(SIG_PLUS_N_MSG, None, &sig_plus_n),
        Err(SignatureError::SignatureVerificationFailed)
    );
}
