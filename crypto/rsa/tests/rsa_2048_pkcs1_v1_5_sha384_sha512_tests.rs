//! RSA-2048 RSASSA-PKCS1-v1_5 with SHA-384 and SHA-512, against Wycheproof's
//! `rsa_signature_2048_sha384_test.json`/`rsa_signature_2048_sha512_test.json`.
//!
//! Each of Wycheproof's `rsa_pkcs1_2048_sig_gen_test.json` groups (including its SHA-384 and
//! SHA-512 ones) uses a *distinct* key -- unlike the SHA-256 case
//! (`rsa_2048_pkcs1_v1_5_tests.rs`), there is no shared key to recover once and reuse across
//! hashes here, and factoring another key per hash is disproportionate to what this step needs:
//! `EMSA-PKCS1-v1_5`'s DigestInfo construction is generic over the hash (see `digest_info`'s own
//! docs) and already exercised end to end for SHA-256, and RSASP1/RSAVP1 do not depend on which
//! hash produced the message representative they are given. So the sign side here is a
//! self-consistency round trip against the SHA-256 key `rsa_2048_pkcs1_v1_5_tests.rs` already
//! recovered (a valid RSA private key signs under any hash choice; nothing about the key ties it
//! to SHA-256), while the verify side -- where the real risk is a wrong OID or digest length for
//! the hash in question -- is checked against all of Wycheproof's real vectors for both hashes.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_core_test_framework::signature::TestFrameworkSignature;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rsa::rsa_2048::{
    PK_LEN, RSA2048PrivateKey, RSA2048PublicKey, RSASSA_PKCS1_v1_5_SHA384,
    RSASSA_PKCS1_v1_5_SHA512, SIG_LEN, SK_LEN,
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

/// The same genuine RSA-2048 keypair `rsa_2048_pkcs1_v1_5_tests.rs` recovers (from
/// `rsa_pkcs1_2048_sig_gen_test.json`'s SHA-256 group) -- reused here as a plain, valid RSA-2048
/// key, not because it has anything to do with SHA-256 specifically.
fn genuine_key() -> RSA2048PrivateKey {
    let p: [u64; 16] = [
        0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
        0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
        0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
        0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
    ];
    let q: [u64; 16] = [
        0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
        0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
        0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
        0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
    ];
    let d_p: [u64; 16] = [
        0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
        0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
        0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
        0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
    ];
    let d_q: [u64; 16] = [
        0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
        0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
        0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
        0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
    ];
    let q_inv: [u64; 16] = [
        0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
        0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
        0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
        0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
    ];
    RSA2048PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
        .expect("recovered CRT components must be accepted")
}

#[test]
fn pkcs1_v1_5_sha384_round_trips() {
    let sk = genuine_key();
    let pk = RSA2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let sig = RSASSA_PKCS1_v1_5_SHA384::sign(&sk, b"hello", None).expect("signing must succeed");
    RSASSA_PKCS1_v1_5_SHA384::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PKCS1_v1_5_SHA384::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pkcs1_v1_5_sha512_round_trips() {
    let sk = genuine_key();
    let pk = RSA2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let sig = RSASSA_PKCS1_v1_5_SHA512::sign(&sk, b"hello", None).expect("signing must succeed");
    RSASSA_PKCS1_v1_5_SHA512::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PKCS1_v1_5_SHA512::verify(&pk, b"goodbye", None, &sig).is_err());
}

fn run_verify_vectors(
    filename: &str,
    verify: impl Fn(&RSA2048PublicKey, &[u8], &[u8; 256]) -> bool,
    expected_sha: &str,
    expected_num_tests: usize,
    expected_num_valid: usize,
    expected_num_invalid: usize,
) {
    let doc: Value = serde_json::from_str(&get_test_data(filename)).expect("valid JSON");

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;
    let mut num_missing_null = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], expected_sha);
        let n: [u64; 32] = limbs_from_hex(group["publicKey"]["modulus"].as_str().unwrap());
        let e = u32::from_str_radix(group["publicKey"]["publicExponent"].as_str().unwrap(), 16)
            .expect("publicExponent fits in u32 for every group here");
        let pk = RSA2048PublicKey::new(&n, e).expect("group public key must be valid");

        for test in group["tests"].as_array().unwrap() {
            num_tests += 1;
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();
            let flags: Vec<&str> =
                test["flags"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();

            let Ok(sig): Result<[u8; 256], _> = sig_bytes.try_into() else {
                assert_ne!(test["result"], "valid", "tcId {tc_id}: wrong-length 'valid' signature");
                num_invalid += 1;
                continue;
            };

            let verified = verify(&pk, &msg, &sig);
            match test["result"].as_str().unwrap() {
                "valid" => {
                    assert!(verified, "tcId {tc_id}: expected valid, got invalid");
                    num_valid += 1;
                }
                "invalid" => {
                    assert!(!verified, "tcId {tc_id}: expected invalid, got valid");
                    num_invalid += 1;
                }
                "acceptable" => {
                    assert_eq!(
                        flags,
                        vec!["MissingNull"],
                        "tcId {tc_id}: unreviewed 'acceptable' flag combination {flags:?}"
                    );
                    assert!(verified, "tcId {tc_id}: MissingNull must be accepted");
                    num_missing_null += 1;
                }
                other => panic!("tcId {tc_id}: unknown result {other:?}"),
            }
        }
    }

    assert_eq!(num_tests, expected_num_tests);
    assert_eq!(num_missing_null, 1);
    assert_eq!(num_valid, expected_num_valid);
    assert_eq!(num_invalid, expected_num_invalid);
}

#[test]
fn rsa_signature_sha384_wycheproof_vectors() {
    run_verify_vectors(
        "rsa_signature_2048_sha384_test.json",
        |pk, msg, sig| RSASSA_PKCS1_v1_5_SHA384::verify(pk, msg, None, sig).is_ok(),
        "SHA-384",
        258,
        7,
        250,
    );
}

#[test]
fn rsa_signature_sha512_wycheproof_vectors() {
    run_verify_vectors(
        "rsa_signature_2048_sha512_test.json",
        |pk, msg, sig| RSASSA_PKCS1_v1_5_SHA512::verify(pk, msg, None, sig).is_ok(),
        "SHA-512",
        259,
        8,
        250,
    );
}

// ---- bouncycastle_core trait conformance ------------------------------------------------------

fn fixed_keypair() -> Result<(RSA2048PublicKey, RSA2048PrivateKey), SignatureError> {
    let sk = genuine_key();
    let pk = RSA2048PublicKey::new(sk.n(), 0x10001)?;
    Ok((pk, sk))
}

/// `core-test-framework`'s conformance suite for the SHA-384 and SHA-512 pairings (deterministic,
/// `ctx` ignored). The exhaustive bit-flip pass runs in `rsa_2048_pkcs1_v1_5_tests.rs`'s SHA-256
/// suite, over the same generic code.
#[test]
fn pkcs1_v1_5_sha384_sha512_trait_conformance_suite() {
    let framework = TestFrameworkSignature::new(true, false);
    framework.test_signature::<
        RSA2048PublicKey,
        RSA2048PrivateKey,
        RSASSA_PKCS1_v1_5_SHA384,
        RSASSA_PKCS1_v1_5_SHA384,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, false);
    framework.test_signature::<
        RSA2048PublicKey,
        RSA2048PrivateKey,
        RSASSA_PKCS1_v1_5_SHA512,
        RSASSA_PKCS1_v1_5_SHA512,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, false);
}
