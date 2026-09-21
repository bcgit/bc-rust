//! RSA-3072 RSASSA-PSS-SHAKE128 (RFC 8702 §3.2.1) against Wycheproof's
//! `rsa_pss_3072_shake128_test.json`, following `rsa_2048_pss_shake128_tests.rs`'s split: a
//! self-consistency round trip for signing (reusing the genuine RSA-3072 key
//! `rsa_3072_tests.rs` recovered), and all of Wycheproof's real vectors for verification.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_core_test_framework::signature::TestFrameworkSignature;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsa_3072::{
    PK_LEN, RSASSA_PSS_SHAKE128, Rsa3072PrivateKey, Rsa3072PublicKey, SIG_LEN, SK_LEN,
};
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Signs through the streaming trait path with a fixed salt (`set_signer_salt`) -- the
/// deterministic PSS mode, for tests against a known salt. Returns `sign_final`'s `Result`.
macro_rules! sign_with_salt {
    ($ty:ty, $sk:expr, $msg:expr, $salt:expr) => {{
        let mut signer = <$ty>::sign_init($sk, None).unwrap();
        signer.set_signer_salt($salt);
        signer.sign_update($msg);
        signer.sign_final()
    }};
}

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

/// The same genuine RSA-3072 keypair `rsa_3072_tests.rs` recovers (from
/// `rsa_pkcs1_3072_sig_gen_test.json`'s SHA-256 group) -- reused here as a plain, valid RSA-3072
/// key, not because it has anything to do with SHA-256/MGF1 specifically.
fn genuine_key() -> Rsa3072PrivateKey {
    let p: [u64; 24] = [
        0xb26d973345bc4c5f, 0x23251a1d29962ca9, 0x554fc3f23d6c9046, 0x89ffe73b1401e9b8,
        0xe0b448b454670aca, 0xa73ea5c2413d1da2, 0xe9539bc7a8d3b351, 0x357984fc116af9cb,
        0xa93e40aac908e4e3, 0xae586c1e7f5c52cd, 0x80deaeaab651c7a9, 0xe261a4f7f4505580,
        0xc5a703b2fc28bfcf, 0x14521a6893f3f3c5, 0x0f08d649107f449a, 0xd96ceabb7ee83ce5,
        0x1b2e8a9b2bb69525, 0x383ead851fac07ad, 0x939deb88dff68550, 0xce9fa16a1cc92120,
        0x43604a7f2be2860f, 0xba55f20a964c4e63, 0x0ed9ac8a812545da, 0xf5eca16e0e83696b,
    ];
    let q: [u64; 24] = [
        0x7981610848c55cdd, 0x8bce03c5d339b975, 0xb8227d7b5d76ce8b, 0x6edee1e9d17781db,
        0x1c127ac3c4d0bd59, 0xb8b28f38951d7bee, 0x496086fa1300249a, 0x790e5c34729a8efb,
        0x9bdb81968f4a6d7c, 0x6018fd4ed9a3545f, 0x6ccb168d5b510dbe, 0xe1d845c6553c0a54,
        0x73ec1d97f669e298, 0x8b898025ef470e43, 0x160deb327e8ace01, 0x640191099b355611,
        0xe0ec501ccc94b2b0, 0x4f98c9ee4fdae41b, 0x0082a3bc42af1a14, 0x510a623c2b47a522,
        0x32057f9da6dbefc4, 0x95ad92b6f295d610, 0x19ddbfcfa2d96704, 0xcf25446f59cf5129,
    ];
    let d_p: [u64; 24] = [
        0xeeb10a8531c470ed, 0xbcd9be04cdc9d65c, 0xb684b458e4ab3854, 0x6a2dafd0d3b23a21,
        0xc812cbd3dccc8b35, 0x3e67363a947405c6, 0xa3ce9c7d391bdbb2, 0xf8bd10156b4bd580,
        0x3c1ce3ae99eb37da, 0xcfa5f4771567cc23, 0x35e0be9a437021c1, 0x8a527b7b967be52e,
        0xc649435b483585d6, 0x1dc154ddadf6bc20, 0x69105ecfc1144838, 0x3dad9bdd05d4f6d4,
        0xf95601b3d122be79, 0x92f1eed27a0ada46, 0x152e93f904cfe6e6, 0x5a6e6d9c19e8bdb3,
        0x6c0437d3cb7c843f, 0x370e84e9f5f0f931, 0x514c6940c20eb67b, 0x6357a59679d26801,
    ];
    let d_q: [u64; 24] = [
        0x1a4dbeba87772d29, 0xe51861bbb4e73e73, 0x9e86b2483e9bf22c, 0xc9ebcf4d7c2d6c9f,
        0xbe8fe9def6b7a62c, 0x4e8805a755ac2904, 0x734f44f3e4e88d18, 0x7626602fc90ae694,
        0xde97c88d40fa1ac4, 0x4eeaf1aafe2e1ba5, 0x25cd66f5205b038b, 0x8fa6bb6ae73b182d,
        0x0c85ab03068cbfee, 0x96f0ae48529b490f, 0xbb4cc906ba283d18, 0x4bf60c135a264919,
        0x4c2cf95ce74fe42c, 0xf4a5e8eed2a70c7a, 0x14ecee22e846a7d3, 0xd2a4139a39cec9df,
        0x4ba0e0801d31cbf5, 0x088a7986f6c2b8c0, 0x8bdc0f566f876191, 0x0004dadabfc15b1a,
    ];
    let q_inv: [u64; 24] = [
        0x45b268741fca195c, 0x94eacf955ae5dacd, 0x3ad1a334fd85aa87, 0xe8b01c83f2aec93e,
        0xd05fdc78929fa0cf, 0x0745ab95edda215b, 0xe5c81a2189f11467, 0xeded3f90e0ba4a97,
        0xfbf69baed9510be5, 0x6bee976c25dbaff8, 0x6ad65e9fe6c28038, 0xef6613dd6bf885c1,
        0x594990da705ebdf7, 0x8ee8b716f19429fb, 0x2662db8c85318de4, 0x22481fc74a7a3d62,
        0xfe6c3600d9b8e9a9, 0x744fac4daabf5488, 0xfbee6ec24b75fbf0, 0x8be552c8be44f139,
        0xfb0da96bd423759d, 0xb3443d93e7e8ca62, 0x36fe01b950885ecd, 0x214a1f73130e48b3,
    ];
    Rsa3072PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
        .expect("recovered CRT components must be accepted")
}

#[test]
fn pss_shake128_sign_with_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = Rsa3072PublicKey::new(sk.n(), 0x10001).unwrap();

    let salt = [0x42u8; 32];
    let sig = sign_with_salt!(RSASSA_PSS_SHAKE128, &sk, b"the message to sign", salt)
        .expect("signing must succeed");
    RSASSA_PSS_SHAKE128::verify(&pk, b"the message to sign", None, &sig).expect("must verify");

    let sig2 = sign_with_salt!(RSASSA_PSS_SHAKE128, &sk, b"the message to sign", salt).unwrap();
    assert_eq!(sig, sig2);

    assert!(RSASSA_PSS_SHAKE128::verify(&pk, b"a different message", None, &sig).is_err());
}

#[test]
fn pss_shake128_sign_with_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = Rsa3072PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();

    let sig_a = RSASSA_PSS_SHAKE128::sign_randomized(&sk, b"hello", &mut rng)
        .expect("signing must succeed");
    let sig_b = RSASSA_PSS_SHAKE128::sign_randomized(&sk, b"hello", &mut rng)
        .expect("signing must succeed");
    assert_ne!(sig_a, sig_b, "PSS is randomized: two signatures of the same message must differ");
    RSASSA_PSS_SHAKE128::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHAKE128::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

#[test]
fn rsa_pss_3072_shake128_wycheproof_vectors() {
    let doc: Value = serde_json::from_str(&get_test_data("rsa_pss_3072_shake128_test.json"))
        .expect("valid JSON");

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], "SHAKE128");
        assert_eq!(group["mgf"], "SHAKE128");
        assert_eq!(group["sLen"], 32);
        let n: [u64; 48] = limbs_from_hex(group["publicKey"]["modulus"].as_str().unwrap());
        let e = u32::from_str_radix(group["publicKey"]["publicExponent"].as_str().unwrap(), 16)
            .expect("publicExponent fits in u32 for every group here");
        let pk = Rsa3072PublicKey::new(&n, e).expect("group public key must be valid");

        for test in group["tests"].as_array().unwrap() {
            num_tests += 1;
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();

            let Ok(sig): Result<[u8; 384], _> = sig_bytes.try_into() else {
                assert_ne!(test["result"], "valid", "tcId {tc_id}: wrong-length 'valid' signature");
                num_invalid += 1;
                continue;
            };

            let verified = RSASSA_PSS_SHAKE128::verify(&pk, &msg, None, &sig).is_ok();
            match test["result"].as_str().unwrap() {
                "valid" => {
                    assert!(verified, "tcId {tc_id}: expected valid, got invalid");
                    num_valid += 1;
                }
                "invalid" => {
                    assert!(!verified, "tcId {tc_id}: expected invalid, got valid");
                    num_invalid += 1;
                }
                other => panic!("tcId {tc_id}: unknown result {other:?}"),
            }
        }
    }

    assert_eq!(num_tests, 114);
    assert_eq!(num_valid, 69);
    assert_eq!(num_invalid, 45);
}

// ---- bouncycastle_core trait conformance ------------------------------------------------------

fn fixed_keypair() -> Result<(Rsa3072PublicKey, Rsa3072PrivateKey), SignatureError> {
    let sk = genuine_key();
    let pk = Rsa3072PublicKey::new(sk.n(), 0x10001)?;
    Ok((pk, sk))
}

#[test]
fn pss_shake128_trait_conformance_suite() {
    TestFrameworkSignature::new(false, false).test_signature::<
        Rsa3072PublicKey,
        Rsa3072PrivateKey,
        RSASSA_PSS_SHAKE128,
        RSASSA_PSS_SHAKE128,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, false);
}
