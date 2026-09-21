//! RSA-4096 against Wycheproof: `rsa_pkcs1_4096_sig_gen_test.json` (sign), `rsa_signature_4096_
//! sha{256,384,512}_test.json` (verify, all three hashes), and `rsa_pss_4096_sha{256,384,512}
//! _mgf1_*_test.json` (PSS verify, all three hashes -- unlike every other size in this crate,
//! Wycheproof has matching-hash-and-MGF PSS vectors for all three at 4096 bits). Only SHA-256 has
//! sig-gen key material to check signing against a known-correct output, so every other sign
//! pairing (PKCS#1 v1.5/SHA-384 and /SHA-512 signing, and PSS signing under all three hashes
//! with both an RNG-drawn and a fixed salt) is exercised by a self-consistency round trip instead, following
//! `rsa_3072_tests.rs`'s own precedent.
//!
//! `p`/`q`/`dP`/`dQ`/`qInv` were recovered from `rsa_pkcs1_4096_sig_gen_test.json`'s SHA-256
//! group's `(n, e, d)` via the same factoring-from-d method as RSA-2048's key, cross-checked
//! against all 8 of that group's real signatures before being pasted here.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_core_test_framework::signature::{
    TestFrameworkSignature, TestFrameworkSignatureKeys,
};
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsa_4096::{
    PK_LEN, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PKCS1_v1_5_SHA384, RSASSA_PKCS1_v1_5_SHA512,
    RSASSA_PSS_SHA256, RSASSA_PSS_SHA384, RSASSA_PSS_SHA512, Rsa4096PrivateKey, Rsa4096PublicKey,
    SIG_LEN, SK_LEN,
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

fn genuine_key() -> Rsa4096PrivateKey {
    let p: [u64; 32] = [
        0x5141acd4afd4771f, 0x5857742b7e4032dc, 0xb7a9b97fe5371396, 0x4b1783c5bc91a6dc,
        0xaf5d0c912d97b728, 0xeb265a7f28b88976, 0x5e993302aa72f11d, 0xc007ad09d76ae22a,
        0x44cbb87b8bec8fd3, 0xf152f15c73b95ac5, 0x8dbdad655fbbad20, 0x59855d0de1c794ac,
        0x4c6060926d878a20, 0xf38860474e44993d, 0x177a91caeef98b13, 0xd1676123544d3def,
        0xc1673063d8487390, 0xfedd55ba2e233a6d, 0x016a5735b883c639, 0xbd813f9fb752805b,
        0x923a7b775b5ffaff, 0xb174e55ca6a12c21, 0x0373077895a6934a, 0x6b725388f54ffea3,
        0x953c09104e1fd2d3, 0x9114f39017871528, 0x33918eb72b786b3c, 0xf43b8626af13d14a,
        0x886a0904eb486140, 0x0037409b81f3a5b3, 0x19e44e26140d2ede, 0xc3c677495c2bd566,
    ];
    let q: [u64; 32] = [
        0xee0745546a6a1c73, 0x8b1050436d882425, 0xdc2e7872ce6fb2b7, 0xf98671ee4899050b,
        0x796a5dd847400804, 0x9ba1f51132355792, 0xc39066a9fc27985b, 0x81f4bca5d15e0962,
        0x6a46cf6dbb6d2ad9, 0xdf3d085ae7693b7e, 0xf58e3c750b6d978a, 0xb52b9000d3a7aab1,
        0xdbb07e23bce1960c, 0x4e291b5c8ddaa6a7, 0x0544a7a7cb3f0792, 0xc695e324fbb11beb,
        0xbded418507f2f175, 0x49fe5f47737ff436, 0xeb37f85b7554d7ad, 0x724d042aef25cea2,
        0xeadbd11dcd2fec7b, 0xb50812705b379f5d, 0xfc50fa98fb67b746, 0x16f2bdf5964b26c7,
        0xcc1c817507859246, 0x6810c2136ad81b16, 0xd7bc78d637e17e0e, 0x6882825347455782,
        0xcdb615d921f5e705, 0x0a982efbe6658e6b, 0x59e96686f7b8752f, 0xc357cf685f9b8d4e,
    ];
    let d_p: [u64; 32] = [
        0x3cd8e91fee6bcdd3, 0x074fdc015ab1c45f, 0x34135987a2288907, 0xf6961d44dfb7505c,
        0x251be32315a85b75, 0xe8982e8493a2ae78, 0xc268493861002977, 0x140fb5806735814e,
        0x35d426d719b12c41, 0xa5f194dbbf374226, 0xa0a6c5314c1a2375, 0x66899d59c04b60c4,
        0x5158d7867dbfec94, 0xec1dde997c00125e, 0x62e5a19b2a71decf, 0x310291892c37e8a2,
        0x223e06c9521f4a45, 0xe4f08e1d5543ed74, 0xcf4dc8de58b9e9ad, 0x9167ad4f122b3263,
        0xf110dbac286712f6, 0x2db237d0f39cda5f, 0xa54b67367c857476, 0x138b37b7b1ed2219,
        0x950d9f4e82aab9bc, 0x90943e671e928e23, 0x44791809c9fcf19f, 0xc70396da054ba478,
        0x77248f6fe00e31bd, 0xf3731b1415d5f2ee, 0xf5242aa6657760cd, 0xa6bbb5460638d2b2,
    ];
    let d_q: [u64; 32] = [
        0xfa935bd36284ea6b, 0x9c255a57d6b3ac0f, 0x35b350881ec52e99, 0xf48d35dd11598957,
        0x61fee5d3763b8cfb, 0xf86f5d1936a161ae, 0x3a8b852507264ae2, 0xe558f90950a572a2,
        0x205aeb15029c95a6, 0x0fa8cf020e960c3b, 0x6a793c66abfb0963, 0xa9c7d7b391d0cbee,
        0x6310f31421e85c6b, 0xc0de89d2edb32796, 0x1cf37af6eab4ed97, 0x1533eacf819c878e,
        0xc700fc7e2a482abe, 0x4d1c62a63d917682, 0x89141558095c3228, 0x029bb05df0b8f121,
        0xa239e00b24ba9b5b, 0x74c3c55d5051f35f, 0x2f45200123860c7d, 0x4fabf224d27abaf1,
        0x0acb80fbf7ed2d86, 0x87db455a8bee03ce, 0x980bbbd1afa8fac6, 0x9d9ee6515ded4930,
        0x4c62a05dae0f744b, 0x69ff90e2839348c9, 0xda141e6d351e42da, 0x178cd58f72bf5118,
    ];
    let q_inv: [u64; 32] = [
        0x5792505b857d3e8d, 0x8a13922b1240c0d2, 0xb5fcb8bf3df1f936, 0x74483606c2cd7ed8,
        0xd40f33bbfd9be093, 0xb5f40ed6632989f5, 0x7f2cc0cd8c8a0661, 0x87630c6b25dddeb5,
        0x7032a5af6ef7c20f, 0x90331600142e6cb9, 0x67b92645b68c6d8f, 0xb63517c7c39843cf,
        0xd50712bf8fc35882, 0x3c421e2447b1a989, 0x7a251afa7aaa6908, 0x43b4de11f99b2654,
        0x1e02735920ef48a3, 0x218fc24da34ce8f0, 0x280446e49b3b9b15, 0x8d96f07411c882bf,
        0x66e283f5d5fb0e6e, 0x0844efd28d853446, 0x5eb4def8dba57b99, 0x474111f92d19f3ab,
        0x748d7b5d94cacd4d, 0xcf634f3a07cea4b7, 0x8dbcca51f4da4379, 0x80774236a54ec9dc,
        0x6a1ef00ee582d3d1, 0xdecfb14ca1e80c8e, 0xc78af5f6c807cc99, 0x484ad86e79415ea3,
    ];
    Rsa4096PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
        .expect("recovered CRT components must be accepted")
}

#[test]
fn pkcs1_v1_5_sig_gen_4096_sha256() {
    let sk = genuine_key();
    let doc: Value =
        serde_json::from_str(&get_test_data("rsa_pkcs1_4096_sig_gen_test.json")).unwrap();
    let group = doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["sha"] == "SHA-256")
        .expect("the SHA-256/4096 group");

    let mut num_tests = 0usize;
    for test in group["tests"].as_array().unwrap() {
        num_tests += 1;
        let tc_id = test["tcId"].as_u64().unwrap();
        let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
        let expected_sig = hex_decode(test["sig"].as_str().unwrap()).unwrap();
        let sig = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, &msg, None).unwrap_or_else(|e| {
            panic!("tcId {tc_id}: signing failed: {e:?}");
        });
        assert_eq!(sig.to_vec(), expected_sig, "tcId {tc_id}: signature mismatch");
    }
    assert_eq!(num_tests, 8);
}

/// Mutation testing found that PKCS#1 v1.5/SHA-384 and /SHA-512 signing were never called by any test at
/// this modulus size (the real Wycheproof verify vectors below only exercise `verify`, and only
/// SHA-256 has a sig-gen file to sign against): a whole-function-body mutant replacing either sign
/// function with a constant still passed the whole suite.
#[test]
fn pkcs1_v1_5_sha384_and_sha512_round_trip() {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001).unwrap();
    let sig384 = RSASSA_PKCS1_v1_5_SHA384::sign(&sk, b"hello", None).unwrap();
    RSASSA_PKCS1_v1_5_SHA384::verify(&pk, b"hello", None, &sig384).unwrap();
    let sig512 = RSASSA_PKCS1_v1_5_SHA512::sign(&sk, b"hello", None).unwrap();
    RSASSA_PKCS1_v1_5_SHA512::verify(&pk, b"hello", None, &sig512).unwrap();
}

fn run_pkcs1_v1_5_verify_vectors(
    filename: &str,
    verify: impl Fn(&Rsa4096PublicKey, &[u8], &[u8; 512]) -> bool,
    expected_sha: &str,
    expected_valid: usize,
    expected_invalid: usize,
) {
    let doc: Value = serde_json::from_str(&get_test_data(filename)).expect("valid JSON");
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;
    let mut num_missing_null = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], expected_sha);
        let n: [u64; 64] = limbs_from_hex(group["publicKey"]["modulus"].as_str().unwrap());
        let e = u32::from_str_radix(group["publicKey"]["publicExponent"].as_str().unwrap(), 16)
            .unwrap();
        let pk = Rsa4096PublicKey::new(&n, e).unwrap();

        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();
            let flags: Vec<&str> =
                test["flags"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();

            let Ok(sig): Result<[u8; 512], _> = sig_bytes.try_into() else {
                assert_ne!(test["result"], "valid");
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
                    assert_eq!(flags, vec!["MissingNull"], "tcId {tc_id}: unreviewed acceptable");
                    assert!(verified);
                    num_missing_null += 1;
                }
                other => panic!("tcId {tc_id}: unknown result {other:?}"),
            }
        }
    }
    assert_eq!(num_missing_null, 1);
    assert_eq!(num_valid, expected_valid, "for {filename}");
    assert_eq!(num_invalid, expected_invalid, "for {filename}");
}

#[test]
fn rsa_signature_4096_sha256_wycheproof_vectors() {
    run_pkcs1_v1_5_verify_vectors(
        "rsa_signature_4096_sha256_test.json",
        |pk, msg, sig| RSASSA_PKCS1_v1_5_SHA256::verify(pk, msg, None, sig).is_ok(),
        "SHA-256",
        7,
        250,
    );
}

#[test]
fn rsa_signature_4096_sha384_wycheproof_vectors() {
    run_pkcs1_v1_5_verify_vectors(
        "rsa_signature_4096_sha384_test.json",
        |pk, msg, sig| RSASSA_PKCS1_v1_5_SHA384::verify(pk, msg, None, sig).is_ok(),
        "SHA-384",
        7,
        251,
    );
}

#[test]
fn rsa_signature_4096_sha512_wycheproof_vectors() {
    run_pkcs1_v1_5_verify_vectors(
        "rsa_signature_4096_sha512_test.json",
        |pk, msg, sig| RSASSA_PKCS1_v1_5_SHA512::verify(pk, msg, None, sig).is_ok(),
        "SHA-512",
        7,
        251,
    );
}

fn run_pss_verify_vectors(
    filename: &str,
    verify: impl Fn(&Rsa4096PublicKey, &[u8], &[u8; 512]) -> bool,
    expected_sha: &str,
    expected_slen: u64,
    expected_valid: usize,
    expected_invalid: usize,
) {
    let doc: Value = serde_json::from_str(&get_test_data(filename)).expect("valid JSON");
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], expected_sha);
        assert_eq!(group["mgfSha"], expected_sha);
        assert_eq!(group["sLen"], expected_slen);
        let n: [u64; 64] = limbs_from_hex(group["publicKey"]["modulus"].as_str().unwrap());
        let e = u32::from_str_radix(group["publicKey"]["publicExponent"].as_str().unwrap(), 16)
            .unwrap();
        let pk = Rsa4096PublicKey::new(&n, e).unwrap();

        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();
            let Ok(sig): Result<[u8; 512], _> = sig_bytes.try_into() else {
                assert_ne!(test["result"], "valid");
                num_invalid += 1;
                continue;
            };
            let verified = verify(&pk, &msg, &sig);
            match test["result"].as_str().unwrap() {
                "valid" => {
                    assert!(verified, "tcId {tc_id}: expected valid");
                    num_valid += 1;
                }
                "invalid" => {
                    assert!(!verified, "tcId {tc_id}: expected invalid");
                    num_invalid += 1;
                }
                other => panic!("unknown result {other:?}"),
            }
        }
    }
    assert_eq!(num_valid, expected_valid, "for {filename}");
    assert_eq!(num_invalid, expected_invalid, "for {filename}");
}

#[test]
fn rsa_pss_4096_sha256_mgf1_32_wycheproof_vectors() {
    run_pss_verify_vectors(
        "rsa_pss_4096_sha256_mgf1_32_test.json",
        |pk, msg, sig| RSASSA_PSS_SHA256::verify(pk, msg, None, sig).is_ok(),
        "SHA-256",
        32,
        63,
        45,
    );
}

#[test]
fn rsa_pss_4096_sha384_mgf1_48_wycheproof_vectors() {
    run_pss_verify_vectors(
        "rsa_pss_4096_sha384_mgf1_48_test.json",
        |pk, msg, sig| RSASSA_PSS_SHA384::verify(pk, msg, None, sig).is_ok(),
        "SHA-384",
        48,
        95,
        46,
    );
}

#[test]
fn rsa_pss_4096_sha512_mgf1_64_wycheproof_vectors() {
    run_pss_verify_vectors(
        "rsa_pss_4096_sha512_mgf1_64_test.json",
        |pk, msg, sig| RSASSA_PSS_SHA512::verify(pk, msg, None, sig).is_ok(),
        "SHA-512",
        64,
        132,
        47,
    );
}

/// Mutation testing found that none of the six PSS signing paths (three hashes, RNG-drawn or fixed salt)
/// were ever called at this modulus size: the real Wycheproof PSS vectors above only exercise
/// `verify` (against externally-sourced signatures), so a whole-function-body mutant replacing any
/// sign function with a constant still passed the whole suite. One fixed-salt-round-trip-plus-
/// rejection test and one RNG-freshness test per hash, matching
/// `rsa_2048_pss_sha384_sha512_tests.rs`'s shape, calls each function at least once.
#[test]
fn pss_sha256_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001).unwrap();
    let salt = [0x22u8; 32];
    let sig =
        sign_with_salt!(RSASSA_PSS_SHA256, &sk, b"hello", salt).expect("signing must succeed");
    RSASSA_PSS_SHA256::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PSS_SHA256::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pss_sha256_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();
    let sig_a =
        RSASSA_PSS_SHA256::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b =
        RSASSA_PSS_SHA256::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b, "PSS is randomized: two signatures of the same message must differ");
    RSASSA_PSS_SHA256::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHA256::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

#[test]
fn pss_sha384_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001).unwrap();
    let salt = [0x11u8; 48];
    let sig =
        sign_with_salt!(RSASSA_PSS_SHA384, &sk, b"hello", salt).expect("signing must succeed");
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PSS_SHA384::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pss_sha384_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();
    let sig_a =
        RSASSA_PSS_SHA384::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b =
        RSASSA_PSS_SHA384::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b, "PSS is randomized: two signatures of the same message must differ");
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

#[test]
fn pss_sha512_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001).unwrap();
    let salt = [0x33u8; 64];
    let sig =
        sign_with_salt!(RSASSA_PSS_SHA512, &sk, b"hello", salt).expect("signing must succeed");
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PSS_SHA512::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pss_sha512_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();
    let sig_a =
        RSASSA_PSS_SHA512::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b =
        RSASSA_PSS_SHA512::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b, "PSS is randomized: two signatures of the same message must differ");
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

// ---- bouncycastle_core trait conformance ------------------------------------------------------

fn fixed_keypair() -> Result<(Rsa4096PublicKey, Rsa4096PrivateKey), SignatureError> {
    let sk = genuine_key();
    let pk = Rsa4096PublicKey::new(sk.n(), 0x10001)?;
    Ok((pk, sk))
}

/// `core-test-framework`'s full conformance suite for one deterministic and one randomized
/// pairing at this width. An RSA-4096 private-key operation is slow enough in a debug build that
/// the suite's dozen signatures per pairing add up, so the remaining pairings get
/// [`trait_round_trip`] instead: the generic code they share has already had the full suite at
/// RSA-2048 and RSA-3072, and only this size's width constants are new.
#[test]
fn sha256_trait_conformance_suites() {
    TestFrameworkSignature::new(true, false).test_signature::<
        Rsa4096PublicKey,
        Rsa4096PrivateKey,
        RSASSA_PKCS1_v1_5_SHA256,
        RSASSA_PKCS1_v1_5_SHA256,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, false);
    TestFrameworkSignature::new(false, false).test_signature::<
        Rsa4096PublicKey,
        Rsa4096PrivateKey,
        RSASSA_PSS_SHA256,
        RSASSA_PSS_SHA256,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, false);
}

#[test]
fn key_trait_boundary_conditions() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<Rsa4096PublicKey, Rsa4096PrivateKey, PK_LEN, SK_LEN>(fixed_keypair);
}

/// Sign one-shot and streamed, verify both, and reject a different message -- what a wrong width
/// constant in this size's aliases would break.
fn trait_round_trip<S>(pk: &Rsa4096PublicKey, sk: &Rsa4096PrivateKey)
where
    S: Signer<Rsa4096PrivateKey, SK_LEN, SIG_LEN>
        + SignatureVerifier<Rsa4096PublicKey, PK_LEN, SIG_LEN>,
{
    let msg = b"RSA-4096 trait round trip";
    let sig = S::sign(sk, msg, None).unwrap();
    S::verify(pk, msg, None, &sig).unwrap();
    let mut signer = S::sign_init(sk, None).unwrap();
    signer.sign_update(&msg[..8]);
    signer.sign_update(&msg[8..]);
    S::verify(pk, msg, None, &signer.sign_final().unwrap()).unwrap();
    assert!(S::verify(pk, b"a different message", None, &sig).is_err());
}

#[test]
fn remaining_pairings_trait_round_trips() {
    let (pk, sk) = fixed_keypair().unwrap();
    trait_round_trip::<RSASSA_PKCS1_v1_5_SHA384>(&pk, &sk);
    trait_round_trip::<RSASSA_PKCS1_v1_5_SHA512>(&pk, &sk);
    trait_round_trip::<RSASSA_PSS_SHA384>(&pk, &sk);
    trait_round_trip::<RSASSA_PSS_SHA512>(&pk, &sk);
}
