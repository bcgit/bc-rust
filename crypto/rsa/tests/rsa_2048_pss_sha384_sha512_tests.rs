//! RSA-2048 RSASSA-PSS with SHA-384 and SHA-512, against Wycheproof's
//! `rsa_pss_2048_sha384_mgf1_48_test.json` for SHA-384. No matching-hash-and-MGF SHA-512 PSS
//! vector file exists in this Wycheproof checkout (only the SHA-512/224 and SHA-512/256 variants,
//! and a mixed SHA-512-hash/MGF1-SHA-256 "params" file, neither of which this crate's SHA-512
//! wiring is), so SHA-512 is covered by self-consistency round trips only, the same as SHA-384's
//! sign side -- see `rsa_2048_pkcs1_v1_5_sha384_sha512_tests.rs` for why reusing the SHA-256
//! sig-gen key here (rather than factoring a fresh one) is the right tradeoff.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{SignatureVerifier, Signer};
use bouncycastle_core_test_framework::signature::TestFrameworkSignature;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsa_2048::{
    PK_LEN, RSASSA_PSS_SHA384, RSASSA_PSS_SHA512, Rsa2048PrivateKey, Rsa2048PublicKey, SIG_LEN,
    SK_LEN,
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

/// The same genuine RSA-2048 keypair used throughout this crate's other test files -- see
/// `rsa_2048_pkcs1_v1_5_tests.rs` for the full, sourced provenance.
fn genuine_key() -> Rsa2048PrivateKey {
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
    Rsa2048PrivateKey::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)
        .expect("recovered CRT components must be accepted")
}

#[test]
fn pss_sha384_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let salt = [0x42u8; 48];
    let sig =
        sign_with_salt!(RSASSA_PSS_SHA384, &sk, b"hello", salt).expect("signing must succeed");
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PSS_SHA384::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pss_sha384_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();
    let sig_a =
        RSASSA_PSS_SHA384::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b =
        RSASSA_PSS_SHA384::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b);
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHA384::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

#[test]
fn pss_sha512_fixed_salt_round_trips() {
    let sk = genuine_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let salt = [0x42u8; 64];
    let sig =
        sign_with_salt!(RSASSA_PSS_SHA512, &sk, b"hello", salt).expect("signing must succeed");
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig).expect("must verify");
    assert!(RSASSA_PSS_SHA512::verify(&pk, b"goodbye", None, &sig).is_err());
}

#[test]
fn pss_sha512_rng_produces_fresh_salts_that_both_verify() {
    let sk = genuine_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();
    let sig_a =
        RSASSA_PSS_SHA512::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b =
        RSASSA_PSS_SHA512::sign_randomized(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b);
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig_a).expect("sig_a must verify");
    RSASSA_PSS_SHA512::verify(&pk, b"hello", None, &sig_b).expect("sig_b must verify");
}

#[test]
fn rsa_pss_sha384_mgf1_48_wycheproof_vectors() {
    let doc: Value = serde_json::from_str(&get_test_data("rsa_pss_2048_sha384_mgf1_48_test.json"))
        .expect("valid JSON");

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], "SHA-384");
        assert_eq!(group["mgfSha"], "SHA-384");
        assert_eq!(group["sLen"], 48);
        let n: [u64; 32] = limbs_from_hex(group["publicKey"]["modulus"].as_str().unwrap());
        let e = u32::from_str_radix(group["publicKey"]["publicExponent"].as_str().unwrap(), 16)
            .expect("publicExponent fits in u32 for every group here");
        let pk = Rsa2048PublicKey::new(&n, e).expect("group public key must be valid");

        for test in group["tests"].as_array().unwrap() {
            num_tests += 1;
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig_bytes = hex_decode(test["sig"].as_str().unwrap()).unwrap();

            let Ok(sig): Result<[u8; 256], _> = sig_bytes.try_into() else {
                assert_ne!(test["result"], "valid", "tcId {tc_id}: wrong-length 'valid' signature");
                num_invalid += 1;
                continue;
            };

            let verified = RSASSA_PSS_SHA384::verify(&pk, &msg, None, &sig).is_ok();
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

    assert_eq!(num_tests, 141);
    assert_eq!(num_valid, 95);
    assert_eq!(num_invalid, 46);
}

// ---- bouncycastle_core trait conformance ------------------------------------------------------

fn fixed_keypair() -> Result<(Rsa2048PublicKey, Rsa2048PrivateKey), SignatureError> {
    let sk = genuine_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001)?;
    Ok((pk, sk))
}

/// `core-test-framework`'s conformance suite for the SHA-384/SHA-512 PSS pairings (randomized,
/// `ctx` ignored); the bit-flip pass runs in `rsa_2048_pss_tests.rs`'s SHA-256 suite.
#[test]
fn pss_sha384_sha512_trait_conformance_suite() {
    let framework = TestFrameworkSignature::new(false, false);
    framework.test_signature::<
        Rsa2048PublicKey,
        Rsa2048PrivateKey,
        RSASSA_PSS_SHA384,
        RSASSA_PSS_SHA384,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, false);
    framework.test_signature::<
        Rsa2048PublicKey,
        Rsa2048PrivateKey,
        RSASSA_PSS_SHA512,
        RSASSA_PSS_SHA512,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, false);
}

#[test]
fn pss_sha384_and_sha512_reject_each_others_signatures() {
    let (pk, sk) = fixed_keypair().unwrap();
    let msg = b"PSS across both APIs";
    RSASSA_PSS_SHA384::verify(&pk, msg, None, &RSASSA_PSS_SHA384::sign(&sk, msg, None).unwrap())
        .unwrap();
    RSASSA_PSS_SHA512::verify(&pk, msg, None, &RSASSA_PSS_SHA512::sign(&sk, msg, None).unwrap())
        .unwrap();
    let mut rng = DefaultRNG::default();
    let free_384 = RSASSA_PSS_SHA384::sign_randomized(&sk, msg, &mut rng).unwrap();
    let free_512 = RSASSA_PSS_SHA512::sign_randomized(&sk, msg, &mut rng).unwrap();
    RSASSA_PSS_SHA384::verify(&pk, msg, None, &free_384).unwrap();
    RSASSA_PSS_SHA512::verify(&pk, msg, None, &free_512).unwrap();
    // The two hash pairings are distinct encodings: neither accepts the other's signature.
    assert!(RSASSA_PSS_SHA384::verify(&pk, msg, None, &free_512).is_err());
    assert!(RSASSA_PSS_SHA512::verify(&pk, msg, None, &free_384).is_err());
}
