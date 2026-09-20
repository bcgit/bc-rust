//! RSA-2048/SHA-256/MGF1-SHA-256/32-byte-salt RSASSA-PSS against Wycheproof
//! (`rsa_pss_2048_sha256_mgf1_32_test.json`), following the same lookup convention as
//! `rsa_2048_pkcs1_v1_5_tests.rs`.
//!
//! Wycheproof carries no PSS sig-gen vectors (PSS is randomized, so there is no single "the"
//! correct signature per message the way PKCS#1 v1.5's deterministic encoding gives one): the
//! sign side is exercised here by a self-consistency round trip (sign then verify) against the
//! same genuine CRT key `rsa_2048_pkcs1_v1_5_tests.rs` recovered from
//! `rsa_pkcs1_2048_sig_gen_test.json`, and the verify side by all 108 real vectors in
//! `rsa_pss_2048_sha256_mgf1_32_test.json` -- the same public key as that sig-gen key (confirmed
//! by comparing moduli in Python before writing this file).

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{RNG, SignatureVerifier, Signer};
use bouncycastle_core_test_framework::signature::TestFrameworkSignature;
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsa_2048::{
    PK_LEN, RSASSA_PSS_SHA256, Rsa2048PrivateKey, Rsa2048PublicKey, SIG_LEN, SK_LEN,
    pss_sign_sha256, pss_sign_sha256_with_salt, pss_verify_sha256,
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

/// The same genuine RSA-2048 keypair `rsa_2048_pkcs1_v1_5_tests.rs` recovers from
/// `rsa_pkcs1_2048_sig_gen_test.json` -- see that file for the full, sourced provenance (p/q
/// recovered from Wycheproof's own `(n, e, d)` via the standard factoring-from-d method).
fn wycheproof_key() -> Rsa2048PrivateKey {
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
fn pss_sign_with_fixed_salt_round_trips() {
    let sk = wycheproof_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001).unwrap();

    let salt = [0x42u8; 32];
    let sig = pss_sign_sha256_with_salt(&sk, b"the message to sign", &salt)
        .expect("signing must succeed");
    pss_verify_sha256(&pk, b"the message to sign", &sig).expect("must verify");

    // Deterministic given the same salt.
    let sig2 = pss_sign_sha256_with_salt(&sk, b"the message to sign", &salt).unwrap();
    assert_eq!(sig, sig2);

    assert!(pss_verify_sha256(&pk, b"a different message", &sig).is_err());
}

#[test]
fn pss_sign_with_rng_produces_fresh_salts_that_both_verify() {
    let sk = wycheproof_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001).unwrap();
    let mut rng = DefaultRNG::default();

    let sig_a = pss_sign_sha256(&sk, b"hello", &mut rng).expect("signing must succeed");
    let sig_b = pss_sign_sha256(&sk, b"hello", &mut rng).expect("signing must succeed");
    assert_ne!(sig_a, sig_b, "PSS is randomized: two signatures of the same message must differ");
    pss_verify_sha256(&pk, b"hello", &sig_a).expect("sig_a must verify");
    pss_verify_sha256(&pk, b"hello", &sig_b).expect("sig_b must verify");
}

#[test]
fn rsa_pss_sha256_mgf1_32_wycheproof_vectors() {
    let doc: Value = serde_json::from_str(&get_test_data("rsa_pss_2048_sha256_mgf1_32_test.json"))
        .expect("valid JSON");

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], "SHA-256");
        assert_eq!(group["mgfSha"], "SHA-256");
        assert_eq!(group["sLen"], 32);
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

            let verified = pss_verify_sha256(&pk, &msg, &sig).is_ok();
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

    assert_eq!(num_tests, 108);
    assert_eq!(num_valid, 63);
    assert_eq!(num_invalid, 45);
}

// ---- bouncycastle_core trait conformance ------------------------------------------------------

fn fixed_keypair() -> Result<(Rsa2048PublicKey, Rsa2048PrivateKey), SignatureError> {
    let sk = wycheproof_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001)?;
    Ok((pk, sk))
}

/// `core-test-framework`'s conformance suite: randomized (`Signer::sign` draws a fresh salt from
/// the default RNG, so two signatures of one message differ), `ctx` ignored, every signature bit
/// flipped in turn -- run here since the generic `RSASSA_PSS` code is the same at every width.
#[test]
fn pss_sha256_trait_conformance_suite() {
    TestFrameworkSignature::new(false, false).test_signature::<
        Rsa2048PublicKey,
        Rsa2048PrivateKey,
        RSASSA_PSS_SHA256,
        RSASSA_PSS_SHA256,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, true);
}

/// The trait's default-RNG salt and the free functions' caller-supplied RNG produce signatures
/// each side's verifier accepts: one encoding, two ways in.
#[test]
fn pss_sha256_trait_and_free_functions_cross_verify() {
    let (pk, sk) = fixed_keypair().unwrap();
    let msg = b"PSS across both APIs";
    let from_trait = RSASSA_PSS_SHA256::sign(&sk, msg, None).unwrap();
    pss_verify_sha256(&pk, msg, &from_trait).unwrap();
    let from_free = pss_sign_sha256(&sk, msg, &mut DefaultRNG::default()).unwrap();
    RSASSA_PSS_SHA256::verify(&pk, msg, None, &from_free).unwrap();
    assert!(RSASSA_PSS_SHA256::verify(&pk, b"other", None, &from_free).is_err());
}

/// A fixed-output RNG (all-`0x42` bytes), as `bouncycastle-ecdsa`'s tests use: pins that
/// `sign_randomized` takes its salt from the caller's RNG and nowhere else.
struct FixedRng;
impl RNG for FixedRng {
    fn add_seed_keymaterial(
        &mut self,
        _additional_seed: &dyn bouncycastle_core::key_material::KeyMaterialTrait,
    ) -> Result<(), bouncycastle_core::errors::RNGError> {
        Ok(())
    }
    fn next_int(&mut self) -> Result<u32, bouncycastle_core::errors::RNGError> {
        Ok(0x42424242)
    }
    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, bouncycastle_core::errors::RNGError> {
        Ok(vec![0x42u8; len])
    }
    fn next_bytes_out(
        &mut self,
        out: &mut [u8],
    ) -> Result<usize, bouncycastle_core::errors::RNGError> {
        out.fill(0x42);
        Ok(out.len())
    }
    fn fill_keymaterial_out(
        &mut self,
        _out: &mut dyn bouncycastle_core::key_material::KeyMaterialTrait,
    ) -> Result<usize, bouncycastle_core::errors::RNGError> {
        unimplemented!()
    }
    fn security_strength(&self) -> bouncycastle_core::traits::SecurityStrength {
        bouncycastle_core::traits::SecurityStrength::_256bit
    }
}

/// `set_signer_salt` fixes the salt on the streaming path (the counterpart of ML-DSA's
/// `set_signer_rnd`): the result is deterministic and byte-identical to the fixed-salt free
/// function over the same salt, while an unfixed streamed signature is fresh.
#[test]
fn set_signer_salt_fixes_the_salt_on_the_streaming_path() {
    let (pk, sk) = fixed_keypair().unwrap();
    let msg = b"fixed salt, streamed in two chunks";
    let salt = [0x42u8; 32];

    let mut signer = RSASSA_PSS_SHA256::sign_init(&sk, None).unwrap();
    signer.set_signer_salt(salt);
    signer.sign_update(&msg[..11]);
    signer.sign_update(&msg[11..]);
    let sig = signer.sign_final().unwrap();
    assert_eq!(sig, pss_sign_sha256_with_salt(&sk, msg, &salt).unwrap());
    RSASSA_PSS_SHA256::verify(&pk, msg, None, &sig).unwrap();

    let mut fresh = RSASSA_PSS_SHA256::sign_init(&sk, None).unwrap();
    fresh.sign_update(msg);
    assert_ne!(fresh.sign_final().unwrap(), sig, "without set_signer_salt the salt is fresh");

    // On a verify-initialised state it has no effect.
    let mut verifier = RSASSA_PSS_SHA256::verify_init(&pk, None).unwrap();
    verifier.set_signer_salt([0xffu8; 32]);
    verifier.verify_update(msg);
    verifier.verify_final(&sig).unwrap();
}

/// `sign_randomized` draws the salt from the caller's RNG (the ECDSA/SM2 shape): with a
/// fixed-output RNG it equals the fixed-salt path over that same output, and with a real RNG it
/// is fresh per call and verifies through both the trait and the free-function verifier.
#[test]
fn sign_randomized_takes_the_salt_from_the_callers_rng() {
    let (pk, sk) = fixed_keypair().unwrap();
    let msg = b"caller-supplied RNG";
    let from_fixed_rng = RSASSA_PSS_SHA256::sign_randomized(&sk, msg, &mut FixedRng).unwrap();
    assert_eq!(from_fixed_rng, pss_sign_sha256_with_salt(&sk, msg, &[0x42u8; 32]).unwrap());

    let mut rng = DefaultRNG::default();
    let a = RSASSA_PSS_SHA256::sign_randomized(&sk, msg, &mut rng).unwrap();
    let b = RSASSA_PSS_SHA256::sign_randomized(&sk, msg, &mut rng).unwrap();
    assert_ne!(a, b);
    RSASSA_PSS_SHA256::verify(&pk, msg, None, &a).unwrap();
    pss_verify_sha256(&pk, msg, &b).unwrap();
    assert!(RSASSA_PSS_SHA256::verify(&pk, b"other", None, &a).is_err());
    let _ = pss_sign_sha256; // the free functions stay the explicit-RNG one-shot path
}
