//! RSA-2048/SHA-256 RSASSA-PKCS1-v1_5 against Wycheproof (`rsa_pkcs1_2048_sig_gen_test.json` and
//! `rsa_signature_2048_sha256_test.json`), following the path/lookup convention
//! `bouncycastle-ecdsa`'s `tests/wycheproof.rs` documents (symlink the clone at
//! `/tmp/wycheproof` for `cargo mutants`).
//!
//! No CAVP SigGen15/SigVer15 vectors exist in this workspace's `bc-test-data` clone at the time
//! of writing (only ECDSA/KDF material does), so Wycheproof alone carries both directions here:
//! `rsa_pkcs1_2048_sig_gen_test.json` for signing (deterministic PKCS#1 v1.5 has exactly one
//! correct signature per message, same as a CAVP SigGen KAT) and `rsa_signature_2048_sha256_test.json`
//! for verification.
//!
//! # Where the private key comes from
//!
//! Wycheproof's sig-gen vectors give `(n, e, d)`, not the CRT quintuple
//! [`RsaPrivateKey::from_crt_components`] needs. `p` and `q` were recovered from `(n, e, d)` in
//! Python via the standard randomized factoring-from-the-private-exponent method (Boneh, *Twenty
//! Years of Attacks on the RSA Cryptosystem*, 1999, §I.B; originally Miller, 1975): `e*d - 1` is a
//! multiple of `λ(n)`, which a few rounds of a Miller-Rabin-shaped search turn into a nontrivial
//! square root of `1 mod n`, and `gcd(that - 1, n)` is a factor with high probability. `dP`, `dQ`,
//! `qInv` were then computed directly from `p`, `q`, `d`, `e`. The recovered CRT key was
//! cross-checked in Python against all eight of this group's vectors (CRT recombination
//! reproducing the exact `sig` bytes) before being pasted here -- this file's own tests are the
//! same check again, in Rust, against RSASSA-PKCS1-v1_5's real API.
//!
//! This factoring step lives only in the throwaway script that produced these constants, never in
//! the crate: `bouncycastle-rsa` has no prime-generation or factoring code (see `src/lib.rs`'s
//! `# Scope`), by design.
//!
//! `p` and `q` here are both genuinely 1024 bits (this key's generator produced balanced primes,
//! as most do) -- [`RsaPrivateKey`] does not require that, see its docs, but this file cannot
//! itself demonstrate the unbalanced case: it works from a real generator's output, not a
//! constructed edge case.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::traits::{Hash, SignatureVerifier, Signer};
use bouncycastle_core_test_framework::signature::{
    TestFrameworkSignature, TestFrameworkSignatureKeys,
};
use bouncycastle_hex::decode as hex_decode;
use bouncycastle_rsa::rsa_2048::{
    PK_LEN, RSASSA_PKCS1_v1_5_SHA256, Rsa2048PrivateKey, Rsa2048PublicKey, SIG_LEN, SK_LEN,
};
use bouncycastle_rsa::rsassa_pkcs1_v1_5;
use bouncycastle_sha2::SHA256;
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

/// Big-endian hex (as Wycheproof/ASN.1 write it, with an optional leading `00` sign-avoidance
/// byte) into this crate's little-endian `[u64; L]` limb form. Duplicated in miniature from
/// `bouncycastle_rsa::codec` (crate-private) rather than exposed from it: this conversion belongs
/// to the test's own data plumbing, not to the crate's public API surface.
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

fn wycheproof_key() -> Rsa2048PrivateKey {
    // Little-endian [u64; 16] limbs -- P[0] is p's *least* significant 64 bits. (An earlier
    // version of this file tried to write these as a single big-endian hex string by
    // concatenating the limbs in array order, which silently reverses significance at each 8-byte
    // boundary and produces a different, even number; `limbs_from_hex` is for genuinely
    // big-endian input, such as the JSON's own hex fields, not for re-deriving these.)
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

/// The first (257-test) group of `rsa_signature_2048_sha256_test.json` uses this exact key
/// (confirmed by comparing moduli in Python before writing this file); the other two groups use
/// unrelated keys and are covered separately by [`rsa_signature_sha256_all_groups`], which parses
/// the public key straight out of each group's JSON instead.
#[test]
fn pkcs1_v1_5_sig_gen_2048_sha256() {
    let sk = wycheproof_key();

    let doc: Value = serde_json::from_str(&get_test_data("rsa_pkcs1_2048_sig_gen_test.json"))
        .expect("valid JSON");
    let group = doc["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["sha"] == "SHA-256" && g["tests"].as_array().unwrap().len() == 8)
        .expect("the main SHA-256/2048 group");

    let mut num_tests = 0usize;
    for test in group["tests"].as_array().unwrap() {
        num_tests += 1;
        let tc_id = test["tcId"].as_u64().unwrap();
        let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
        let expected_sig = hex_decode(test["sig"].as_str().unwrap()).unwrap();
        assert_eq!(test["result"], "valid", "tcId {tc_id}: sig-gen vectors are all 'valid'");

        let sig = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, &msg, None).unwrap_or_else(|e| {
            panic!("tcId {tc_id}: signing failed: {e:?}");
        });
        assert_eq!(sig.to_vec(), expected_sig, "tcId {tc_id}: signature mismatch");
    }
    assert_eq!(num_tests, 8);
}

// ---- bouncycastle_core trait conformance ------------------------------------------------------

/// The same genuine key pair as the sig-gen test above, in the `fn() -> Result<(PK, SK)>`
/// shape `core-test-framework` takes in place of a key generator (this crate has none).
fn fixed_keypair() -> Result<(Rsa2048PublicKey, Rsa2048PrivateKey), SignatureError> {
    let sk = wycheproof_key();
    let pk = Rsa2048PublicKey::new(sk.n(), 0x10001)?;
    Ok((pk, sk))
}

/// The shared `Signer`/`SignatureVerifier` conformance suite (per QUALITY_AND_STYLE's rule that
/// trait conformance lives in `core-test-framework`, not per implementation): deterministic
/// (PKCS#1 v1.5 has no randomness), `ctx` ignored (RSA has no context input), and with every bit
/// of a signature flipped in turn -- 2048 verifications, run at this size and scheme since the
/// generic `RSASSA_PKCS1_v1_5` code under test is the same at every width.
#[test]
fn pkcs1_v1_5_sha256_trait_conformance_suite() {
    TestFrameworkSignature::new(true, false).test_signature::<
        Rsa2048PublicKey,
        Rsa2048PrivateKey,
        RSASSA_PKCS1_v1_5_SHA256,
        RSASSA_PKCS1_v1_5_SHA256,
        PK_LEN,
        SK_LEN,
        SIG_LEN,
    >(fixed_keypair, true);
}

#[test]
fn key_trait_boundary_conditions() {
    TestFrameworkSignatureKeys::new()
        .test_keys::<Rsa2048PublicKey, Rsa2048PrivateKey, PK_LEN, SK_LEN>(fixed_keypair);
}

/// Streamed and one-shot signing are one computation: PKCS#1 v1.5 is deterministic, so the
/// chunked `sign_init`/`sign_update`/`sign_final` path reproduces `Signer::sign` byte for byte.
#[test]
fn streamed_signature_equals_one_shot() {
    let (pk, sk) = fixed_keypair().unwrap();
    let msg = b"the same message, two ways";
    let one_shot = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, msg, None).unwrap();
    let mut signer = RSASSA_PKCS1_v1_5_SHA256::sign_init(&sk, None).unwrap();
    signer.sign_update(&msg[..10]);
    signer.sign_update(&msg[10..]);
    let streamed = signer.sign_final().unwrap();
    assert_eq!(streamed, one_shot);
    RSASSA_PKCS1_v1_5_SHA256::verify(&pk, msg, None, &streamed).unwrap();
}

/// RFC 8017 §8.2.2 step 1 ("If the length of the signature S is not k octets, output 'invalid
/// signature'"): the trait's `&[u8]` signature makes this a runtime check. `core-test-framework`
/// covers the too-long case; this is the too-short one.
#[test]
fn trait_verify_rejects_short_signature() {
    let (pk, sk) = fixed_keypair().unwrap();
    let sig = RSASSA_PKCS1_v1_5_SHA256::sign(&sk, b"msg", None).unwrap();
    assert!(matches!(
        RSASSA_PKCS1_v1_5_SHA256::verify(&pk, b"msg", None, &sig[..SIG_LEN - 1]),
        Err(SignatureError::SignatureVerificationFailed)
    ));
    assert!(matches!(
        RSASSA_PKCS1_v1_5_SHA256::verify(&pk, b"msg", None, &[]),
        Err(SignatureError::SignatureVerificationFailed)
    ));
}

/// One type serves both trait roles; finishing a state with the other role's `_final` is a
/// `GenericError`, not a silent wrong answer.
#[test]
fn trait_final_in_the_wrong_role_is_an_error() {
    let (pk, sk) = fixed_keypair().unwrap();
    let mut out = [0u8; SIG_LEN];

    let verifier = RSASSA_PKCS1_v1_5_SHA256::verify_init(&pk, None).unwrap();
    assert!(matches!(verifier.sign_final(), Err(SignatureError::GenericError(_))));
    let verifier = RSASSA_PKCS1_v1_5_SHA256::verify_init(&pk, None).unwrap();
    assert!(matches!(verifier.sign_final_out(&mut out), Err(SignatureError::GenericError(_))));

    let signer = RSASSA_PKCS1_v1_5_SHA256::sign_init(&sk, None).unwrap();
    assert!(matches!(signer.verify_final(&out), Err(SignatureError::GenericError(_))));
}

/// All three groups of `rsa_signature_2048_sha256_test.json` (259 vectors; the first group's key
/// is [`wycheproof_key`]'s, the other two are unrelated keys parsed from the JSON) through
/// `SignatureVerifier::verify`'s `&[u8]` signature, so the wrong-length vectors reach the
/// verifier and must come back as `SignatureVerificationFailed` (RFC 8017 §8.2.2 step 1). The one
/// "acceptable" vector is `MissingNull` (a `DigestInfo` whose `AlgorithmIdentifier` omits the
/// `NULL` parameters), accepted by this crate's explicit policy -- see
/// `emsa_pkcs1_v1_5::emsa_pkcs1_v1_5_verify_from_hash`'s docs.
#[test]
fn rsa_signature_sha256_all_groups() {
    let doc: Value = serde_json::from_str(&get_test_data("rsa_signature_2048_sha256_test.json"))
        .expect("valid JSON");

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;
    let mut num_wrong_length = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        let n: [u64; 32] = limbs_from_hex(group["publicKey"]["modulus"].as_str().unwrap());
        let e = u32::from_str_radix(group["publicKey"]["publicExponent"].as_str().unwrap(), 16)
            .unwrap();
        let pk = Rsa2048PublicKey::new(&n, e).unwrap();

        for test in group["tests"].as_array().unwrap() {
            num_tests += 1;
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig = hex_decode(test["sig"].as_str().unwrap()).unwrap();
            let result = RSASSA_PKCS1_v1_5_SHA256::verify(&pk, &msg, None, &sig);
            match test["result"].as_str().unwrap() {
                // "acceptable" is only ever MissingNull in this file, accepted by policy (see above).
                "valid" | "acceptable" => {
                    result.unwrap_or_else(|e| panic!("tcId {tc_id}: expected valid, got {e:?}"));
                    num_valid += 1;
                }
                "invalid" => {
                    assert!(result.is_err(), "tcId {tc_id}: expected invalid, got valid");
                    if sig.len() != SIG_LEN {
                        assert!(
                            matches!(result, Err(SignatureError::SignatureVerificationFailed)),
                            "tcId {tc_id}: a {}-byte signature must fail step 1's length check \
                             as 'invalid signature', got {result:?}",
                            sig.len()
                        );
                        num_wrong_length += 1;
                    }
                    num_invalid += 1;
                }
                other => panic!("tcId {tc_id}: unknown result {other:?}"),
            }
        }
    }

    assert_eq!(num_tests, 259);
    assert_eq!(num_valid, 10);
    assert_eq!(num_invalid, 249);
    assert!(num_wrong_length > 0, "the file must contain wrong-length signatures to exercise");
}

/// RFC 8017 §8.2.2 step 2.b: RSAVP1's "signature representative out of range" is "invalid
/// signature" through the trait (whose contract, like the RFC's, has one answer for every way a
/// signature can fail), while the generic `rsassa_pkcs1_v1_5::verify_from_hash` deliberately
/// surfaces RSAVP1's own `DecodingError` so vector-driven callers can tell malformed from wrong
/// -- see its docs. `0xff..ff` is `2^2048 - 1 >= n` for any 2048-bit `n`.
#[test]
fn trait_verify_reports_out_of_range_representative_as_invalid_signature() {
    let (pk, _) = fixed_keypair().unwrap();
    let too_big = [0xffu8; SIG_LEN];
    let mut digest = [0u8; 32];
    SHA256::default().hash_out(b"msg", &mut digest);
    assert!(matches!(
        rsassa_pkcs1_v1_5::verify_from_hash::<SHA256, 32, 32, 64, 65, SIG_LEN>(
            &pk, &digest, &too_big
        ),
        Err(SignatureError::DecodingError(_))
    ));
    assert!(matches!(
        RSASSA_PKCS1_v1_5_SHA256::verify(&pk, b"msg", None, &too_big),
        Err(SignatureError::SignatureVerificationFailed)
    ));
}
