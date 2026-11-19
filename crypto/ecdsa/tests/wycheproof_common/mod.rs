//! The Wycheproof ECDSA runner, once over the curve and the hash: the project wycheproof repo
//! (https://github.com/C2SP/wycheproof) must be cloned at `../wycheproof` relative to the root of
//! this git project, as `bouncycastle-mldsa`'s `tests/wycheproof.rs` expects too. Each per-curve
//! file names the `(hash, file)` pairs it runs: the `_p1363_` files carry raw `r || s`, this
//! crate's native encoding, and the plain files DER `SEQUENCE { r, s }` (RFC 3279 Section
//! 2.2.3), decoded with `bouncycastle_ecdsa::der::decode` first.
//!
//! These are verify-only sets (`EcdsaP1363Verify` / `EcdsaVerify`): their value is the
//! malleability, invalid-encoding (malformed DER too: extra bytes, non-minimal lengths, wrong
//! tags) and edge-case `r`/`s` coverage, not KATs for signing (RFC 6979's appendix covers that).
//! A group whose public key is a deliberately invalid point (the EdgeCasePublicKey groups) makes
//! every "valid" test in it impossible by construction; SP 800-186 Appendix D.1.1.1 validation
//! on decode rejects those keys, which counts the group's tests as correctly rejected.
//!
//! Verdicts: `valid` must verify and `invalid` must not; `acceptable` (none in the v1 files
//! today) fails the test outright, so that adding such vectors forces a per-flag decision here.
//! `ecdsa_secp256k1_sha256_bitcoin_test.json` is deliberately not read: its
//! `SignatureMalleabilityBitcoin` vectors require rejecting `s > n/2`, a Bitcoin consensus rule
//! rather than part of ECDSA.

#![allow(dead_code)]

use bouncycastle_core::signature_key::VerifyingKey;
use bouncycastle_core::traits::SignaturePublicKey;
use bouncycastle_ec::curve::Curve;
use bouncycastle_ecdsa::der;
use bouncycastle_ecdsa::ecdsa::ECDSA;
use bouncycastle_ecdsa::ecdsa::EcdsaHash;
use bouncycastle_ecdsa::keys::ECDSAPublicKey;
use bouncycastle_hex::decode as hex_decode;
use serde_json::Value;
use std::fs;
use std::path::Path;

const TEST_DATA_PATH_RELATIVE: &str = "../../../wycheproof/testvectors_v1";
const TEST_DATA_PATH: &str = "../wycheproof/testvectors_v1";

/// Panics, failing the test, if the wycheproof clone is missing: these suites are the only
/// adversarial check on this crate's verification, and a green run that never read them would
/// be indistinguishable from one that did. (For `cargo mutants`, symlink the clone at
/// `/tmp/wycheproof`; its copied tree resolves the relative path there.)
fn get_test_data(filename: &str) -> String {
    for dir in [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH] {
        let path = format!("{dir}/{filename}");
        if Path::new(&path).exists() {
            return fs::read_to_string(path).unwrap();
        }
    }
    panic!(
        "wycheproof not found (looked for {filename} in {TEST_DATA_PATH_RELATIVE:?} and \
         {TEST_DATA_PATH:?}); these suites require it rather than skipping"
    );
}

/// Whether the file's signatures are raw `r || s` or DER.
#[derive(Clone, Copy)]
pub enum Encoding {
    P1363,
    Der,
}

/// Runs one file under `ECDSA<C, H>`, checking the group's `sha` is `sha` and every group's
/// `curve` is `curve`, and returns the number of tests run.
pub fn run<C, H, const PK_LEN: usize, const SIG_LEN: usize>(
    file: &str,
    curve: &str,
    sha: &str,
    encoding: Encoding,
) -> usize
where
    C: Curve<PkUncompressed = [u8; PK_LEN], Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    let contents = get_test_data(file);
    let doc: Value = serde_json::from_str(&contents).unwrap();

    let mut num_tests = 0usize;
    let mut num_valid = 0usize;
    let mut num_invalid = 0usize;

    for group in doc["testGroups"].as_array().unwrap() {
        assert_eq!(group["sha"], sha, "{file}: hash");
        assert_eq!(group["publicKey"]["curve"], curve, "{file}: curve");
        let pk_bytes = hex_decode(group["publicKey"]["uncompressed"].as_str().unwrap()).unwrap();
        let pk = ECDSAPublicKey::<C, H>::from_bytes(&pk_bytes).ok();

        for test in group["tests"].as_array().unwrap() {
            num_tests += 1;
            let tc_id = test["tcId"].as_u64().unwrap();
            let msg = hex_decode(test["msg"].as_str().unwrap()).unwrap();
            let sig = hex_decode(test["sig"].as_str().unwrap()).unwrap();
            // Only two of wycheproof's three verdicts are decided here; see the module docs.
            let flags = &test["flags"];
            let expect_valid = match test["result"].as_str().unwrap() {
                "valid" => true,
                "invalid" => false,
                other => panic!(
                    "{file} tcId {tc_id}: result {other:?} with flags {flags} needs an explicit \
                     accept/reject decision in this test"
                ),
            };
            if expect_valid {
                num_valid += 1;
            } else {
                num_invalid += 1;
            }

            let result = pk.as_ref().and_then(|pk| match encoding {
                Encoding::P1363 => {
                    VerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(pk, &msg, None, &sig).ok()
                }
                Encoding::Der => verify_der::<C, H, SIG_LEN>(pk, &msg, &sig),
            });
            assert_eq!(
                result.is_some(),
                expect_valid,
                "{file} tcId {tc_id}: expected valid={expect_valid}, flags {flags}, comment={:?}",
                test["comment"]
            );
        }
    }

    println!("{file}: {num_tests} test cases passed ({num_valid} valid, {num_invalid} invalid).");
    num_tests
}

/// Decodes a DER `SEQUENCE { r, s }` with [`der::decode`] and verifies the raw signature; a
/// malformed encoding is a failed verification, which is what the invalid-encoding cases expect.
fn verify_der<C, H, const SIG_LEN: usize>(
    pk: &ECDSAPublicKey<C, H>,
    msg: &[u8],
    sig: &[u8],
) -> Option<()>
where
    C: Curve<Signature = [u8; SIG_LEN]>,
    H: EcdsaHash,
{
    let mut raw = [0u8; SIG_LEN];
    let (r, s) = raw.split_at_mut(SIG_LEN / 2);
    der::decode(sig, r, s)?;
    VerifyingKey::<ECDSA<C, H>, SIG_LEN>::verify(pk, msg, None, &raw).ok()
}
