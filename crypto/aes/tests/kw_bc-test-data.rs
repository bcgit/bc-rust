//! Known-answer tests against the NIST ACVP `ACVP-AES-KW` and `ACVP-AES-KWP` vectors from the
//! `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the tests print a warning and pass,
//! matching the convention of the other ACVP suites.
//!
//! The response file carries the answer against a `tcId` and the request file carries the inputs
//! and the group metadata (`direction`, `keyLen`, `payloadLen`, `kwCipher`), so both are read and
//! joined on `tcId`.
//!
//! # Coverage
//!
//! Each set has 1800 AFT cases: 300 per direction per AES key length, over payloads of 128, 192
//! and 512 bits. The decrypt groups include cases whose ciphertext has been corrupted, marked
//! `testPassed: false` in the response; those must be rejected with `DecryptionFailed` and nothing
//! else, and the test counts them so the coverage stays visible. Every case is run through the
//! run-time (`wrap_out` / `unwrap_out`) API, and since all three payload lengths are fixed, through
//! the compile-time (`wrap_key` / `unwrap_key`) API as well.
//!
//! `kwCipher` is `"cipher"` throughout: the forward cipher is the designated cipher function
//! (SP 800-38F Sec 5.1). The "inverse" variant, where decryption wraps, is not implemented and
//! would be skipped and counted if a group asked for it.

use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::{KW, KWP};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_core_test_framework::test_data_loaders::{Value, bc_test_data_json, hex_field};
use std::collections::BTreeMap;

#[path = "common/acvp_helpers.rs"]
mod acvp_helpers;
use acvp_helpers::cipher_key;

const TEST_DATA_DIR: &str = "crypto/aes_tdes_vectors/AES";
const KW_REQUEST_FILE: &str = "ACVP-AES-KW.4014525.req.json";
const KW_RESPONSE_FILE: &str = "ACVP-AES-KW.4014525.rsp.json";
const KWP_REQUEST_FILE: &str = "ACVP-AES-KWP.4014526.req.json";
const KWP_RESPONSE_FILE: &str = "ACVP-AES-KWP.4014526.rsp.json";

/// What one case expects.
enum Expected {
    /// The wrap or unwrap must succeed and produce these bytes.
    Bytes(Vec<u8>),
    /// The unwrap must fail: the vector's ciphertext is a forgery.
    Failure,
}

#[derive(Default)]
struct Stats {
    encrypt: usize,
    decrypt: usize,
    forgeries: usize,
    skipped: usize,
}

/// Runs one case through both APIs of the key `kek`.
fn run_case<K, const KEK_LEN: usize>(
    kek: &K,
    input: &[u8],
    encrypt: bool,
    expected: &Expected,
    tc_id: u64,
) where
    K: KeyWrappingKey<KEK_LEN> + KeyUnwrappingKey<KEK_LEN>,
{
    if encrypt {
        let Expected::Bytes(ct) = expected else {
            panic!("tcId {tc_id}: an encrypt case cannot expect failure");
        };
        let mut out = vec![0u8; kek.wrap_out_len(input.len())];
        let n = kek
            .wrap_out(input, &mut out)
            .unwrap_or_else(|e| panic!("tcId {tc_id}: wrap_out: {e:?}"));
        assert_eq!(&out[..n], ct, "tcId {tc_id}: wrap_out ciphertext");

        // The fixed-length API, for the payload lengths the set uses.
        let fixed = match input.len() {
            16 => kek.wrap_key::<16, 24>(input.try_into().unwrap()).map(|c| c.to_vec()),
            24 => kek.wrap_key::<24, 32>(input.try_into().unwrap()).map(|c| c.to_vec()),
            64 => kek.wrap_key::<64, 72>(input.try_into().unwrap()).map(|c| c.to_vec()),
            other => panic!("tcId {tc_id}: unexpected payload length {other}"),
        };
        assert_eq!(fixed.unwrap().as_slice(), ct, "tcId {tc_id}: wrap_key ciphertext");
    } else {
        let mut out = vec![0u8; kek.unwrap_out_max_len(input.len())];
        let result = kek.unwrap_out(input, &mut out);
        match expected {
            Expected::Bytes(pt) => {
                let n = result.unwrap_or_else(|e| panic!("tcId {tc_id}: unwrap_out: {e:?}"));
                assert_eq!(&out[..n], pt, "tcId {tc_id}: unwrap_out plaintext");
                let fixed = match pt.len() {
                    16 => kek.unwrap_key::<16, 24>(input.try_into().unwrap()).map(|k| k.to_vec()),
                    24 => kek.unwrap_key::<24, 32>(input.try_into().unwrap()).map(|k| k.to_vec()),
                    64 => kek.unwrap_key::<64, 72>(input.try_into().unwrap()).map(|k| k.to_vec()),
                    other => panic!("tcId {tc_id}: unexpected payload length {other}"),
                };
                assert_eq!(fixed.unwrap().as_slice(), pt, "tcId {tc_id}: unwrap_key plaintext");
            }
            Expected::Failure => {
                assert!(
                    matches!(result, Err(SymmetricCipherError::DecryptionFailed)),
                    "tcId {tc_id}: a forged ciphertext must fail with DecryptionFailed, got {result:?}"
                );
                assert!(
                    out.iter().all(|b| *b == 0),
                    "tcId {tc_id}: the buffer is scrubbed on failure"
                );
                let fixed: Result<Vec<u8>, _> = match input.len() {
                    24 => kek.unwrap_key::<16, 24>(input.try_into().unwrap()).map(|k| k.to_vec()),
                    32 => kek.unwrap_key::<24, 32>(input.try_into().unwrap()).map(|k| k.to_vec()),
                    72 => kek.unwrap_key::<64, 72>(input.try_into().unwrap()).map(|k| k.to_vec()),
                    other => panic!("tcId {tc_id}: unexpected ciphertext length {other}"),
                };
                assert!(
                    matches!(fixed, Err(SymmetricCipherError::DecryptionFailed)),
                    "tcId {tc_id}: unwrap_key must reject the forgery too"
                );
            }
        }
    }
}

/// Walks one ACVP set under the mode `M`, dispatching each group to the key type for its length.
fn run_set<M>(algorithm: &str, request_file: &str, response_file: &str) -> Option<Stats>
where
    M: Mode<bouncycastle_aes::hazmat::AES128Internal>
        + Mode<bouncycastle_aes::hazmat::AES192Internal>
        + Mode<bouncycastle_aes::hazmat::AES256Internal>,
    AES128Key<M>: KeyWrappingKey<16> + KeyUnwrappingKey<16>,
    AES192Key<M>: KeyWrappingKey<24> + KeyUnwrappingKey<24>,
    AES256Key<M>: KeyWrappingKey<32> + KeyUnwrappingKey<32>,
{
    let req = bc_test_data_json(TEST_DATA_DIR, request_file)?;
    let rsp = bc_test_data_json(TEST_DATA_DIR, response_file)?;
    let request = &req[1];
    let response = &rsp[1];
    assert_eq!(request["algorithm"].as_str(), Some(algorithm), "wrong vector file");

    // Index the answers by tcId across every group.
    let mut answers: BTreeMap<u64, &Value> = BTreeMap::new();
    for group in response["testGroups"].as_array().expect("response testGroups") {
        for test in group["tests"].as_array().expect("response tests") {
            answers.insert(test["tcId"].as_u64().expect("tcId"), test);
        }
    }

    let mut stats = Stats::default();
    for group in request["testGroups"].as_array().expect("request testGroups") {
        assert_eq!(group["testType"].as_str(), Some("AFT"), "only AFT groups are expected");
        if group["kwCipher"].as_str() != Some("cipher") {
            stats.skipped += group["tests"].as_array().map_or(0, Vec::len);
            continue;
        }
        let encrypt = match group["direction"].as_str() {
            Some("encrypt") => true,
            Some("decrypt") => false,
            other => panic!("unexpected direction {other:?}"),
        };
        let key_len = group["keyLen"].as_u64().expect("keyLen");

        for test in group["tests"].as_array().expect("request tests") {
            let tc_id = test["tcId"].as_u64().expect("tcId");
            let answer = answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
            let key = hex_field(test, "key", tc_id);
            let (input, expected) = if encrypt {
                (hex_field(test, "pt", tc_id), Expected::Bytes(hex_field(answer, "ct", tc_id)))
            } else if answer["testPassed"] == Value::Bool(false) {
                (hex_field(test, "ct", tc_id), Expected::Failure)
            } else {
                (hex_field(test, "ct", tc_id), Expected::Bytes(hex_field(answer, "pt", tc_id)))
            };

            match key_len {
                128 => {
                    let kek = AES128Key::<M>::from_key_material(&cipher_key::<16>(&key)).unwrap();
                    run_case::<_, 16>(&kek, &input, encrypt, &expected, tc_id)
                }
                192 => {
                    let kek = AES192Key::<M>::from_key_material(&cipher_key::<24>(&key)).unwrap();
                    run_case::<_, 24>(&kek, &input, encrypt, &expected, tc_id)
                }
                256 => {
                    let kek = AES256Key::<M>::from_key_material(&cipher_key::<32>(&key)).unwrap();
                    run_case::<_, 32>(&kek, &input, encrypt, &expected, tc_id)
                }
                other => panic!("unexpected keyLen {other}"),
            }

            match (encrypt, &expected) {
                (true, _) => stats.encrypt += 1,
                (false, Expected::Bytes(_)) => stats.decrypt += 1,
                (false, Expected::Failure) => stats.forgeries += 1,
            }
        }
    }
    Some(stats)
}

#[test]
fn acvp_aes_kw() {
    let Some(stats) = run_set::<KW>("ACVP-AES-KW", KW_REQUEST_FILE, KW_RESPONSE_FILE) else {
        return;
    };
    println!(
        "ACVP-AES-KW: {} wrap, {} unwrap, {} rejected forgeries, {} skipped",
        stats.encrypt, stats.decrypt, stats.forgeries, stats.skipped
    );
    assert_eq!(stats.encrypt, 900);
    assert_eq!(stats.decrypt + stats.forgeries, 900);
    assert!(stats.forgeries > 0, "the set should contain forged ciphertexts");
    assert_eq!(stats.skipped, 0);
}

#[test]
fn acvp_aes_kwp() {
    let Some(stats) = run_set::<KWP>("ACVP-AES-KWP", KWP_REQUEST_FILE, KWP_RESPONSE_FILE) else {
        return;
    };
    println!(
        "ACVP-AES-KWP: {} wrap, {} unwrap, {} rejected forgeries, {} skipped",
        stats.encrypt, stats.decrypt, stats.forgeries, stats.skipped
    );
    assert_eq!(stats.encrypt, 900);
    assert_eq!(stats.decrypt + stats.forgeries, 900);
    assert!(stats.forgeries > 0, "the set should contain forged ciphertexts");
    assert_eq!(stats.skipped, 0);
}
