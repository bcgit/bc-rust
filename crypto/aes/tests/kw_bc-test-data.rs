//! Known-answer tests against the NIST ACVP `ACVP-AES-KW` and `ACVP-AES-KWP` vectors from the
//! `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the tests print a warning and pass,
//! matching the convention of the other ACVP suites -- `cargo test` must stay green for someone
//! who has only cloned this repository.
//!
//! # Joining the request and response files
//!
//! As for the CBC set, the response file carries the answer against a `tcId` and the request file
//! carries the inputs and the group metadata (`direction`, `keyLen`, `payloadLen`, `kwCipher`), so
//! both are read and joined on `tcId`.
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

use bouncycastle_aes::{AES_KW_128, AES_KW_192, AES_KW_256, AES_KWP_128, AES_KWP_192, AES_KWP_256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KeyUnwrapper, KeyWrapper};
use bouncycastle_hex as hex;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] = [
    "../../../bc-test-data/crypto/aes_tdes_vectors/AES",
    "../bc-test-data/crypto/aes_tdes_vectors/AES",
];

const KW_REQUEST_FILE: &str = "ACVP-AES-KW.4014525.req.json";
const KW_RESPONSE_FILE: &str = "ACVP-AES-KW.4014525.rsp.json";
const KWP_REQUEST_FILE: &str = "ACVP-AES-KWP.4014526.req.json";
const KWP_RESPONSE_FILE: &str = "ACVP-AES-KWP.4014526.rsp.json";

fn test_data_dir(request_file: &str, response_file: &str) -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.join(request_file).exists() && path.join(response_file).exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); \
         ACVP {request_file} tests will be skipped"
    );
    None
}

/// The ACVP files are a two-element array: a version header, then the payload.
fn load(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("reading {path:?}: {e}"));
    let value: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {path:?}: {e}"));
    value
        .as_array()
        .and_then(|a| a.get(1))
        .cloned()
        .unwrap_or_else(|| panic!("{path:?}: not a two-element ACVP array"))
}

/// Builds a `KeyMaterial` from raw ACVP key bytes, including the all-zero keys the set contains.
fn cipher_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the group's keyLen");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("ACVP key bytes fit the buffer");
    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting a NIST all-zero test key");
    }
    key
}

fn hex_field(test: &Value, name: &str) -> Vec<u8> {
    let tc_id = test["tcId"].as_u64().unwrap_or(0);
    let s = test[name].as_str().unwrap_or_else(|| panic!("tcId {tc_id}: missing field {name}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {name}"))
}

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

/// Runs one case through both APIs. `W` is the alias for the group's key length.
fn run_case<W, const KEK_LEN: usize>(
    key_bytes: &[u8],
    input: &[u8],
    encrypt: bool,
    expected: &Expected,
    tc_id: u64,
) where
    W: KeyWrapper<KEK_LEN> + KeyUnwrapper<KEK_LEN>,
{
    let kek = cipher_key::<KEK_LEN>(key_bytes);

    if encrypt {
        let Expected::Bytes(ct) = expected else {
            panic!("tcId {tc_id}: an encrypt case cannot expect failure");
        };
        let mut out = vec![0u8; W::wrap_out_len(input.len())];
        let n = W::wrap_out(&kek, input, &mut out)
            .unwrap_or_else(|e| panic!("tcId {tc_id}: wrap_out: {e:?}"));
        assert_eq!(&out[..n], ct, "tcId {tc_id}: wrap_out ciphertext");

        // The fixed-length API, for the payload lengths the set uses.
        let fixed = match input.len() {
            16 => W::wrap_key::<16, 24>(&kek, input.try_into().unwrap()).map(|c| c.to_vec()),
            24 => W::wrap_key::<24, 32>(&kek, input.try_into().unwrap()).map(|c| c.to_vec()),
            64 => W::wrap_key::<64, 72>(&kek, input.try_into().unwrap()).map(|c| c.to_vec()),
            other => panic!("tcId {tc_id}: unexpected payload length {other}"),
        };
        assert_eq!(fixed.unwrap().as_slice(), ct, "tcId {tc_id}: wrap_key ciphertext");
    } else {
        let mut out = vec![0u8; W::unwrap_out_max_len(input.len())];
        let result = W::unwrap_out(&kek, input, &mut out);
        match expected {
            Expected::Bytes(pt) => {
                let n = result.unwrap_or_else(|e| panic!("tcId {tc_id}: unwrap_out: {e:?}"));
                assert_eq!(&out[..n], pt, "tcId {tc_id}: unwrap_out plaintext");
                let fixed =
                    match pt.len() {
                        16 => W::unwrap_key::<16, 24>(&kek, input.try_into().unwrap())
                            .map(|k| k.to_vec()),
                        24 => W::unwrap_key::<24, 32>(&kek, input.try_into().unwrap())
                            .map(|k| k.to_vec()),
                        64 => W::unwrap_key::<64, 72>(&kek, input.try_into().unwrap())
                            .map(|k| k.to_vec()),
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
                let fixed: Result<Vec<u8>, _> =
                    match input.len() {
                        24 => W::unwrap_key::<16, 24>(&kek, input.try_into().unwrap())
                            .map(|k| k.to_vec()),
                        32 => W::unwrap_key::<24, 32>(&kek, input.try_into().unwrap())
                            .map(|k| k.to_vec()),
                        72 => W::unwrap_key::<64, 72>(&kek, input.try_into().unwrap())
                            .map(|k| k.to_vec()),
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

/// Walks one ACVP set, dispatching each group to the alias for its key length.
fn run_set<W128, W192, W256>(
    algorithm: &str,
    request_file: &str,
    response_file: &str,
) -> Option<Stats>
where
    W128: KeyWrapper<16> + KeyUnwrapper<16>,
    W192: KeyWrapper<24> + KeyUnwrapper<24>,
    W256: KeyWrapper<32> + KeyUnwrapper<32>,
{
    let dir = test_data_dir(request_file, response_file)?;
    let request = load(&dir.join(request_file));
    let response = load(&dir.join(response_file));
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
            let key = hex_field(test, "key");
            let (input, expected) = if encrypt {
                (hex_field(test, "pt"), Expected::Bytes(hex_field(answer, "ct")))
            } else if answer["testPassed"] == Value::Bool(false) {
                (hex_field(test, "ct"), Expected::Failure)
            } else {
                (hex_field(test, "ct"), Expected::Bytes(hex_field(answer, "pt")))
            };

            match key_len {
                128 => run_case::<W128, 16>(&key, &input, encrypt, &expected, tc_id),
                192 => run_case::<W192, 24>(&key, &input, encrypt, &expected, tc_id),
                256 => run_case::<W256, 32>(&key, &input, encrypt, &expected, tc_id),
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
    let Some(stats) = run_set::<AES_KW_128, AES_KW_192, AES_KW_256>(
        "ACVP-AES-KW", KW_REQUEST_FILE, KW_RESPONSE_FILE,
    ) else {
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
    let Some(stats) = run_set::<AES_KWP_128, AES_KWP_192, AES_KWP_256>(
        "ACVP-AES-KWP", KWP_REQUEST_FILE, KWP_RESPONSE_FILE,
    ) else {
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
