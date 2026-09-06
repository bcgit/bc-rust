//! Known-answer tests against the NIST ACVP `ACVP-AES-CBC` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the ML-KEM, ML-DSA and `aes-lowmemory` suites -- `cargo test`
//! must stay green for someone who has only cloned this repository.
//!
//! These are the counterpart to `crypto/aes-lowmemory/tests/acvp_tests.rs`, which consumes the
//! `ACVP-AES-ECB` file to test the raw permutation. CBC is a mode, so its vectors belong here.
//!
//! # Joining the request and response files
//!
//! Unlike the ECB response file, which echoes `key`, `pt` and `ct` for every case, the CBC response
//! file carries **only the answer** (`ct` for an encrypt group, `pt` for a decrypt group) against a
//! `tcId`. The key, IV and input live in the request file, and the group metadata that says which
//! direction a case is -- `direction` and `keyLen` -- lives only there too. So both files are read
//! and joined on `tcId`; there is no way to drive this from the response file alone.
//!
//! # Coverage
//!
//! 2150 AFT (Algorithm Functional Test) cases across all three key lengths and both directions,
//! including 60 whose payload spans 2 to 10 blocks. Every case is run **twice**: once block by
//! block, and once in pairs with a one-block remainder for odd lengths. The second pass is what
//! puts the multi-block cases through `BlockPermutation::decrypt_blocks2`, so the pair path is
//! exercised against real vectors and not only against the toy in `cbc_tests.rs`.
//!
//! The 6 MCT (Monte Carlo Test) groups are **not** implemented: their expected output is a
//! `resultsArray` produced by a chained update rule defined in the ACVP AES specification rather
//! than in SP 800-38A, and implementing it from anything else would be guesswork. The test reports
//! how many it skipped so the gap stays visible.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation, SecurityStrength,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Cbc, Decrypting, Encrypting};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const BLOCK_LEN: usize = 16;

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] = [
    "../../../bc-test-data/crypto/aes_tdes_vectors/AES",
    "../bc-test-data/crypto/aes_tdes_vectors/AES",
];

const REQUEST_FILE: &str = "ACVP-AES-CBC.4014528.req.json";
const RESPONSE_FILE: &str = "ACVP-AES-CBC.4014528.rsp.json";

fn test_data_dir() -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.join(REQUEST_FILE).exists() && path.join(RESPONSE_FILE).exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); \
         ACVP AES-CBC tests will be skipped"
    );
    None
}

/// Builds a `KeyMaterial` from raw ACVP key bytes, including the all-zero keys.
///
/// The ACVP set deliberately includes an all-zero key. `KeyMaterial` tags an all-zero buffer as
/// `KeyType::Zeroized` and will not promote it outside a `do_hazardous_operations` closure, which
/// is the right default -- so this opts in explicitly rather than the engine weakening its guard.
fn cipher_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
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

/// How to walk the blocks of one case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Grouping {
    /// One block per call. Never forms a pair.
    Single,
    /// Two blocks per call, with a one-block remainder for odd lengths. Uses the pair path.
    Pairs,
}

/// Runs one CBC case in one direction, for a given permutation, under the given grouping.
///
/// Encryption is driven through `do_encrypt_init_rng` with a `FixedSeedRNG` emitting the vector's
/// IV, and the returned init data is checked against that IV before any ciphertext is compared --
/// so a change that ignored the RNG could not pass silently.
fn run_case<P, const KEY_LEN: usize>(
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[[u8; BLOCK_LEN]],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<[u8; BLOCK_LEN]>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    let key = cipher_key::<KEY_LEN>(key_bytes);
    let mut out: Vec<[u8; BLOCK_LEN]> = Vec::with_capacity(input.len());

    if encrypt {
        let (mut enc, got_iv) = Cbc::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init_rng(
            &key,
            &mut FixedSeedRNG::<BLOCK_LEN>::new(iv),
        )
        .expect("encrypt init");
        assert_eq!(got_iv, iv, "the pinned RNG should reproduce the vector's IV");

        match grouping {
            Grouping::Single => {
                for block in input {
                    let [c] = enc.do_encrypt_blocks(&[*block]).unwrap();
                    out.push(c);
                }
            }
            Grouping::Pairs => {
                let (pairs, tail) = input.as_chunks::<2>();
                for pair in pairs {
                    out.extend_from_slice(&enc.do_encrypt_blocks(pair).unwrap());
                }
                for block in tail {
                    let [c] = enc.do_encrypt_blocks(&[*block]).unwrap();
                    out.push(c);
                }
            }
        }
    } else {
        let mut dec =
            Cbc::<P, Decrypting, KEY_LEN, BLOCK_LEN>::do_decrypt_init(&key, &iv).expect("dec init");

        match grouping {
            Grouping::Single => {
                for block in input {
                    let [p] = dec.do_decrypt_blocks(&[*block]).unwrap();
                    out.push(p);
                }
            }
            Grouping::Pairs => {
                let (pairs, tail) = input.as_chunks::<2>();
                for pair in pairs {
                    out.extend_from_slice(&dec.do_decrypt_blocks(pair).unwrap());
                }
                for block in tail {
                    let [p] = dec.do_decrypt_blocks(&[*block]).unwrap();
                    out.push(p);
                }
            }
        }
    }

    out
}

/// Dispatches on key length, which is what selects the AES parameter set.
fn run_case_for_key_len(
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[[u8; BLOCK_LEN]],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<[u8; BLOCK_LEN]> {
    match key_bytes.len() {
        16 => run_case::<Aes128, 16>(key_bytes, iv, input, encrypt, grouping),
        24 => run_case::<Aes192, 24>(key_bytes, iv, input, encrypt, grouping),
        32 => run_case::<Aes256, 32>(key_bytes, iv, input, encrypt, grouping),
        other => panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}"),
    }
}

fn to_blocks(bytes: &[u8]) -> Vec<[u8; BLOCK_LEN]> {
    assert_eq!(bytes.len() % BLOCK_LEN, 0, "ACVP CBC payloads are block-aligned");
    bytes.chunks(BLOCK_LEN).map(|c| c.try_into().unwrap()).collect()
}

fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

#[test]
fn acvp_aes_cbc_known_answer_tests() {
    let Some(dir) = test_data_dir() else { return };

    let req: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(REQUEST_FILE)).expect("readable request file"),
    )
    .expect("valid ACVP request JSON");
    let rsp: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(RESPONSE_FILE)).expect("readable response file"),
    )
    .expect("valid ACVP response JSON");

    // The response file carries only the answer, against a tcId. Index it.
    let mut answers: BTreeMap<u64, Value> = BTreeMap::new();
    for group in rsp
        .get(1)
        .and_then(|s| s.get("testGroups"))
        .and_then(Value::as_array)
        .expect("response testGroups")
    {
        for test in group.get("tests").and_then(Value::as_array).expect("response tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            answers.insert(tc_id, test.clone());
        }
    }

    let groups = req
        .get(1)
        .and_then(|s| s.get("testGroups"))
        .and_then(Value::as_array)
        .expect("request testGroups");

    let mut checked = 0usize;
    let mut multi_block = 0usize;
    let mut skipped_mct = 0usize;
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();

    for group in groups {
        let test_type = group.get("testType").and_then(Value::as_str).expect("testType");
        let direction = group.get("direction").and_then(Value::as_str).expect("direction");
        let encrypt = match direction {
            "encrypt" => true,
            "decrypt" => false,
            other => panic!("unexpected direction {other}"),
        };

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");

            if test_type == "MCT" {
                skipped_mct += 1;
                continue;
            }

            let answer = answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));
            if answer.get("resultsArray").is_some() {
                skipped_mct += 1;
                continue;
            }

            let key_bytes = decode(test, "key", tc_id);
            let iv: [u8; BLOCK_LEN] = decode(test, "iv", tc_id).try_into().expect("a 16-byte IV");

            // Input comes from the request, expected output from the response.
            let (input_field, output_field) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
            let input = to_blocks(&decode(test, input_field, tc_id));
            let expected = to_blocks(&decode(answer, output_field, tc_id));

            assert_eq!(input.len(), expected.len(), "tcId {tc_id}: length mismatch");
            if input.len() > 1 {
                multi_block += 1;
            }

            for grouping in [Grouping::Single, Grouping::Pairs] {
                let got = run_case_for_key_len(&key_bytes, iv, &input, encrypt, grouping);
                assert_eq!(
                    got,
                    expected,
                    "tcId {tc_id}: AES-{} CBC {direction}, {} blocks, {grouping:?} grouping",
                    key_bytes.len() * 8,
                    input.len()
                );
            }

            *per_kind.entry(format!("AES-{} {direction}", key_bytes.len() * 8)).or_default() += 1;
            checked += 1;
        }
    }

    for (kind, n) in &per_kind {
        println!("ACVP AES-CBC {kind}: {n} cases");
    }
    println!(
        "ACVP AES-CBC: {checked} AFT cases checked in two groupings each \
         ({multi_block} of them multi-block); {skipped_mct} MCT cases skipped"
    );

    // Guard against a silently-empty or partial run.
    assert!(checked > 2000, "expected the full ACVP AFT set, only checked {checked}");
    assert!(multi_block >= 60, "expected the multi-block cases, found {multi_block}");
    assert_eq!(per_kind.len(), 6, "expected all three key lengths in both directions");
}
