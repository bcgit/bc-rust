//! Known-answer tests against the NIST ACVP `ACVP-AES-CTR` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the other ACVP suites -- `cargo test` must stay green for
//! someone who has only cloned this repository.
//!
//! # Only the zero-counter cases apply, and that is most of them
//!
//! ACVP gives each case a full 16-byte `iv`, which for CTR is the **initial counter block**.
//! [`Ctr`] takes a *nonce* and starts its counter at zero, so a case is expressible through this
//! API exactly when its initial counter block ends in `CTR_LEN` zero bytes: then the nonce is the
//! leading bytes and the counter is already where this mode starts.
//!
//! With the 12-byte nonce used here (a 4-byte counter), **1853 of the 2138** functional cases
//! qualify. The other 285 begin at a non-zero counter and are skipped with the count reported, so
//! the gap stays visible; they test the cipher and the XOR, both of which the qualifying cases
//! already cover, and not the counter construction, which `ctr_tests.rs` pins against the spec.
//!
//! # Joining the request and response files
//!
//! As with the other AES sets, the response file carries **only the answer** (`ct` for an encrypt
//! group, `pt` for a decrypt group) against a `tcId`. The key, IV and input live in the request
//! file, and the group metadata that says which direction a case is lives only there too. So both
//! files are read and joined on `tcId`.
//!
//! # Coverage
//!
//! Every qualifying case is run in four groupings -- the whole payload in one call, block by block,
//! in 8-byte calls and in 3-byte calls -- so the batch paths and the byte path are both exercised
//! against real vectors. The payloads are a single block each, so counter *increment* is not
//! covered here; `ctr_tests.rs` covers it against the raw permutation across a 255-to-256 carry,
//! and the OpenSSL cross-check in `cli/tests/aes_ctr_cli_tests.rs` covers it end to end.
//!
//! The 6 MCT (Monte Carlo Test) groups are **not** implemented: their expected output is a
//! `resultsArray` produced by a chained update rule defined in the ACVP AES specification rather
//! than in SP 800-38A, and implementing it from anything else would be guesswork.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    ElectronicCodeBook, SecurityStrength, StreamCipherDecryptor, StreamCipherEncryptor,
};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Ctr, Decrypting, Encrypting};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const BLOCK_LEN: usize = 16;
/// The nonce length under test; the remaining 4 bytes of the block are the counter.
const NONCE_LEN: usize = 12;

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] = [
    "../../../bc-test-data/crypto/aes_tdes_vectors/AES",
    "../bc-test-data/crypto/aes_tdes_vectors/AES",
];

const REQUEST_FILE: &str = "ACVP-AES-CTR.4014537.req.json";
const RESPONSE_FILE: &str = "ACVP-AES-CTR.4014537.rsp.json";

fn test_data_dir() -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.join(REQUEST_FILE).exists() && path.join(RESPONSE_FILE).exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); \
         ACVP AES-CTR tests will be skipped"
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

/// How to walk the bytes of one case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Grouping {
    /// The whole payload in one call: eights, then pairs, then the remaining bytes singly.
    Whole,
    /// One whole block per call.
    Blocks,
    /// Eight bytes per call, so no call is a whole block and the keystream carries across calls.
    Eights,
    /// Three bytes per call, a size that lines up with neither the block nor the batch.
    Threes,
}

impl Grouping {
    fn chunk_len(self, payload_len: usize) -> usize {
        match self {
            Grouping::Whole => payload_len.max(1),
            Grouping::Blocks => BLOCK_LEN,
            Grouping::Eights => 8,
            Grouping::Threes => 3,
        }
    }
}

/// Runs one CTR case in one direction, for a given permutation, under the given grouping.
///
/// Encryption is driven through `do_encrypt_init_rng` with a `FixedSeedRNG` emitting the vector's
/// IV, and the returned init data is checked against that IV before any ciphertext is compared --
/// so a change that ignored the RNG could not pass silently.
fn run_case<P, const KEY_LEN: usize>(
    key_bytes: &[u8],
    nonce: [u8; NONCE_LEN],
    input: &[u8],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<u8>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let key = cipher_key::<KEY_LEN>(key_bytes);
    let mut data = input.to_vec();
    let chunk = grouping.chunk_len(data.len());

    if encrypt {
        let (mut enc, got_iv) =
            Ctr::<P, Encrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN>::do_encrypt_init_rng(
                &key,
                &mut FixedSeedRNG::<NONCE_LEN>::new(nonce),
            )
            .expect("encrypt init");
        assert_eq!(got_iv, nonce, "the pinned RNG should reproduce the vector's nonce");
        for piece in data.chunks_mut(chunk) {
            enc.do_encrypt(piece).unwrap();
        }
    } else {
        let mut dec =
            Ctr::<P, Decrypting, KEY_LEN, BLOCK_LEN, NONCE_LEN>::do_decrypt_init(&key, &nonce)
                .expect("dec init");
        for piece in data.chunks_mut(chunk) {
            dec.do_decrypt(piece).unwrap();
        }
    }

    data
}

/// Dispatches on key length, which is what selects the AES parameter set.
fn run_case_for_key_len(
    key_bytes: &[u8],
    nonce: [u8; NONCE_LEN],
    input: &[u8],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<u8> {
    match key_bytes.len() {
        16 => run_case::<Aes128, 16>(key_bytes, nonce, input, encrypt, grouping),
        24 => run_case::<Aes192, 24>(key_bytes, nonce, input, encrypt, grouping),
        32 => run_case::<Aes256, 32>(key_bytes, nonce, input, encrypt, grouping),
        other => panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}"),
    }
}

fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

#[test]
fn acvp_aes_ctr_known_answer_tests() {
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
    let mut skipped_mct = 0usize;
    let mut skipped_nonzero_counter = 0usize;
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

            // Anything that is not a functional test is a Monte Carlo group. This file labels
            // those "CTR" rather than "MCT", unlike the CBC and CFB sets, so the test is written
            // against what an AFT case *is* rather than against one spelling of what it is not.
            if test_type != "AFT" {
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

            // Only an initial counter block whose counter is already zero is expressible through
            // this API; see the module docs.
            if iv[NONCE_LEN..] != [0u8; BLOCK_LEN - NONCE_LEN] {
                skipped_nonzero_counter += 1;
                continue;
            }
            let nonce: [u8; NONCE_LEN] = iv[..NONCE_LEN].try_into().expect("the nonce");

            // Input comes from the request, expected output from the response.
            let (input_field, output_field) = if encrypt { ("pt", "ct") } else { ("ct", "pt") };
            let input = decode(test, input_field, tc_id);
            let expected = decode(answer, output_field, tc_id);

            assert_eq!(input.len(), expected.len(), "tcId {tc_id}: length mismatch");
            for grouping in [Grouping::Whole, Grouping::Blocks, Grouping::Eights, Grouping::Threes]
            {
                let got = run_case_for_key_len(&key_bytes, nonce, &input, encrypt, grouping);
                assert_eq!(
                    got,
                    expected,
                    "tcId {tc_id}: AES-{} CTR {direction}, {} bytes, {grouping:?} grouping",
                    key_bytes.len() * 8,
                    input.len()
                );
            }

            *per_kind.entry(format!("AES-{} {direction}", key_bytes.len() * 8)).or_default() += 1;
            checked += 1;
        }
    }

    for (kind, n) in &per_kind {
        println!("ACVP AES-CTR {kind}: {n} cases");
    }
    println!(
        "ACVP AES-CTR: {checked} AFT cases checked in four groupings each; \
         {skipped_nonzero_counter} skipped for a non-zero initial counter, \
         {skipped_mct} MCT cases skipped"
    );

    // Guard against a silently-empty or partial run.
    assert!(checked > 1800, "expected the zero-counter ACVP AFT cases, only checked {checked}");
    assert_eq!(
        checked + skipped_nonzero_counter,
        2138,
        "every AFT case should be either checked or explicitly skipped for its counter"
    );
    assert_eq!(skipped_mct, 6, "the six Monte Carlo groups should be skipped, and only those");
    assert_eq!(per_kind.len(), 6, "expected all three key lengths in both directions");
}
