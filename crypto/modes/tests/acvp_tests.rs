//! Known-answer tests against the NIST ACVP `ACVP-AES-CBC` and `ACVP-AES-CFB128` vectors from the
//! `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the tests print a warning and pass,
//! matching the convention used by the ML-KEM, ML-DSA and `aes-lowmemory` suites -- `cargo test`
//! must stay green for someone who has only cloned this repository.
//!
//! These are the counterpart to `crypto/aes-lowmemory/tests/acvp_tests.rs`, which consumes the
//! `ACVP-AES-ECB` file to test the raw permutation. CBC and CFB are modes, so their vectors belong
//! here. `ACVP-AES-CFB128` is the `s = b` segment size, which is the variant `Cfb` implements; the
//! separate `ACVP-AES-CFB8` file is for a segment size this crate does not provide, and stays
//! unused.
//!
//! # Joining the request and response files
//!
//! Unlike the ECB response file, which echoes `key`, `pt` and `ct` for every case, these response
//! files carry **only the answer** (`ct` for an encrypt group, `pt` for a decrypt group) against a
//! `tcId`. The key, IV and input live in the request file, and the group metadata that says which
//! direction a case is -- `direction` and `keyLen` -- lives only there too. So both files are read
//! and joined on `tcId`; there is no way to drive this from the response file alone.
//!
//! # Coverage
//!
//! | Vector set | AFT cases | Multi-block | MCT (skipped) |
//! |---|---|---|---|
//! | `ACVP-AES-CBC` | 2150 | 60 | 6 |
//! | `ACVP-AES-CFB128` | 2138 | 54 | 6 |
//!
//! Both across all three key lengths and both directions, with the multi-block cases spanning 2 to
//! 10 blocks. Every case is run **twice**: once block by block, and once in pairs with a one-block
//! remainder for odd lengths. The second pass is what puts the multi-block cases through the
//! permutation's two-block path -- `decrypt_blocks2` for CBC, `encrypt_blocks2` for CFB, since CFB
//! decryption uses the forward cipher -- so the pair path is exercised against real vectors and not
//! only against the toys in `cbc_tests.rs` and `cfb_tests.rs`.
//!
//! The MCT (Monte Carlo Test) groups are **not** implemented: their expected output is a
//! `resultsArray` produced by a chained update rule defined in the ACVP AES specification rather
//! than in SP 800-38A, and implementing it from anything else would be guesswork. The tests report
//! how many they skipped so the gap stays visible.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, SecurityStrength};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Cbc, Cfb, Decrypting, Encrypting};
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

/// Which mode a vector set is for. Selects both the files and the types under test.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Cbc,
    Cfb128,
}

impl Mode {
    fn request_file(self) -> &'static str {
        match self {
            Mode::Cbc => "ACVP-AES-CBC.4014528.req.json",
            Mode::Cfb128 => "ACVP-AES-CFB128.4014530.req.json",
        }
    }

    fn response_file(self) -> &'static str {
        match self {
            Mode::Cbc => "ACVP-AES-CBC.4014528.rsp.json",
            Mode::Cfb128 => "ACVP-AES-CFB128.4014530.rsp.json",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Mode::Cbc => "AES-CBC",
            Mode::Cfb128 => "AES-CFB128",
        }
    }
}

fn test_data_dir(mode: Mode) -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.join(mode.request_file()).exists() && path.join(mode.response_file()).exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); \
         ACVP {} tests will be skipped",
        mode.label()
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

/// Runs one case in one direction, for a given encryptor/decryptor pair, under the given grouping.
///
/// Generic over the mode types rather than over the permutation, so the same body drives CBC and
/// CFB. Encryption is driven through `do_encrypt_init_rng` with a `FixedSeedRNG` emitting the
/// vector's IV, and the returned init data is checked against that IV before any ciphertext is
/// compared -- so a change that ignored the RNG could not pass silently.
fn run_case<E, D, const KEY_LEN: usize>(
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[[u8; BLOCK_LEN]],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<[u8; BLOCK_LEN]>
where
    E: BlockCipherEncryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
    D: BlockCipherDecryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN>,
{
    let key = cipher_key::<KEY_LEN>(key_bytes);
    let mut out: Vec<[u8; BLOCK_LEN]> = Vec::with_capacity(input.len());

    if encrypt {
        let (mut enc, got_iv) =
            E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<BLOCK_LEN>::new(iv))
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
        let mut dec = D::do_decrypt_init(&key, &iv).expect("dec init");

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

/// Dispatches on the mode and the key length, which together select the concrete types.
fn run_case_for(
    mode: Mode,
    key_bytes: &[u8],
    iv: [u8; BLOCK_LEN],
    input: &[[u8; BLOCK_LEN]],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<[u8; BLOCK_LEN]> {
    match (mode, key_bytes.len()) {
        (Mode::Cbc, 16) => run_case::<
            Cbc<Aes128, Encrypting, 16, BLOCK_LEN>,
            Cbc<Aes128, Decrypting, 16, BLOCK_LEN>,
            16,
        >(key_bytes, iv, input, encrypt, grouping),
        (Mode::Cbc, 24) => run_case::<
            Cbc<Aes192, Encrypting, 24, BLOCK_LEN>,
            Cbc<Aes192, Decrypting, 24, BLOCK_LEN>,
            24,
        >(key_bytes, iv, input, encrypt, grouping),
        (Mode::Cbc, 32) => run_case::<
            Cbc<Aes256, Encrypting, 32, BLOCK_LEN>,
            Cbc<Aes256, Decrypting, 32, BLOCK_LEN>,
            32,
        >(key_bytes, iv, input, encrypt, grouping),
        (Mode::Cfb128, 16) => run_case::<
            Cfb<Aes128, Encrypting, 16, BLOCK_LEN>,
            Cfb<Aes128, Decrypting, 16, BLOCK_LEN>,
            16,
        >(key_bytes, iv, input, encrypt, grouping),
        (Mode::Cfb128, 24) => run_case::<
            Cfb<Aes192, Encrypting, 24, BLOCK_LEN>,
            Cfb<Aes192, Decrypting, 24, BLOCK_LEN>,
            24,
        >(key_bytes, iv, input, encrypt, grouping),
        (Mode::Cfb128, 32) => run_case::<
            Cfb<Aes256, Encrypting, 32, BLOCK_LEN>,
            Cfb<Aes256, Decrypting, 32, BLOCK_LEN>,
            32,
        >(key_bytes, iv, input, encrypt, grouping),
        (_, other) => {
            panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}")
        }
    }
}

fn to_blocks(bytes: &[u8]) -> Vec<[u8; BLOCK_LEN]> {
    assert_eq!(bytes.len() % BLOCK_LEN, 0, "ACVP payloads here are block-aligned");
    bytes.chunks(BLOCK_LEN).map(|c| c.try_into().unwrap()).collect()
}

fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

/// Drives one whole vector set. Asserts everything; returns nothing.
///
/// `min_cases` and `min_multi_block` guard against a silently-empty or partial run, which is the
/// failure mode a data-driven test is most prone to.
fn run_vector_set(mode: Mode, min_cases: usize, min_multi_block: usize) {
    let Some(dir) = test_data_dir(mode) else { return };

    let req: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(mode.request_file())).expect("readable request file"),
    )
    .expect("valid ACVP request JSON");
    let rsp: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(mode.response_file())).expect("readable response file"),
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
                let got = run_case_for(mode, &key_bytes, iv, &input, encrypt, grouping);
                assert_eq!(
                    got,
                    expected,
                    "tcId {tc_id}: {} AES-{} {direction}, {} blocks, {grouping:?} grouping",
                    mode.label(),
                    key_bytes.len() * 8,
                    input.len()
                );
            }

            *per_kind.entry(format!("AES-{} {direction}", key_bytes.len() * 8)).or_default() += 1;
            checked += 1;
        }
    }

    for (kind, n) in &per_kind {
        println!("ACVP {} {kind}: {n} cases", mode.label());
    }
    println!(
        "ACVP {}: {checked} AFT cases checked in two groupings each \
         ({multi_block} of them multi-block); {skipped_mct} MCT cases skipped",
        mode.label()
    );

    assert!(
        checked >= min_cases,
        "expected at least {min_cases} AFT cases for {}, only checked {checked}",
        mode.label()
    );
    assert!(
        multi_block >= min_multi_block,
        "expected at least {min_multi_block} multi-block cases for {}, found {multi_block}",
        mode.label()
    );
    assert_eq!(per_kind.len(), 6, "expected all three key lengths in both directions");
}

#[test]
fn acvp_aes_cbc_known_answer_tests() {
    run_vector_set(Mode::Cbc, 2150, 60);
}

#[test]
fn acvp_aes_cfb128_known_answer_tests() {
    run_vector_set(Mode::Cfb128, 2138, 54);
}
