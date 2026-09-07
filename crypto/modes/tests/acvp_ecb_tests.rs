//! Known-answer tests against the NIST ACVP `ACVP-AES-ECB` vectors from the `bc-test-data` repo,
//! driven through [`Ecb`] -- the mode API -- rather than the raw permutation.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the other ACVP suites -- `cargo test` must stay green for someone
//! who has only cloned this repository.
//!
//! `crypto/aes/tests/acvp_tests.rs` runs the same file against the permutation's block
//! methods; this file is what pins that the mode adds nothing and loses nothing on the way: every
//! case is run through the `BlockCipherEncryptor` / `BlockCipherDecryptor` API in three groupings
//! -- block by block, in pairs with a remainder, and the whole payload in one hook call (which for
//! the 8-to-10-block cases reaches the eight-block path) -- in both directions.
//!
//! Unlike the CBC and CFB response files, the ECB one records `key`, `pt` and `ct` for every case,
//! so it is read alone and each case is checked in both directions regardless of its group's
//! declared direction. The MCT (Monte Carlo) groups carry a `resultsArray` defined by the ACVP AES
//! specification rather than SP 800-38A and are skipped, with the count reported.

use bouncycastle_aes::{Aes128, Aes192, Aes256};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook, SecurityStrength,
};
use bouncycastle_hex as hex;
use bouncycastle_modes::{Decrypting, Ecb, Encrypting};
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

const RESPONSE_FILE: &str = "ACVP-AES-ECB.4014527.rsp.json";

fn test_data_dir() -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.join(RESPONSE_FILE).exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); \
         ACVP AES-ECB mode tests will be skipped"
    );
    None
}

/// Builds a `KeyMaterial` from raw ACVP key bytes, including the all-zero keys the set contains.
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
    /// One block per call.
    Single,
    /// Two blocks per call, with a one-block remainder for odd lengths.
    Pairs,
    /// The whole payload in one hook call: eights, then pairs, then the remainder.
    Whole,
}

fn run_case<P, const KEY_LEN: usize>(
    key_bytes: &[u8],
    input: &[[u8; BLOCK_LEN]],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<[u8; BLOCK_LEN]>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let key = cipher_key::<KEY_LEN>(key_bytes);
    let mut out = input.to_vec();

    // Both directions have the same shape; `step` applies the right one to a slice of blocks.
    let mut enc = encrypt
        .then(|| Ecb::<P, Encrypting, KEY_LEN, BLOCK_LEN>::do_encrypt_init(&key).expect("init").0);
    let mut dec = (!encrypt).then(|| {
        Ecb::<P, Decrypting, KEY_LEN, BLOCK_LEN>::do_decrypt_init(&key, &[]).expect("init")
    });
    let mut step = |blocks: &mut [[u8; BLOCK_LEN]]| {
        if let Some(e) = enc.as_mut() {
            e.do_encrypt_blocks(blocks).unwrap();
        } else {
            dec.as_mut().unwrap().do_decrypt_blocks(blocks).unwrap();
        }
    };

    match grouping {
        Grouping::Single => {
            for block in out.iter_mut() {
                step(core::slice::from_mut(block));
            }
        }
        Grouping::Pairs => {
            let (pairs, tail) = out.as_chunks_mut::<2>();
            for pair in pairs {
                step(pair);
            }
            step(tail);
        }
        Grouping::Whole => step(&mut out),
    }
    out
}

fn run_case_for_key_len(
    key_bytes: &[u8],
    input: &[[u8; BLOCK_LEN]],
    encrypt: bool,
    grouping: Grouping,
) -> Vec<[u8; BLOCK_LEN]> {
    match key_bytes.len() {
        16 => run_case::<Aes128, 16>(key_bytes, input, encrypt, grouping),
        24 => run_case::<Aes192, 24>(key_bytes, input, encrypt, grouping),
        32 => run_case::<Aes256, 32>(key_bytes, input, encrypt, grouping),
        other => panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}"),
    }
}

fn to_blocks(bytes: &[u8]) -> Vec<[u8; BLOCK_LEN]> {
    assert_eq!(bytes.len() % BLOCK_LEN, 0, "ACVP ECB payloads are block-aligned");
    bytes.chunks(BLOCK_LEN).map(|c| c.try_into().unwrap()).collect()
}

#[test]
fn acvp_aes_ecb_through_the_mode_api() {
    let Some(dir) = test_data_dir() else { return };

    let parsed: Value = serde_json::from_str(
        &fs::read_to_string(dir.join(RESPONSE_FILE)).expect("readable response file"),
    )
    .expect("valid ACVP JSON");
    let groups = parsed
        .get(1)
        .and_then(|set| set.get("testGroups"))
        .and_then(Value::as_array)
        .expect("testGroups array");

    let mut checked = 0usize;
    let mut multi_block = 0usize;
    let mut eight_or_more = 0usize;
    let mut skipped_mct = 0usize;
    let mut per_key_len: BTreeMap<usize, usize> = BTreeMap::new();

    for group in groups {
        for test in group.get("tests").and_then(Value::as_array).expect("tests array") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            if test.get("resultsArray").is_some() {
                skipped_mct += 1;
                continue;
            }
            let get = |name: &str| -> Vec<u8> {
                let s = test
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {name}"));
                hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {name}"))
            };
            let key = get("key");
            let pt = to_blocks(&get("pt"));
            let ct = to_blocks(&get("ct"));
            assert_eq!(pt.len(), ct.len(), "tcId {tc_id}: pt and ct differ in length");
            multi_block += usize::from(pt.len() > 1);
            eight_or_more += usize::from(pt.len() >= 8);

            for grouping in [Grouping::Single, Grouping::Pairs, Grouping::Whole] {
                assert_eq!(
                    run_case_for_key_len(&key, &pt, true, grouping),
                    ct,
                    "tcId {tc_id}: AES-{} ECB encrypt, {} blocks, {grouping:?}",
                    key.len() * 8,
                    pt.len()
                );
                assert_eq!(
                    run_case_for_key_len(&key, &ct, false, grouping),
                    pt,
                    "tcId {tc_id}: AES-{} ECB decrypt, {} blocks, {grouping:?}",
                    key.len() * 8,
                    pt.len()
                );
            }
            *per_key_len.entry(key.len() * 8).or_default() += 1;
            checked += 1;
        }
    }

    for (bits, n) in &per_key_len {
        println!("ACVP AES-ECB via Ecb, AES-{bits}: {n} cases, both directions");
    }
    println!(
        "ACVP AES-ECB via Ecb: {checked} AFT cases checked in three groupings each \
         ({multi_block} multi-block, {eight_or_more} of eight or more blocks); {skipped_mct} MCT cases skipped"
    );

    // Guard against a silently-empty or partial run.
    assert!(checked > 2000, "expected the full ACVP AFT set, only checked {checked}");
    assert!(eight_or_more > 0, "expected cases that reach the eight-block path");
    assert_eq!(per_key_len.len(), 3, "expected all three key lengths");
}
