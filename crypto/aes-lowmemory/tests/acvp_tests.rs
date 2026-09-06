//! Known-answer tests against the NIST ACVP `ACVP-AES-ECB` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the tests print a warning and pass,
//! matching the convention used by the ML-KEM and ML-DSA test suites -- `cargo test` must stay
//! green for someone who has only cloned this repository.
//!
//! # Why ECB, and where the other ACVP AES files are used
//!
//! ECB applies the raw permutation to each block independently, so an ECB test vector *is* a
//! block-permutation test vector -- which is the only reason ECB is mentioned in this crate. See
//! the crate docs on why you must never use ECB to encrypt data.
//!
//! `bc-test-data` ships thirteen ACVP AES vector sets, one per mode. This file deliberately
//! consumes only `ACVP-AES-ECB`, because that is the one that tests the permutation rather than a
//! mode. The others belong with whatever implements the mode:
//!
//! | Vector set | Consumed by |
//! |---|---|
//! | `ACVP-AES-ECB` | this file |
//! | `ACVP-AES-CBC` | `crypto/modes/tests/acvp_tests.rs` |
//! | `ACVP-AES-CBC-CS1` / `-CS2` / `-CS3` | nothing yet (ciphertext stealing is unimplemented) |
//! | `ACVP-AES-CFB8` / `-CFB128` | nothing yet (CFB is unimplemented) |
//! | `ACVP-AES-OFB` | nothing yet (OFB is unimplemented) |
//! | `ACVP-AES-CTR` | nothing yet (CTR is unimplemented) |
//! | `ACVP-AES-KW` / `-KWP` | nothing yet (key wrap is unimplemented) |
//! | `ACVP-AES-FF1` / `-FF3-1` | nothing yet (format-preserving encryption is unimplemented) |
//!
//! So an unused vector set here means an unimplemented mode, not an untested one. Adding a mode
//! should include wiring up its file.
//!
//! The response file records `key`, `pt` and `ct` for every test case regardless of the group's
//! declared direction, so each case is checked in **both** directions: encrypting `pt` must give
//! `ct` and decrypting `ct` must give `pt`. That is strictly stronger than honouring the declared
//! direction, and it means the group metadata in the request file is not needed.
//!
//! # Coverage and one gap
//!
//! The AFT (Algorithm Functional Test) groups cover all three key lengths in both directions,
//! including cases whose plaintext spans several blocks. The six MCT (Monte Carlo Test) groups
//! are **not** implemented: their expected output is a `resultsArray` produced by a chained
//! key/plaintext update rule defined in the ACVP AES specification rather than in FIPS 197, and
//! implementing it from anything other than that specification would be guesswork. The test
//! reports how many it skipped so the gap is visible rather than silent.

use bouncycastle_aes_lowmemory::{Aes128, Aes192, Aes256, BLOCK_LEN};
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::SecurityStrength;
use bouncycastle_hex as hex;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] = [
    "../../../bc-test-data/crypto/aes_tdes_vectors/AES",
    "../bc-test-data/crypto/aes_tdes_vectors/AES",
];

const RESPONSE_FILE: &str = "ACVP-AES-ECB.4014527.rsp.json";

/// Locates the ACVP AES directory, or `None` if `bc-test-data` is not checked out.
fn test_data_dir() -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.join(RESPONSE_FILE).exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); \
         ACVP AES-ECB tests will be skipped"
    );
    None
}

/// Builds a `KeyMaterial` from raw ACVP key bytes, including the all-zero keys.
///
/// The ACVP set deliberately includes an all-zero key (the GFSbox-style groups vary only the
/// plaintext under a zero key). `KeyMaterial` tags an all-zero buffer as [`KeyType::Zeroized`]
/// and will not promote it outside a [`do_hazardous_operations`] closure, which is the right
/// default -- an all-zero key normally means a broken RNG, and `Aes128::new` rejecting it is
/// tested in `fips197_tests.rs`. Here the zero key is deliberate and comes from NIST, so this
/// opts in explicitly rather than the library weakening its guard.
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

/// A single-block transformation, resolved once per test case rather than per block.
type BlockTransform = Box<dyn Fn(&mut [u8; BLOCK_LEN])>;

/// Encrypts or decrypts `data` block by block, i.e. ECB, dispatching on the key length.
fn ecb(key: &[u8], data: &[u8], encrypt: bool) -> Vec<u8> {
    assert_eq!(data.len() % BLOCK_LEN, 0, "ACVP ECB data must be block-aligned");

    let transform: BlockTransform = match key.len() {
        16 => {
            let km = cipher_key::<16>(key);
            let aes = Aes128::new(&km).expect("valid AES-128 key");
            if encrypt {
                Box::new(move |b| aes.encrypt_block(b))
            } else {
                Box::new(move |b| aes.decrypt_block(b))
            }
        }
        24 => {
            let km = cipher_key::<24>(key);
            let aes = Aes192::new(&km).expect("valid AES-192 key");
            if encrypt {
                Box::new(move |b| aes.encrypt_block(b))
            } else {
                Box::new(move |b| aes.decrypt_block(b))
            }
        }
        32 => {
            let km = cipher_key::<32>(key);
            let aes = Aes256::new(&km).expect("valid AES-256 key");
            if encrypt {
                Box::new(move |b| aes.encrypt_block(b))
            } else {
                Box::new(move |b| aes.decrypt_block(b))
            }
        }
        other => panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}"),
    };

    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(BLOCK_LEN) {
        // Cannot fail: the length is asserted block-aligned above.
        let mut block: [u8; BLOCK_LEN] = chunk.try_into().unwrap();
        transform(&mut block);
        out.extend_from_slice(&block);
    }
    out
}

/// The same, using the two-block entry points where a pair is available.
fn ecb_pairwise(key: &[u8], data: &[u8], encrypt: bool) -> Vec<u8> {
    assert_eq!(data.len() % BLOCK_LEN, 0, "ACVP ECB data must be block-aligned");
    let mut blocks: Vec<[u8; BLOCK_LEN]> =
        data.chunks(BLOCK_LEN).map(|c| c.try_into().unwrap()).collect();

    match key.len() {
        16 => {
            let km = cipher_key::<16>(key);
            let aes = Aes128::new(&km).unwrap();
            run_pairwise(&mut blocks, encrypt, |p, e| {
                if e { aes.encrypt_blocks2(p) } else { aes.decrypt_blocks2(p) }
            });
        }
        24 => {
            let km = cipher_key::<24>(key);
            let aes = Aes192::new(&km).unwrap();
            run_pairwise(&mut blocks, encrypt, |p, e| {
                if e { aes.encrypt_blocks2(p) } else { aes.decrypt_blocks2(p) }
            });
        }
        32 => {
            let km = cipher_key::<32>(key);
            let aes = Aes256::new(&km).unwrap();
            run_pairwise(&mut blocks, encrypt, |p, e| {
                if e { aes.encrypt_blocks2(p) } else { aes.decrypt_blocks2(p) }
            });
        }
        other => panic!("ACVP AES vectors should only use 16, 24 or 32 byte keys, got {other}"),
    }

    blocks.concat()
}

/// Walks `blocks` two at a time, leaving a trailing odd block to a duplicated pair.
fn run_pairwise(
    blocks: &mut [[u8; BLOCK_LEN]],
    encrypt: bool,
    transform: impl Fn(&mut [[u8; BLOCK_LEN]; 2], bool),
) {
    let mut chunks = blocks.chunks_exact_mut(2);
    for pair in &mut chunks {
        // Cannot fail: `chunks_exact_mut(2)` yields slices of length 2.
        let pair: &mut [[u8; BLOCK_LEN]; 2] = pair.try_into().unwrap();
        transform(pair, encrypt);
    }
    // An odd trailing block still has to go through the two-block path.
    if let [last] = chunks.into_remainder() {
        let mut pair = [*last, *last];
        transform(&mut pair, encrypt);
        *last = pair[0];
    }
}

#[test]
fn acvp_aes_ecb_known_answer_tests() {
    let Some(dir) = test_data_dir() else { return };

    let contents = fs::read_to_string(dir.join(RESPONSE_FILE)).expect("readable response file");
    let parsed: Value = serde_json::from_str(&contents).expect("valid ACVP JSON");

    // The ACVP file is an array: element 0 is the version header, element 1 the vector set.
    let groups = parsed
        .get(1)
        .and_then(|set| set.get("testGroups"))
        .and_then(Value::as_array)
        .expect("testGroups array");

    let mut checked = 0usize;
    let mut skipped_mct = 0usize;
    let mut by_key_len = [0usize; 3]; // 128, 192, 256

    for group in groups {
        let tests = group.get("tests").and_then(Value::as_array).expect("tests array");
        for test in tests {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");

            // Monte Carlo groups carry a chained resultsArray instead of a single pt/ct pair.
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
            let pt = get("pt");
            let ct = get("ct");

            assert_eq!(pt.len(), ct.len(), "tcId {tc_id}: pt and ct differ in length");

            assert_eq!(ecb(&key, &pt, true), ct, "tcId {tc_id}: AES-{} encrypt", key.len() * 8);
            assert_eq!(ecb(&key, &ct, false), pt, "tcId {tc_id}: AES-{} decrypt", key.len() * 8);

            // The two-block path must agree with the single-block path on real vectors too.
            assert_eq!(
                ecb_pairwise(&key, &pt, true),
                ct,
                "tcId {tc_id}: AES-{} encrypt via encrypt_blocks2",
                key.len() * 8
            );
            assert_eq!(
                ecb_pairwise(&key, &ct, false),
                pt,
                "tcId {tc_id}: AES-{} decrypt via decrypt_blocks2",
                key.len() * 8
            );

            by_key_len[match key.len() {
                16 => 0,
                24 => 1,
                _ => 2,
            }] += 1;
            checked += 1;
        }
    }

    println!(
        "ACVP AES-ECB: {checked} test cases checked in both directions \
         (AES-128: {}, AES-192: {}, AES-256: {}); {skipped_mct} MCT cases skipped",
        by_key_len[0], by_key_len[1], by_key_len[2]
    );

    // Guard against a silently-empty run: the published vector set has thousands of AFT cases
    // across all three key lengths.
    assert!(checked > 1000, "expected the full ACVP AFT set, only checked {checked}");
    assert!(by_key_len.iter().all(|&n| n > 0), "every key length should be covered");
}
