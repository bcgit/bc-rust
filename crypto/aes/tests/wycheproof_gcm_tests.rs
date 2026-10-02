//! Known-answer tests against Project Wycheproof's `aes_gcm_test.json`, vendored into
//! `bc-test-data/crypto/wycheproof/` alongside the sibling `aes_ccm_test.json`.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the ACVP suites in this crate.
//!
//! # Why this set is worth having alongside the ACVP one
//!
//! `acvp_gcm_tests.rs` covers the NIST set, whose only failures are tag-check failures on an
//! otherwise well-formed message. Wycheproof's set is adversarial in the ways ACVP is not: a tag
//! with every one of a chosen set of bits flipped (`ModifiedTag`, 81 cases), so that a comparison
//! which checks only part of the tag is caught; IV lengths from 0 to 2056 bits (`ZeroLengthIv`,
//! `SmallIv`, `LongIv`); IVs chosen so that the 32-bit counter wraps (`CounterWrap`); and
//! pseudorandom sizes meant to catch an implementation that only handles the common cases. See
//! `bc-test-data/crypto/wycheproof/aes_gcm_test.json`'s own `"notes"` object for exactly what each
//! `flags` entry is checking.
//!
//! # Ciphertext and tag are separate fields
//!
//! Wycheproof's AEAD schema (`aead_test_schema_v1`) carries `ct` and `tag` as distinct fields, so
//! these cases go through the detached pair, [`AEADCipherEncryptor::encrypt_detached_out_rng`] /
//! [`AEADCipherDecryptor::decrypt_detached_out`]. [`Gcm`] generates its own nonce, so the vector's
//! `iv` is supplied through a `FixedSeedRNG` and the returned nonce is asserted to be exactly that
//! IV, the same technique as `acvp_gcm_tests.rs`.
//!
//! # Only the 96-bit-IV groups can be dispatched to, by design
//!
//! [`Gcm`] fixes the nonce at [`GCM_NONCE_LEN`] (SP 800-38D Sec 5.2.1.1 recommends restricting
//! support to 96 bits) and does not implement the `len(IV) != 96` branch of Algorithm 4 step 2. A
//! group with any other `ivSize` therefore has no instantiation to dispatch to: not a case that
//! can fail, but a shape the library never sees. That is most of the file's groups -- the point
//! of `ZeroLengthIv`, `SmallIv`, `LongIv` and `CounterWrap` is to probe exactly that boundary --
//! and they are counted as skipped rather than silently dropped, with the counts asserted at the
//! end so a change in the vector file's shape is visible. Every group in the file uses a 128-bit
//! tag, which is within the `12..=16` bytes `Gcm` accepts, so the tag size never skips a case.

use bouncycastle_aes::hazmat::{AES128Internal, AES192Internal, AES256Internal};
use bouncycastle_cipher::modes::{GCM_NONCE_LEN, Gcm};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] = [
    "../../../bc-test-data/crypto/wycheproof/aes_gcm_test.json",
    "../bc-test-data/crypto/wycheproof/aes_gcm_test.json",
];

fn test_data_file() -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); \
         Wycheproof AES-GCM tests will be skipped"
    );
    None
}

fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

/// Wraps the vector's raw key bytes, promoting them if `KeyMaterial`'s entropy heuristic declined
/// to call them a cipher key. Same helper as the ACVP and CCM suites in this crate.
fn cipher_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("wycheproof key bytes fit the buffer");

    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting a wycheproof test key");
    }
    key
}

/// Runs one case at a fully-instantiated `(KEY_LEN, TAG_LEN, P)`.
///
/// For a `result: "valid"` case, `msg` must encrypt to exactly `expected_ct`/`expected_tag` under
/// the vector's IV, and `expected_ct`/`expected_tag` must decrypt back to `msg`. For
/// `result: "invalid"`, only the decrypt direction is checked -- re-encrypting `msg` has no
/// reason to reproduce a deliberately corrupted tag -- and it must fail the tag check rather than
/// return a payload, leaving the caller's buffer zeroized as the trait contract requires.
#[allow(clippy::too_many_arguments)]
fn run_case<const KEY_LEN: usize, const TAG_LEN: usize, P>(
    tc_id: u64,
    key_bytes: &[u8],
    iv: [u8; GCM_NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    let key = cipher_key::<KEY_LEN>(key_bytes);
    let tag: [u8; TAG_LEN] =
        expected_tag.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad tag length"));

    if valid {
        let mut ct = vec![0u8; msg.len()];
        let (got_iv, written, got_tag) =
            Gcm::<P, Encrypting, KEY_LEN, TAG_LEN>::encrypt_detached_out_rng(
                &key,
                &mut FixedSeedRNG::<GCM_NONCE_LEN>::new(iv),
                aad,
                msg,
                &mut ct,
            )
            .unwrap_or_else(|e| panic!("tcId {tc_id}: valid case failed to encrypt: {e:?}"));
        assert_eq!(got_iv, iv, "tcId {tc_id}: the seeded RNG must reproduce the vector's IV");
        assert_eq!(written, msg.len(), "tcId {tc_id}: encrypt_detached writes exactly msg.len()");
        assert_eq!(ct, expected_ct, "tcId {tc_id}: ciphertext mismatch");
        assert_eq!(got_tag, tag, "tcId {tc_id}: tag mismatch");
    }

    let mut plaintext = vec![0u8; expected_ct.len()];
    match Gcm::<P, Decrypting, KEY_LEN, TAG_LEN>::decrypt_detached_out(
        &key, &iv, aad, expected_ct, &tag, &mut plaintext,
    ) {
        Ok(n) => {
            assert!(valid, "tcId {tc_id}: an invalid vector decrypted and verified anyway");
            plaintext.truncate(n);
            assert_eq!(plaintext, msg, "tcId {tc_id}: decrypted plaintext mismatch");
        }
        Err(SymmetricCipherError::AEADTagCheckFailed) => {
            assert!(!valid, "tcId {tc_id}: a valid vector failed its tag check");
            assert!(
                plaintext.iter().all(|&b| b == 0),
                "tcId {tc_id}: a failed tag check must leave the output buffer zeroized"
            );
        }
        Err(e) => panic!("tcId {tc_id}: unexpected GCM error: {e:?}"),
    }
}

/// Dispatches to one of the three key lengths at the 96-bit nonce and 128-bit tag `Gcm` and the
/// vector file share, or reports that the case's IV or tag size has no instantiation to dispatch
/// to at all.
#[allow(clippy::too_many_arguments)]
fn dispatch(
    tc_id: u64,
    key_bytes: &[u8],
    iv_bytes: &[u8],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) -> bool {
    // The nonce length is fixed by the type, so a case is dispatched on its actual `iv` length,
    // not the group's declared `ivSize`.
    let Ok(iv) = <[u8; GCM_NONCE_LEN]>::try_from(iv_bytes) else { return false };
    // Every group in the file is a 128-bit tag; anything else would need its own `TAG_LEN`
    // instantiation, and `Gcm` accepts only 12..=16 bytes, so report rather than guess.
    if expected_tag.len() != 16 {
        return false;
    }
    match key_bytes.len() {
        16 => run_case::<16, 16, AES128Internal>(
            tc_id, key_bytes, iv, aad, msg, expected_ct, expected_tag, valid,
        ),
        24 => run_case::<24, 16, AES192Internal>(
            tc_id, key_bytes, iv, aad, msg, expected_ct, expected_tag, valid,
        ),
        32 => run_case::<32, 16, AES256Internal>(
            tc_id, key_bytes, iv, aad, msg, expected_ct, expected_tag, valid,
        ),
        _ => return false,
    }
    true
}

#[test]
fn wycheproof_aes_gcm_known_answer_tests() {
    let Some(path) = test_data_file() else { return };

    let doc: Value = serde_json::from_str(&fs::read_to_string(&path).expect("readable file"))
        .expect("valid wycheproof JSON");
    assert_eq!(
        doc.get("algorithm").and_then(Value::as_str),
        Some("AES-GCM"),
        "this is the AES-GCM vector file"
    );

    let groups = doc.get("testGroups").and_then(Value::as_array).expect("testGroups");

    let mut run = 0usize;
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;
    let mut skipped_groups = 0usize;
    let mut skipped_cases = 0usize;

    for group in groups {
        let iv_size_bits = group.get("ivSize").and_then(Value::as_u64).expect("ivSize");
        let key_size_bits = group.get("keySize").and_then(Value::as_u64).expect("keySize");
        let tag_size_bits = group.get("tagSize").and_then(Value::as_u64).expect("tagSize");
        assert_eq!(iv_size_bits % 8, 0, "ivSize must be a whole number of octets");
        assert_eq!(key_size_bits % 8, 0, "keySize must be a whole number of octets");
        assert_eq!(tag_size_bits % 8, 0, "tagSize must be a whole number of octets");

        // A per-group tally for the printout; the per-case counts below come from `dispatch`,
        // which is the authority on what it can run.
        if iv_size_bits as usize != 8 * GCM_NONCE_LEN || tag_size_bits != 128 {
            skipped_groups += 1;
        }

        let tests = group.get("tests").and_then(Value::as_array).expect("tests");

        for test in tests {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let key_bytes = decode(test, "key", tc_id);
            let iv_bytes = decode(test, "iv", tc_id);
            let aad = decode(test, "aad", tc_id);
            let msg = decode(test, "msg", tc_id);
            let ct = decode(test, "ct", tc_id);
            let tag = decode(test, "tag", tc_id);
            let result = test.get("result").and_then(Value::as_str).expect("result");
            let valid = match result {
                "valid" => true,
                "invalid" => false,
                other => panic!("tcId {tc_id}: unexpected result {other}"),
            };

            let ran = dispatch(tc_id, &key_bytes, &iv_bytes, &aad, &msg, &ct, &tag, valid);

            if ran {
                run += 1;
                if valid {
                    valid_count += 1;
                } else {
                    invalid_count += 1;
                }
            } else {
                skipped_cases += 1;
            }
        }
    }

    println!(
        "Wycheproof AES-GCM: {run} cases run ({valid_count} valid, {invalid_count} invalid), \
         {skipped_cases} cases in {skipped_groups} groups skipped (no 96-bit-IV instantiation)"
    );

    // Guards against a silently-vacuous run: the three 96-bit-IV groups must have been dispatched
    // to and must have included both valid and tag-modified cases.
    assert!(run > 0, "expected the 96-bit-IV groups to be dispatchable");
    assert!(valid_count > 0, "expected at least some valid cases to be run");
    assert!(invalid_count > 0, "expected at least some invalid (tag-failure) cases to be run");
    assert!(skipped_groups > 0, "expected the other-IV-length groups to be outside Gcm's shape");
}
