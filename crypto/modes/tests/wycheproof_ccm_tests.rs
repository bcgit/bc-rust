//! Known-answer tests against Project Wycheproof's `aes_ccm_test.json`, vendored into
//! `bc-test-data/crypto/wycheproof/` alongside the sibling `sm4_ccm_test.json`.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the ACVP suite in this crate.
//!
//! # Why this set is worth having alongside the ACVP one
//!
//! `acvp_ccm_tests.rs` covers 480 cases, but every one of them uses a 96-bit nonce, and the only
//! failures it carries are tag-check failures on an otherwise well-formed message. Wycheproof's
//! set is deliberately adversarial in the ways ACVP is not: malformed and truncated tags, every
//! nonce length from 8 to 2144 *bits* (most of which A.1 does not permit at all), a tag size of
//! 16 bits that SP 800-38C Appendix B.2 calls insecure, and pseudorandom sizes meant to catch an
//! implementation that only handles the common cases. See
//! `bc-test-data/crypto/wycheproof/aes_ccm_test.json`'s own `"notes"` object for exactly what each
//! `flags` entry is checking.
//!
//! # Ciphertext and tag are separate fields, unlike the ACVP set
//!
//! Wycheproof's AEAD schema carries `ct` and `tag` as distinct fields (the `aead_test_schema_v1`
//! schema), so these cases go through [`Ccm::encrypt_detached`] / [`Ccm::decrypt_detached`], not
//! the inline pair `acvp_ccm_tests.rs` uses.
//!
//! # Most of the parameter space cannot be dispatched to at all, by design
//!
//! `Ccm`'s `NONCE_LEN` and `TAG_LEN` are const generics restricted to A.1's sets --
//! `NONCE_LEN` in `7..=13` bytes, `TAG_LEN` in `{4, 6, 8, 10, 12, 14, 16}` bytes -- so there is no
//! instantiation to dispatch a group whose `ivSize`/`tagSize` falls outside them to at all; unlike
//! a runtime check, this is not something a case can "fail", because it is a compile-time property
//! of the type, not a value the library ever sees. Those groups (most of the file: the point of
//! `InvalidNonceSize`/`InvalidTagSize` and most of the `Pseudorandom` groups is to probe exactly
//! this boundary) are counted as skipped rather than silently dropped, and the counts are asserted
//! at the end so a change in the vector file's shape is visible.

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{ElectronicCodeBook, SecurityStrength};
use bouncycastle_hex as hex;
use bouncycastle_modes::{Ccm, Decrypting, Encrypting};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] = [
    "../../../bc-test-data/crypto/wycheproof/aes_ccm_test.json",
    "../bc-test-data/crypto/wycheproof/aes_ccm_test.json",
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
         Wycheproof AES-CCM tests will be skipped"
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
/// to call them a cipher key. Same helper as the ACVP suite in this crate.
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

/// Runs one case at a fully-instantiated `(KEY_LEN, NONCE_LEN, TAG_LEN, P)`.
///
/// For a `result: "valid"` case, `msg` must encrypt to exactly `expected_ct`/`expected_tag`
/// ([`Ccm::encrypt_detached`]), and `expected_ct`/`expected_tag` must decrypt back to `msg`
/// ([`Ccm::decrypt_detached`]). For `result: "invalid"`, only the decrypt direction is checked --
/// re-encrypting `msg` has no reason to reproduce a deliberately corrupted `ct`/`tag` -- and it
/// must fail the tag check rather than return a payload.
#[allow(clippy::too_many_arguments)]
fn run_case<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize, P>(
    tc_id: u64,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    let key = cipher_key::<KEY_LEN>(key_bytes);
    let nonce: [u8; NONCE_LEN] =
        nonce_bytes.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad nonce length"));
    let tag: [u8; TAG_LEN] =
        expected_tag.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad tag length"));

    if valid {
        let mut ct = vec![0u8; msg.len()];
        let (written, got_tag) =
            Ccm::<P, Encrypting, KEY_LEN, 16, NONCE_LEN, TAG_LEN>::encrypt_detached(
                &key, &nonce, aad, msg, &mut ct,
            )
            .unwrap_or_else(|e| panic!("tcId {tc_id}: valid case failed to encrypt: {e:?}"));
        assert_eq!(written, msg.len(), "tcId {tc_id}: encrypt_detached writes exactly msg.len()");
        assert_eq!(ct, expected_ct, "tcId {tc_id}: ciphertext mismatch");
        assert_eq!(got_tag, tag, "tcId {tc_id}: tag mismatch");
    }

    let mut plaintext = vec![0u8; expected_ct.len()];
    match Ccm::<P, Decrypting, KEY_LEN, 16, NONCE_LEN, TAG_LEN>::decrypt_detached(
        &key, &nonce, aad, expected_ct, &tag, &mut plaintext,
    ) {
        Ok(n) => {
            assert!(valid, "tcId {tc_id}: an invalid vector decrypted and verified anyway");
            plaintext.truncate(n);
            assert_eq!(plaintext, msg, "tcId {tc_id}: decrypted plaintext mismatch");
        }
        Err(SymmetricCipherError::AEADTagCheckFailed) => {
            assert!(!valid, "tcId {tc_id}: a valid vector failed its tag check");
        }
        Err(e) => panic!("tcId {tc_id}: unexpected CCM error: {e:?}"),
    }
}

/// Dispatches to one of the 3 (key) x 7 (nonce) x 7 (tag) valid instantiations, or reports that
/// the case's parameter sizes have no instantiation to dispatch to at all.
#[allow(clippy::too_many_arguments)]
fn dispatch(
    tc_id: u64,
    key_len_bytes: u64,
    nonce_len_bytes: u64,
    tag_len_bytes: u64,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) -> bool {
    macro_rules! with_key_len {
        ($n:literal, $t:literal) => {
            match key_len_bytes {
                16 => {
                    run_case::<16, $n, $t, AES_128>(
                        tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                    );
                    true
                }
                24 => {
                    run_case::<24, $n, $t, AES_192>(
                        tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                    );
                    true
                }
                32 => {
                    run_case::<32, $n, $t, AES_256>(
                        tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                    );
                    true
                }
                _ => false,
            }
        };
    }
    macro_rules! with_tag_len {
        ($n:literal) => {
            match tag_len_bytes {
                4 => with_key_len!($n, 4),
                6 => with_key_len!($n, 6),
                8 => with_key_len!($n, 8),
                10 => with_key_len!($n, 10),
                12 => with_key_len!($n, 12),
                14 => with_key_len!($n, 14),
                16 => with_key_len!($n, 16),
                _ => false,
            }
        };
    }
    match nonce_len_bytes {
        7 => with_tag_len!(7),
        8 => with_tag_len!(8),
        9 => with_tag_len!(9),
        10 => with_tag_len!(10),
        11 => with_tag_len!(11),
        12 => with_tag_len!(12),
        13 => with_tag_len!(13),
        _ => false,
    }
}

#[test]
fn wycheproof_aes_ccm_known_answer_tests() {
    let Some(path) = test_data_file() else { return };

    let doc: Value = serde_json::from_str(&fs::read_to_string(&path).expect("readable file"))
        .expect("valid wycheproof JSON");

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

        // A group is only fully within A.1's dispatchable sets if its *declared* nonce/tag sizes
        // are; a `Pseudorandom` group whose individual tests vary can still contribute some
        // dispatched and some skipped cases, so this is a per-group tally for the printout, not
        // something the per-case counts below depend on.
        if !(7..=13).contains(&(iv_size_bits / 8))
            || ![4u64, 6, 8, 10, 12, 14, 16].contains(&(tag_size_bits / 8))
        {
            skipped_groups += 1;
        }

        let tests = group.get("tests").and_then(Value::as_array).expect("tests");

        // Each case is dispatched on its own actual field lengths, not the group's declared
        // sizes: a `Pseudorandom` group's whole point is varying them per test, and `dispatch`
        // itself is the authority on what it can run (only A.1's own sets).
        for test in tests {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let key_bytes = decode(test, "key", tc_id);
            let nonce_bytes = decode(test, "iv", tc_id);
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

            let ran = dispatch(
                tc_id,
                key_bytes.len() as u64,
                nonce_bytes.len() as u64,
                tag.len() as u64,
                &key_bytes,
                &nonce_bytes,
                &aad,
                &msg,
                &ct,
                &tag,
                valid,
            );

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
        "Wycheproof AES-CCM: {run} cases run ({valid_count} valid, {invalid_count} invalid), \
         {skipped_cases} cases in {skipped_groups} groups skipped (no A.1 instantiation)"
    );

    // Guards against a silently-vacuous run: at least the common 96-bit-nonce/128-bit-tag groups
    // must have been dispatched to and must have included both valid and invalid cases.
    assert!(run > 0, "expected at least some cases to be within A.1's dispatchable sets");
    assert!(valid_count > 0, "expected at least some valid cases to be run");
    assert!(invalid_count > 0, "expected at least some invalid (tag-failure) cases to be run");
    assert!(skipped_groups > 0, "expected most of this adversarial set to be outside A.1's sets");
}
