//! Known-answer tests against the NIST ACVP `ACVP-AES-CCM` vectors from the `bc-test-data` repo.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, i.e. at `../bc-test-data`
//! relative to the root of this git project. If it is absent the test prints a warning and passes,
//! matching the convention used by the other ACVP suites -- `cargo test` must stay green for
//! someone who has only cloned this repository.
//!
//! # The tag is inline, so this drives the inline API
//!
//! The set has **no `tag` field anywhere**. An encrypt group's answer `ct` is the ciphertext with
//! the tag appended, and a decrypt group's input `ct` is the same, which is exactly SP 800-38C
//! Sec 6.1 step 8's own output string. So the cases go through [`Ccm::encrypt`] / [`Ccm::decrypt`],
//! the inline pair, and the group's `payloadLen` / `tagLen` are only needed to pick `TAG_LEN` and
//! to check the answer's length.
//!
//! # Failure cases are part of the vectors
//!
//! 52 of the 240 decrypt cases are inauthentic, and the response file marks them with
//! `"testPassed": false` and no `pt`. There is no `decryptVerificationFailed` field in this set.
//! Those cases are run and required to come back
//! [`AEADTagCheckFailed`](SymmetricCipherError::AEADTagCheckFailed) -- they are the only official
//! negative vectors this library has for CCM, so they are checked, not skipped.
//!
//! # Joining the request and response files
//!
//! As with the other AES sets, the response file carries only the answer against a `tcId`; the key,
//! nonce, AAD and input live in the request file, and so does the group metadata that says which
//! direction a case is. Both files are read and joined on `tcId`, which is unique across the whole
//! set.
//!
//! # What this set does *not* cover
//!
//! Worth stating, so the gaps stay visible rather than looking like coverage:
//!
//! * **`ivLen` is 96 in every group**, so `n = 12` and `q = 3` throughout. The nonce-length /
//!   payload-limit tradeoff of A.1 is entirely untested here; `sp800_38c_tests.rs` covers `q` of 8,
//!   7, 3 and 2 against Appendix C.
//! * **`tagLen` is only 96 or 128.** The short tags A.1 permits (`t` of 4 or 6) appear in Appendix
//!   C instead.
//! * **No empty AAD and no empty payload**: `aadLen` is 128 or 256 bits and `payloadLen` is 64,
//!   128 or 192. Sec 5.3 permits both to be empty, and `sp800_38c_tests.rs` covers that.
//! * **Every payload is 8, 16 or 24 bytes**, i.e. one or two blocks, so nothing here stresses a
//!   long message. The `chunks` sweep below and the Appendix C.4 case cover the multi-block paths.
//!
//! The 6 Monte Carlo groups that the CTR and CBC sets have do not exist here: every group in this
//! set is `testType: "AFT"`, so nothing is skipped for that reason.

use bouncycastle_aes::{AES_128, AES_192, AES_256};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{ElectronicCodeBook, SecurityStrength};
use bouncycastle_hex as hex;
use bouncycastle_modes::{Ccm, Decrypting, Encrypting};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Every group in this set has `ivLen: 96`.
const NONCE_LEN: usize = 12;

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] = [
    "../../../bc-test-data/crypto/aes_tdes_vectors/CCM",
    "../bc-test-data/crypto/aes_tdes_vectors/CCM",
];

const REQUEST_FILE: &str = "ACVP-AES-CCM.4014548.req.json";
const RESPONSE_FILE: &str = "ACVP-AES-CCM.4014548.rsp.json";

fn test_data_dir() -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate);
        if path.join(REQUEST_FILE).exists() && path.join(RESPONSE_FILE).exists() {
            return Some(path.to_path_buf());
        }
    }
    println!(
        "WARNING: bc-test-data not found (looked in {TEST_DATA_PATHS:?}); \
         ACVP AES-CCM tests will be skipped"
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
/// to call them a cipher key. Same helper as the other ACVP suites in this crate.
fn cipher_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("ACVP key bytes fit the buffer");

    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting a NIST test key");
    }
    key
}

/// The outcome of one decrypt case, so that an expected authentication failure can be asserted
/// rather than merely tolerated.
enum Decrypted {
    Plaintext(Vec<u8>),
    TagCheckFailed,
}

/// Runs one encrypt case: `Ccm::encrypt` must produce the response file's `ct`, which is
/// `ciphertext || tag`.
///
/// Also re-runs it through the length-declared streaming API in several chunkings, since these are
/// the only real vectors available for that path and the one-shot is a single call over the whole
/// payload.
fn encrypt_case<const KEY_LEN: usize, const TAG_LEN: usize, P>(
    key: &KeyMaterial<KEY_LEN>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8>
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    let mut inline = vec![0u8; plaintext.len() + TAG_LEN];
    let written = Ccm::<P, Encrypting, KEY_LEN, 16, NONCE_LEN, TAG_LEN>::encrypt(
        key, nonce, aad, plaintext, &mut inline,
    )
    .expect("CCM encryption of a valid ACVP case");
    assert_eq!(written, inline.len(), "the inline layout writes ciphertext || tag");

    // The same answer must come out of the streaming API, in any chunking of both phases.
    for chunk in [1usize, 5, 16] {
        let mut ccm = Ccm::<P, Encrypting, KEY_LEN, 16, NONCE_LEN, TAG_LEN>::new(
            key,
            nonce,
            aad,
            plaintext.len(),
        )
        .expect("streaming init");
        let mut streamed = plaintext.to_vec();
        for piece in streamed.chunks_mut(chunk) {
            ccm.do_encrypt_update(piece).expect("update");
        }
        let tag = ccm.do_encrypt_final().expect("final");
        assert_eq!(&streamed[..], &inline[..plaintext.len()], "streamed in {chunk}-byte chunks");
        assert_eq!(&tag[..], &inline[plaintext.len()..], "streamed tag, {chunk}-byte chunks");
    }

    inline
}

/// Runs one decrypt case over the inline `ciphertext || tag` string the vectors carry.
fn decrypt_case<const KEY_LEN: usize, const TAG_LEN: usize, P>(
    key: &KeyMaterial<KEY_LEN>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct_and_tag: &[u8],
) -> Decrypted
where
    P: ElectronicCodeBook<KEY_LEN, 16>,
{
    let mut plaintext = vec![0u8; ct_and_tag.len().saturating_sub(TAG_LEN)];
    match Ccm::<P, Decrypting, KEY_LEN, 16, NONCE_LEN, TAG_LEN>::decrypt(
        key, nonce, aad, ct_and_tag, &mut plaintext,
    ) {
        Ok(n) => {
            plaintext.truncate(n);
            Decrypted::Plaintext(plaintext)
        }
        Err(SymmetricCipherError::AEADTagCheckFailed) => {
            assert!(
                plaintext.iter().all(|b| *b == 0),
                "Sec 6.2: the payload must not be revealed when the check fails"
            );
            Decrypted::TagCheckFailed
        }
        Err(other) => panic!("unexpected CCM decryption error: {other:?}"),
    }
}

/// Dispatches a case to the right `(KEY_LEN, TAG_LEN)` instantiation.
///
/// Both are const generics, so the six combinations this set uses are spelled out. `ivLen` is 96 in
/// every group, so `NONCE_LEN` is not part of the dispatch; an unexpected value is a hard failure
/// rather than a silent skip, so that a future revision of the vector file cannot quietly reduce
/// coverage.
#[allow(clippy::too_many_arguments)]
fn run_case(
    tc_id: u64,
    key_len: u64,
    tag_len: u64,
    encrypt: bool,
    key_bytes: &[u8],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, ()> {
    macro_rules! dispatch {
        ($k:literal, $t:literal, $p:ty) => {{
            let key = cipher_key::<$k>(key_bytes);
            if encrypt {
                Ok(encrypt_case::<$k, $t, $p>(&key, nonce, aad, input))
            } else {
                match decrypt_case::<$k, $t, $p>(&key, nonce, aad, input) {
                    Decrypted::Plaintext(p) => Ok(p),
                    Decrypted::TagCheckFailed => Err(()),
                }
            }
        }};
    }

    // A macro here rather than the unrolled six arms purely because the *type* arguments differ:
    // `KEY_LEN`, `TAG_LEN` and the AES type all vary together, and a function cannot take them as
    // runtime values. The body is one expression, and each arm is its own instantiation, so
    // `cargo mutants` still sees the code it expands to.
    match (key_len, tag_len) {
        (128, 96) => dispatch!(16, 12, AES_128),
        (128, 128) => dispatch!(16, 16, AES_128),
        (192, 96) => dispatch!(24, 12, AES_192),
        (192, 128) => dispatch!(24, 16, AES_192),
        (256, 96) => dispatch!(32, 12, AES_256),
        (256, 128) => dispatch!(32, 16, AES_256),
        other => panic!("tcId {tc_id}: unexpected (keyLen, tagLen) {other:?}"),
    }
}

#[test]
fn acvp_aes_ccm_known_answer_tests() {
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

    let mut encrypt_cases = 0usize;
    let mut decrypt_pass_cases = 0usize;
    let mut decrypt_fail_cases = 0usize;
    let mut per_kind: BTreeMap<String, usize> = BTreeMap::new();

    for group in groups {
        let test_type = group.get("testType").and_then(Value::as_str).expect("testType");
        assert_eq!(test_type, "AFT", "this set is documented as AFT-only");
        let direction = group.get("direction").and_then(Value::as_str).expect("direction");
        let encrypt = match direction {
            "encrypt" => true,
            "decrypt" => false,
            other => panic!("unexpected direction {other}"),
        };
        let key_len = group.get("keyLen").and_then(Value::as_u64).expect("keyLen");
        let tag_len = group.get("tagLen").and_then(Value::as_u64).expect("tagLen");
        let iv_len = group.get("ivLen").and_then(Value::as_u64).expect("ivLen");
        let payload_len = group.get("payloadLen").and_then(Value::as_u64).expect("payloadLen");
        assert_eq!(iv_len, 96, "every group in this set has a 96-bit nonce");
        assert_eq!(tag_len % 8, 0, "tagLen must be a whole number of octets");

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let answer = answers.get(&tc_id).unwrap_or_else(|| panic!("tcId {tc_id}: no answer"));

            let key_bytes = decode(test, "key", tc_id);
            let nonce_bytes = decode(test, "iv", tc_id);
            let nonce: [u8; NONCE_LEN] = nonce_bytes
                .try_into()
                .unwrap_or_else(|_| panic!("tcId {tc_id}: iv is not 12 bytes"));
            let aad = decode(test, "aad", tc_id);

            // Input comes from the request, expected output from the response.
            let input = decode(test, if encrypt { "pt" } else { "ct" }, tc_id);

            let expect_failure = answer
                .get("testPassed")
                .and_then(Value::as_bool)
                .map(|passed| !passed)
                .unwrap_or(false);

            let got = run_case(tc_id, key_len, tag_len, encrypt, &key_bytes, &nonce, &aad, &input);

            if encrypt {
                assert!(!expect_failure, "tcId {tc_id}: an encrypt case cannot be a failure case");
                let expected = decode(answer, "ct", tc_id);
                assert_eq!(
                    expected.len() as u64,
                    (payload_len + tag_len) / 8,
                    "tcId {tc_id}: the answer must be ciphertext || tag"
                );
                let got = got.expect("an encrypt case never reports a tag failure");
                assert_eq!(got, expected, "tcId {tc_id}: AES-{key_len} CCM encrypt");
                encrypt_cases += 1;
            } else if expect_failure {
                assert!(
                    got.is_err(),
                    "tcId {tc_id}: the vectors say this ciphertext is inauthentic, \
                     but decryption returned a payload"
                );
                decrypt_fail_cases += 1;
            } else {
                let expected = decode(answer, "pt", tc_id);
                let got = got.unwrap_or_else(|()| {
                    panic!("tcId {tc_id}: an authentic ACVP case failed its tag check")
                });
                assert_eq!(got, expected, "tcId {tc_id}: AES-{key_len} CCM decrypt");
                decrypt_pass_cases += 1;
            }

            *per_kind.entry(format!("AES-{key_len} t={} {direction}", tag_len / 8)).or_default() +=
                1;
        }
    }

    println!("ACVP AES-CCM cases by parameter set:");
    for (kind, count) in &per_kind {
        println!("  {kind}: {count}");
    }
    println!(
        "  totals: {encrypt_cases} encrypt, {decrypt_pass_cases} decrypt-authentic, \
         {decrypt_fail_cases} decrypt-inauthentic"
    );

    // Guard against a silently-empty or partial run. These are the exact counts of the vector set,
    // so a file that changed shape fails loudly instead of quietly testing less.
    assert_eq!(encrypt_cases, 240, "expected 240 encrypt cases");
    assert_eq!(decrypt_pass_cases, 188, "expected 188 authentic decrypt cases");
    assert_eq!(decrypt_fail_cases, 52, "expected 52 inauthentic decrypt cases");
    assert_eq!(
        encrypt_cases + decrypt_pass_cases + decrypt_fail_cases,
        480,
        "every case in the set should be checked; none are skipped"
    );
    // Three key lengths x two tag lengths x two directions: the full cross product, so every one
    // of the six `run_case` instantiations is exercised in both directions.
    assert_eq!(
        per_kind.len(),
        12,
        "expected all three key lengths at both tag lengths, in both directions"
    );
}
