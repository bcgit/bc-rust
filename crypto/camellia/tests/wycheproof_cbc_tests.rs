//! Known-answer tests against Google/C2SP **Wycheproof** `Camellia-CBC-PKCS5` vectors.
//!
//! Requires `bc-test-data` to be cloned alongside this repository, with the Wycheproof file under
//! `crypto/wycheproof/`. If it is absent the test prints a warning and passes, matching the
//! convention the ACVP suites use -- `cargo test` must stay green for someone who has only cloned
//! this repository.
//!
//! # Why these are worth having on top of the ACVP and published vectors
//!
//! Every other vector set here is block-aligned and valid: it checks that correct input produces
//! the right ciphertext. Wycheproof's value is the other half. Of its 216 cases, **72 are valid and
//! 144 are invalid**, and 141 of those carry the `BadPadding` flag: ciphertexts whose plaintext
//! does not end in well-formed PKCS#7 padding, which decryption must **reject**. That is the path
//! `bouncycastle-padding`'s constant-time `unpad` exists for, and nothing else in the tree drives
//! it with adversarially chosen input.
//!
//! PKCS#5 and PKCS#7 are the same padding for a 16-byte block; the name in the file is Wycheproof's.
//!
//! # How the vectors map onto this API
//!
//! Decryption takes the IV as init data, so an invalid case is simply required to fail and a valid
//! one to reproduce the message. Encryption never accepts an IV -- see the crate docs -- so the
//! valid cases are driven through `encrypt_out_rng` with a [`FixedSeedRNG`] emitting the vector's
//! IV, and the returned init data is checked against it before any ciphertext is compared.

use bouncycastle_camellia::{Camellia_CBC_128, Camellia_CBC_192, Camellia_CBC_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{SimpleCipherDecryptor, SimpleCipherEncryptor};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hex as hex;
use bouncycastle_modes::{Decrypting, Encrypting};
use bouncycastle_padding::PKCS7;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const VECTOR_FILE: &str = "camellia_cbc_pkcs5_test.json";

/// Candidate locations, covering `cargo test` run from the crate root or from the repo root.
const TEST_DATA_PATHS: [&str; 2] =
    ["../../../bc-test-data/crypto/wycheproof", "../bc-test-data/crypto/wycheproof"];

fn vector_file() -> Option<PathBuf> {
    for candidate in TEST_DATA_PATHS {
        let path = Path::new(candidate).join(VECTOR_FILE);
        if path.exists() {
            return Some(path);
        }
    }
    println!(
        "WARNING: {VECTOR_FILE} not found (looked in {TEST_DATA_PATHS:?}); \
         Wycheproof Camellia-CBC-PKCS5 tests will be skipped"
    );
    None
}

fn key_material<const N: usize>(raw: &[u8]) -> KeyMaterial<N> {
    assert_eq!(raw.len(), N, "key length should match the group");
    KeyMaterial::<N>::from_bytes_as_type(raw, KeyType::SymmetricCipherKey)
        .expect("a valid symmetric cipher key")
}

fn decode(v: &Value, field: &str, tc: u64) -> Vec<u8> {
    let s = v.get(field).and_then(Value::as_str).unwrap_or_else(|| panic!("tcId {tc}: no {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc}: bad hex in {field}"))
}

/// Runs one case for a given key length. Returns `true` if it was a valid case.
fn run_case<Enc, Dec, const N: usize>(t: &Value) -> bool
where
    Enc: SimpleCipherEncryptor<N, 16, 16>,
    Dec: SimpleCipherDecryptor<N, 16, 16>,
{
    let tc = t.get("tcId").and_then(Value::as_u64).expect("tcId");
    let key = key_material::<N>(&decode(t, "key", tc));
    let iv: [u8; 16] = decode(t, "iv", tc).try_into().expect("a 16-byte IV");
    let msg = decode(t, "msg", tc);
    let ct = decode(t, "ct", tc);
    let result = t.get("result").and_then(Value::as_str).expect("result");
    let comment = t.get("comment").and_then(Value::as_str).unwrap_or("");

    let mut out = vec![0u8; Dec::decrypt_out_max_len(ct.len())];
    let decrypted = Dec::decrypt_out(&key, &iv, &ct, &mut out);

    match result {
        "valid" => {
            let n = decrypted.unwrap_or_else(|e| {
                panic!("tcId {tc} ({comment}): valid case failed to decrypt: {e:?}")
            });
            assert_eq!(&out[..n], &msg[..], "tcId {tc} ({comment}): wrong plaintext");

            // ...and encryption reproduces the ciphertext under the vector's IV.
            let mut ct_out = vec![0u8; Enc::encrypt_out_len(msg.len())];
            let (got_iv, written) =
                Enc::encrypt_out_rng(&key, &mut FixedSeedRNG::<16>::new(iv), &msg, &mut ct_out)
                    .unwrap_or_else(|e| panic!("tcId {tc}: encryption failed: {e:?}"));
            assert_eq!(got_iv, iv, "tcId {tc}: the pinned RNG should reproduce the vector's IV");
            assert_eq!(&ct_out[..written], &ct[..], "tcId {tc} ({comment}): wrong ciphertext");
            true
        }
        "invalid" => {
            assert!(
                decrypted.is_err(),
                "tcId {tc} ({comment}): an invalid ciphertext must be rejected, not decrypted"
            );
            false
        }
        other => panic!("tcId {tc}: unexpected result {other}"),
    }
}

#[test]
fn wycheproof_cbc_pkcs5_vectors() {
    let Some(path) = vector_file() else { return };
    let doc: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("readable vector file"))
            .expect("valid Wycheproof JSON");

    let mut valid = 0usize;
    let mut invalid = 0usize;

    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        let key_size = group.get("keySize").and_then(Value::as_u64).expect("keySize");
        let iv_size = group.get("ivSize").and_then(Value::as_u64).expect("ivSize");
        assert_eq!(iv_size, 128, "these vectors should all use a 16-byte IV");

        for t in group.get("tests").and_then(Value::as_array).expect("tests") {
            let was_valid = match key_size {
                128 => run_case::<
                    Camellia_CBC_128<Encrypting, PKCS7>,
                    Camellia_CBC_128<Decrypting, PKCS7>,
                    16,
                >(t),
                192 => run_case::<
                    Camellia_CBC_192<Encrypting, PKCS7>,
                    Camellia_CBC_192<Decrypting, PKCS7>,
                    24,
                >(t),
                256 => run_case::<
                    Camellia_CBC_256<Encrypting, PKCS7>,
                    Camellia_CBC_256<Decrypting, PKCS7>,
                    32,
                >(t),
                other => panic!("unexpected key size {other}"),
            };
            if was_valid { valid += 1 } else { invalid += 1 }
        }
    }

    println!("Wycheproof Camellia-CBC-PKCS5: {valid} valid and {invalid} invalid cases checked");
    assert_eq!(valid + invalid, 216, "expected the whole Wycheproof set");
    assert!(invalid > 100, "the invalid cases are the point of this suite; found {invalid}");
}
