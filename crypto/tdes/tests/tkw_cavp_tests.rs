//! Known-answer tests against the NIST CAVP sample files for TKW, `TKW_AE.txt` and `TKW_AD.txt`
//! from `kwtestvectors.zip` ("Key Wrap Validation System" sample vectors, CAVS 17.4), read from
//! `bc-test-data/crypto/aes_tdes_vectors/TDES` through the framework's `bc_test_data` loader;
//! without `bc-test-data` beside this repository the tests print a warning and pass.
//!
//! Each file carries five `[PLAINTEXT LENGTH = n]` sections of 100 trials, for 64, 96, 128, 160
//! and 2048 bits. `TKW_AE` gives `K`, `P` and `C`; `TKW_AD` gives `K`, `C` and either `P` or
//! `FAIL`, 20 forgeries per section. The forward cipher function is the designated one (the
//! `_inv` files of the zip are not used). `K` is `KEY1 || KEY2 || KEY3`, 24 bytes.

use bouncycastle_cipher::modes::TKW;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data;
use bouncycastle_hex as hex;
use bouncycastle_tdes::{KEY_LEN, TDES3Key};

const CAVP_DIR: &str = "crypto/aes_tdes_vectors/TDES";

/// One trial: `plaintext` is `None` for a `FAIL` line.
#[derive(Default)]
struct Case {
    section: String,
    count: u32,
    key: Vec<u8>,
    plaintext: Option<Vec<u8>>,
    ciphertext: Vec<u8>,
}

/// Parses a CAVS sample file: `[PLAINTEXT LENGTH = n]` headers, `COUNT = n` starting a case,
/// `K`, `P` and `C` hex fields, and a bare `FAIL` line.
fn parse(text: &str) -> Vec<Case> {
    let mut cases: Vec<Case> = Vec::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = name.to_string();
            continue;
        }
        if line == "FAIL" {
            let case = cases.last_mut().expect("a FAIL after a COUNT");
            assert!(case.plaintext.is_none(), "FAIL on a case that has a plaintext");
            continue;
        }
        let (name, value) = line.split_once(" = ").expect("`NAME = value` line");
        if name == "COUNT" {
            cases.push(Case {
                section: section.clone(),
                count: value.parse().expect("a decimal COUNT"),
                ..Default::default()
            });
            continue;
        }
        let case = cases.last_mut().expect("a field before any COUNT");
        let bytes = hex::decode(value).expect("hex field");
        match name {
            "K" => case.key = bytes,
            "P" => case.plaintext = Some(bytes),
            "C" => case.ciphertext = bytes,
            other => panic!("unexpected field {other}"),
        }
    }
    cases
}

fn load(file: &str) -> Option<Vec<Case>> {
    let cases = parse(&bc_test_data(CAVP_DIR, file)?);
    assert_eq!(cases.len(), 500, "{file}: five sections of 100 trials");
    println!("{file}: {} cases found under bc-test-data/{CAVP_DIR}", cases.len());
    Some(cases)
}

fn kek(case: &Case) -> TDES3Key<TKW> {
    let key: [u8; KEY_LEN] = case.key.as_slice().try_into().expect("a 24-byte K");
    let material = KeyMaterial::<KEY_LEN>::from_bytes_as_type(&key, KeyType::SymmetricCipherKey)
        .expect("a symmetric cipher key");
    TDES3Key::<TKW>::from_key_material(&material).unwrap_or_else(|e| {
        panic!("[{}] COUNT = {}: the CAVP bundle was refused: {e:?}", case.section, case.count)
    })
}

#[test]
fn tkw_ae() {
    let Some(cases) = load("TKW_AE.txt") else { return };
    for case in &cases {
        let where_ = format!("[{}] COUNT = {}", case.section, case.count);
        let plaintext = case.plaintext.as_ref().expect("an AE case has a plaintext");
        let kek = kek(case);
        assert_eq!(kek.wrap(plaintext).unwrap(), case.ciphertext, "{where_}: wrap");
        assert_eq!(kek.unwrap(&case.ciphertext).unwrap(), *plaintext, "{where_}: unwrap");
    }
}

#[test]
fn tkw_ad() {
    let Some(cases) = load("TKW_AD.txt") else { return };
    let mut forgeries = 0;
    for case in &cases {
        let where_ = format!("[{}] COUNT = {}", case.section, case.count);
        let kek = kek(case);
        let result = kek.unwrap(&case.ciphertext);
        match &case.plaintext {
            Some(plaintext) => assert_eq!(result.unwrap(), *plaintext, "{where_}: unwrap"),
            None => {
                assert!(
                    matches!(result, Err(SymmetricCipherError::DecryptionFailed)),
                    "{where_}: a forgery must fail with DecryptionFailed, got {result:?}"
                );
                forgeries += 1;
            }
        }
    }
    assert_eq!(forgeries, 100, "20 forgeries in each of the five sections");
}
