//! Known-answer tests against Wycheproof's `aria_wrap_test.json` (KW) and `aria_kwp_test.json`
//! (KWP).
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! missing, the tests print a warning and pass without checking anything.
//!
//! A `valid` case must wrap to the given ciphertext and unwrap back. An `invalid` case's
//! ciphertext must not unwrap; where its plaintext is one KW is not defined on (`WrongDataSize`,
//! `EmptyKey`), wrapping must refuse it as well. The `ShortKey` cases, an 8-byte key wrapped as the
//! one block RFC 3394 allows and SP 800-38F does not, are `acceptable`: this crate follows
//! SP 800-38F and rejects them, which the suite permits.

use bouncycastle_aria::{ARIA128Key, ARIA192Key, ARIA256Key};
use bouncycastle_cipher::modes::{KW, KWP};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::Mode;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey};
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};

fn material<const N: usize>(key: &[u8]) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(key, KeyType::SymmetricCipherKey)
        .expect("a symmetric cipher key of the group's length")
}

/// One case at one key length.
fn run_case<const N: usize, K>(tc_id: u64, key: &[u8], msg: &[u8], ct: &[u8], test: &Value)
where
    K: FromKeyMaterial<N> + KeyWrappingKey<N> + KeyUnwrappingKey<N>,
{
    let kek = K::from_key_material(&material::<N>(key)).unwrap();
    let flags: Vec<&str> =
        test["flags"].as_array().unwrap().iter().map(|f| f.as_str().unwrap()).collect();
    match test["result"].as_str().unwrap() {
        "valid" => {
            assert_eq!(kek.wrap(msg).unwrap(), ct, "tcId {tc_id}: wrap");
            assert_eq!(kek.unwrap(ct).unwrap(), msg, "tcId {tc_id}: unwrap");
        }
        "invalid" | "acceptable" => {
            assert!(kek.unwrap(ct).is_err(), "tcId {tc_id}: the ciphertext must not unwrap");
            if flags.iter().any(|f| ["WrongDataSize", "EmptyKey", "ShortKey"].contains(f)) {
                assert!(
                    matches!(kek.wrap(msg), Err(SymmetricCipherError::InvalidInputLength(_))),
                    "tcId {tc_id}: a plaintext of {} bytes is not a KW input",
                    msg.len()
                );
            }
        }
        other => panic!("tcId {tc_id}: unexpected result {other}"),
    }
}

/// Runs one Wycheproof set under the mode `M`, returning the number of cases run.
fn run_set<M>(file: &str) -> Option<usize>
where
    M: Mode<bouncycastle_aria::hazmat::ARIA128Internal>
        + Mode<bouncycastle_aria::hazmat::ARIA192Internal>
        + Mode<bouncycastle_aria::hazmat::ARIA256Internal>,
    ARIA128Key<M>: KeyWrappingKey<16> + KeyUnwrappingKey<16>,
    ARIA192Key<M>: KeyWrappingKey<24> + KeyUnwrappingKey<24>,
    ARIA256Key<M>: KeyWrappingKey<32> + KeyUnwrappingKey<32>,
{
    let set = wycheproof_json(file)?;
    let mut count = 0;
    for group in set["testGroups"].as_array().unwrap() {
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let key = hex_field(test, "key", tc_id);
            let msg = hex_field(test, "msg", tc_id);
            let ct = hex_field(test, "ct", tc_id);
            match key.len() {
                16 => run_case::<16, ARIA128Key<M>>(tc_id, &key, &msg, &ct, test),
                24 => run_case::<24, ARIA192Key<M>>(tc_id, &key, &msg, &ct, test),
                32 => run_case::<32, ARIA256Key<M>>(tc_id, &key, &msg, &ct, test),
                other => panic!("tcId {tc_id}: unexpected key length {other}"),
            }
            count += 1;
        }
    }
    Some(count)
}

#[test]
fn wycheproof_aria_kw() {
    let Some(count) = run_set::<KW>("aria_wrap_test.json") else { return };
    println!("Wycheproof ARIA-KW: {count} cases");
    assert_eq!(count, 159, "expected all 159 Wycheproof ARIA key-wrap cases to run");
}

#[test]
fn wycheproof_aria_kwp() {
    let Some(count) = run_set::<KWP>("aria_kwp_test.json") else { return };
    println!("Wycheproof ARIA-KWP: {count} cases");
    assert_eq!(count, 252, "expected all 252 Wycheproof ARIA key-wrap-with-padding cases to run");
}
