//! Known-answer tests against Project Wycheproof's
//! `testvectors_v1/ascon_sp800_232_aead128_test.json` (Ascon-AEAD128, NIST SP 800-232).
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! absent the test prints a warning and passes, matching the convention used by the other vector
//! suites in this crate.
//!
//! A `valid` case must encrypt to exactly `ct || tag` and decrypt back to `msg`. An `invalid` case
//! must be rejected with `AEADTagCheckFailed`, leaving the output buffer zeroized.

use bouncycastle_ascon::ascon_aead128::{AsconAead128, KEY_LEN, NONCE_LEN, TAG_LEN};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core_test_framework::test_data_loaders::wycheproof;
use bouncycastle_hex as hex;
use serde_json::Value;

fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}

/// Wraps the vector's key bytes as a cipher key, promoting them if `KeyMaterial`'s entropy
/// heuristic declined to (as `ascon_bc-test-data.rs` does for the NIST KAT keys).
fn cipher_key(bytes: &[u8]) -> KeyMaterial<KEY_LEN> {
    let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("a 16-byte key");
    do_hazardous_operations(&mut key, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(SecurityStrength::_128bit)
    })
    .expect("promoting a wycheproof test key");
    key
}

#[test]
fn wycheproof_ascon_aead128() {
    let Some(contents) = wycheproof("ascon_sp800_232_aead128_test.json") else { return };

    let doc: Value = serde_json::from_str(&contents).expect("valid wycheproof JSON");
    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some("ASCON-AEAD128"));

    let (mut valid_count, mut invalid_count) = (0usize, 0usize);
    for group in doc.get("testGroups").and_then(Value::as_array).expect("testGroups") {
        for (field, len) in [("keySize", KEY_LEN), ("ivSize", NONCE_LEN), ("tagSize", TAG_LEN)] {
            let bits = group.get(field).and_then(Value::as_u64).expect(field);
            assert_eq!(bits as usize, 8 * len, "every group uses Ascon-AEAD128's fixed {field}");
        }

        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let key = cipher_key(&decode(test, "key", tc_id));
            let nonce: [u8; NONCE_LEN] =
                decode(test, "iv", tc_id).try_into().expect("a 16-byte nonce");
            let aad = decode(test, "aad", tc_id);
            let ad = if aad.is_empty() { None } else { Some(aad.as_slice()) };
            let msg = decode(test, "msg", tc_id);
            let ct_and_tag = [decode(test, "ct", tc_id), decode(test, "tag", tc_id)].concat();

            let mut pt = vec![0xEEu8; ct_and_tag.len().saturating_sub(TAG_LEN)];
            let decrypted = AsconAead128::decrypt(&key, &nonce, ad, &ct_and_tag, &mut pt);

            match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => {
                    let mut out = vec![0u8; msg.len() + TAG_LEN];
                    let n = AsconAead128::encrypt(&key, &nonce, ad, &msg, &mut out)
                        .unwrap_or_else(|e| panic!("tcId {tc_id}: encrypt failed: {e:?}"));
                    assert_eq!(&out[..n], &ct_and_tag[..], "tcId {tc_id}: ct || tag");

                    let n = decrypted.unwrap_or_else(|e| panic!("tcId {tc_id}: decrypt: {e:?}"));
                    assert_eq!(&pt[..n], &msg[..], "tcId {tc_id}: decrypted plaintext");
                    valid_count += 1;
                }
                "invalid" => {
                    assert!(
                        matches!(decrypted, Err(SymmetricCipherError::AEADTagCheckFailed)),
                        "tcId {tc_id}: expected AEADTagCheckFailed, got {decrypted:?}"
                    );
                    assert!(pt.iter().all(|&b| b == 0), "tcId {tc_id}: output not zeroized");
                    invalid_count += 1;
                }
                other => panic!("tcId {tc_id}: unexpected result {other}"),
            }
        }
    }

    println!("Wycheproof Ascon-AEAD128: {valid_count} valid and {invalid_count} invalid cases run");
    assert!(valid_count > 0 && invalid_count > 0, "expected both valid and invalid cases");
}
