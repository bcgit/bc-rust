//! Known-answer tests against Wycheproof's `aes_cmac_test.json`.
//!
//! Requires the Wycheproof repository (https://github.com/C2SP/wycheproof) to be cloned alongside
//! this repository, i.e. at `../wycheproof` relative to the root of this git project. If it is
//! missing, the test prints a warning and passes without checking anything.
//!
//! Every tag is checked through the worker an `AES*Key<CMAC>` hands out and through the key's own
//! one-shots, so the two routes are held to the same answers.

use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::{CMAC, CMAC_MIN_TAG_LEN};
use bouncycastle_core::symmetric_key::{FromKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::MAC;
use bouncycastle_core_test_framework::test_data_loaders::{hex_field, wycheproof_json};

#[path = "common/cmac_helpers.rs"]
mod cmac_helpers;
use cmac_helpers::mac_key;

/// One case at one key length, through both routes.
fn run_case<const N: usize, K>(tc_id: u64, key: &[u8], msg: &[u8], tag: &[u8], valid: bool)
where
    K: FromKeyMaterial<N> + MacGenerationKey + MacVerificationKey,
    <K as MacGenerationKey>::Generator: MAC,
{
    let material = mac_key::<N>(key);
    let key = K::from_key_material(&material).unwrap_or_else(|e| panic!("tcId {tc_id}: {e:?}"));
    let full = key.create_generator().mac(msg);
    assert_eq!(full == tag, valid, "tcId {tc_id}");
    assert_eq!(key.create_generator().verify(msg, tag), valid, "tcId {tc_id}");

    assert_eq!(key.verify(msg, tag), valid, "tcId {tc_id}: via the key's one-shot");
    if valid {
        assert_eq!(key.mac(msg), tag, "tcId {tc_id}: via the key's one-shot");
        let mut out = [0u8; CMAC_MIN_TAG_LEN];
        key.mac_out(msg, &mut out).unwrap();
        assert_eq!(out[..], tag[..CMAC_MIN_TAG_LEN], "tcId {tc_id}: truncated tag");
    }
}

#[test]
fn wycheproof_aes_cmac() {
    let Some(set) = wycheproof_json("aes_cmac_test.json") else { return };

    let (mut valid, mut invalid, mut bad_key) = (0usize, 0usize, 0usize);
    for group in set["testGroups"].as_array().unwrap() {
        assert_eq!(group["tagSize"].as_u64(), Some(128));
        for test in group["tests"].as_array().unwrap() {
            let tc_id = test["tcId"].as_u64().unwrap();
            let key = hex_field(test, "key", tc_id);
            let msg = hex_field(test, "msg", tc_id);
            let tag = hex_field(test, "tag", tc_id);
            let expect_valid = match test["result"].as_str().unwrap() {
                "valid" => true,
                "invalid" => false,
                other => panic!("tcId {tc_id}: unexpected result {other}"),
            };

            match key.len() {
                16 => run_case::<16, AES128Key<CMAC>>(tc_id, &key, &msg, &tag, expect_valid),
                24 => run_case::<24, AES192Key<CMAC>>(tc_id, &key, &msg, &tag, expect_valid),
                32 => run_case::<32, AES256Key<CMAC>>(tc_id, &key, &msg, &tag, expect_valid),
                _ => {
                    // "InvalidKeySize": no `AES*Key<CMAC>` takes it, since the key length is in
                    // the `KeyMaterial<16 | 24 | 32>` type; nothing to run at runtime.
                    assert!(!expect_valid, "tcId {tc_id}");
                    bad_key += 1;
                    continue;
                }
            }
            if expect_valid { valid += 1 } else { invalid += 1 }
        }
    }
    println!(
        "Wycheproof AES-CMAC: {valid} valid, {invalid} invalid tags, {bad_key} invalid key sizes"
    );
    assert_eq!(valid + invalid + bad_key, 311, "expected all 311 Wycheproof AES-CMAC cases to run");
}
