//! Known-answer tests against Project Wycheproof's `testvectors_v1/sm4_gcm_test.json`, through
//! the `GCM` hazmat mode traits over `SM4Internal`'s key state.
//!
//! The same suite as `crypto/aes/tests/gcm_wycheproof.rs` at SM4's one key length; see that file
//! for what the set probes and why only the 96-bit-IV groups have an instantiation to dispatch to
//! (`Gcm` fixes the nonce at `GCM_NONCE_LEN`). The key carries no AEAD role, so the cases run
//! over the mode's key state directly, as `rfc8998_tests.rs` does. Requires the Wycheproof
//! repository at `../wycheproof`; absent, the test warns and passes.

use bouncycastle_cipher::modes::{GCM, GCM_NONCE_LEN};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{
    AeadDecryptMode, AeadEncryptMode, ElectronicCodeBook, Mode, do_hazardous_operations,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_sm4::KEY_LEN;
use bouncycastle_sm4::hazmat::SM4Internal;

/// The tag length every group in the file uses.
const TAG_LEN: usize = 16;

/// The `GCM` key state for the vector's raw key bytes, promoted if `KeyMaterial`'s entropy
/// heuristic declined to call them a cipher key.
fn key_state(bytes: &[u8]) -> <GCM as Mode<SM4Internal>>::KeyState {
    let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("wycheproof key bytes fit the buffer");
    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(KEY_LEN))
        })
        .expect("promoting a wycheproof test key");
    }
    <GCM as Mode<SM4Internal>>::key_state(
        <SM4Internal as ElectronicCodeBook<KEY_LEN, 16>>::new(&key).expect("a wycheproof key"),
    )
}

/// Runs one case. A valid case must encrypt to exactly `expected_ct`/`expected_tag` under the
/// vector's IV and decrypt back; an invalid one is checked on the decrypt direction only and must
/// fail the tag check with the buffer zeroized.
#[allow(clippy::too_many_arguments)]
fn run_case(
    tc_id: u64,
    key_bytes: &[u8],
    iv: [u8; GCM_NONCE_LEN],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) {
    let state = key_state(key_bytes);
    let tag: [u8; TAG_LEN] =
        expected_tag.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad tag length"));

    if valid {
        let mut ct = msg.to_vec();
        let encrypt = <GCM as AeadEncryptMode<
            SM4Internal,
            KEY_LEN,
            GCM_NONCE_LEN,
            TAG_LEN,
            TAG_LEN,
        >>::encrypt_detached_in_place_nonce;
        let got_tag = encrypt(&state, &iv, aad, &mut ct)
            .unwrap_or_else(|e| panic!("tcId {tc_id}: valid case failed to encrypt: {e:?}"));
        assert_eq!(ct, expected_ct, "tcId {tc_id}: ciphertext mismatch");
        assert_eq!(got_tag, tag, "tcId {tc_id}: tag mismatch");
    }

    let mut plaintext = expected_ct.to_vec();
    let decrypt = <GCM as AeadDecryptMode<SM4Internal, KEY_LEN, GCM_NONCE_LEN, TAG_LEN, TAG_LEN>>::
        decrypt_detached_in_place;
    match decrypt(&state, &iv, aad, &mut plaintext, &tag) {
        Ok(()) => {
            assert!(valid, "tcId {tc_id}: an invalid vector decrypted and verified anyway");
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

#[test]
fn wycheproof_sm4_gcm_known_answer_tests() {
    let Some(doc) = wycheproof_json("sm4_gcm_test.json") else { return };
    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some("SM4-GCM"));

    let groups = doc.get("testGroups").and_then(Value::as_array).expect("testGroups");

    let mut run = 0usize;
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;
    let mut unsupported_cases = 0usize;

    // A case is dispatched on its actual `iv` length, since the nonce length is fixed by the type.
    for group in groups {
        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let key_bytes = hex_field(test, "key", tc_id);
            let iv_bytes = hex_field(test, "iv", tc_id);
            let aad = hex_field(test, "aad", tc_id);
            let msg = hex_field(test, "msg", tc_id);
            let ct = hex_field(test, "ct", tc_id);
            let tag = hex_field(test, "tag", tc_id);
            let valid = match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => true,
                "invalid" => false,
                other => panic!("tcId {tc_id}: unexpected result {other}"),
            };

            let iv = <[u8; GCM_NONCE_LEN]>::try_from(iv_bytes.as_slice());
            match iv {
                Ok(iv) if key_bytes.len() == KEY_LEN && tag.len() == TAG_LEN => {
                    run_case(tc_id, &key_bytes, iv, &aad, &msg, &ct, &tag, valid);
                    run += 1;
                    if valid { valid_count += 1 } else { invalid_count += 1 }
                }
                _ => unsupported_cases += 1,
            }
        }
    }

    println!(
        "Wycheproof SM4-GCM: {run} cases run ({valid_count} valid, {invalid_count} invalid), \
         {unsupported_cases} cases not supported (no 96-bit-IV instantiation)"
    );

    // Guards against a silently-vacuous run, as the AES suite does.
    assert!(run > 0, "expected the 96-bit-IV groups to be dispatchable");
    assert!(valid_count > 0, "expected at least some valid cases to be run");
    assert!(invalid_count > 0, "expected at least some invalid (tag-failure) cases to be run");
    assert!(unsupported_cases > 0, "expected the other-IV-length cases to be outside Gcm's shape");
}
