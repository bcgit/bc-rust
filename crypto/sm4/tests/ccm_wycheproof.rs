//! Known-answer tests against Project Wycheproof's `testvectors_v1/sm4_ccm_test.json`, through
//! the `CCM<N, T>` hazmat mode traits over `SM4Internal`.
//!
//! The same suite as `crypto/aes/tests/ccm_wycheproof.rs` at SM4's one key length; see that file
//! for what the set probes and why most of its groups have no instantiation to dispatch to (the
//! mode's `NONCE_LEN` is `7..=13` bytes and its `TAG_LEN` one of `4, 6, .., 16`). The key carries
//! no AEAD role, so the cases run over the permutation directly, as `rfc8998_tests.rs` does.
//! Requires the Wycheproof repository at `../wycheproof`; absent, the test warns and passes.

use bouncycastle_cipher::modes::CCM;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, ElectronicCodeBook, do_hazardous_operations,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core_test_framework::test_data_loaders::{Value, hex_field, wycheproof_json};
use bouncycastle_sm4::KEY_LEN;
use bouncycastle_sm4::hazmat::SM4Internal;

/// Wraps the vector's raw key bytes, promoting them if `KeyMaterial`'s entropy heuristic declined
/// to call them a cipher key.
fn permutation(bytes: &[u8]) -> SM4Internal {
    let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("wycheproof key bytes fit the buffer");
    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(KEY_LEN))
        })
        .expect("promoting a wycheproof test key");
    }
    <SM4Internal as ElectronicCodeBook<KEY_LEN, 16>>::new(&key).expect("a wycheproof key")
}

/// Runs one case at a fully-instantiated `(NONCE_LEN, TAG_LEN)`. A valid case must encrypt to
/// exactly `expected_ct`/`expected_tag` and decrypt back; an invalid one is checked on the
/// decrypt direction only and must fail the tag check with the buffer zeroized.
#[allow(clippy::too_many_arguments)]
fn run_case<const NONCE_LEN: usize, const TAG_LEN: usize>(
    tc_id: u64,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) {
    type Mode<const N: usize, const T: usize> = CCM<N, T>;
    let perm = permutation(key_bytes);
    let nonce: [u8; NONCE_LEN] =
        nonce_bytes.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad nonce length"));
    let tag: [u8; TAG_LEN] =
        expected_tag.try_into().unwrap_or_else(|_| panic!("tcId {tc_id}: bad tag length"));

    if valid {
        let mut ct = msg.to_vec();
        let got_tag = <Mode<NONCE_LEN, TAG_LEN> as AeadDeclaredEncryptMode<
            SM4Internal,
            KEY_LEN,
            NONCE_LEN,
            TAG_LEN,
            TAG_LEN,
        >>::encrypt_detached_in_place_nonce(&perm, &nonce, aad, &mut ct)
        .unwrap_or_else(|e| panic!("tcId {tc_id}: valid case failed to encrypt: {e:?}"));
        assert_eq!(ct, expected_ct, "tcId {tc_id}: ciphertext mismatch");
        assert_eq!(got_tag, tag, "tcId {tc_id}: tag mismatch");
    }

    let mut plaintext = expected_ct.to_vec();
    match <Mode<NONCE_LEN, TAG_LEN> as AeadDeclaredDecryptMode<
        SM4Internal,
        KEY_LEN,
        NONCE_LEN,
        TAG_LEN,
        TAG_LEN,
    >>::decrypt_detached_in_place(&perm, &nonce, aad, &mut plaintext, &tag)
    {
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
        Err(e) => panic!("tcId {tc_id}: unexpected CCM error: {e:?}"),
    }
}

/// Dispatches to one of the 7 (nonce) x 7 (tag) instantiations, or reports that the case's sizes
/// have none.
#[allow(clippy::too_many_arguments)]
fn dispatch(
    tc_id: u64,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    aad: &[u8],
    msg: &[u8],
    expected_ct: &[u8],
    expected_tag: &[u8],
    valid: bool,
) -> bool {
    if key_bytes.len() != KEY_LEN {
        return false;
    }
    macro_rules! with_tag_len {
        ($n:literal) => {
            match expected_tag.len() {
                4 => run_case::<$n, 4>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                6 => run_case::<$n, 6>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                8 => run_case::<$n, 8>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                10 => run_case::<$n, 10>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                12 => run_case::<$n, 12>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                14 => run_case::<$n, 14>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                16 => run_case::<$n, 16>(
                    tc_id, key_bytes, nonce_bytes, aad, msg, expected_ct, expected_tag, valid,
                ),
                _ => return false,
            }
        };
    }
    match nonce_bytes.len() {
        7 => with_tag_len!(7),
        8 => with_tag_len!(8),
        9 => with_tag_len!(9),
        10 => with_tag_len!(10),
        11 => with_tag_len!(11),
        12 => with_tag_len!(12),
        13 => with_tag_len!(13),
        _ => return false,
    }
    true
}

#[test]
fn wycheproof_sm4_ccm_known_answer_tests() {
    let Some(doc) = wycheproof_json("sm4_ccm_test.json") else { return };
    assert_eq!(doc.get("algorithm").and_then(Value::as_str), Some("SM4-CCM"));

    let groups = doc.get("testGroups").and_then(Value::as_array).expect("testGroups");

    let mut run = 0usize;
    let mut valid_count = 0usize;
    let mut invalid_count = 0usize;
    let mut unsupported_cases = 0usize;

    // Each case is dispatched on its own field lengths, not the group's declared sizes: a
    // `Pseudorandom` group varies them per test.
    for group in groups {
        for test in group.get("tests").and_then(Value::as_array).expect("tests") {
            let tc_id = test.get("tcId").and_then(Value::as_u64).expect("tcId");
            let key_bytes = hex_field(test, "key", tc_id);
            let nonce_bytes = hex_field(test, "iv", tc_id);
            let aad = hex_field(test, "aad", tc_id);
            let msg = hex_field(test, "msg", tc_id);
            let ct = hex_field(test, "ct", tc_id);
            let tag = hex_field(test, "tag", tc_id);
            let valid = match test.get("result").and_then(Value::as_str).expect("result") {
                "valid" => true,
                "invalid" => false,
                other => panic!("tcId {tc_id}: unexpected result {other}"),
            };

            if dispatch(tc_id, &key_bytes, &nonce_bytes, &aad, &msg, &ct, &tag, valid) {
                run += 1;
                if valid { valid_count += 1 } else { invalid_count += 1 }
            } else {
                unsupported_cases += 1;
            }
        }
    }

    println!(
        "Wycheproof SM4-CCM: {run} cases run ({valid_count} valid, {invalid_count} invalid), \
         {unsupported_cases} cases not supported (no A.1 instantiation)"
    );

    // Guards against a silently-vacuous run, as the AES suite does.
    assert!(run > 0, "expected at least some cases to be within A.1's dispatchable sets");
    assert!(valid_count > 0, "expected at least some valid cases to be run");
    assert!(invalid_count > 0, "expected at least some invalid (tag-failure) cases to be run");
    assert!(
        unsupported_cases > 0,
        "expected some of this adversarial set to be outside A.1's sets"
    );
}
