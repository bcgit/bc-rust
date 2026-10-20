//! Uses the sibling Wycheproof checkout.
//! No JSON vectors are embedded or packaged with this crate. Unsupported nonce/tag sizes
//! cannot be passed to the fixed-array API; those cases are counted and reported separately.
mod common;

use bouncycastle_chacha20_poly1305_aead::ChaCha20_Poly1305;
use bouncycastle_cipher::Decrypting;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::traits::{AEADCipherDecryptor, SymmetricCipherDecryptor};
use bouncycastle_core_test_framework::test_data_loaders::wycheproof_json;

type Dec = ChaCha20_Poly1305<Decrypting>;

#[test]
fn wycheproof_chacha20_poly1305() {
    let Some(doc) = wycheproof_json("chacha20_poly1305_test.json") else {
        return;
    };
    assert_eq!(doc["algorithm"], "CHACHA20-POLY1305");
    let mut valid = 0;
    let mut invalid = 0;
    let mut unsupported = 0;
    for group in doc["testGroups"].as_array().unwrap() {
        for case in group["tests"].as_array().unwrap() {
            let id = &case["tcId"];
            let valid_case = match case["result"].as_str().unwrap() {
                "valid" => true,
                "invalid" => false,
                other => panic!("tcId {id}: unexpected result {other}"),
            };
            let key_bytes = common::decode(case, "key");
            let nonce = common::decode(case, "iv");
            let tag = common::decode(case, "tag");
            if key_bytes.len() != 32 || nonce.len() != 12 || tag.len() != 16 {
                assert!(!valid_case, "tcId {id}: unsupported parameters on a valid case");
                unsupported += 1;
                continue;
            }
            let key = common::key(&key_bytes);
            let nonce = nonce.try_into().unwrap();
            let tag = tag.try_into().unwrap();
            let aad = common::decode(case, "aad");
            let msg = common::decode(case, "msg");
            let ct = common::decode(case, "ct");
            if valid_case {
                common::check_valid(&key, &nonce, &aad, &msg, &ct, &tag, &[1, 17, 65]);
                valid += 1;
            } else {
                let mut out = vec![0xa5; ct.len()];
                assert_eq!(
                    Dec::decrypt_detached_out(&key, &nonce, &aad, &ct, &tag, &mut out),
                    Err(SymmetricCipherError::AEADTagCheckFailed),
                    "tcId {id}"
                );
                // The core default zeroizes the whole output buffer on entry, and leaves it so
                // when the tag fails.
                assert!(out.iter().all(|&b| b == 0), "tcId {id}");
                let mut inline = ct.clone();
                inline.extend_from_slice(&tag);
                assert_eq!(
                    Dec::decrypt_with_aad_out(&key, &nonce, &aad, &inline, &mut out),
                    Err(SymmetricCipherError::AEADTagCheckFailed),
                    "tcId {id}"
                );
                assert!(out.iter().all(|&b| b == 0), "tcId {id}");

                // The detached final-output buffer is also erased on authentication failure.
                let mut dec = Dec::do_decrypt_init(&key, &nonce).unwrap();
                dec.do_update_aad(&aad).unwrap();
                dec.do_decrypt_out(&ct, &mut out).unwrap();
                let mut last = [0xa5; 16];
                assert_eq!(
                    dec.do_decrypt_final_detached_out(&tag, &mut last),
                    Err(SymmetricCipherError::AEADTagCheckFailed)
                );
                assert_eq!(last, [0; 16]);
                invalid += 1;
            }
        }
    }
    assert_eq!(valid + invalid + unsupported, doc["numberOfTests"].as_u64().unwrap());
    assert!(valid > 0 && invalid > 0);
    println!(
        "Wycheproof: {valid} valid and {invalid} invalid cases passed; {unsupported} cases excluded by fixed nonce/tag sizes"
    );
}
