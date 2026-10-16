//! RFC vectors live in the sibling bc-test-data repository, never in the crate package.
//! Set BC_TEST_DATA to override that repository's root. Missing default data is reported and
//! skipped, following the other crypto integration suites; an explicit override must exist.
use bouncycastle_chacha20::ChaCha20;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use serde_json::Value;
use std::{fs, path::PathBuf};

#[test]
fn rfc8439_blocks_encryption_and_one_time_keys() {
    let override_root = std::env::var_os("BC_TEST_DATA");
    let root = override_root
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../bc-test-data"));
    let path = root.join("crypto/rfc8439/chacha20.json");
    if !path.exists() && override_root.is_none() {
        eprintln!("WARNING: {} not found; RFC 8439 ChaCha20 vectors skipped", path.display());
        return;
    }
    let document: Value =
        serde_json::from_str(&fs::read_to_string(&path).expect("RFC vector file")).unwrap();
    let cases = document["tests"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        let decode = |field: &str| bouncycastle_hex::decode(case[field].as_str().unwrap()).unwrap();
        let id = case["id"].as_str().unwrap();
        let mut key = KeyMaterial::<32>::new();
        do_hazardous_operations(&mut key, |key| {
            key.set_bytes_as_type(&decode("key"), KeyType::SymmetricCipherKey)?;
            key.set_security_strength(SecurityStrength::_256bit)
        })
        .unwrap();
        let nonce: [u8; 12] = decode("nonce").try_into().unwrap();
        let counter = u32::try_from(case["counter"].as_u64().unwrap()).unwrap();
        let message = decode("msg");
        let expected = decode("output");
        for chunk in [1, 3, 16, 63, 64, 65, 127, 512] {
            let mut actual = message.clone();
            let mut cipher = ChaCha20::new(&key, &nonce, counter).unwrap();
            for bytes in actual.chunks_mut(chunk) {
                cipher.apply_keystream(bytes).unwrap();
                cipher.apply_keystream(&mut []).unwrap();
            }
            assert_eq!(actual, expected, "RFC {id}, chunk {chunk}");
            ChaCha20::new(&key, &nonce, counter).unwrap().apply_keystream(&mut actual).unwrap();
            assert_eq!(actual, message, "RFC {id} decryption");
        }
    }
    println!("RFC 8439 ChaCha20: {} vectors passed", cases.len());
}
