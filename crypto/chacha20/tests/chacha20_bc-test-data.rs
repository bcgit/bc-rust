//! RFC vectors live in the sibling bc-test-data repository, never in the crate package.
use bouncycastle_chacha20::ChaCha20;
use bouncycastle_chacha20::hazmat::{ChaCha20KeyState, ChaCha20KeyStream};
use bouncycastle_cipher::Encrypting;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::StreamCipherEncryptor;
use bouncycastle_core_test_framework::test_data_loaders::bc_test_data_json;

#[test]
fn rfc8439_blocks_encryption_and_one_time_keys() {
    let Some(document) = bc_test_data_json("crypto/rfc8439", "chacha20.json") else { return };
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
        let state = ChaCha20KeyState::new(&key).unwrap();
        let nonce: [u8; 12] = decode("nonce").try_into().unwrap();
        let counter = u32::try_from(case["counter"].as_u64().unwrap()).unwrap();
        let message = decode("msg");
        let expected = decode("output");
        for chunk in [1, 3, 16, 63, 64, 65, 127, 512] {
            let mut actual = message.clone();
            let mut cipher = at(&state, &nonce, counter);
            for bytes in actual.chunks_mut(chunk) {
                cipher.do_encrypt_inplace(bytes).unwrap();
                cipher.do_encrypt_inplace(&mut []).unwrap();
            }
            assert_eq!(actual, expected, "RFC {id}, chunk {chunk}");
            at(&state, &nonce, counter).do_encrypt_inplace(&mut actual).unwrap();
            assert_eq!(actual, message, "RFC {id} decryption");
        }
    }
    println!("RFC 8439 ChaCha20: {} vectors passed", cases.len());
}

/// The RFC's vectors start at counters other than 0, which only the hazmat keystream takes.
fn at<'k>(state: &'k ChaCha20KeyState, nonce: &[u8; 12], counter: u32) -> ChaCha20<'k, Encrypting> {
    ChaCha20::from_keystream(ChaCha20KeyStream::start_at(state, nonce, counter))
}
