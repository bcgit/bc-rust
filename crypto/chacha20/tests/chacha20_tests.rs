use bouncycastle_chacha20::{ChaCha20, ChaCha20Decryptor, ChaCha20Encryptor};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core_test_framework::symmetric_ciphers::{
    TestFrameworkStreamCipher, TestFrameworkSymmetricCipher,
};

fn key() -> KeyMaterial<32> {
    KeyMaterial::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap()
}

#[test]
fn core_stream_and_symmetric_contracts() {
    TestFrameworkStreamCipher::new().test::<32, 12, ChaCha20Encryptor, ChaCha20Decryptor>();
    TestFrameworkSymmetricCipher::new()
        .test_encryptor_decryptor::<32, 12, 0, ChaCha20Encryptor, ChaCha20Decryptor>();
}

#[test]
fn counter_exhaustion_is_atomic_and_retains_partial_blocks() {
    for used in [0, 1, 31, 63, 64] {
        let key = key();
        let nonce = [7; 12];
        let mut reference = [0x5a; 64];
        ChaCha20::new(&key, &nonce, u32::MAX).unwrap().apply_keystream(&mut reference).unwrap();
        let mut cipher = ChaCha20::new(&key, &nonce, u32::MAX).unwrap();
        let mut actual = [0x5a; 64];
        cipher.apply_keystream(&mut actual[..used]).unwrap();
        assert_eq!(cipher.remaining_bytes(), (64 - used) as u64);

        let mut too_long = vec![0xa5; 65 - used];
        assert!(matches!(
            cipher.apply_keystream(&mut too_long),
            Err(SymmetricCipherError::StateError(_))
        ));
        assert!(too_long.iter().all(|&b| b == 0xa5));
        assert_eq!(cipher.remaining_bytes(), (64 - used) as u64);
        cipher.apply_keystream(&mut actual[used..]).unwrap();
        assert_eq!(actual, reference);
        assert_eq!(cipher.remaining_bytes(), 0);
        assert_eq!(cipher.apply_keystream(&mut []).unwrap(), 0);
        assert!(cipher.apply_keystream(&mut [0]).is_err());
    }
}

#[test]
fn last_two_blocks_work_in_arbitrary_chunks() {
    let key = key();
    let nonce = [9; 12];
    let mut expected = [0u8; 128];
    ChaCha20::new(&key, &nonce, u32::MAX - 1).unwrap().apply_keystream(&mut expected).unwrap();
    for chunk in [1, 3, 63, 64, 65, 127] {
        let mut cipher = ChaCha20::new(&key, &nonce, u32::MAX - 1).unwrap();
        let mut out = [0u8; 128];
        for bytes in out.chunks_mut(chunk) {
            cipher.apply_keystream(bytes).unwrap();
        }
        assert_eq!(out, expected);
        assert_eq!(cipher.remaining_bytes(), 0);
    }
    assert_eq!(ChaCha20::new(&key, &nonce, 0).unwrap().remaining_bytes(), 1u64 << 38);
}

#[test]
fn key_capacity_does_not_replace_key_length() {
    for len in 0..32 {
        let mut key = key();
        key.set_key_len(len).unwrap();
        assert!(matches!(
            ChaCha20::new(&key, &[0; 12], 0),
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidLength))
        ));
    }
}
