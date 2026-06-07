use crate::{DUMMY_SEED_512, DUMMY_SEED_1024};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    AEADCipher, BlockCipher, SecurityStrength, StreamCipher, SymmetricCipher,
};

pub struct TestFrameworkSymmetricCipher {
    // Put any config options here
}

impl TestFrameworkSymmetricCipher {
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait Hash against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        C: SymmetricCipher<KEY_LEN, INIT_DATA_LEN>,
    >(
        &self,
    ) {
        let msg = b"The quick brown fox jumps over the lazy dog";

        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED_512[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // one-shot API
        let mut ct = [0u8; 1024];
        let (iv, ct_bytes_written) = C::encrypt_out(&key, msg, &mut ct).unwrap();
        assert_ne!(ct_bytes_written, 0);

        let mut pt = [0u8; 1024];
        let pt_bytes_written = C::decrypt_out(&key, iv, &ct[..ct_bytes_written], &mut pt).unwrap();
        assert_ne!(pt_bytes_written, 0);
        assert_eq!(msg, &pt[..pt_bytes_written]);

        // todo -- add tests for encrypt() / decrypt() wrapped in a #[cfg(std)]

        // messing with the ciphertext does not give back the same plaintext (or failing to decrypt is also ok)
        ct[17] ^= 0xFF;
        match C::decrypt_out(&key, iv, &ct[..ct_bytes_written], &mut pt) {
            Ok(bytes_written) => {
                // so it decrypted something, but it had better not match the original plaintext
                assert_eq!(bytes_written, pt_bytes_written);
                assert_ne!(&pt[..bytes_written], msg);
            }
            Err(SymmetricCipherError::DecryptionFailed) => { /* also ok */ }
            _ => panic!("Unexpected error"),
        };

        // error case: KeyMaterial of wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED_512[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match C::encrypt_out(&mac_key, msg, &mut ct) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };

        // error case: security strengths too weak and too strong
        let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED_512[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        key.allow_hazardous_operations();

        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            key.set_security_strength(ss.clone()).unwrap();

            match C::encrypt_out(&key, msg, &mut ct) {
                Ok(_) => {
                    if ss >= &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should not have accepted a key weaker than algorithm");
                    }
                }
                _ => panic!("Unexpected error"),
            };
        }
    }
}

pub struct TestFrameworkBlockCipher {
    // Put any config options here
}

impl TestFrameworkBlockCipher {
    pub fn new() -> Self {
        Self {}
    }

    pub fn test<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        C: BlockCipher<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    >(
        &self,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED_512[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // to test blocks, we'll chunk our dummy seed
        let (mut encryptor, iv) = C::do_encrypt_init(&key).unwrap();
        let mut decryptor = C::do_decrypt_init(&key, &iv).unwrap();

        for msg_chunk in DUMMY_SEED_512.as_chunks::<BLOCK_LEN>().0.iter() {
            let ct = encryptor.do_encrypt_block(msg_chunk).unwrap();
            let pt = decryptor.do_decrypt_block(&ct).unwrap();
            assert_eq!(msg_chunk, &pt);
        }

        // do it again using the _out versions

        let (mut encryptor, iv) = C::do_encrypt_init(&key).unwrap();
        let mut decryptor = C::do_decrypt_init(&key, &iv).unwrap();

        let mut ct = [0u8; BLOCK_LEN];
        let mut pt = [0u8; BLOCK_LEN];
        for msg_chunk in DUMMY_SEED_1024.as_chunks::<BLOCK_LEN>().0.iter() {
            let ct_bytes_written = encryptor.do_encrypt_block_out(msg_chunk, &mut ct).unwrap();
            assert_eq!(ct_bytes_written, BLOCK_LEN);

            let pt_bytes_written = decryptor.do_decrypt_block_out(&ct, &mut pt).unwrap();
            assert_eq!(pt_bytes_written, BLOCK_LEN);

            assert_eq!(msg_chunk, &pt);
        }

        // test that the iv is random (ie not the same on two runs)
        let (_encryptor, iv1) = C::do_encrypt_init(&key).unwrap();
        let (_encryptor, iv2) = C::do_encrypt_init(&key).unwrap();
        assert_ne!(iv1, iv2);

        // error case: KeyMaterial of wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED_512[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match C::do_encrypt_init(&mac_key) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };

        // error case: security strengths too weak and too strong
        let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED_512[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        key.allow_hazardous_operations();

        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            key.set_security_strength(ss.clone()).unwrap();

            match C::do_encrypt_init(&key) {
                Ok(_) => {
                    if ss >= &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should not have accepted a key weaker than algorithm");
                    }
                }
                _ => panic!("Unexpected error"),
            };
        }
    }
}

pub struct TestFrameworkAEADCipher {
    // Put any config options here
}

impl TestFrameworkAEADCipher {
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait Hash against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        C: AEADCipher<KEY_LEN, NONCE_LEN, TAG_LEN>,
    >(
        &self,
    ) {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let aad = b"some associated data";

        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED_512[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // one-shot API
        let mut ct = [0u8; 1024];
        let (nonce, ct_bytes_written, tag) = C::aead_encrypt_out(&key, aad, msg, &mut ct).unwrap();
        if nonce.len() != 0 {
            assert_ne!(nonce, [0u8; NONCE_LEN]);
        }
        assert_ne!(ct_bytes_written, 0);
        assert_ne!(tag, [0u8; TAG_LEN]);

        let mut pt = [0u8; 1024];
        let pt_bytes_written =
            C::aead_decrypt_out(&key, &nonce, aad, &ct[..ct_bytes_written], &tag, &mut pt).unwrap();
        assert_ne!(pt_bytes_written, 0);
        assert_eq!(msg, &pt[..pt_bytes_written]);

        // todo -- add tests for aead_encrypt() / aead_decrypt() wrapped in a #[cfg(std)]

        // messing with the ciphertext does not give back the same plaintext (or failing to decrypt is also ok)
        ct[17] ^= 0xFF;
        match C::aead_decrypt_out(&key, &nonce, aad, &ct[..ct_bytes_written], &tag, &mut pt) {
            Ok(bytes_written) => {
                // so it decrypted something, but it had better not match the original plaintext
                assert_eq!(bytes_written, pt_bytes_written);
                assert_ne!(&pt[..bytes_written], msg);
            }
            Err(SymmetricCipherError::DecryptionFailed) => { /* also ok */ }
            _ => panic!("Unexpected error"),
        };

        // messing with the aad causes the aead_decrypt to fail
        match C::aead_decrypt_out(
            &key,
            &nonce,
            b"not the right associated data",
            &ct[..ct_bytes_written],
            &tag,
            &mut pt,
        ) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            _ => panic!("Expected TagCheckFailed error"),
        };

        // messing with the tag causes the aead_decrypt to fail
        match C::aead_decrypt_out(
            &key,
            &nonce,
            aad,
            &ct[..ct_bytes_written],
            &[3u8; TAG_LEN],
            &mut pt,
        ) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            _ => panic!("Expected TagCheckFailed error"),
        };

        // multiple invocations give different nonces
        let (nonce1, _ct_bytes_written, _tag) =
            C::aead_encrypt_out(&key, aad, msg, &mut ct).unwrap();
        let (nonce2, _ct_bytes_written, _tag) =
            C::aead_encrypt_out(&key, aad, msg, &mut ct).unwrap();
        assert_ne!(nonce1, nonce2);

        // error case: KeyMaterial of wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED_512[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match C::encrypt_out(&mac_key, msg, &mut ct) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };

        // error case: security strengths too weak and too strong
        let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED_512[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        key.allow_hazardous_operations();

        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            key.set_security_strength(ss.clone()).unwrap();

            match C::encrypt_out(&mac_key, msg, &mut ct) {
                Ok(_) => {
                    if ss >= &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < &C::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should not have accepted a key weaker than algorithm");
                    }
                }
                _ => panic!("Unexpected error"),
            };
        }
    }
}

pub struct TestFrameworkStreamCipher {
    // Put any config options here
}

impl TestFrameworkStreamCipher {
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait Hash against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        C: StreamCipher<KEY_LEN, INIT_DATA_LEN>,
    >(
        &self,
    ) {
        todo!()
    }
}
