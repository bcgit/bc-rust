//! Generic behaviour tests for the symmetric cipher traits.

use crate::{DUMMY_SEED, FixedSeedRNG};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::{
    AEADCipher, BlockCipherDecryptor, BlockCipherEncryptor, SecurityStrength, StreamCipher,
    SymmetricCipher,
};

/// Instance of the test framework.
pub struct TestFrameworkSymmetricCipher {
    // Put any config options here
}

impl TestFrameworkSymmetricCipher {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait SymmetricCipher against the given input-output pair.
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
            &DUMMY_SEED[..KEY_LEN],
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
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match C::encrypt_out(&mac_key, msg, &mut ct) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };

        // error case: security strengths too weak and too strong
        let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            // Tag the key at an arbitrary strength for the purpose of this test. Inside a
            // do_hazardous_operations() closure, set_security_strength() raises the strength
            // (and bypasses the key-length guard) without complaining.
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();

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

/// Instance of the test framework.
pub struct TestFrameworkBlockCipher {
    // Put any config options here
}

impl TestFrameworkBlockCipher {
    ///
    pub fn new() -> Self {
        Self {}
    }

    ///
    pub fn test<
        const KEY_LEN: usize,
        const INIT_DATA_LEN: usize,
        const BLOCK_LEN: usize,
        E: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
        D: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    >(
        &self,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();

        // to test blocks, we'll chunk our dummy seed
        let (mut encryptor, iv) = E::do_encrypt_init(&key).unwrap();
        let mut decryptor = D::do_decrypt_init(&key, &iv).unwrap();

        // one block at a time, through the flat streaming methods (LEN = BLOCK_LEN), in place
        for msg_chunk in DUMMY_SEED.as_chunks::<BLOCK_LEN>().0.iter() {
            let mut buf = *msg_chunk;
            encryptor.do_encrypt(&mut buf).unwrap();
            decryptor.do_decrypt(&mut buf).unwrap();
            assert_eq!(msg_chunk, &buf);
        }

        // multi-block (N = 2) through the implementor hook `do_*_blocks`: blocks encrypted together
        // must decrypt both together and one at a time, and blocks encrypted one at a time must
        // decrypt together.
        let (mut encryptor, iv) = E::do_encrypt_init(&key).unwrap();
        let mut decryptor = D::do_decrypt_init(&key, &iv).unwrap();

        for msg_pair in DUMMY_SEED.as_chunks::<BLOCK_LEN>().0.as_chunks::<2>().0.iter() {
            // encrypt together, decrypt together
            let mut buf = *msg_pair;
            encryptor.do_encrypt_blocks(&mut buf).unwrap();
            decryptor.do_decrypt_blocks(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);

            // encrypt together, decrypt one at a time
            let mut buf = *msg_pair;
            encryptor.do_encrypt_blocks(&mut buf).unwrap();
            for (msg_chunk, block) in msg_pair.iter().zip(buf.iter_mut()) {
                decryptor.do_decrypt(block).unwrap();
                assert_eq!(msg_chunk, block);
            }

            // encrypt one at a time, decrypt together
            let mut buf = *msg_pair;
            for block in buf.iter_mut() {
                encryptor.do_encrypt(block).unwrap();
            }
            decryptor.do_decrypt_blocks(&mut buf).unwrap();
            assert_eq!(msg_pair, &buf);
        }

        // one-shot API: a block-aligned byte array, in place. It must round-trip and agree with the
        // streaming API for the same key and init data. Only LEN = BLOCK_LEN can be formed
        // generically here (`2 * BLOCK_LEN` needs generic_const_exprs); multi-block one-shots are
        // covered by the modes crate's tests with a concrete BLOCK_LEN.
        let one_block: &[u8; BLOCK_LEN] = &DUMMY_SEED.as_chunks::<BLOCK_LEN>().0[0];
        let mut buf = *one_block;
        let iv = E::encrypt(&key, &mut buf).unwrap();
        let ct = buf;
        D::decrypt(&key, &iv, &mut buf).unwrap();
        assert_eq!(buf, *one_block);
        // ...and it must agree with the streaming API under the same init data.
        let mut streamed = D::do_decrypt_init(&key, &iv).unwrap();
        let mut buf = ct;
        streamed.do_decrypt(&mut buf).unwrap();
        assert_eq!(buf, *one_block);

        // the RNG-taking one-shot must give the streaming API's answer for the same RNG stream
        let pinned = [0xA5u8; INIT_DATA_LEN];
        let mut expected = *one_block;
        let (mut streamed, iv_streamed) =
            E::do_encrypt_init_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned)).unwrap();
        streamed.do_encrypt(&mut expected).unwrap();
        let mut buf = *one_block;
        let iv = E::encrypt_rng(&key, &mut FixedSeedRNG::<INIT_DATA_LEN>::new(pinned), &mut buf)
            .unwrap();
        assert_eq!(iv, iv_streamed);
        assert_eq!(buf, expected);

        // test that the iv is random (ie not the same on two runs)
        let (_encryptor, iv1) = E::do_encrypt_init(&key).unwrap();
        let (_encryptor, iv2) = E::do_encrypt_init(&key).unwrap();
        assert_ne!(iv1, iv2);

        // error case: KeyMaterial of wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match E::do_encrypt_init(&mac_key) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };

        // error case: security strengths too weak and too strong
        let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            // `set_security_strength` enforces its key-length guard even inside a
            // do_hazardous_operations() closure -- a KEY_LEN-byte key cannot be tagged at a
            // strength above `from_bytes(KEY_LEN)` -- so skip the strengths this key cannot carry
            // rather than unwrapping an error. (A 16-byte key can reach 128-bit and no higher.)
            // Do NOT "fix" this by relaxing that guard in `KeyMaterial`: core's
            // `test_hazardous_ops_error_handling` requires it to stay enforced.
            if ss > &SecurityStrength::from_bytes(KEY_LEN) {
                continue;
            }

            // Tag the key at an arbitrary strength for the purpose of this test.
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();

            match E::do_encrypt_init(&key) {
                Ok(_) => {
                    if ss >= &E::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < &E::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should not have accepted a key weaker than algorithm");
                    }
                }
                _ => panic!("Unexpected error"),
            };
        }
    }
}

/// Instance of the test framework.
pub struct TestFrameworkAEADCipher {
    // Put any config options here
}

impl TestFrameworkAEADCipher {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait AEADCipher against the given input-output pair.
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
            &DUMMY_SEED[..KEY_LEN],
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

        // Modifying the ciphertext MUST cause an AEAD failure: unlike an unauthenticated cipher,
        // a conformant AEAD must never return plaintext for a ciphertext that fails its tag check.
        ct[17] ^= 0xFF;
        match C::aead_decrypt_out(&key, &nonce, aad, &ct[..ct_bytes_written], &tag, &mut pt) {
            Err(SymmetricCipherError::AEADTagCheckFailed) => { /* good */ }
            Err(SymmetricCipherError::DecryptionFailed) => { /* also acceptable */ }
            _ => panic!("Modified ciphertext must fail the AEAD tag check"),
        };
        // restore the ciphertext so the AAD- and tag-tamper checks below each test one variable
        ct[17] ^= 0xFF;

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
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match C::aead_encrypt_out(&mac_key, aad, msg, &mut ct) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };

        // error case: security strengths too weak and too strong
        let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            // Tag the key at an arbitrary strength for the purpose of this test. Inside a
            // do_hazardous_operations() closure, set_security_strength() raises the strength
            // (and bypasses the key-length guard) without complaining.
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();

            // The key-strength requirement must be enforced both by the AEAD one-shot and by the
            // inherited SymmetricCipher one-shot (encrypt_out), so exercise both.
            let check_strength = |result: Result<(), SymmetricCipherError>| match result {
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
            check_strength(C::aead_encrypt_out(&key, aad, msg, &mut ct).map(|_| ()));
            check_strength(C::encrypt_out(&key, msg, &mut ct).map(|_| ()));
        }
    }
}

/// Instance of the test framework.
pub struct TestFrameworkStreamCipher {
    // Put any config options here
}

impl TestFrameworkStreamCipher {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait StreamCipher against the given input-output pair.
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
