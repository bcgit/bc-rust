#[cfg(test)]
mod tests {
    use bouncycastle_core_interface::errors::{KeyMaterialError, RNGError};
    use bouncycastle_core_interface::key_material::{
        KeyMaterial0, KeyMaterial256, KeyMaterialInternal, KeyType,
    };
    use bouncycastle_core_interface::traits::{KeyMaterial, RNG, SecurityStrength};
    use bouncycastle_core_test_framework::DUMMY_SEED_512;
    use bouncycastle_rng::Sp80090ADrbg;
    use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512};

    #[test]
    fn basic_test() {
        // SHA256
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = [0u8; 32];
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        let mut rng = HashDRBG_SHA256::default();
        let mut out = [0u8; 32];
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        let mut rng = HashDRBG_SHA256::new();
        let mut out = [0u8; 32];
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        // SHA512
        let mut rng = HashDRBG_SHA512::new_from_os();
        let mut out = [0u8; 32];
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        let mut rng = HashDRBG_SHA512::default();
        let mut out = [0u8; 32];
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        let mut rng = HashDRBG_SHA512::new();
        let mut out = [0u8; 32];
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn test_init() {
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let mut out = [0u8; 32];
        match rng.generate_out(&[], &mut out) {
            Err(RNGError::Uninitialized) => { /* good */ }
            _ => panic!("Expected Uninitialized error"),
        }
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        // Success case: seed len equals required entropy
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let mut out = [0u8; 32];
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        // Error case: seed != KeyType::Seed
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::SymmetricCipherKey)
                .unwrap();
        match rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit) {
            Err(RNGError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Error case: seed too short
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..8], KeyType::Seed).unwrap();
        match rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit) {
            Err(RNGError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings, because they're in the gigabyte range and that'll blow up the test suite.

        // Error case: security strength requested at init is higher than the underlying hash function's max security strength
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
        match rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_256bit) {
            Err(RNGError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Success case: security strength requested at init is lower than the underlying hash function's max security strength
        // ... 112 bit
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
        // ... 128 bit
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();

        // Error case: double initialize
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
        match rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit) {
            Err(RNGError::GenericError(_)) => { /*good*/ }
            _ => panic!("Expected GenericError error"),
        }
    }

    #[test]
    fn test_reseed() {
        // Basic success case
        let mut rng = HashDRBG_SHA256::new_from_os();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
        rng.reseed(&seed, &[0u8; 32]).unwrap();

        // Success case: seed len equals required entropy
        let mut rng = HashDRBG_SHA256::new_from_os();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::Seed).unwrap();
        rng.reseed(&seed, &[0u8; 32]).unwrap();

        // Error case: uninitialized
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();
        match rng.reseed(&seed, &[0u8; 32]) {
            Err(RNGError::Uninitialized) => { /*good*/ }
            _ => panic!("Expected Uninitialized error"),
        }

        // Error case: seed != KeyType::Seed
        let mut rng = HashDRBG_SHA256::new_from_os();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::SymmetricCipherKey)
                .unwrap();
        match rng.reseed(&seed, &[0u8; 32]) {
            Err(RNGError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Error case: seed too short
        let mut rng = HashDRBG_SHA256::new();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..8], KeyType::Seed).unwrap();
        match rng.reseed(&seed, &[0u8; 32]) {
            Err(RNGError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings, because they're in the gigabyte range and that'll blow up the test suite.
    }

    #[test]
    fn test_generate() {
        // Basic success case
        let mut rng = HashDRBG_SHA256::new_from_os();
        let out = rng.generate(&[], 32).unwrap();
        assert_eq!(out.len(), 32);
        assert_ne!(out, [0u8; 32]);

        // Success case: request zero-length output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let out = rng.generate(&[], 0).unwrap();
        assert_eq!(out.len(), 0);
        assert_eq!(out, []);

        // Success case: one-byte output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let out = rng.generate(&[], 1).unwrap();
        assert_eq!(out.len(), 1);

        // Success case: more than a block of output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let out = rng.generate(&[], 1024).unwrap();
        assert_eq!(out.len(), 1024);
        assert_ne!(out, [0u8; 1024]);

        // Error case: uninitialized
        let mut rng = HashDRBG_SHA256::new_unititialized();
        match rng.generate(&[], 32) {
            Err(RNGError::Uninitialized) => { /*good*/ }
            _ => panic!("Expected Uninitialized error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings, because they're in the gigabyte range and that'll blow up the test suite.

        // TODO: tests for ReseedRequired. How do I trigger this? The limits are in the exobyte range.
    }

    #[test]
    fn test_generate_out() {
        // Basic success case
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = [0u8; 32];
        let bytes_written = rng.generate_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 32);
        assert_ne!(out, [0u8; 32]);

        // Success case: request zero-length output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = [0u8; 0];
        let bytes_written = rng.generate_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 0);
        assert_eq!(out, []);

        // Success case: one-byte output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = [0u8; 1];
        let bytes_written = rng.generate_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 1);
        assert_eq!(out.len(), 1);

        // Success case: more than a block of output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = [0u8; 1024];
        let bytes_written = rng.generate_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 1024);
        assert_eq!(out.len(), 1024);
        assert_ne!(out, [0u8; 1024]);

        // Error case: uninitialized
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let mut out = [0u8; 32];
        match rng.generate_out(&[], &mut out) {
            Err(RNGError::Uninitialized) => { /*good*/ }
            _ => panic!("Expected Uninitialized error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings, because they're in the gigabyte range and that'll blow up the test suite.

        // TODO: tests for ReseedRequired. How do I trigger this? The limits are in the exobyte range.
    }

    #[test]
    fn test_generate_keymaterial() {
        // Basic success case -- exactly a block of output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = KeyMaterial256::new();
        let bytes_written = rng.generate_keymaterial_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 32);
        assert_ne!(out.ref_to_bytes(), [0u8; 32]);
        assert_eq!(out.security_strength(), SecurityStrength::_128bit);

        // Success case: request zero-length output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = KeyMaterial0::new();
        let bytes_written = rng.generate_keymaterial_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 0);
        assert_eq!(out.ref_to_bytes(), []);
        assert_eq!(out.security_strength(), SecurityStrength::None);

        // Success case: one-byte output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = KeyMaterialInternal::<1>::new();
        let bytes_written = rng.generate_keymaterial_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 1);
        assert_eq!(out.key_len(), 1);
        assert_eq!(out.security_strength(), SecurityStrength::None);

        // Success case: more than a block of output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = KeyMaterialInternal::<1024>::new();
        let bytes_written = rng.generate_keymaterial_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 1024);
        assert_eq!(out.key_len(), 1024);
        assert_ne!(out.ref_to_bytes(), [0u8; 1024]);
        assert_eq!(out.security_strength(), SecurityStrength::_128bit);

        // // Error case: uninitialized
        let mut rng = HashDRBG_SHA256::new_unititialized();
        let mut out = KeyMaterial256::new();
        match rng.generate_keymaterial_out(&[], &mut out) {
            Err(RNGError::Uninitialized) => { /*good*/ }
            _ => panic!("Expected Uninitialized error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings, because they're in the gigabyte range and that'll blow up the test suite.

        // TODO: tests for ReseedRequired. How do I trigger this? The limits are in the exobyte range.
    }

    #[test]
    fn test_rng_trait() {
        let mut rng = HashDRBG_SHA256::new_from_os();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::Seed).unwrap();

        /* test add_seed_keymaterial */
        rng.add_seed_keymaterial(seed).unwrap();

        /* test next_int */
        let out1: u32 = rng.next_int().unwrap();
        let out2: u32 = rng.next_int().unwrap();
        let out3: u32 = rng.next_int().unwrap();
        // Note: this will fail with some absurdly small probability if the RNG is truly random.
        assert!(out1 != out2 && out2 != out3);

        /* test next_bytes */
        let out = rng.next_bytes(32).unwrap();
        assert_eq!(out.len(), 32);
        assert_ne!(out, [0u8; 32]);

        /* test next_bytes_out */
        let mut out = [0u8; 32];
        let bytes_written = rng.next_bytes_out(&mut out).unwrap();
        assert_eq!(bytes_written, 32);
        assert_ne!(out, [0u8; 32]);

        /* test fill_keymaterial */
        let mut key = KeyMaterial256::new();
        rng.fill_keymaterial_out(&mut key).unwrap();
        assert_eq!(key.key_len(), 32);
        assert_ne!(key.ref_to_bytes(), [0u8; 32]);
        assert_eq!(key.security_strength(), rng.security_strength());
    }
}
