#[cfg(test)]
mod tests {
    use bouncycastle_core::errors::{KeyMaterialError, RNGError};
    use bouncycastle_core::key_material::{
        KeyMaterial, KeyMaterial0, KeyMaterial256, KeyMaterialTrait, KeyType,
    };
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::RNG;
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_rng::hazmat::NewUninitialized;
    use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512};
    use bouncycastle_rng::{MIN_NONCE_LEN, Sp80090ADrbg};

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
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let mut out = [0u8; 32];
        match rng.generate_out(&[], &mut out) {
            Err(RNGError::Uninitialized) => { /* good */ }
            _ => panic!("Expected Uninitialized error"),
        }
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        // Success case: seed len equals required entropy, with a nonce
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let mut out = [0u8; 32];
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::Seed).unwrap();
        let nonce = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[16..24], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &nonce, &[], SecurityStrength::_128bit).unwrap();
        rng.generate_out(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 32]);

        // Error case: seed != KeyType::Seed
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::SymmetricCipherKey)
                .unwrap();
        match rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit) {
            Err(RNGError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Error case: seed too short, even with a nonce
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..15], KeyType::Seed).unwrap();
        let nonce = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[16..32], KeyType::Seed).unwrap();
        match rng.instantiate(false, seed, &nonce, &[], SecurityStrength::_128bit) {
            Err(RNGError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings
        // because they are on the order of a gigabyte in size.
        // Testing would blow up the test suite.

        // Error case: security strength requested at init is higher than the underlying
        // hash function's max security strength
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        match rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_256bit) {
            Err(RNGError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Success case: security strength requested at init is lower than the underlying
        // hash function's max security strength
        // ... 112 bit
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
        // ... 128 bit
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();

        // Error case: double initialize
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit).unwrap();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        match rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit) {
            Err(RNGError::GenericError(_)) => { /*good*/ }
            _ => panic!("Expected GenericError error"),
        }
    }

    /// SP 800-90A Rev. 1 Section 8.6.1 requires a nonce; Section 9.1 lets its entropy come with
    /// the entropy input instead, which then carries 3/2 of the strength. A nonce shorter than
    /// `MIN_NONCE_LEN` is refused.
    #[test]
    fn a_nonce_or_a_longer_seed_is_required() {
        fn instantiate<D: Sp80090ADrbg + NewUninitialized>(
            seed_len: usize,
            nonce_len: usize,
            strength: SecurityStrength,
        ) -> Result<(), RNGError> {
            let seed =
                KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..seed_len], KeyType::Seed)
                    .unwrap();
            let nonce = KeyMaterial::<64>::from_bytes_as_type(
                &DUMMY_SEED[64 - nonce_len..64],
                KeyType::Seed,
            )
            .unwrap();
            D::new_uninitialized().instantiate(false, seed, &nonce, &[], strength)
        }
        fn refused(r: Result<(), RNGError>) -> bool {
            matches!(r, Err(RNGError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))))
        }
        assert_eq!(MIN_NONCE_LEN, 8);
        for (strength, seed_len) in
            [(SecurityStrength::_112bit, 14), (SecurityStrength::_128bit, 16)]
        {
            let no_nonce_len = seed_len * 3 / 2;
            instantiate::<HashDRBG_SHA256>(seed_len, MIN_NONCE_LEN, strength).unwrap();
            assert!(refused(instantiate::<HashDRBG_SHA256>(seed_len, MIN_NONCE_LEN - 1, strength)));
            assert!(refused(instantiate::<HashDRBG_SHA256>(seed_len, 1, strength)));
            instantiate::<HashDRBG_SHA256>(no_nonce_len, 0, strength).unwrap();
            assert!(refused(instantiate::<HashDRBG_SHA256>(no_nonce_len - 1, 0, strength)));
        }
        for (strength, seed_len) in
            [(SecurityStrength::_192bit, 24), (SecurityStrength::_256bit, 32)]
        {
            let no_nonce_len = seed_len * 3 / 2;
            instantiate::<HashDRBG_SHA512>(seed_len, MIN_NONCE_LEN, strength).unwrap();
            assert!(refused(instantiate::<HashDRBG_SHA512>(seed_len, MIN_NONCE_LEN - 1, strength)));
            instantiate::<HashDRBG_SHA512>(no_nonce_len, 0, strength).unwrap();
            assert!(refused(instantiate::<HashDRBG_SHA512>(no_nonce_len - 1, 0, strength)));
        }
    }

    #[test]
    fn test_reseed() {
        // Basic success case
        let mut rng = HashDRBG_SHA256::new_from_os();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        rng.reseed(&seed, &[0u8; 32]).unwrap();

        // Success case: seed len equals required entropy
        let mut rng = HashDRBG_SHA256::new_from_os();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::Seed).unwrap();
        rng.reseed(&seed, &[0u8; 32]).unwrap();

        // Error case: uninitialized
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        match rng.reseed(&seed, &[0u8; 32]) {
            Err(RNGError::Uninitialized) => { /*good*/ }
            _ => panic!("Expected Uninitialized error"),
        }

        // Error case: seed != KeyType::Seed
        let mut rng = HashDRBG_SHA256::new_from_os();
        let seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::SymmetricCipherKey)
                .unwrap();
        match rng.reseed(&seed, &[0u8; 32]) {
            Err(RNGError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Error case: seed too short
        let mut rng = HashDRBG_SHA256::new();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..8], KeyType::Seed).unwrap();
        match rng.reseed(&seed, &[0u8; 32]) {
            Err(RNGError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings
        // because they are on the order of a gigabyte in size.
        // Testing would blow up the test suite.
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
        assert_eq!(out, [0u8; 0]);

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
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        match rng.generate(&[], 32) {
            Err(RNGError::Uninitialized) => { /*good*/ }
            _ => panic!("Expected Uninitialized error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings
        // because they are on the order of a gigabyte in size.
        // Testing would blow up the test suite.

        // TODO: Tests for ReseedRequired. Investigate how this gets triggered. The limits are in the exobyte range.
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
        assert_eq!(out, [0u8; 0]);

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
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let mut out = [0u8; 32];
        match rng.generate_out(&[], &mut out) {
            Err(RNGError::Uninitialized) => { /*good*/ }
            _ => panic!("Expected Uninitialized error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings
        // because they are on the order of a gigabyte in size.
        // Testing would blow up the test suite.

        // TODO: tests for ReseedRequired. Investigate how this gets triggered. The limits are in the exobyte range.
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
        assert_eq!(out.ref_to_bytes(), [0u8; 0]);
        assert_eq!(out.security_strength(), SecurityStrength::None);

        // Success case: one-byte output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = KeyMaterial::<1>::new();
        let bytes_written = rng.generate_keymaterial_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 1);
        assert_eq!(out.key_len(), 1);
        assert_eq!(out.security_strength(), SecurityStrength::None);

        // Success case: more than a block of output
        let mut rng = HashDRBG_SHA256::new_from_os();
        let mut out = KeyMaterial::<1024>::new();
        let bytes_written = rng.generate_keymaterial_out(&[], &mut out).unwrap();
        assert_eq!(bytes_written, 1024);
        assert_eq!(out.key_len(), 1024);
        assert_ne!(out.ref_to_bytes(), [0u8; 1024]);
        assert_eq!(out.security_strength(), SecurityStrength::_128bit);

        // // Error case: uninitialized
        let mut rng = HashDRBG_SHA256::new_uninitialized();
        let mut out = KeyMaterial256::new();
        match rng.generate_keymaterial_out(&[], &mut out) {
            Err(RNGError::Uninitialized) => { /*good*/ }
            Err(e) => panic!("{:?}", e),
            Ok(_) => panic!("Expected Uninitialized error"),
        }

        // Skipping tests for max lengths of seeds and personalization strings
        // because they are on the order of a gigabyte in size.
        // Testing would blow up the test suite.

        // TODO: tests for ReseedRequired. Investigate how this gets triggered. The limits are in the exobyte range.
    }

    #[test]
    fn test_rng_trait() {
        let mut rng = HashDRBG_SHA256::new_from_os();
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();

        /* test add_seed_keymaterial */
        rng.add_seed_keymaterial(&seed).unwrap();

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

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// The reseed counter is added into V at the end of every generate (Section 10.1.1.4 step 5)
    /// and incremented (step 6); the CAVP files stop at the second generate, whose output does not
    /// yet depend on the increment, so a third generate is pinned here. Expected values are from a
    /// Hash_DRBG written independently in Python from Sections 10.1.1.2-10.1.1.4 and 10.3.1 and
    /// checked against the CAVP no-reseed vectors first; the inputs are those vectors' COUNT 0.
    #[test]
    fn a_third_generate_matches_an_independent_reference() {
        fn third<D: Sp80090ADrbg + NewUninitialized>(
            entropy: &str,
            nonce: &str,
            strength: SecurityStrength,
            len: usize,
        ) -> Vec<u8> {
            let mut drbg = D::new_uninitialized();
            let seed = KeyMaterial::<64>::from_bytes_as_type(&hex(entropy), KeyType::Seed).unwrap();
            let nonce = KeyMaterial::<64>::from_bytes_as_type(&hex(nonce), KeyType::Seed).unwrap();
            drbg.instantiate(false, seed, &nonce, &[], strength).unwrap();
            drbg.generate(&[], len).unwrap();
            drbg.generate(&[], len).unwrap();
            drbg.generate(&[], len).unwrap()
        }
        assert_eq!(
            third::<HashDRBG_SHA256>(
                "a65ad0f345db4e0effe875c3a2e71f42c7129d620ff5c119a9ef55f05185e0fb",
                "8581f9317517276e06e9607ddbcbcc2e",
                SecurityStrength::_128bit,
                128
            ),
            hex(
                "c585885f220a9e616817c24192a6314f2170c6e066b3ebb7be43717a427d3bc36f83390195fe191a990a6926709ec3b59b6a88074dbab83a443ca69061c3e4a645597cd6733e068631b63c731250672134b50898579b17b6a4e9e0f121ec809c46135738e8009fde4f2464a0cd2893c3a1a1c1d96b1b36040271d6e71bb3d430"
            )
        );
        assert_eq!(
            third::<HashDRBG_SHA512>(
                "6b50a7d8f8a55d7a3df8bb40bcc3b722d8708de67fda010b03c4c84d72096f8c",
                "3ec649cc6256d9fa31db7a2904aaf025",
                SecurityStrength::_256bit,
                256
            ),
            hex(
                "356ad18ba9f67f3a5b5f56d9a20731a05f02f13aa1659eb3906d557e825078208c094ce00e403ec150cfdf98cea7825a54274c23e8194f3f400afe492731987b7e37cbe10eccddb32900b93e859a029ac9032e057428de67af2ad84a877776429ef6d325670be177b0ef1c0a15ad2907bd04cf6b910607abbb179e332b74645dc8d117c4d87da5242c2903216d3ada8ec01402144b61f90ed94b838e298c7a314fe9ebacae1a968dda321de4a9ae1681efa0e714d9f94845e2be898738c1d8b6e288f6599dddf3f4bd049b3512a5046e53b0b5e41276fb94ce63e24371cadc43353bf3dedd9e3b72697f6c10210b261945e052f3f0b1a9c533d4082d5414e61c"
            )
        );
    }

    /// Table 2: `max_number_of_bits_per_request` is 2^19 bits, 65536 bytes; one more is refused.
    #[test]
    fn the_per_request_limit_is_enforced() {
        let mut rng = HashDRBG_SHA256::new_from_os();
        assert_eq!(rng.generate(&[], 65536).unwrap().len(), 65536);
        assert!(matches!(rng.generate(&[], 65537), Err(RNGError::GenericError(_))));
        let mut out = vec![0u8; 65537];
        assert!(matches!(rng.generate_out(&[], &mut out), Err(RNGError::GenericError(_))));
    }

    /// `add_seed_keymaterial` is the full reseed of Section 10.1.1.3: two instances from one seed
    /// agree until one is reseeded, and disagree from then on.
    #[test]
    fn reseeding_changes_the_stream() {
        fn instance() -> HashDRBG_SHA256 {
            let mut rng = HashDRBG_SHA256::new_uninitialized();
            let seed =
                KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
            rng.instantiate(false, seed, &KeyMaterial0::new(), &[], SecurityStrength::_128bit)
                .unwrap();
            rng
        }
        let (mut a, mut b) = (instance(), instance());
        assert_eq!(a.next_bytes(32).unwrap(), b.next_bytes(32).unwrap());
        let fresh = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::Seed).unwrap();
        b.add_seed_keymaterial(&fresh).unwrap();
        assert_ne!(a.next_bytes(32).unwrap(), b.next_bytes(32).unwrap());
    }
}
