#[cfg(test)]
mod hkdf_tests {
    use bouncycastle_core_interface::errors::{KDFError, KeyMaterialError, MACError};
    use bouncycastle_core_interface::key_material::{KeyMaterial0, KeyMaterial128, KeyMaterial256, KeyMaterial512, KeyMaterialInternal, KeyType};
    use bouncycastle_core_interface::traits::{HashAlgParams, KeyMaterial, SecurityStrength, KDF};
    use bouncycastle_core_test_framework::DUMMY_SEED_512;
    use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
    use bouncycastle_hex as hex;
    use bouncycastle_hkdf::{HKDF, HKDF_SHA256, HKDF_SHA512};
    use bouncycastle_sha2::{SHA256};
    use bouncycastle_utils::ct;

    #[test]
    fn test_streaming_apis() {
        // setup variables
        let salt = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::MACKey).unwrap();
        let ikm = KeyMaterial256::from_bytes(&DUMMY_SEED_512[16..48]).unwrap();
        let info = &DUMMY_SEED_512[48..64];
        let mut okm = KeyMaterial512::new();
        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, info, 64, &mut okm).unwrap();

        // Test that streaming API do_extract gets the same result
        let mut hkdf = HKDF::<SHA256>::default();
        hkdf.do_extract_init(&salt).unwrap();
        hkdf.do_extract_update_bytes(ikm.ref_to_bytes()).unwrap();
        let prk = hkdf.do_extract_final().unwrap();
        let mut okm2 = KeyMaterial512::new();
        HKDF_SHA256::expand_out(&prk, info, 64, &mut okm2).unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), okm2.ref_to_bytes()));
    }

    #[test]
    fn derive_and_derive_from_multiple() {
        // This test does not use known-answer tests, but instead tests that the various APIs are equivalent
        // to each other as documented.

        // derive_key is equivalent to extract_and_expand() with a zero salt,
        // which is actually equivalent to no salt because of how HMAC pads the key internally.

        // Set up input variables
        let info: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\0xF";

        let zero_key = KeyMaterial0::new();
        let key1 = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::MACKey).unwrap();
        let key2 = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[32..64], KeyType::MACKey).unwrap();
        let key3 = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[64..96], KeyType::MACKey).unwrap();


        /* test case: 0 input keys (ie empty salt and no ikm's) */
        let mut expected_okm = KeyMaterial512::new();
        HKDF_SHA256::extract_and_expand_out(&KeyMaterial256::new(), &KeyMaterial0::new(), info, 32, &mut expected_okm).unwrap();

        let okm1 = HKDF_SHA256::new().derive_key(&zero_key, info).unwrap();
        assert_eq!(okm1.ref_to_bytes(), expected_okm.ref_to_bytes());
        assert!(ct::ct_eq_bytes(okm1.ref_to_bytes(), expected_okm.ref_to_bytes()));

        let keys = [&KeyMaterial0::new(), &KeyMaterial0::new()];
        let okm2 = HKDF_SHA256::new().derive_key_from_multiple(&keys, info).unwrap();
        assert!(ct::ct_eq_bytes(okm2.ref_to_bytes(), expected_okm.ref_to_bytes()));



        /* test case: 1 input ikm key (ie empty salt) */
        // derive_key_from_multiple(&[&KeyMaterial0, &key) is equivalent to derive_key(&key) above
        // which is equivalent to extract_and_expand((&KeyMaterial0::new(), &key, info)
        let mut expected_okm = KeyMaterial512::new();
        HKDF_SHA256::extract_and_expand_out(&KeyMaterial0::new(), &key1, info, 32, &mut expected_okm).unwrap();

        let okm1 = HKDF_SHA256::new().derive_key(&key1, info).unwrap();
        assert!(ct::ct_eq_bytes(okm1.ref_to_bytes(), expected_okm.ref_to_bytes()));

        let keys = [&KeyMaterial256::new(), &key1];
        let okm2 = HKDF_SHA256::new().derive_key_from_multiple(&keys, info).unwrap();
        assert!(ct::ct_eq_bytes(okm2.ref_to_bytes(), expected_okm.ref_to_bytes()));


        /* test case: 1 input keys (salt and no ikm's) */
        let mut expected_okm = KeyMaterial512::new();
        HKDF_SHA256::extract_and_expand_out(&key1, &zero_key, info, 32, &mut expected_okm).unwrap();

        // no way to test this with .derive_key since it hard-codes a zero salt

        let keys = [&key1, &KeyMaterial256::new()];
        let okm2 = HKDF_SHA256::new().derive_key_from_multiple(&keys, info).unwrap();
        assert!(ct::ct_eq_bytes(okm2.ref_to_bytes(), expected_okm.ref_to_bytes()));


        /* test case: 2 input keys (ie salt and one ikm) */
        let mut expected_okm = KeyMaterial512::new();
        HKDF_SHA256::extract_and_expand_out(&key1, &key2, info, 32, &mut expected_okm).unwrap();

        // no way to test this with .derive_key since it hard-codes a zero salt

        let keys = [&key1, &key2];
        let okm2 = HKDF_SHA256::new().derive_key_from_multiple(&keys, info).unwrap();
        assert!(ct::ct_eq_bytes(okm2.ref_to_bytes(), expected_okm.ref_to_bytes()));


        /* test case: 3 input keys (ie salt and two ikm's) */
        let key23 = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[32..96], KeyType::MACKey).unwrap();
        let mut expected_okm = KeyMaterial512::new();
        HKDF_SHA256::extract_and_expand_out(&key1, &key23, info, 32, &mut expected_okm).unwrap();

        // no way to test this with .derive_key since it hard-codes a zero salt

        let keys = [&key1, &key2, &key3];
        let okm2 = HKDF_SHA256::new().derive_key_from_multiple(&keys, info).unwrap();
        assert!(ct::ct_eq_bytes(okm2.ref_to_bytes(), expected_okm.ref_to_bytes()));
    }

    #[test]
    fn test_entropy_tracking() {

        // test the thresholds of HMAC-SHA256
        let key255 = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..31], KeyType::MACKey).unwrap();
        let key256 = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::MACKey).unwrap();
        let key512 = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::MACKey).unwrap();
        let zero_key = KeyMaterial0::new();

        // not enough
        assert_eq!(key255.security_strength(), SecurityStrength::_192bit);
        let mut okm = HKDF_SHA256::extract(&key255, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(okm.security_strength(), SecurityStrength::None);
        _ = HKDF_SHA256::extract_and_expand_out(&key255, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(okm.security_strength(), SecurityStrength::None);

        // too much
        assert_eq!(key512.security_strength(), SecurityStrength::_256bit);
        let mut okm = HKDF_SHA256::extract(&key512, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);
        // should get downgraded to match hash alg
        assert_eq!(okm.security_strength(), SecurityStrength::_128bit);
        _ = HKDF_SHA256::extract_and_expand_out(&key512, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(okm.security_strength(), SecurityStrength::_128bit);

        // just right
        let mut okm = HKDF_SHA256::extract(&key256, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);
        _ = HKDF_SHA256::extract_and_expand_out(&key256, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);


        // test the thresholds of HMAC-SHA512
        let key511 = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..63], KeyType::MACKey).unwrap();
        let key512 = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::MACKey).unwrap();
        let zero_key = KeyMaterial0::new();

        // not enough
        let mut okm = HKDF_SHA512::extract(&key511, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);
        _ = HKDF_SHA512::extract_and_expand_out(&key511, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        // just right
        let mut okm = HKDF_SHA512::extract(&key512, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);
        _ = HKDF_SHA512::extract_and_expand_out(&key512, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);



        // variable setup
        let low_entropy_key = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::BytesLowEntropy).unwrap();
        let mut okm = KeyMaterial256::new();


        // failure case: should complain if low entropy bytes are provided

        // only as salt
        match HKDF_SHA256::extract_and_expand_out(&low_entropy_key, &KeyMaterial0::new(), &[], 32, &mut okm) {
            Ok(_) => { panic!("Should have thrown a KeyMaterialError"); },
            Err(KDFError::MACError(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))) => { /* good */ },
            Err(_) => { panic!("Should have thrown a KeyMaterialError"); }
        };

        let keys = [&low_entropy_key];
        match HKDF_SHA256::new().derive_key_from_multiple(&keys, &[]) {
            Ok(_) => { panic!("Should have thrown a KeyMaterialError"); },
            Err(KDFError::MACError(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))) => { /* good */ },
            Err(_) => { panic!("Should have thrown a KeyMaterialError"); }
        };


        // as both salt and ikm
        match HKDF_SHA256::extract_and_expand_out(&low_entropy_key, &low_entropy_key, &[], 32, &mut okm) {
            Ok(_) => { panic!("Should have thrown a KeyMaterialError"); },
            Err(KDFError::MACError(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))) => { /* good */ },
            Err(_) => { panic!("Should have thrown a KeyMaterialError"); }
        };

        let keys = [&low_entropy_key, &low_entropy_key];
        match HKDF_SHA256::new().derive_key_from_multiple(&keys, &[]) {
            Ok(_) => { panic!("Should have thrown a KeyMaterialError"); },
            Err(KDFError::MACError(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))) => { /* good */ },
            Err(_) => { panic!("Should have thrown a KeyMaterialError"); }
        };



        // zero-length salt is allowed -- zeroized ikm
        _ = HKDF_SHA256::extract_and_expand_out(&KeyMaterial0::new(), &KeyMaterial0::new(), &[], 32, &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        HKDF_SHA256::new().derive_key_out(&KeyMaterial0::new(), &[], &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        let keys = [&KeyMaterial0::new(), &KeyMaterial0::new()];
        HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);


        // zero-length salt is allowed -- low entropy ikm
        _ = HKDF_SHA256::extract_and_expand_out(&KeyMaterial0::new(), &low_entropy_key, &[], 32, &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        HKDF_SHA256::new().derive_key_out(&low_entropy_key, &[], &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        let keys = [&KeyMaterial256::new(), &low_entropy_key];
        HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);



        // salt and ikm are full-entropy, but not enough to seed the HKDF, according to FIPS
        // first, error case; not a MACKey
        let salt = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[..8], KeyType::BytesFullEntropy).unwrap();
        let ikm = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[8..16], KeyType::BytesFullEntropy).unwrap();

        match HKDF_SHA256::extract_and_expand_out(&salt, &ikm, &[], 32, &mut okm) {
            Ok(_) => { panic!("Should have thrown a KeyMaterialError that you didn't give it a MACKey"); },
            Err(KDFError::MACError(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))) => { /* good */ },
            Err(_) => { panic!("Should have thrown a KeyMaterialError that you didn't give it a MACKey"); }
        };

        // derive_key has a different behaviour here, since it hard-codes a zero salt as the HMAC key, which is valid,
        // it will produce output of Keytype::BytesLowEntropy
        _ = HKDF_SHA256::new().derive_key_out(&ikm, &[], &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        let keys = [&salt, &ikm];
        match HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], &mut okm) {
            Ok(_) => { panic!("Should have thrown a KeyMaterialError that you didn't give it a MACKey"); },
            Err(KDFError::MACError(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))) => { /* good */ },
            Err(_) => { panic!("Should have thrown a KeyMaterialError that you didn't give it a MACKey"); }
        };


        // success case -- insufficient entropy returns KeyType::BytesLowEntropy
        let salt = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[..8], KeyType::MACKey).unwrap();
        let ikm = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[8..16], KeyType::BytesFullEntropy).unwrap();

        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        _ = HKDF_SHA256::new().derive_key_out(&salt, &[], &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        let keys = [&salt, &ikm];
        _ = HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);



        // success case -- sufficient entropy returns the highest input key type -- KeyType::BytesFullEntropy
        // Note that FIPS requires it to be seeded to a full internal block (which is, for example 512 bits for SHA256)
        // Note: will still return BytesFullEntropy because that one was first in the inputs.
        let salt = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::MACKey).unwrap();
        let ikm = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[32..64], KeyType::BytesFullEntropy).unwrap();

        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);

        let salt1 = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::MACKey).unwrap();
        _ = HKDF_SHA256::new().derive_key_out(&salt1, &[], &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);

        let keys = [&salt, &ikm];
        _ = HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesFullEntropy);


        // success case -- insufficient entropy due to key types -- KeyType::BytesLowEntropy
        // Note: will still return MACKey because that one was first in the inputs.
        let salt = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::MACKey).unwrap();
        let ikm = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[16..32], KeyType::BytesLowEntropy).unwrap();

        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);

        // no way to test this on derive_out

        let keys = [&salt, &ikm];
        _ = HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], &mut okm);
        assert_eq!(okm.key_type(), KeyType::BytesLowEntropy);


        /* get_entropy */
        // This requires using the stateful streaming API and check the amount of entropy it tracks after each addition.
        let salt16 = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::MACKey).unwrap();
        let salt64 = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::MACKey).unwrap();
        let low_entropy_key16 = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::BytesLowEntropy).unwrap();
        let full_entropy_key16 = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED_512[16..32], KeyType::BytesFullEntropy).unwrap();

        // can't test with a low entropy salt because the salt has to be full entropy or zero.
        // but can test with a zeroized key
        let mut hkdf = HKDF::<SHA256>::new();
        assert_eq!(hkdf.get_entropy(), 0);
        hkdf.do_extract_init(&KeyMaterial0::new()).unwrap();
        assert_eq!(hkdf.get_entropy(), 0);
        assert_eq!(hkdf.is_fully_seeded(), false);

        // test do_extract_init with a full entropy salt
        let mut hkdf = HKDF::<SHA256>::new();
        assert_eq!(hkdf.get_entropy(), 0);
        hkdf.do_extract_init(&salt16).unwrap();
        assert_eq!(hkdf.get_entropy(), 16);
        assert_eq!(hkdf.is_fully_seeded(), false);

        // with enough entropy in the salt.
        let mut hkdf = HKDF::<SHA256>::new();
        assert_eq!(hkdf.get_entropy(), 0);
        hkdf.do_extract_init(&salt64).unwrap();
        assert_eq!(hkdf.get_entropy(), 64);
        assert_eq!(hkdf.is_fully_seeded(), true);

        // building up to full entropy
        let mut hkdf = HKDF::<SHA256>::new();
        assert_eq!(hkdf.get_entropy(), 0);
        hkdf.do_extract_init(&salt16).unwrap();
        assert_eq!(hkdf.get_entropy(), 16);
        assert_eq!(hkdf.is_fully_seeded(), false);
        hkdf.do_extract_update_key(&full_entropy_key16).unwrap();
        assert_eq!(hkdf.get_entropy(), 32);
        assert_eq!(hkdf.is_fully_seeded(), true);
        hkdf.do_extract_update_key(&full_entropy_key16).unwrap();
        assert_eq!(hkdf.get_entropy(), 48);
        assert_eq!(hkdf.is_fully_seeded(), true);
        hkdf.do_extract_update_bytes(low_entropy_key16.ref_to_bytes()).unwrap();
        assert_eq!(hkdf.get_entropy(), 48);
        assert_eq!(hkdf.is_fully_seeded(), true);
    }

    #[test]
    fn test_overcapacity() {
        // test the case of requesting more output than FIPS / RFC allows
        let hash_len = SHA256::OUTPUT_LEN;
        // output limit is 255 * hash_len, which for sha256 is 225*32 = 8160 bytes.

        // success case: large but not over-limit
        let mut mega_huge_key = KeyMaterialInternal::<8100>::new();
        assert!(mega_huge_key.capacity() < 255 * hash_len);
        _ = HKDF_SHA256::extract_and_expand_out(&KeyMaterial0::new(), &KeyMaterial0::new(), &[], 8100, &mut mega_huge_key).unwrap();

        // test exactly the capacity
        let mut mega_huge_key = KeyMaterialInternal::<8160>::new();
        assert_eq!(mega_huge_key.capacity(), 255 * hash_len);
        _ = HKDF_SHA256::extract_and_expand_out(&KeyMaterial0::new(), &KeyMaterial0::new(), &[], 8160, &mut mega_huge_key).unwrap();


        // failure case
        let mut mega_huge_key = KeyMaterialInternal::<8192>::new();
        assert!(mega_huge_key.capacity() > 255 * hash_len);
        match HKDF_SHA256::extract_and_expand_out(&KeyMaterial0::new(), &KeyMaterial0::new(), &[], 8192, &mut mega_huge_key) {
            Ok(_) => { panic!("Should have thrown a KeyMaterialError"); },
            Err(KDFError::InvalidLength(_)) => { /* good */ },
            Err(_) => { panic!("Should have thrown a KeyMaterialError"); }
        };
    }

    #[test]
    fn rfc5869_test_cases() {
        // Test Case 1
        rfc5896_sha256(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            42,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        // Test Case 2
        rfc5896_sha256(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            82,
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );

        // Test Case 3
        rfc5896_sha256(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            42,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
    }

    /*** Helper Functions ***/
    #[allow(non_snake_case)]
    fn rfc5896_sha256(ikm: &str, salt: &str, info: &str, prk: &str, L: usize, okm: &str) {
        /*** First with the one-shot APIs ::extract() and ::expand_out(). ***/

        let mut ikm_key = KeyMaterialInternal::<100>::new();
        ikm_key.allow_hazardous_operations();
        let r = ikm_key.set_bytes_as_type(&hex::decode(ikm).unwrap(), KeyType::BytesFullEntropy); // just for testing, ignore the error about zeroized keys
        if r.is_err() {
            ikm_key.allow_hazardous_operations();
            ikm_key.set_key_type(KeyType::MACKey).unwrap();
        }

        let mut salt_key = KeyMaterialInternal::<100>::new();
        salt_key.allow_hazardous_operations();
        let r = salt_key.set_bytes_as_type(&hex::decode(salt).unwrap(), KeyType::MACKey); // just for testing, ignore the error about zeroized keys
        if r.is_err() {
            salt_key.allow_hazardous_operations();
            ikm_key.set_key_type(KeyType::MACKey).unwrap();
        }

        let info = hex::decode(info).unwrap();
        let mut prk_key = HKDF_SHA256::extract(&salt_key, &ikm_key).unwrap();
        assert_eq!(prk_key.ref_to_bytes(), hex::decode(prk).unwrap());

        // Some of the RFC5896 test vectors have input keys that are too short to meet the entropy seeding rules.
        // So, just for testing, we'll bump this up to full entropy, regardless of what entropy HKDF::extract()
        // thinks it should be based on the inputs.
        prk_key.allow_hazardous_operations();
        prk_key.set_key_type(KeyType::MACKey).unwrap();

        let mut okm_key = KeyMaterialInternal::<100>::new();
        _ = HKDF_SHA256::expand_out(&prk_key, &info, L, &mut okm_key).unwrap();
        okm_key.truncate(L).unwrap();
        assert_eq!(okm_key.ref_to_bytes().len(), L);
        assert_eq!(okm_key.ref_to_bytes(), hex::decode(okm).unwrap());

        /*** with extract_and_expand() ***/
        match HKDF_SHA256::extract_and_expand_out(&salt_key, &ikm_key, &info, L, &mut okm_key) {
            Ok(_) => {
                assert_eq!(okm_key.ref_to_bytes().len(), L);
                assert_eq!(okm_key.ref_to_bytes(), hex::decode(okm).unwrap());
            },
            Err(KDFError::KeyMaterialError(_)) => { /* some of the rfc5896 test vectors are in fact low entropy, so just skip */ },
            Err(_) => panic!("Should have returned a MACError::KeyMaterialError.")
        }

        /*** with the streaming APIs ... do_extract_final() ***/
        let mut hkdf = HKDF_SHA256::new();
        hkdf.do_extract_init(&salt_key).unwrap();
        for chunk in ikm_key.ref_to_bytes().chunks(4) {
            hkdf.do_extract_update_bytes(chunk).unwrap();
        }
        let mut prk_key = hkdf.do_extract_final().unwrap();
        assert_eq!(prk_key.ref_to_bytes(), hex::decode(prk).unwrap());
        HKDF_SHA256::expand_out(&prk_key, &info, L, &mut okm_key).unwrap();
        assert_eq!(okm_key.ref_to_bytes().len(), L);
        assert_eq!(okm_key.ref_to_bytes(), hex::decode(okm).unwrap());

        /*** with the streaming APIs ... do_extract_final_out() ***/

        let mut hkdf = HKDF_SHA256::new();
        hkdf.do_extract_init(&salt_key).unwrap();
        for chunk in ikm_key.ref_to_bytes().chunks(4) {
            hkdf.do_extract_update_bytes(chunk).unwrap();
        }
        let bytes_written = hkdf.do_extract_final_out(&mut prk_key).unwrap();
        assert_eq!(bytes_written, 32);
        assert_eq!(bytes_written, prk_key.ref_to_bytes().len());
        HKDF_SHA256::expand_out(&prk_key, &info, L, &mut okm_key).unwrap();
        assert_eq!(okm_key.ref_to_bytes().len(), L);
        assert_eq!(okm_key.ref_to_bytes(), hex::decode(okm).unwrap());
    }

    #[test]
    fn hkdf_state_tests() {
        // setup
        let key = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::MACKey).unwrap();

        // error case: try to initialize twice
        let mut hkdf = HKDF_SHA256::new();
        hkdf.do_extract_init(&key).unwrap();
        match hkdf.do_extract_init(&KeyMaterial256::new()) {
            Ok(_) => {
                panic!("Should have returned a MACError::InvalidState.")
            }
            Err(MACError::InvalidState(_)) => { /* good */ }
            Err(_) => {
                panic!("Should have returned a MACError::InvalidState.")
            }
        }

        // error case: do_extract_update without init
        let mut hkdf = HKDF_SHA256::new();
        match hkdf.do_extract_update_bytes(&[0u8; 4]) {
            Ok(_) => {
                panic!("Should have returned a MACError::InvalidState.")
            }
            Err(MACError::InvalidState(_)) => { /* good */ }
            Err(_) => {
                panic!("Should have returned a MACError::InvalidState.")
            }
        }

        // error case: do_extract_final without init
        let hkdf = HKDF_SHA256::new();
        match hkdf.do_extract_final() {
            Ok(_) => {
                panic!("Should have returned a MACError::InvalidState.")
            }
            Err(MACError::InvalidState(_)) => { /* good */ }
            Err(_) => {
                panic!("Should have returned a MACError::InvalidState.")
            }
        }

        // error case: do_extract_update after do_extract_update_key
        let mut hkdf = HKDF_SHA256::new();
        hkdf.do_extract_init(&key).unwrap();
        hkdf.do_extract_update_key(&key).unwrap();
        hkdf.do_extract_update_key(&key).unwrap();
        hkdf.do_extract_update_bytes(key.ref_to_bytes()).unwrap();
        match hkdf.do_extract_update_key(&key) {
            Ok(_) => {
                panic!("Should have returned a MACError::InvalidState.")
            }
            Err(MACError::InvalidState(_)) => { /* good */ }
            Err(_) => {
                panic!("Should have returned a MACError::InvalidState.")
            }
        }
    }

    #[test]
    fn test_hkdf_as_kdf() {
        let testframework = TestFrameworkKDF::new();

        /*
         * HKDF-SHA2-256 Test vector:
         * {"tcId":501,
         *  "kdfParameter":{"kdfType":"hkdf",
         *      "salt":"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
         *      "z":"25C807590CF01685757BCBF7CFB806DDB9F1EB0AB810BEDF969779C81A1E806DCEAAE3B3AE31021F97D83A4901BB2FD02594A607558205097BB58B0E0FAE5DB0C4CCB2FF882B7160F8408CBE193A9421A6897778CE453A81A96CDE2092FB602396",
         *      "l":1024},
         *  "fixedInfoPartyU":{
         *      "partyId":"338D1F2A8B222598565C798886E7B35B",
         *      "ephemeralData":"6D4BD5DD3018C899548C52A40A5A5EE82A93FF7F50E8BE7ADCF0DAA15B90CD292F5D14F905A3CA036D47A62F37C140954AE90CCDA9E4E08145DB80FA1B36E1FABC89664AF0A8D13761A963316A04565DEAF5D73C8B89B295A804A2D7DA2BADD178"},
         *  "fixedInfoPartyV":{"partyId":"03EEF6BD71BCE550BBA98D7C0080B582"}
         * }
         *
         * resp:
         * {"tcId":501,
         *  "dkm":"1f6f7381c72f1d46d83e819bedeb482944adb0e3352cf2718e4bd334d95699e7256d01a48f35016f807bc1b739d41f5d53e442c67f6b455776d50d8667d62b3f3b632c5a88c371f7229a4c88beea1f28752a95fb2c533af28e6bfb19e69d750bbadc6609b2715dac19de9d9a6cfe3472a5e5312eabfd9bdbfa222cc7046ce3f7"
         * }
         *
        **/

        // SP800-56Cr2 tcId 1
        let mut salt = KeyMaterialInternal::<128>::new(); // have to do it this way for it to accept a zeroized key
        salt.allow_hazardous_operations();
        salt.set_bytes_as_type(&hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(), KeyType::MACKey).unwrap();

        // ikm = z||t
        // let ikm = KeyMaterial_internal::<128>::from_bytes_as_type(&hex::decode("589410408990A227518017C37997BE2F770AF54063E7393B2AA5463196136D18F365733139EB74CDD6B7268F41D33DB6").unwrap(), KeyType::MACKey).unwrap();
        let ikm = KeyMaterialInternal::<128>::from_bytes_as_type(&hex::decode("25C807590CF01685757BCBF7CFB806DDB9F1EB0AB810BEDF969779C81A1E806DCEAAE3B3AE31021F97D83A4901BB2FD02594A607558205097BB58B0E0FAE5DB0C4CCB2FF882B7160F8408CBE193A9421A6897778CE453A81A96CDE2092FB602396").unwrap(), KeyType::MACKey).unwrap();

        // info = uPartyInfo||vPartyInfo||i32(l)
        let mut additional_input: Vec<u8> = Vec::<u8>::new();
        /*fixedInfoPartyU*/additional_input.append(&mut hex::decode("338D1F2A8B222598565C798886E7B35B6D4BD5DD3018C899548C52A40A5A5EE82A93FF7F50E8BE7ADCF0DAA15B90CD292F5D14F905A3CA036D47A62F37C140954AE90CCDA9E4E08145DB80FA1B36E1FABC89664AF0A8D13761A963316A04565DEAF5D73C8B89B295A804A2D7DA2BADD178").unwrap());
        /*fixedInfoPartyV*/additional_input.append(&mut hex::decode("03EEF6BD71BCE550BBA98D7C0080B582").unwrap());
        /*L*/additional_input.append(&mut hex::decode("00000400").unwrap());

        let mut expected_key = KeyMaterialInternal::<128>::from_bytes_as_type(&hex::decode("1f6f7381c72f1d46d83e819bedeb482944adb0e3352cf2718e4bd334d95699e7256d01a48f35016f807bc1b739d41f5d53e442c67f6b455776d50d8667d62b3f3b632c5a88c371f7229a4c88beea1f28752a95fb2c533af28e6bfb19e69d750bbadc6609b2715dac19de9d9a6cfe3472a5e5312eabfd9bdbfa222cc7046ce3f7").unwrap(), KeyType::MACKey).unwrap();


        // do it manually just to check that we have the test vector right.
        let mut output_key = KeyMaterialInternal::<128>::new();
        let bytes_written = HKDF::<SHA256>::extract_and_expand_out(&salt, &ikm, additional_input.as_slice(), 128, &mut output_key).unwrap();
        assert_eq!(bytes_written, 128);
        assert_eq!(output_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // One-key derive_key -- since HKDF.derive_key() doesn't accept a salt but sets it to zero, we can only test vectors with a zero salt.
        let hkdf = HKDF::<SHA256>::default();
        let output_key = hkdf.derive_key(&ikm, &additional_input).unwrap();
        // kdf.derive_key is a one-step that doesn't expand, so need to truncate the expected key to match.
        let mut expected_key_truncated = expected_key.clone();
        expected_key_truncated.truncate(output_key.key_len()).unwrap();
        assert_eq!(output_key.ref_to_bytes(), expected_key_truncated.ref_to_bytes());

        testframework.test_kdf_single_key::<HKDF<SHA256>>(&ikm, &additional_input, &expected_key_truncated);

        let keys = [&salt, &ikm];
        testframework.test_kdf_multiple_key::<HKDF<SHA256>>(&keys, additional_input.as_slice(), &mut expected_key);
    }
}
