#[cfg(test)]
mod hkdf_tests {
    use bouncycastle_core::errors::{KDFError, KeyMaterialError, MACError};
    use bouncycastle_core::hazmat::do_hazardous_operations;
    use bouncycastle_core::kdf_params::{KdfDescription, KdfParams, KeyLen};
    use bouncycastle_core::key_material::{
        KeyMaterial, KeyMaterial0, KeyMaterial128, KeyMaterial256, KeyMaterial512,
        KeyMaterialTrait, KeyType,
    };
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
    use bouncycastle_core::traits::{
        Algorithm, AlgorithmInfo, HashAlgParams, HashOneShot, KDF, KDF_ONE_SHOT_MAX_LEN,
    };
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
    use bouncycastle_hex as hex;
    use bouncycastle_hkdf::{HKDF, HkdfDescription};
    use bouncycastle_hmac::hazmat as hmac_hazmat;
    use bouncycastle_hmac::{HMACParams, HmacKey};
    use bouncycastle_sha2::hkdf::{HKDF_SHA256, HKDF_SHA256_NAME, HKDF_SHA512, HKDF_SHA512_NAME};
    use bouncycastle_sha2::{SHA256, SHA512};
    use bouncycastle_utils::ct;

    #[test]
    fn algorithm_tests() {
        // The name is the hash's HKDF name; the strength is the hash's, both through the
        // constants and through AlgorithmInfo on an instance.
        assert_eq!(HKDF_SHA256::ALG_NAME, HKDF_SHA256_NAME);
        assert_eq!(HKDF_SHA512::ALG_NAME, HKDF_SHA512_NAME);
        assert_eq!(HKDF_SHA256::MAX_SECURITY_STRENGTH, SHA256::MAX_SECURITY_STRENGTH);
        assert_eq!(HKDF_SHA512::MAX_SECURITY_STRENGTH, SHA512::MAX_SECURITY_STRENGTH);
        assert_eq!(HKDF_SHA256::new().alg_name(), HKDF_SHA256_NAME);
        assert_eq!(HKDF_SHA512::new().max_security_strength(), SecurityStrength::_256bit);
    }

    #[test]
    fn test_streaming_apis() {
        // setup variables
        let salt = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::MACKey).unwrap();
        let ikm = KeyMaterial256::from_bytes(&DUMMY_SEED[16..48]).unwrap();
        let info = &DUMMY_SEED[48..64];
        let mut okm = KeyMaterial512::new();
        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, info, 64, &mut okm).unwrap();

        // Test that streaming API do_extract gets the same result
        let mut hkdf = HKDF_SHA256::default();
        hkdf.do_extract_init(&salt).unwrap();
        hkdf.do_extract_update_bytes(ikm.ref_to_bytes()).unwrap();
        let prk = hkdf.do_extract_final().unwrap();
        let mut okm2 = KeyMaterial512::new();
        HKDF_SHA256::expand_out(&prk, info, 64, &mut okm2).unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), okm2.ref_to_bytes()));
    }

    #[test]
    fn derive_and_derive_from_multiple() {
        // No known answers here: the KDF trait's methods must agree with extract_and_expand_out,
        // the salt being the instance's (HKDF::new_with_salt) or the absent one (HKDF::new), and
        // the keys of derive_key_from_multiple the IKM in order.
        let info: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\0xF";

        let zero_key = KeyMaterial0::new();
        let key1 = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();
        let key2 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::MACKey).unwrap();
        let key3 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[64..96], KeyType::MACKey).unwrap();
        let expected = |salt: &dyn KeyMaterialTrait, ikm: &dyn KeyMaterialTrait| {
            let mut expected_okm = KeyMaterial512::new();
            HKDF_SHA256::extract_and_expand_out(salt, ikm, info, 32, &mut expected_okm).unwrap();
            expected_okm
        };

        /* no salt, no IKM */
        let okm = HKDF_SHA256::new().derive_key(&zero_key, info, 32).unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), expected(&zero_key, &zero_key).ref_to_bytes()));
        let keys: [&dyn KeyMaterialTrait; 2] = [&KeyMaterial0::new(), &KeyMaterial0::new()];
        let okm = HKDF_SHA256::new().derive_key_from_multiple(&keys, info, 32).unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), expected(&zero_key, &zero_key).ref_to_bytes()));

        /* no salt, one IKM: derive_key and the one-key multi form agree with the absent salt */
        let okm = HKDF_SHA256::new().derive_key(&key1, info, 32).unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), expected(&zero_key, &key1).ref_to_bytes()));
        let keys: [&dyn KeyMaterialTrait; 1] = [&key1];
        let okm = HKDF_SHA256::new().derive_key_from_multiple(&keys, info, 32).unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), expected(&zero_key, &key1).ref_to_bytes()));

        /* a salt and no IKM */
        let okm =
            HKDF_SHA256::new_with_salt(&key1).unwrap().derive_key(&zero_key, info, 32).unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), expected(&key1, &zero_key).ref_to_bytes()));

        /* a salt and one IKM */
        let okm = HKDF_SHA256::new_with_salt(&key1).unwrap().derive_key(&key2, info, 32).unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), expected(&key1, &key2).ref_to_bytes()));

        /* a salt and two IKMs: the keys concatenate */
        let key23 =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[32..96], KeyType::MACKey).unwrap();
        let keys: [&dyn KeyMaterialTrait; 2] = [&key2, &key3];
        let okm = HKDF_SHA256::new_with_salt(&key1)
            .unwrap()
            .derive_key_from_multiple(&keys, info, 32)
            .unwrap();
        assert!(ct::ct_eq_bytes(okm.ref_to_bytes(), expected(&key1, &key23).ref_to_bytes()));

        /* the instance is reusable: a second derivation with the same salt gives the same key */
        let hkdf = HKDF_SHA256::new_with_salt(&key1).unwrap();
        let a = hkdf.derive_key(&key2, info, 32).unwrap();
        let b = hkdf.derive_key(&key2, info, 32).unwrap();
        assert!(ct::ct_eq_bytes(a.ref_to_bytes(), b.ref_to_bytes()));

        /* a salt typed Unknown is refused by the constructor */
        let unknown =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Unknown).unwrap();
        assert!(matches!(
            HKDF_SHA256::new_with_salt(&unknown),
            Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
        ));
    }

    #[test]
    fn test_entropy_tracking() {
        // test the thresholds of HMAC-SHA256: half the hash output, 16 bytes
        let key255 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..15], KeyType::MACKey).unwrap();
        let key256 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::MACKey).unwrap();
        let key512 =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::MACKey).unwrap();
        let zero_key = KeyMaterial0::new();

        // not enough
        assert_eq!(key255.security_strength(), SecurityStrength::_112bit);
        let mut okm = HKDF_SHA256::extract(&key255, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::Unknown);
        assert_eq!(okm.security_strength(), SecurityStrength::None);
        _ = HKDF_SHA256::extract_and_expand_out(&key255, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::Unknown);
        assert_eq!(okm.security_strength(), SecurityStrength::None);

        // too much
        assert_eq!(key512.security_strength(), SecurityStrength::_256bit);
        let mut okm = HKDF_SHA256::extract(&key512, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);
        // should get downgraded to match hash alg
        assert_eq!(okm.security_strength(), SecurityStrength::_128bit);
        _ = HKDF_SHA256::extract_and_expand_out(&key512, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);
        assert_eq!(okm.security_strength(), SecurityStrength::_128bit);

        // just right: 16 bytes seed HKDF-SHA256, and the output's strength is theirs
        let mut okm = HKDF_SHA256::extract(&key256, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);
        assert_eq!(okm.security_strength(), SecurityStrength::_128bit);
        _ = HKDF_SHA256::extract_and_expand_out(&key256, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);
        assert_eq!(okm.security_strength(), SecurityStrength::_128bit);

        // test the thresholds of HMAC-SHA512: half the hash output, 32 bytes
        let key511 =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..31], KeyType::MACKey).unwrap();
        let key512 =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();
        let zero_key = KeyMaterial0::new();

        // not enough
        let mut okm = HKDF_SHA512::extract(&key511, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::Unknown);
        _ = HKDF_SHA512::extract_and_expand_out(&key511, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::Unknown);

        // just right
        let mut okm = HKDF_SHA512::extract(&key512, &zero_key).unwrap();
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);
        _ = HKDF_SHA512::extract_and_expand_out(&key512, &zero_key, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);

        // variable setup
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Unknown).unwrap();
        let mut okm = KeyMaterial256::new();

        // failure case: should complain if low entropy bytes are provided

        // only as salt
        match HKDF_SHA256::extract_and_expand_out(
            &low_entropy_key,
            &KeyMaterial0::new(),
            &[],
            32,
            &mut okm,
        ) {
            Ok(_) => {
                panic!("Should have thrown a KeyMaterialError");
            }
            Err(KDFError::MACError(MACError::KeyMaterialError(
                KeyMaterialError::InvalidKeyType(_),
            ))) => { /* good */ }
            Err(_) => {
                panic!("Should have thrown a KeyMaterialError");
            }
        };

        // the KDF trait's keys are IKM, never the salt, so an Unknown one is derived from
        let keys: [&dyn KeyMaterialTrait; 1] = [&low_entropy_key];
        let okm_unknown = HKDF_SHA256::new().derive_key_from_multiple(&keys, &[], 32).unwrap();
        assert_eq!(okm_unknown.key_type(), KeyType::Unknown);

        // as both salt and ikm
        match HKDF_SHA256::extract_and_expand_out(
            &low_entropy_key,
            &low_entropy_key,
            &[],
            32,
            &mut okm,
        ) {
            Ok(_) => {
                panic!("Should have thrown a KeyMaterialError");
            }
            Err(KDFError::MACError(MACError::KeyMaterialError(
                KeyMaterialError::InvalidKeyType(_),
            ))) => { /* good */ }
            Err(_) => {
                panic!("Should have thrown a KeyMaterialError");
            }
        };

        let keys: [&dyn KeyMaterialTrait; 2] = [&low_entropy_key, &low_entropy_key];
        let okm_unknown = HKDF_SHA256::new().derive_key_from_multiple(&keys, &[], 32).unwrap();
        assert_eq!(okm_unknown.key_type(), KeyType::Unknown);

        // zero-length salt is allowed -- zeroized ikm
        _ = HKDF_SHA256::extract_and_expand_out(
            &KeyMaterial0::new(),
            &KeyMaterial0::new(),
            &[],
            32,
            &mut okm,
        )
        .unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::Unknown);

        HKDF_SHA256::new().derive_key_out(&KeyMaterial0::new(), &[], 32, &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::Unknown);

        let keys: [&dyn KeyMaterialTrait; 2] = [&KeyMaterial0::new(), &KeyMaterial0::new()];
        HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], 32, &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::Unknown);

        // zero-length salt is allowed -- low entropy ikm
        _ = HKDF_SHA256::extract_and_expand_out(
            &KeyMaterial0::new(),
            &low_entropy_key,
            &[],
            32,
            &mut okm,
        )
        .unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::Unknown);

        HKDF_SHA256::new().derive_key_out(&low_entropy_key, &[], 32, &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::Unknown);

        let keys: [&dyn KeyMaterialTrait; 2] = [&KeyMaterial256::new(), &low_entropy_key];
        HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], 32, &mut okm).unwrap();
        // okm should be tracked as LowEntropy
        assert_eq!(okm.key_type(), KeyType::Unknown);

        // salt and ikm are full-entropy but together below the seeding threshold. A salt of any
        // key type but Unknown keys the extract, so this is accepted and the output is Unknown.
        let salt =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[..8], KeyType::CryptographicRandom)
                .unwrap();
        let ikm =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[8..16], KeyType::CryptographicRandom)
                .unwrap();

        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::Unknown);

        // derive_key uses the zero salt and ikm alone: the same output type.
        _ = HKDF_SHA256::new().derive_key_out(&ikm, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::Unknown);

        // through the KDF trait both keys are IKM, but an 8-byte key is too short to carry a
        // strength (64 bits, below 112) and credits nothing, so 8 + 8 does not reach the 16
        // that seed HKDF-SHA256
        let keys: [&dyn KeyMaterialTrait; 2] = [&salt, &ikm];
        HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::Unknown);
        assert_eq!(okm.security_strength(), SecurityStrength::None);

        // two distinct 14-byte keys carry 112 bits each and together reach the threshold, and
        // the output is labelled at that strength, never CryptographicRandom with none
        let key_a =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[..14], KeyType::CryptographicRandom)
                .unwrap();
        let key_b =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[14..28], KeyType::CryptographicRandom)
                .unwrap();
        let keys: [&dyn KeyMaterialTrait; 2] = [&key_a, &key_b];
        HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);
        assert_eq!(okm.security_strength(), SecurityStrength::_112bit);

        // a full-entropy key whose owner lowered its strength to None credits nothing
        let mut lowered =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
                .unwrap();
        lowered.set_security_strength(SecurityStrength::None).unwrap();
        HKDF_SHA256::new().derive_key_out(&lowered, &[], 32, &mut okm).unwrap();
        assert_eq!(okm.key_type(), KeyType::Unknown);

        // success case -- insufficient entropy returns KeyType::Unknown: a secret salt and the
        // IKM both credit, but 4 + 8 bytes is below the 16 that seed HKDF-SHA256
        let salt = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[..4], KeyType::MACKey).unwrap();
        let ikm =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[8..16], KeyType::CryptographicRandom)
                .unwrap();

        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::Unknown);

        _ = HKDF_SHA256::new().derive_key_out(&salt, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::Unknown);

        let keys: [&dyn KeyMaterialTrait; 2] = [&salt, &ikm];
        _ = HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::Unknown);

        // success case -- sufficient entropy returns the highest input key type -- KeyType::BytesFullEntropy
        // Note that FIPS requires it to be seeded to a full internal block (which is, for example 512 bits for SHA256)
        // Note: will still return BytesFullEntropy because that one was first in the inputs.
        let salt = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();
        let ikm =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::CryptographicRandom)
                .unwrap();

        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);

        let salt1 = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::MACKey).unwrap();
        _ = HKDF_SHA256::new().derive_key_out(&salt1, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);

        let keys: [&dyn KeyMaterialTrait; 2] = [&salt, &ikm];
        _ = HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);

        // success case -- insufficient entropy due to key types -- KeyType::Unknown: the
        // Unknown-typed IKM credits nothing, and the 8-byte secret salt alone is below 16
        let salt = KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[..8], KeyType::MACKey).unwrap();
        let ikm =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[16..32], KeyType::Unknown).unwrap();

        _ = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::Unknown);

        // derive_key_out can't reproduce the two-input salt+ikm arrangement

        let keys: [&dyn KeyMaterialTrait; 2] = [&salt, &ikm];
        _ = HKDF_SHA256::new().derive_key_from_multiple_out(&keys, &[], 32, &mut okm);
        assert_eq!(okm.key_type(), KeyType::Unknown);

        /* get_entropy */
        // This requires using the stateful streaming API and check the amount of entropy it tracks after each addition.
        // The SHA-256 threshold is 16 bytes, so the parts are 8-byte ones.
        let salt14 =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[..14], KeyType::MACKey).unwrap();
        let salt64 =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::MACKey).unwrap();
        let low_entropy_key16 =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::Unknown).unwrap();
        // 14 bytes carry 112 bits, the least a key credits; 8 would carry nothing
        let full_entropy_key14 =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[16..30], KeyType::CryptographicRandom)
                .unwrap();

        // can't test with a low entropy salt because the salt has to be full entropy or zero.
        // but can test with a zeroized key
        let mut hkdf = HKDF_SHA256::new();
        assert_eq!(hkdf.get_entropy(), 0);
        hkdf.do_extract_init(&KeyMaterial0::new()).unwrap();
        assert_eq!(hkdf.get_entropy(), 0);
        assert_eq!(hkdf.is_fully_seeded(), false);

        // test do_extract_init with a full entropy salt
        let mut hkdf = HKDF_SHA256::new();
        assert_eq!(hkdf.get_entropy(), 0);
        hkdf.do_extract_init(&salt14).unwrap();
        assert_eq!(hkdf.get_entropy(), 14);
        assert_eq!(hkdf.is_fully_seeded(), false);

        // with enough entropy in the salt.
        let mut hkdf = HKDF_SHA256::new();
        assert_eq!(hkdf.get_entropy(), 0);
        hkdf.do_extract_init(&salt64).unwrap();
        assert_eq!(hkdf.get_entropy(), 64);
        assert_eq!(hkdf.is_fully_seeded(), true);

        // building up to full entropy
        let mut hkdf = HKDF_SHA256::new();
        assert_eq!(hkdf.get_entropy(), 0);
        hkdf.do_extract_init(&salt14).unwrap();
        assert_eq!(hkdf.get_entropy(), 14);
        assert_eq!(hkdf.is_fully_seeded(), false);
        hkdf.do_extract_update_key(&full_entropy_key14).unwrap();
        assert_eq!(hkdf.get_entropy(), 28);
        assert_eq!(hkdf.is_fully_seeded(), true);
        hkdf.do_extract_update_key(&full_entropy_key14).unwrap();
        assert_eq!(hkdf.get_entropy(), 42);
        assert_eq!(hkdf.is_fully_seeded(), true);
        hkdf.do_extract_update_bytes(low_entropy_key16.ref_to_bytes()).unwrap();
        assert_eq!(hkdf.get_entropy(), 42);
        assert_eq!(hkdf.is_fully_seeded(), true);
    }

    #[test]
    fn test_overcapacity() {
        // test the case of requesting more output than FIPS / RFC allows
        let hash_len = SHA256::OUTPUT_LEN;
        // output limit is 255 * hash_len, which for sha256 is 225*32 = 8160 bytes.

        // success case: large but not over-limit
        let mut mega_huge_key = KeyMaterial::<8100>::new();
        assert!(mega_huge_key.capacity() < 255 * hash_len);
        _ = HKDF_SHA256::extract_and_expand_out(
            &KeyMaterial0::new(),
            &KeyMaterial0::new(),
            &[],
            8100,
            &mut mega_huge_key,
        )
        .unwrap();

        // test exactly the capacity
        let mut mega_huge_key = KeyMaterial::<8160>::new();
        assert_eq!(mega_huge_key.capacity(), 255 * hash_len);
        _ = HKDF_SHA256::extract_and_expand_out(
            &KeyMaterial0::new(),
            &KeyMaterial0::new(),
            &[],
            8160,
            &mut mega_huge_key,
        )
        .unwrap();

        // failure case
        let mut mega_huge_key = KeyMaterial::<8192>::new();
        assert!(mega_huge_key.capacity() > 255 * hash_len);
        match HKDF_SHA256::extract_and_expand_out(
            &KeyMaterial0::new(),
            &KeyMaterial0::new(),
            &[],
            8192,
            &mut mega_huge_key,
        ) {
            Ok(_) => {
                panic!("Should have thrown a KeyMaterialError");
            }
            Err(KDFError::InvalidLength(_)) => { /* good */ }
            Err(_) => {
                panic!("Should have thrown a KeyMaterialError");
            }
        };
    }

    #[test]
    fn rfc5869_test_cases() {
        // Test Case 1
        rfc5869_sha256(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            42,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        // Test Case 2
        rfc5869_sha256(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
            82,
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );

        // Test Case 3
        rfc5869_sha256(
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
            42,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        );
    }

    /// An 8-byte key is below the SHA-256 seeding threshold (16 bytes), so the output is `Unknown`
    /// with no strength. The multi-key path must agree with the single-key one rather than erroring.
    #[test]
    fn test_derive_key_from_multiple_partial_entropy_matches_derive_key() {
        let key =
            KeyMaterial128::from_bytes_as_type(&DUMMY_SEED[..8], KeyType::CryptographicRandom)
                .unwrap();
        let single = HKDF_SHA256::new().derive_key(&key, b"info", 32).unwrap();
        assert_eq!(single.key_type(), KeyType::Unknown);
        assert_eq!(single.security_strength(), SecurityStrength::None);

        // An empty first key is the absent salt, so this is derive_key(&key) through the other path.
        let multi = HKDF_SHA256::new()
            .derive_key_from_multiple(&[&KeyMaterial128::new(), &key], b"info", 32)
            .unwrap();
        assert_eq!(multi.key_type(), KeyType::Unknown);
        assert_eq!(multi.security_strength(), SecurityStrength::None);
        assert_eq!(multi.ref_to_bytes(), single.ref_to_bytes());

        // The key alone, as the salt.
        let salt_only = HKDF_SHA256::new().derive_key_from_multiple(&[&key], b"info", 32).unwrap();
        assert_eq!(salt_only.key_type(), KeyType::Unknown);
        assert_eq!(salt_only.security_strength(), SecurityStrength::None);
    }

    /// `KdfParams` borrows the KDF's description and the info: the description names the salt
    /// (readable, a zero-length one being the absent salt), its engine is an instance keyed with
    /// it, a derivation through that is `extract_and_expand` with the salt, and the value is
    /// `Copy`.
    #[test]
    fn kdf_params_carry_the_description_and_info() {
        let salt =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..13], KeyType::CryptographicRandom)
                .unwrap();
        let ikm = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::Seed).unwrap();
        let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
        assert_eq!(hkdf.salt().unwrap().ref_to_bytes(), salt.ref_to_bytes());
        assert_eq!(hkdf.alg_name(), HKDF_SHA256_NAME);
        let params = KdfParams::new(&hkdf, b"info", KeyLen::<32>);
        let copy = params;
        assert_eq!(params.info(), b"info");
        let via_params = params.kdf().engine().unwrap().derive_key(&ikm, copy.info(), 32).unwrap();
        let mut direct = KeyMaterial256::new();
        HKDF_SHA256::extract_and_expand_out(&salt, &ikm, b"info", 32, &mut direct).unwrap();
        assert!(via_params.equals(&direct));

        // the absent salt, as `new` and as a zero-length `with_salt`
        let absent = KeyMaterial0::new();
        for no_salt in
            [HkdfDescription::<SHA256>::new(), HkdfDescription::with_salt(&absent).unwrap()]
        {
            let params = KdfParams::new(&no_salt, b"", KeyLen::<32>);
            let via_params =
                params.kdf().engine().unwrap().derive_key(&ikm, params.info(), 32).unwrap();
            let mut direct = KeyMaterial256::new();
            HKDF_SHA256::extract_and_expand_out(&absent, &ikm, b"", 32, &mut direct).unwrap();
            assert!(via_params.equals(&direct));
        }
        assert!(HkdfDescription::<SHA256>::new().salt().is_none());

        // a copy of a description is the same description: the salt comes with it
        let copied = hkdf;
        assert_eq!(copied.salt().unwrap().ref_to_bytes(), salt.ref_to_bytes());
        #[allow(clippy::clone_on_copy)]
        let cloned = hkdf.clone();
        assert_eq!(cloned.salt().unwrap().ref_to_bytes(), salt.ref_to_bytes());

        // what the engine would refuse is refused before any parameters exist
        let unknown =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Unknown).unwrap();
        assert!(matches!(
            HkdfDescription::<SHA256>::with_salt(&unknown),
            Err(KeyMaterialError::InvalidKeyType(_))
        ));
        assert!(HKDF_SHA256::new_with_salt(&unknown).is_err());
    }

    /// RFC 5869 Section 2.2 types the salt only as "a non-secret random value"; material of any
    /// `KeyType` must key the extract as the `MACKey`-typed copy of it does.
    #[test]
    fn test_extract_accepts_a_salt_of_any_key_type() {
        let ikm = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        let as_mac =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::MACKey).unwrap();
        let expected = HKDF_SHA256::extract(&as_mac, &ikm).unwrap();
        for key_type in [KeyType::CryptographicRandom, KeyType::Seed, KeyType::SymmetricCipherKey] {
            let salt = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], key_type).unwrap();
            let prk = HKDF_SHA256::extract(&salt, &ikm).unwrap();
            assert_eq!(prk.ref_to_bytes(), expected.ref_to_bytes(), "{key_type:?}");
        }

        // Two random keys through the KDF trait, the first of which is the salt.
        let a = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
            .unwrap();
        let b =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::CryptographicRandom)
                .unwrap();
        let okm = HKDF_SHA256::new().derive_key_from_multiple(&[&a, &b], b"", 32).unwrap();
        assert_eq!(okm.key_type(), KeyType::CryptographicRandom);
    }

    /// HMAC hashes a key longer than its block (RFC 2104 Section 3), so a salt longer than the
    /// block must give the PRK that its hash, as the salt, gives.
    #[test]
    fn test_extract_with_a_salt_longer_than_the_block() {
        let ikm = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        let mut digest = [0u8; 32];
        SHA256::hash_out(&DUMMY_SEED[..100], &mut digest);
        let hashed = KeyMaterial256::from_bytes_as_type(&digest, KeyType::MACKey).unwrap();
        let expected = HKDF_SHA256::extract(&hashed, &ikm).unwrap();

        for key_type in [KeyType::MACKey, KeyType::CryptographicRandom] {
            let long =
                KeyMaterial::<100>::from_bytes_as_type(&DUMMY_SEED[..100], key_type).unwrap();
            let prk = HKDF_SHA256::extract(&long, &ikm).unwrap();
            assert_eq!(prk.ref_to_bytes(), expected.ref_to_bytes(), "{key_type:?}");
        }
    }

    /// `(0..n)` as a MACKey-typed PRK of `n` bytes.
    fn prk_of(n: usize) -> KeyMaterial<1024> {
        let bytes: Vec<u8> = (0..n).map(|i| i as u8).collect();
        KeyMaterial::<1024>::from_bytes_as_type(&bytes, KeyType::MACKey).unwrap()
    }

    /// RFC 5869 Section 2.3: the PRK is "of at least HashLen octets".
    #[test]
    fn test_expand_prk_length() {
        let mut okm = KeyMaterial512::new();
        for (short, ok) in [(31usize, 32usize), (16, 64)] {
            assert!(matches!(
                HKDF_SHA256::expand_out(&prk_of(short), b"", 32, &mut okm),
                Err(KDFError::InvalidLength(_))
            ));
            assert_eq!(HKDF_SHA256::expand_out(&prk_of(ok), b"", 32, &mut okm).unwrap(), 32);
        }
        assert!(matches!(
            HKDF_SHA512::expand_out(&prk_of(63), b"", 64, &mut okm),
            Err(KDFError::InvalidLength(_))
        ));
        assert_eq!(HKDF_SHA512::expand_out(&prk_of(64), b"", 64, &mut okm).unwrap(), 64);
    }

    /// A refused expand leaves nothing of the output behind: the buffer is zeroized before any
    /// check, as every `_out` function's is.
    #[test]
    fn test_expand_failure_leaves_okm_zeroized() {
        let mut okm = KeyMaterial512::from_bytes_as_type(&[0xAA; 64], KeyType::MACKey).unwrap();
        assert!(HKDF_SHA256::expand_out(&prk_of(31), b"info", 32, &mut okm).is_err());
        assert_eq!(okm.key_len(), 0);
        assert_eq!(okm.key_type(), KeyType::Zeroized);
    }

    /// A refused extract leaves nothing of the output behind either: `extract_out` and
    /// `extract_and_expand_out` with a salt typed `Unknown`, and `do_extract_final_out` on an
    /// instance never initialised, zeroize the buffer before the check that refuses them.
    #[test]
    fn test_extract_failure_leaves_output_zeroized() {
        let unknown =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Unknown).unwrap();
        let ikm = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::MACKey).unwrap();
        let prefilled = || KeyMaterial512::from_bytes_as_type(&[0x5A; 64], KeyType::Seed).unwrap();

        let mut prk = prefilled();
        assert!(HKDF_SHA256::extract_out(&unknown, &ikm, &mut prk).is_err());
        assert_eq!(prk.key_len(), 0);
        assert_eq!(prk.key_type(), KeyType::Zeroized);

        let mut okm = prefilled();
        assert!(
            HKDF_SHA256::extract_and_expand_out(&unknown, &ikm, b"info", 32, &mut okm).is_err()
        );
        assert_eq!(okm.key_len(), 0);
        assert_eq!(okm.key_type(), KeyType::Zeroized);

        let mut prk = prefilled();
        assert!(HKDF_SHA256::new().do_extract_final_out(&mut prk).is_err());
        assert_eq!(prk.key_len(), 0);
        assert_eq!(prk.key_type(), KeyType::Zeroized);
    }

    /// A PRK longer than the hash block gives what HMAC keyed with it gives (RFC 2104 Section 3
    /// hashes such a key first): T(1) || T(2) computed with HMAC directly.
    fn check_expand_long_prk<H>(lens: &[usize])
    where
        H: HMACParams,
    {
        let hash_len = H::OUTPUT_LEN;
        for &n in lens {
            let prk = prk_of(n);
            let key = HmacKey::<H>::from_key_material(&prk).unwrap();
            let mut expected = [0u8; 128];
            // HMAC as its hazmat halves, which are generic over the hash where the role
            // impls want the tag length as a const.
            let mut t1 = hmac_hazmat::inner_state(&key);
            t1.do_update(b"info");
            t1.do_update(&[1]);
            hmac_hazmat::finish_out(&key, t1, &mut expected[..hash_len]);
            let mut t2 = hmac_hazmat::inner_state(&key);
            t2.do_update(&expected[..hash_len]);
            t2.do_update(b"info");
            t2.do_update(&[2]);
            hmac_hazmat::finish_out(&key, t2, &mut expected[hash_len..2 * hash_len]);

            let mut okm = KeyMaterial::<128>::new();
            let written = HKDF::<H>::expand_out(&prk, b"info", 2 * hash_len, &mut okm).unwrap();
            assert_eq!(written, 2 * hash_len, "PRK of {n} bytes");
            assert_eq!(okm.ref_to_bytes(), &expected[..2 * hash_len], "PRK of {n} bytes");
        }
    }

    #[test]
    fn test_expand_long_prk() {
        // 64 is SHA-256's block, taken verbatim; 65 and up are hashed. 128 is SHA-512's block, the
        // boundary that pins `<=`: verbatim and hashed differ there.
        check_expand_long_prk::<SHA256>(&[64, 65, 128, 129, 144, 145, 1000]);
        check_expand_long_prk::<SHA512>(&[65, 128, 129, 144, 145, 1000]);
    }

    /*** Helper Functions ***/
    #[allow(non_snake_case)]
    fn rfc5869_sha256(ikm: &str, salt: &str, info: &str, prk: &str, L: usize, okm: &str) {
        /*** First with the one-shot APIs ::extract() and ::expand_out(). ***/

        let mut ikm_key = KeyMaterial::<100>::new();
        do_hazardous_operations(&mut ikm_key, |ikm_key| {
            // just for testing, ignore the error about zeroized keys
            ikm_key.set_bytes_as_type(&hex::decode(ikm).unwrap(), KeyType::CryptographicRandom)
        })
        .unwrap();

        let mut salt_key = KeyMaterial::<100>::new();
        do_hazardous_operations(&mut salt_key, |salt_key| {
            // just for testing, ignore the error about zeroized keys
            salt_key.set_bytes_as_type(&hex::decode(salt).unwrap(), KeyType::MACKey)
        })
        .unwrap();

        let info = hex::decode(info).unwrap();
        let mut prk_key = HKDF_SHA256::extract(&salt_key, &ikm_key).unwrap();
        assert_eq!(prk_key.ref_to_bytes(), hex::decode(prk).unwrap());

        // Some of the RFC 5869 test vectors have input keys that are too short to meet the entropy seeding rules.
        // So, just for testing, we'll bump this up to full entropy, regardless of what entropy HKDF::extract()
        // thinks it should be based on the inputs.
        do_hazardous_operations(&mut prk_key, |prk_key| prk_key.set_key_type(KeyType::MACKey))
            .unwrap();

        let mut okm_key = KeyMaterial::<100>::new();
        _ = HKDF_SHA256::expand_out(&prk_key, &info, L, &mut okm_key).unwrap();
        okm_key.set_key_len(L).unwrap();
        assert_eq!(okm_key.ref_to_bytes().len(), L);
        assert_eq!(okm_key.ref_to_bytes(), hex::decode(okm).unwrap());

        /*** with extract_and_expand() ***/
        match HKDF_SHA256::extract_and_expand_out(&salt_key, &ikm_key, &info, L, &mut okm_key) {
            Ok(_) => {
                assert_eq!(okm_key.ref_to_bytes().len(), L);
                assert_eq!(okm_key.ref_to_bytes(), hex::decode(okm).unwrap());
            }
            Err(KDFError::KeyMaterialError(_)) => {
                /* some of the RFC 5869 test vectors are in fact low entropy, so just skip */
            }
            Err(_) => panic!("Should have returned a MACError::KeyMaterialError."),
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
        let key = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();

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

        // SP800-56Cr2 tcId 1. The vector's salt is 64 zero bytes, typed here as a public value:
        // it keys the extract as any typing of the same bytes does, and credits nothing, which the
        // framework's entropy checks on the instance rely on (a MACKey salt would seed the output
        // on its own).
        let mut salt = KeyMaterial::<128>::new(); // have to do it this way for it to accept a zeroized key
        do_hazardous_operations(&mut salt, |salt| {
            salt.set_bytes_as_type(&hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap(), KeyType::CryptographicRandom)
        }).unwrap();

        // ikm = z||t
        // let ikm = KeyMaterial_internal::<128>::from_bytes_as_type(&hex::decode("589410408990A227518017C37997BE2F770AF54063E7393B2AA5463196136D18F365733139EB74CDD6B7268F41D33DB6").unwrap(), KeyType::MACKey).unwrap();
        let ikm = KeyMaterial::<128>::from_bytes_as_type(&hex::decode("25C807590CF01685757BCBF7CFB806DDB9F1EB0AB810BEDF969779C81A1E806DCEAAE3B3AE31021F97D83A4901BB2FD02594A607558205097BB58B0E0FAE5DB0C4CCB2FF882B7160F8408CBE193A9421A6897778CE453A81A96CDE2092FB602396").unwrap(), KeyType::MACKey).unwrap();

        // info = uPartyInfo||vPartyInfo||i32(l)
        let mut additional_input: Vec<u8> = Vec::<u8>::new();
        /*fixedInfoPartyU*/
        additional_input.append(&mut hex::decode("338D1F2A8B222598565C798886E7B35B6D4BD5DD3018C899548C52A40A5A5EE82A93FF7F50E8BE7ADCF0DAA15B90CD292F5D14F905A3CA036D47A62F37C140954AE90CCDA9E4E08145DB80FA1B36E1FABC89664AF0A8D13761A963316A04565DEAF5D73C8B89B295A804A2D7DA2BADD178").unwrap());
        /*fixedInfoPartyV*/
        additional_input.append(&mut hex::decode("03EEF6BD71BCE550BBA98D7C0080B582").unwrap());
        /*L*/
        additional_input.append(&mut hex::decode("00000400").unwrap());

        let expected_key = KeyMaterial::<128>::from_bytes_as_type(&hex::decode("1f6f7381c72f1d46d83e819bedeb482944adb0e3352cf2718e4bd334d95699e7256d01a48f35016f807bc1b739d41f5d53e442c67f6b455776d50d8667d62b3f3b632c5a88c371f7229a4c88beea1f28752a95fb2c533af28e6bfb19e69d750bbadc6609b2715dac19de9d9a6cfe3472a5e5312eabfd9bdbfa222cc7046ce3f7").unwrap(), KeyType::MACKey).unwrap();

        // do it manually just to check that we have the test vector right.
        let mut output_key = KeyMaterial::<128>::new();
        let bytes_written = HKDF_SHA256::extract_and_expand_out(
            &salt,
            &ikm,
            additional_input.as_slice(),
            128,
            &mut output_key,
        )
        .unwrap();
        assert_eq!(bytes_written, 128);
        assert_eq!(output_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // The KDF trait with the vector's salt in the instance, at the vector's full length.
        let hkdf = HKDF_SHA256::new_with_salt(&salt).unwrap();
        let output_key = hkdf.derive_key(&ikm, &additional_input, 128).unwrap();
        assert_eq!(output_key.ref_to_bytes(), expected_key.ref_to_bytes());

        testframework.test_kdf_single_key(&hkdf, &ikm, &additional_input, &expected_key);

        // The IKM in two halves through the multi-key form is the same IKM.
        let (ikm_a, ikm_b) = {
            let bytes = ikm.ref_to_bytes();
            let mid = bytes.len() / 2;
            (
                KeyMaterial::<128>::from_bytes_as_type(&bytes[..mid], ikm.key_type()).unwrap(),
                KeyMaterial::<128>::from_bytes_as_type(&bytes[mid..], ikm.key_type()).unwrap(),
            )
        };
        let keys: [&dyn KeyMaterialTrait; 2] = [&ikm_a, &ikm_b];
        testframework.test_kdf_multiple_key(
            &hkdf,
            &keys,
            additional_input.as_slice(),
            &expected_key,
        );
    }

    /// The entropy counter is bookkeeping a resumed state may set to anything: the next credit
    /// saturates rather than overflowing.
    /// A salt is RFC 5869 Section 2.2's "non-secret random value" unless the caller types it as a
    /// key: a `CryptographicRandom` salt credits nothing, so a PRK made from it and an empty IKM,
    /// which anyone who knows the salt can compute, is `Unknown`; the same bytes typed `MACKey`
    /// are the secret salt of SP 800-56Cr2 Section 5.1 and are credited.
    #[test]
    fn a_public_salt_credits_no_entropy() {
        let empty = KeyMaterial0::new();
        let public =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
                .unwrap();
        let prk = HKDF_SHA256::extract(&public, &empty).unwrap();
        assert_eq!(prk.key_type(), KeyType::Unknown);
        assert_eq!(prk.security_strength(), SecurityStrength::None);

        let secret =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();
        let prk_secret = HKDF_SHA256::extract(&secret, &empty).unwrap();
        assert_eq!(prk_secret.key_type(), KeyType::CryptographicRandom);
        assert_eq!(prk_secret.security_strength(), SecurityStrength::_128bit);
        assert_eq!(prk_secret.ref_to_bytes(), prk.ref_to_bytes(), "the same PRK bytes either way");

        let mut hkdf = HKDF_SHA256::new();
        assert_eq!(hkdf.do_extract_init(&public).unwrap(), 0, "nothing credited for a public salt");
        assert_eq!(hkdf.get_entropy(), 0);
        let seed = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::Seed).unwrap();
        assert_eq!(hkdf.do_extract_update_key(&seed).unwrap(), 32, "the IKM is credited");
        assert!(hkdf.is_fully_seeded());
    }

    /// A key agreement's `Z` is credited as keying material, but its strength, not its length,
    /// bounds the output's label: a 32-byte `SharedSecret` at 128 bits gives 128-bit output from
    /// HKDF-SHA256 and from HKDF-SHA512 alike, never the 256 bits its length would suggest; and
    /// one whose producer stated no strength credits nothing, so the output is `Unknown`.
    #[test]
    fn a_shared_secret_bounds_the_output_by_its_strength() {
        let mut z =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::SharedSecret).unwrap();
        let salt =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::CryptographicRandom)
                .unwrap();
        assert_eq!(z.security_strength(), SecurityStrength::None, "the default for a Z");
        {
            let prk = HKDF_SHA512::extract(&salt, &z).unwrap();
            assert_eq!(prk.key_type(), KeyType::Unknown);
            assert_eq!(prk.security_strength(), SecurityStrength::None);
        }

        do_hazardous_operations(&mut z, |z| z.set_security_strength(SecurityStrength::_128bit))
            .unwrap();
        let prk = HKDF_SHA256::extract(&salt, &z).unwrap();
        assert_eq!(prk.key_type(), KeyType::CryptographicRandom);
        assert_eq!(prk.security_strength(), SecurityStrength::_128bit);

        let prk = HKDF_SHA512::extract(&salt, &z).unwrap();
        assert_eq!(prk.key_type(), KeyType::CryptographicRandom);
        assert_eq!(prk.security_strength(), SecurityStrength::_128bit);
    }

    /// The provided one-shots derive exactly `KDF_ONE_SHOT_MAX_LEN` bytes and refuse one more,
    /// before the function's own bound, which for HKDF-SHA256 lies well past it.
    #[test]
    fn the_one_shots_derive_up_to_their_cap() {
        let ikm = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
        let hkdf = HKDF_SHA256::new();
        let at_cap = hkdf.derive_key(&ikm, b"info", KDF_ONE_SHOT_MAX_LEN).unwrap();
        assert_eq!(at_cap.key_len(), KDF_ONE_SHOT_MAX_LEN);
        let keys: [&dyn KeyMaterialTrait; 1] = [&ikm];
        let multiple = hkdf.derive_key_from_multiple(&keys, b"info", KDF_ONE_SHOT_MAX_LEN).unwrap();
        assert!(multiple.equals(&*at_cap));
        assert!(matches!(
            hkdf.derive_key(&ikm, b"info", KDF_ONE_SHOT_MAX_LEN + 1),
            Err(KDFError::InvalidLength(_))
        ));
        assert!(matches!(
            hkdf.derive_key_from_multiple(&keys, b"info", KDF_ONE_SHOT_MAX_LEN + 1),
            Err(KDFError::InvalidLength(_))
        ));
        // the _out form takes the length the function allows
        let mut long = KeyMaterial::<{ KDF_ONE_SHOT_MAX_LEN + 1 }>::new();
        assert_eq!(
            hkdf.derive_key_out(&ikm, b"info", KDF_ONE_SHOT_MAX_LEN + 1, &mut long).unwrap(),
            KDF_ONE_SHOT_MAX_LEN + 1
        );
    }

    /// RFC 5869 Sec 2.3: "OKM = first L octets of T", for any L up to 255 * HashLen, so a shorter
    /// output is a prefix of a longer one. Every L from 1 to 200 covers each value of L mod HashLen
    /// for both hashes: the last block used to be produced as an HMAC truncated to the remaining
    /// length, which HMAC refuses below 4 bytes, so every L with L mod HashLen in 1..=3 failed.
    #[test]
    fn every_output_length_is_a_prefix_of_a_longer_one() {
        let salt = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();
        let ikm = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::Seed).unwrap();
        const MAX_L: usize = 200;

        let mut full = KeyMaterial::<MAX_L>::new();
        HKDF_SHA256::extract_and_expand_out(&salt, &ikm, b"info", MAX_L, &mut full).unwrap();
        for l in 1..=MAX_L {
            let mut okm = KeyMaterial::<MAX_L>::new();
            let n = HKDF_SHA256::extract_and_expand_out(&salt, &ikm, b"info", l, &mut okm)
                .unwrap_or_else(|e| panic!("HKDF-SHA256, L = {l}: {e:?}"));
            assert_eq!(n, l, "HKDF-SHA256, L = {l}: bytes written");
            assert_eq!(okm.ref_to_bytes(), &full.ref_to_bytes()[..l], "HKDF-SHA256, L = {l}");
        }

        let mut full = KeyMaterial::<MAX_L>::new();
        HKDF_SHA512::extract_and_expand_out(&salt, &ikm, b"info", MAX_L, &mut full).unwrap();
        for l in 1..=MAX_L {
            let mut okm = KeyMaterial::<MAX_L>::new();
            let n = HKDF_SHA512::extract_and_expand_out(&salt, &ikm, b"info", l, &mut okm)
                .unwrap_or_else(|e| panic!("HKDF-SHA512, L = {l}: {e:?}"));
            assert_eq!(n, l, "HKDF-SHA512, L = {l}: bytes written");
            assert_eq!(okm.ref_to_bytes(), &full.ref_to_bytes()[..l], "HKDF-SHA512, L = {l}");
        }
    }
}
