//! HKDF-SM3 tests. There are no published HKDF-SM3 vectors (RFC 5869 covers SHA-1 and SHA-256,
//! Wycheproof has no SM3 HKDF file), so the known answers are RFC 5869 Appendix A's three
//! SHA-256 test-case inputs run through OpenSSL 3.0.13
//! (`openssl kdf -kdfopt digest:SM3 ... HKDF`, `mode:EXTRACT_ONLY` for the PRK), whose SHA-256
//! output for the same inputs reproduces the RFC's values.

#[cfg(test)]
mod hkdf_sm3_tests {
    use bouncycastle_core::hazmat::do_hazardous_operations;
    use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{Algorithm, AlgorithmInfo};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
    use bouncycastle_hex as hex;
    use bouncycastle_sm3::hkdf::{HKDF_SM3, HKDF_SM3_NAME, SUSPENDED_HKDF_SM3_STATE_LEN};

    /// Key material of any length and content, including empty or all-zero, as the RFC 5869
    /// vectors need.
    fn key(hex_str: &str, key_type: KeyType) -> KeyMaterial<100> {
        let mut k = KeyMaterial::<100>::new();
        do_hazardous_operations(&mut k, |k| {
            k.set_bytes_as_type(&hex::decode(hex_str).unwrap(), key_type)
        })
        .unwrap();
        k
    }

    #[test]
    fn algorithm() {
        assert_eq!(HKDF_SM3::ALG_NAME, HKDF_SM3_NAME);
        assert_eq!(HKDF_SM3::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
        assert_eq!(HKDF_SM3::new().alg_name(), "HKDF-SM3");
        assert_eq!(SUSPENDED_HKDF_SM3_STATE_LEN, 122);
    }

    /// `(ikm, salt, info, prk, okm)`, from RFC 5869 Appendix A.1, A.2 and A.3's inputs.
    const KATS: [(&str, &str, &str, &str, &str); 3] = [
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "000102030405060708090a0b0c",
            "f0f1f2f3f4f5f6f7f8f9",
            "e0d6f7b0bd056327b7659f1f39ad850561fbcf4fb10fb58e88eafa55cf7cd01e",
            "c69fe91b7aaee2dd5718d72dcaee0cce93f1b8e41f792da51261b6a517e68b36ed2c595572b01dfa359b",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "1a43a7fedb2d111eb33babd0d256c272aa3262cdb12e6b43d4321ae8888485d5",
            "c1226236bbdefa7921f9febe27b864f33e449201b436d8844ea53f58170dd6426defbd22ed1f3c5960f35523e62e3b6c0d657f2c61893436f539013199bfaef25aafd1e7726ede927623a9f5cbb8885c7e5d",
        ),
        (
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "",
            "",
            "004fc37143377d072d74e82ff480e8d7937ec607411bc1ec65dd34401871ff9c",
            "c8c91a38ae2fb3b023a7c38ce9f0748f28230d59b6b950ba3ba949bf0d713a5774815778801741cb2034",
        ),
    ];

    #[test]
    fn known_answers() {
        for (ikm, salt, info, prk, okm) in KATS {
            let ikm = key(ikm, KeyType::CryptographicRandom);
            let salt = key(salt, KeyType::MACKey);
            let info = hex::decode(info).unwrap();
            let okm = hex::decode(okm).unwrap();

            // Extract, then expand.
            let mut prk_key = HKDF_SM3::extract(&salt, &ikm).unwrap();
            assert_eq!(prk_key.ref_to_bytes(), hex::decode(prk).unwrap());
            // Some inputs are too short to meet the seeding rules; the PRK is used as a key anyway.
            do_hazardous_operations(&mut prk_key, |p| p.set_key_type(KeyType::MACKey)).unwrap();
            let mut out = KeyMaterial::<100>::new();
            HKDF_SM3::expand_out(&prk_key, &info, okm.len(), &mut out).unwrap();
            assert_eq!(out.ref_to_bytes(), &okm[..]);

            // The streaming extract gives the same PRK.
            let mut hkdf = HKDF_SM3::new();
            hkdf.do_extract_init(&salt).unwrap();
            for chunk in ikm.ref_to_bytes().chunks(5) {
                hkdf.do_extract_update_bytes(chunk).unwrap();
            }
            assert_eq!(hkdf.do_extract_final().unwrap().ref_to_bytes(), hex::decode(prk).unwrap());
        }
    }

    #[test]
    fn as_kdf() {
        // derive_key uses an all-zero salt and a hash-length output, which is the extract and
        // expand of the same inputs truncated to 32 bytes.
        let ikm = key(&hex::encode(&DUMMY_SEED[..64]), KeyType::MACKey);
        let zero_salt = key(&"00".repeat(32), KeyType::MACKey);
        let info = &DUMMY_SEED[64..80];

        let mut expected = KeyMaterial::<64>::new();
        HKDF_SM3::extract_and_expand_out(&zero_salt, &ikm, info, 64, &mut expected).unwrap();
        let mut expected_truncated = expected.clone();
        expected_truncated.set_key_len(32).unwrap();

        let framework = TestFrameworkKDF::new();
        framework.test_kdf_single_key::<HKDF_SM3>(&ikm, info, &expected_truncated);
        framework.test_kdf_multiple_key::<HKDF_SM3>(&[&zero_salt, &ikm], info, &mut expected);
    }

    #[test]
    fn suspendable_keyed_state() {
        use bouncycastle_core::traits::SuspendableKeyed;
        use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;

        let salt = key("000102030405060708090a0b0c", KeyType::MACKey);
        let (part1, part2) = DUMMY_SEED[..48].split_at(20);

        let mut hkdf = HKDF_SM3::new();
        hkdf.do_extract_init(&salt).unwrap();
        hkdf.do_extract_update_bytes(part1).unwrap();
        TestFrameworkSuspendableKeyedState::new().test(&hkdf, &salt);

        let mut uninterrupted = hkdf.clone();
        uninterrupted.do_extract_update_bytes(part2).unwrap();
        let expected = uninterrupted.do_extract_final().unwrap();

        let state = hkdf.suspend();
        assert_eq!(state.len(), SUSPENDED_HKDF_SM3_STATE_LEN);
        let mut resumed = HKDF_SM3::from_suspended(state, &salt).unwrap();
        resumed.do_extract_update_bytes(part2).unwrap();
        assert_eq!(resumed.do_extract_final().unwrap().ref_to_bytes(), expected.ref_to_bytes());
    }

    #[test]
    fn struct_size() {
        assert_eq!(size_of::<HKDF_SM3>(), 368);
    }
}
