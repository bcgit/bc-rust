//! ML-KEM with its shared secret derived through HKDF: the three pairings through the core
//! framework, on plain and expanded keys, and what the derivation is.

// `K` is FIPS 203's name for the shared secret key.
#![allow(non_snake_case)]

#[cfg(test)]
mod mlkem_hkdf_tests {
    use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
    use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{Algorithm, AlgorithmInfo, KEMDecapsulator};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::kem::TestFrameworkKEM;
    use bouncycastle_mlkem::{
        KdfParams, MLKEM512, MLKEM512_CT_LEN, MLKEM512_HKDF_SHA256, MLKEM512_HKDF_SHA256_SS_LEN,
        MLKEM512PrivateKey, MLKEM512PrivateKeyExpanded, MLKEM512PublicKey,
        MLKEM512PublicKeyExpanded, MLKEM768, MLKEM768_CT_LEN, MLKEM768_HKDF_SHA512,
        MLKEM768_HKDF_SHA512_SS_LEN, MLKEM768PrivateKey, MLKEM768PublicKey, MLKEM1024,
        MLKEM1024_CT_LEN, MLKEM1024_HKDF_SHA512, MLKEM1024_HKDF_SHA512_SS_LEN, MLKEM1024PrivateKey,
        MLKEM1024PublicKey, MLKEMTrait,
    };
    use bouncycastle_rng::DefaultRNG;
    use bouncycastle_sha2::hkdf::{HKDF_SHA256, HKDF_SHA512};

    /// A 32-byte salt of the kind a protocol draws: typed, not secret.
    fn salt() -> KeyMaterial<32> {
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[64..96], KeyType::CryptographicRandom)
            .unwrap()
    }

    const INFO: &[u8] = b"mlkem hkdf tests";

    #[test]
    fn core_framework_tests() {
        let tf = TestFrameworkKEM::new(false, true);
        let salt = salt();
        let hkdf256 = HKDF_SHA256::new_with_salt(&salt).unwrap();
        let hkdf512 = HKDF_SHA512::new_with_salt(&salt).unwrap();
        let sha256 = KdfParams::new(&hkdf256, INFO);
        let sha512 = KdfParams::new(&hkdf512, INFO);

        tf.test_kem::<
            KdfParams<'_, HKDF_SHA256>,
            MLKEM512PublicKey,
            MLKEM512PrivateKey,
            MLKEM512_CT_LEN,
            MLKEM512_HKDF_SHA256_SS_LEN,
        >(|| MLKEM512::keygen(&mut DefaultRNG::default()), sha256, false);
        tf.test_kem::<
            KdfParams<'_, HKDF_SHA512>,
            MLKEM768PublicKey,
            MLKEM768PrivateKey,
            MLKEM768_CT_LEN,
            MLKEM768_HKDF_SHA512_SS_LEN,
        >(|| MLKEM768::keygen(&mut DefaultRNG::default()), sha512, false);
        tf.test_kem::<
            KdfParams<'_, HKDF_SHA512>,
            MLKEM1024PublicKey,
            MLKEM1024PrivateKey,
            MLKEM1024_CT_LEN,
            MLKEM1024_HKDF_SHA512_SS_LEN,
        >(|| MLKEM1024::keygen(&mut DefaultRNG::default()), sha512, false);

        // the expanded keys carry the same roles
        tf.test_kem::<
            KdfParams<'_, HKDF_SHA256>,
            MLKEM512PublicKeyExpanded,
            MLKEM512PrivateKeyExpanded,
            MLKEM512_CT_LEN,
            MLKEM512_HKDF_SHA256_SS_LEN,
        >(
            || {
                let (pk, sk) = MLKEM512::keygen(&mut DefaultRNG::default())?;
                Ok((MLKEM512PublicKeyExpanded::from(&pk), MLKEM512PrivateKeyExpanded::from(&sk)))
            },
            sha256,
            false,
        );
    }

    /// The derived key is HKDF-Hash(salt, K, info) over the plain ML-KEM secret of the same
    /// ciphertext, one hash output long, typed and at the marker's strength.
    #[test]
    fn the_derived_key_is_hkdf_over_the_plain_secret() {
        let mut rng = DefaultRNG::default();
        let salt = salt();
        let hkdf256 = HKDF_SHA256::new_with_salt(&salt).unwrap();
        let hkdf512 = HKDF_SHA512::new_with_salt(&salt).unwrap();

        let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
        let params = KdfParams::new(&hkdf256, INFO);
        let (key, ct) = pk.encaps(&mut rng, params).unwrap();
        let K = sk.decaps(&ct, ()).unwrap();
        let mut expected = KeyMaterial::<MLKEM512_HKDF_SHA256_SS_LEN>::new();
        HKDF_SHA256::extract_and_expand_out(
            &salt,
            &K,
            INFO,
            MLKEM512_HKDF_SHA256_SS_LEN,
            &mut expected,
        )
        .unwrap();
        assert_eq!(key, expected);
        assert_eq!(key.key_len(), MLKEM512_HKDF_SHA256_SS_LEN);
        assert_eq!(key.key_type(), KeyType::CryptographicRandom);
        assert_eq!(key.security_strength(), SecurityStrength::_128bit);
        assert_eq!(sk.decaps(&ct, params).unwrap(), expected);

        let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();
        let params = KdfParams::new(&hkdf512, INFO);
        let (key, ct) = pk.encaps(&mut rng, params).unwrap();
        let K = sk.decaps(&ct, ()).unwrap();
        let mut expected = KeyMaterial::<MLKEM768_HKDF_SHA512_SS_LEN>::new();
        HKDF_SHA512::extract_and_expand_out(
            &salt,
            &K,
            INFO,
            MLKEM768_HKDF_SHA512_SS_LEN,
            &mut expected,
        )
        .unwrap();
        assert_eq!(key, expected);
        assert_eq!(key.key_len(), MLKEM768_HKDF_SHA512_SS_LEN);
        assert_eq!(key.key_type(), KeyType::CryptographicRandom);
        assert_eq!(key.security_strength(), SecurityStrength::_192bit);

        let (pk, sk) = MLKEM1024::keygen(&mut rng).unwrap();
        let (key, ct) = pk.encaps(&mut rng, params).unwrap();
        let K = sk.decaps(&ct, ()).unwrap();
        let mut expected = KeyMaterial::<MLKEM1024_HKDF_SHA512_SS_LEN>::new();
        HKDF_SHA512::extract_and_expand_out(
            &salt,
            &K,
            INFO,
            MLKEM1024_HKDF_SHA512_SS_LEN,
            &mut expected,
        )
        .unwrap();
        assert_eq!(key, expected);
        assert_eq!(key.security_strength(), SecurityStrength::_256bit);
    }

    /// The salt and the info are both part of the derivation, and a zero-length salt is RFC 5869's
    /// absent one.
    #[test]
    fn salt_and_info_select_the_key() {
        let mut rng = DefaultRNG::default();
        let salt = salt();
        let hkdf256 = HKDF_SHA256::new_with_salt(&salt).unwrap();
        let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
        let params = KdfParams::new(&hkdf256, INFO);
        let (key, ct) = pk.encaps(&mut rng, params).unwrap();

        let other_info = KdfParams::new(&hkdf256, b"another context");
        assert_ne!(sk.decaps(&ct, other_info).unwrap(), key);

        let other_salt =
            KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[96..128], KeyType::MACKey).unwrap();
        let hkdf_other_salt = HKDF_SHA256::new_with_salt(&other_salt).unwrap();
        let other = KdfParams::new(&hkdf_other_salt, INFO);
        assert_ne!(sk.decaps(&ct, other).unwrap(), key);

        let absent = KeyMaterial0::new();
        let hkdf_absent = HKDF_SHA256::new_with_salt(&absent).unwrap();
        let no_salt = KdfParams::new(&hkdf_absent, INFO);
        let derived = sk.decaps(&ct, no_salt).unwrap();
        assert_ne!(derived, key);
        let K = sk.decaps(&ct, ()).unwrap();
        let mut expected = KeyMaterial::<MLKEM512_HKDF_SHA256_SS_LEN>::new();
        HKDF_SHA256::extract_and_expand_out(
            &absent,
            &K,
            INFO,
            MLKEM512_HKDF_SHA256_SS_LEN,
            &mut expected,
        )
        .unwrap();
        assert_eq!(derived, expected);
    }

    #[test]
    fn algorithm_names_and_strengths() {
        assert_eq!(MLKEM512_HKDF_SHA256::ALG_NAME, "ML-KEM-512-HKDF-SHA256");
        assert_eq!(MLKEM512_HKDF_SHA256::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
        assert_eq!(MLKEM768_HKDF_SHA512::ALG_NAME, "ML-KEM-768-HKDF-SHA512");
        assert_eq!(MLKEM768_HKDF_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
        assert_eq!(MLKEM1024_HKDF_SHA512::ALG_NAME, "ML-KEM-1024-HKDF-SHA512");
        assert_eq!(MLKEM1024_HKDF_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);

        let salt = salt();
        let hkdf512 = HKDF_SHA512::new_with_salt(&salt).unwrap();
        let (_pk, sk) = MLKEM768::keygen(&mut DefaultRNG::default()).unwrap();
        let worker = sk.create_decapsulator(KdfParams::new(&hkdf512, INFO)).unwrap();
        assert_eq!(worker.alg_name(), "ML-KEM-768-HKDF-SHA512");
        let _: &dyn KEMDecapsulator<MLKEM768_CT_LEN, MLKEM768_HKDF_SHA512_SS_LEN> = &worker;
    }
}
