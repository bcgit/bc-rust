//! ML-KEM with its shared secret derived through HKDF: the three pairings through the core
//! framework, on plain and expanded keys, and what the derivation is.

// `K` is FIPS 203's name for the shared secret key.
#![allow(non_snake_case)]

#[cfg(test)]
mod mlkem_hkdf_tests {
    use bouncycastle_core::errors::{KEMError, KeyMaterialError};
    use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
    use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{Algorithm, AlgorithmInfo, KEMDecapsulator};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::kem::TestFrameworkKEM;
    use bouncycastle_mlkem::{
        HkdfParams, MLKEM512, MLKEM512_CT_LEN, MLKEM512_HKDF_SHA256, MLKEM512_HKDF_SHA256_SS_LEN,
        MLKEM512PrivateKey, MLKEM512PrivateKeyExpanded, MLKEM512PublicKey,
        MLKEM512PublicKeyExpanded, MLKEM768, MLKEM768_CT_LEN, MLKEM768_HKDF_SHA512,
        MLKEM768_HKDF_SHA512_SS_LEN, MLKEM768PrivateKey, MLKEM768PublicKey, MLKEM1024,
        MLKEM1024_CT_LEN, MLKEM1024_HKDF_SHA512, MLKEM1024_HKDF_SHA512_SS_LEN, MLKEM1024PrivateKey,
        MLKEM1024PublicKey, MLKEMTrait,
    };
    use bouncycastle_rng::DefaultRNG;
    use bouncycastle_sha2::hkdf::{HKDF_SHA256, HKDF_SHA512};
    use bouncycastle_sha2::{SHA256, SHA512};

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
        let sha256 = HkdfParams::<SHA256>::new(&salt, INFO);
        let sha512 = HkdfParams::<SHA512>::new(&salt, INFO);

        tf.test_kem::<
            HkdfParams<'_, SHA256>,
            MLKEM512PublicKey,
            MLKEM512PrivateKey,
            MLKEM512_CT_LEN,
            MLKEM512_HKDF_SHA256_SS_LEN,
        >(|| MLKEM512::keygen(&mut DefaultRNG::default()), sha256, false);
        tf.test_kem::<
            HkdfParams<'_, SHA512>,
            MLKEM768PublicKey,
            MLKEM768PrivateKey,
            MLKEM768_CT_LEN,
            MLKEM768_HKDF_SHA512_SS_LEN,
        >(|| MLKEM768::keygen(&mut DefaultRNG::default()), sha512, false);
        tf.test_kem::<
            HkdfParams<'_, SHA512>,
            MLKEM1024PublicKey,
            MLKEM1024PrivateKey,
            MLKEM1024_CT_LEN,
            MLKEM1024_HKDF_SHA512_SS_LEN,
        >(|| MLKEM1024::keygen(&mut DefaultRNG::default()), sha512, false);

        // the expanded keys carry the same roles
        tf.test_kem::<
            HkdfParams<'_, SHA256>,
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

        let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
        let params = HkdfParams::<SHA256>::new(&salt, INFO);
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
        let params = HkdfParams::<SHA512>::new(&salt, INFO);
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
        let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
        let params = HkdfParams::<SHA256>::new(&salt, INFO);
        let (key, ct) = pk.encaps(&mut rng, params).unwrap();

        let other_info = HkdfParams::<SHA256>::new(&salt, b"another context");
        assert_ne!(sk.decaps(&ct, other_info).unwrap(), key);

        let other_salt =
            KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[96..128], KeyType::MACKey).unwrap();
        let other = HkdfParams::<SHA256>::new(&other_salt, INFO);
        assert_ne!(sk.decaps(&ct, other).unwrap(), key);

        let absent = KeyMaterial0::new();
        let no_salt = HkdfParams::<SHA256>::new(&absent, INFO);
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

    /// A salt typed `Unknown` is refused when the worker is made, by every construction path.
    #[test]
    fn an_unknown_salt_is_refused_at_construction() {
        let mut rng = DefaultRNG::default();
        let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
        let unknown =
            KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Unknown).unwrap();
        let params = HkdfParams::<SHA256>::new(&unknown, INFO);
        let refused = |r: Result<_, KEMError>| {
            assert!(matches!(
                r,
                Err(KEMError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
            ));
        };
        refused(pk.create_encapsulator(params).map(|_| ()));
        refused(sk.create_decapsulator(params).map(|_| ()));
        refused(pk.encaps(&mut rng, params).map(|_| ()));
        refused(sk.decaps(&[0u8; MLKEM512_CT_LEN], params).map(|_| ()));
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
        let (_pk, sk) = MLKEM768::keygen(&mut DefaultRNG::default()).unwrap();
        let worker = sk.create_decapsulator(HkdfParams::<SHA512>::new(&salt, INFO)).unwrap();
        assert_eq!(worker.alg_name(), "ML-KEM-768-HKDF-SHA512");
        let _: &dyn KEMDecapsulator<MLKEM768_CT_LEN, MLKEM768_HKDF_SHA512_SS_LEN> = &worker;
    }
}
