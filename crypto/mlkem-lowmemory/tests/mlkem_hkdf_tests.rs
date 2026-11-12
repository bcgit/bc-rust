//! ML-KEM with its shared secret derived through HKDF: the three pairings through the core
//! framework, on seed and expanded keys, what the derivation is, and agreement with
//! `bouncycastle-mlkem` on the same keys.

// `K` is FIPS 203's name for the shared secret key.
#![allow(non_snake_case)]

#[cfg(test)]
mod mlkem_hkdf_tests {
    use bouncycastle_core::errors::KeyMaterialError;
    use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
    use bouncycastle_core::key_material::{
        KeyMaterial, KeyMaterial0, KeyMaterial512, KeyMaterialTrait, KeyType,
    };
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{Algorithm, AlgorithmInfo, KEMDecapsulator};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::kem::TestFrameworkKEM;
    use bouncycastle_hkdf::HkdfDescription;
    use bouncycastle_mlkem as full;
    use bouncycastle_mlkem_lowmemory::{
        KdfParams, KeyLen, MLKEM512, MLKEM512_CT_LEN, MLKEM512_HKDF_SHA256,
        MLKEM512_HKDF_SHA256_SS_LEN, MLKEM512PrivateKey, MLKEM512PrivateKeyExpanded,
        MLKEM512PublicKey, MLKEM768, MLKEM768_CT_LEN, MLKEM768_HKDF_SHA512,
        MLKEM768_HKDF_SHA512_SS_LEN, MLKEM768PrivateKey, MLKEM768PublicKey, MLKEM1024,
        MLKEM1024_CT_LEN, MLKEM1024_HKDF_SHA512, MLKEM1024_HKDF_SHA512_SS_LEN, MLKEM1024PrivateKey,
        MLKEM1024PublicKey, MLKEMTrait,
    };
    use bouncycastle_rng::DefaultRNG;
    use bouncycastle_sha2::hkdf::{HKDF_SHA256, HKDF_SHA512};
    use bouncycastle_sha2::{SHA256, SHA512};
    #[allow(unused_imports)]
    use full::MLKEMTrait as _;

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
        let hkdf256 = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
        let hkdf512 = HkdfDescription::<SHA512>::with_salt(&salt).unwrap();
        let sha256 = KdfParams::new(&hkdf256, INFO, KeyLen::<MLKEM512_HKDF_SHA256_SS_LEN>);
        let sha512 = KdfParams::new(&hkdf512, INFO, KeyLen::<MLKEM768_HKDF_SHA512_SS_LEN>);

        tf.test_kem::<
            KdfParams<'_, HkdfDescription<'_, SHA256>, MLKEM512_HKDF_SHA256_SS_LEN>,
            MLKEM512PublicKey,
            MLKEM512PrivateKey,
            MLKEM512_CT_LEN,
            MLKEM512_HKDF_SHA256_SS_LEN,
        >(|| MLKEM512::keygen(&mut DefaultRNG::default()), sha256, false);
        tf.test_kem::<
            KdfParams<'_, HkdfDescription<'_, SHA512>, MLKEM768_HKDF_SHA512_SS_LEN>,
            MLKEM768PublicKey,
            MLKEM768PrivateKey,
            MLKEM768_CT_LEN,
            MLKEM768_HKDF_SHA512_SS_LEN,
        >(|| MLKEM768::keygen(&mut DefaultRNG::default()), sha512, false);
        // a derived key shorter than the strength's bytes carries what it can
        tf.test_kem::<KdfParams<'_, HkdfDescription<'_, SHA512>, 16>, MLKEM768PublicKey, MLKEM768PrivateKey, MLKEM768_CT_LEN, 16>(
            || MLKEM768::keygen(&mut DefaultRNG::default()),
            KdfParams::new(&hkdf512, INFO, KeyLen::<16>),
            false,
        );
        tf.test_kem::<
            KdfParams<'_, HkdfDescription<'_, SHA512>, MLKEM1024_HKDF_SHA512_SS_LEN>,
            MLKEM1024PublicKey,
            MLKEM1024PrivateKey,
            MLKEM1024_CT_LEN,
            MLKEM1024_HKDF_SHA512_SS_LEN,
        >(|| MLKEM1024::keygen(&mut DefaultRNG::default()), sha512, false);

        // the expanded private key carries the same role
        tf.test_kem::<
            KdfParams<'_, HkdfDescription<'_, SHA256>, MLKEM512_HKDF_SHA256_SS_LEN>,
            MLKEM512PublicKey,
            MLKEM512PrivateKeyExpanded,
            MLKEM512_CT_LEN,
            MLKEM512_HKDF_SHA256_SS_LEN,
        >(
            || {
                let (pk, sk) = MLKEM512::keygen(&mut DefaultRNG::default())?;
                Ok((pk, MLKEM512PrivateKeyExpanded::from(&sk)))
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
        let hkdf256 = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
        let hkdf512 = HkdfDescription::<SHA512>::with_salt(&salt).unwrap();

        let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
        let params = KdfParams::new(&hkdf256, INFO, KeyLen::<MLKEM512_HKDF_SHA256_SS_LEN>);
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
        let params = KdfParams::new(&hkdf512, INFO, KeyLen::<MLKEM768_HKDF_SHA512_SS_LEN>);
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
        let hkdf256 = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
        let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
        let params = KdfParams::new(&hkdf256, INFO, KeyLen::<MLKEM512_HKDF_SHA256_SS_LEN>);
        let (key, ct) = pk.encaps(&mut rng, params).unwrap();

        let other_info =
            KdfParams::new(&hkdf256, b"another context", KeyLen::<MLKEM512_HKDF_SHA256_SS_LEN>);
        assert_ne!(sk.decaps(&ct, other_info).unwrap(), key);

        let other_salt =
            KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[96..128], KeyType::MACKey).unwrap();
        let hkdf_other_salt = HkdfDescription::<SHA256>::with_salt(&other_salt).unwrap();
        assert_ne!(
            sk.decaps(
                &ct,
                KdfParams::new(&hkdf_other_salt, INFO, KeyLen::<MLKEM512_HKDF_SHA256_SS_LEN>)
            )
            .unwrap(),
            key
        );

        let absent = KeyMaterial0::new();
        let hkdf_absent = HkdfDescription::<SHA256>::with_salt(&absent).unwrap();
        let derived = sk
            .decaps(&ct, KdfParams::new(&hkdf_absent, INFO, KeyLen::<MLKEM512_HKDF_SHA256_SS_LEN>))
            .unwrap();
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

    /// The parameters name the derived key's length: ML-KEM-768-HKDF-SHA512 derives 32 bytes
    /// when asked, the first 32 of the 64-byte key (RFC 5869 Section 2.3's OKM is the first L
    /// octets of T), typed and at the pairing's strength; 16 bytes carry what 16 bytes can; and
    /// 255 hash outputs is the most, for either HKDF.
    #[test]
    fn the_parameters_name_the_length() {
        let mut rng = DefaultRNG::default();
        let salt = salt();
        let hkdf512 = HkdfDescription::<SHA512>::with_salt(&salt).unwrap();
        let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();
        let (key, ct) = pk.encaps(&mut rng, KdfParams::new(&hkdf512, INFO, KeyLen::<64>)).unwrap();

        let short = sk.decaps(&ct, KdfParams::new(&hkdf512, INFO, KeyLen::<32>)).unwrap();
        assert_eq!(short.key_len(), 32);
        assert_eq!(short.ref_to_bytes(), &key.ref_to_bytes()[..32]);
        assert_eq!(short.key_type(), KeyType::CryptographicRandom);
        assert_eq!(short.security_strength(), SecurityStrength::_192bit);

        let tiny = sk.decaps(&ct, KdfParams::new(&hkdf512, INFO, KeyLen::<16>)).unwrap();
        assert_eq!(tiny.ref_to_bytes(), &key.ref_to_bytes()[..16]);
        assert_eq!(tiny.security_strength(), SecurityStrength::_128bit);

        let long = sk.decaps(&ct, KdfParams::new(&hkdf512, INFO, KeyLen::<{ 255 * 64 }>)).unwrap();
        assert_eq!(long.key_len(), 255 * 64);
        assert_eq!(&long.ref_to_bytes()[..64], key.ref_to_bytes());
        assert_eq!(long.security_strength(), SecurityStrength::_192bit);

        // HKDF-SHA256's cap is 255 of its own outputs
        let hkdf256 = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
        let (pk, sk) = MLKEM512::keygen(&mut rng).unwrap();
        let (key, ct) = pk.encaps(&mut rng, KdfParams::new(&hkdf256, INFO, KeyLen::<32>)).unwrap();
        let long = sk.decaps(&ct, KdfParams::new(&hkdf256, INFO, KeyLen::<{ 255 * 32 }>)).unwrap();
        assert_eq!(long.key_len(), 255 * 32);
        assert_eq!(&long.ref_to_bytes()[..32], key.ref_to_bytes());
    }

    /// A secret salt (SP 800-56C Rev. 2 Section 5.1, a `MACKey`) is credited by HKDF, which
    /// labels the derivation above the KEM's strength; the pairing caps the key's label at its
    /// own.
    #[test]
    fn a_secret_salt_does_not_lift_the_key_above_the_pairings_strength() {
        let mut rng = DefaultRNG::default();
        let secret_salt =
            KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::MACKey).unwrap();
        let hkdf512 = HkdfDescription::<SHA512>::with_salt(&secret_salt).unwrap();
        let params = KdfParams::new(&hkdf512, INFO, KeyLen::<MLKEM768_HKDF_SHA512_SS_LEN>);
        let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();
        let (key, ct) = pk.encaps(&mut rng, params).unwrap();
        assert_eq!(key.key_type(), KeyType::CryptographicRandom);
        assert_eq!(key.security_strength(), MLKEM768_HKDF_SHA512::MAX_SECURITY_STRENGTH);
        assert_eq!(key.security_strength(), SecurityStrength::_192bit);
        assert_eq!(sk.decaps(&ct, params).unwrap(), key);

        // the same derivation through HKDF alone carries the salt's strength
        let K = sk.decaps(&ct, ()).unwrap();
        let mut alone = KeyMaterial::<MLKEM768_HKDF_SHA512_SS_LEN>::new();
        HKDF_SHA512::extract_and_expand_out(
            &secret_salt,
            &K,
            INFO,
            MLKEM768_HKDF_SHA512_SS_LEN,
            &mut alone,
        )
        .unwrap();
        assert_eq!(alone.security_strength(), SecurityStrength::_256bit);
        assert_eq!(alone.ref_to_bytes(), key.ref_to_bytes());
    }

    /// A description an engine cannot be built from does not exist: a salt typed `Unknown` is
    /// refused where the description is made, and the salt a description holds is readable, so
    /// a key held in a token can hand its device the same derivation.
    #[test]
    fn a_description_names_a_readable_salt_and_refuses_an_unknown_one() {
        let salt = salt();
        let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
        assert_eq!(hkdf.salt().unwrap().ref_to_bytes(), salt.ref_to_bytes());
        assert_eq!(hkdf.salt().unwrap().key_type(), KeyType::CryptographicRandom);
        assert!(HkdfDescription::<SHA256>::new().salt().is_none());
        let unknown =
            KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Unknown).unwrap();
        assert!(matches!(
            HkdfDescription::<SHA256>::with_salt(&unknown),
            Err(KeyMaterialError::InvalidKeyType(_))
        ));
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
        let hkdf512 = HkdfDescription::<SHA512>::with_salt(&salt).unwrap();
        let (_pk, sk) = MLKEM768::keygen(&mut DefaultRNG::default()).unwrap();
        let worker = sk
            .create_decapsulator(KdfParams::new(
                &hkdf512,
                INFO,
                KeyLen::<MLKEM768_HKDF_SHA512_SS_LEN>,
            ))
            .unwrap();
        assert_eq!(worker.alg_name(), "ML-KEM-768-HKDF-SHA512");
        let _: &dyn KEMDecapsulator<MLKEM768_CT_LEN, MLKEM768_HKDF_SHA512_SS_LEN> = &worker;
    }

    /// The two crates derive the same key from the same seed, parameters and ciphertext.
    #[test]
    fn agrees_with_the_full_crate() {
        let mut rng = DefaultRNG::default();
        let seed = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::Seed).unwrap();
        let salt = salt();
        let hkdf256 = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
        let hkdf512 = HkdfDescription::<SHA512>::with_salt(&salt).unwrap();

        let (pk_low, sk_low) = MLKEM512::keygen_from_seed(&seed).unwrap();
        let (pk_full, sk_full) = full::MLKEM512::keygen_from_seed(&seed).unwrap();
        let params = KdfParams::new(&hkdf256, INFO, KeyLen::<MLKEM512_HKDF_SHA256_SS_LEN>);
        let (key, ct) = pk_low.encaps(&mut rng, params).unwrap();
        assert_eq!(sk_full.decaps(&ct, params).unwrap(), key);
        let (key, ct) = pk_full.encaps(&mut rng, params).unwrap();
        assert_eq!(sk_low.decaps(&ct, params).unwrap(), key);

        let (pk_low, sk_low) = MLKEM1024::keygen_from_seed(&seed).unwrap();
        let (_pk_full, sk_full) = full::MLKEM1024::keygen_from_seed(&seed).unwrap();
        let params = KdfParams::new(&hkdf512, INFO, KeyLen::<MLKEM1024_HKDF_SHA512_SS_LEN>);
        let (key, ct) = pk_low.encaps(&mut rng, params).unwrap();
        assert_eq!(sk_full.decaps(&ct, params).unwrap(), key);
        assert_eq!(sk_low.decaps(&ct, params).unwrap(), key);
    }
}
