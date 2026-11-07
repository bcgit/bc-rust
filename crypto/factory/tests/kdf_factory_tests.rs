#[cfg(test)]
mod kdf_factory_tests {
    use bouncycastle_core::key_material::{
        KeyMaterial256, KeyMaterial512, KeyMaterialTrait, KeyType,
    };
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{AlgorithmInfo, KDF};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_factory as factory;
    use bouncycastle_factory::AlgorithmFactory;
    use bouncycastle_factory::kdf_factory::KDFFactory;
    use bouncycastle_sha2::hkdf::HKDF_SHA384;
    use bouncycastle_sm3::hkdf::HKDF_SM3;
    use bouncycastle_utils::ct;

    /// `AlgorithmInfo` answers for the algorithm the factory selected, not for the factory.
    #[test]
    fn alg_name_and_strength_follow_the_variant() {
        use SecurityStrength::*;
        use bouncycastle_sha2::hkdf::{HKDF_SHA256_NAME, HKDF_SHA384_NAME, HKDF_SHA512_NAME};
        use bouncycastle_sha3::{
            SHA3_224_NAME, SHA3_256_NAME, SHA3_384_NAME, SHA3_512_NAME, SHAKE128_NAME,
            SHAKE256_NAME,
        };
        use bouncycastle_sm3::hkdf::HKDF_SM3_NAME;
        let table = [
            (HKDF_SHA256_NAME, _128bit),
            (HKDF_SHA384_NAME, _192bit),
            (HKDF_SHA512_NAME, _256bit),
            (HKDF_SM3_NAME, _128bit),
            (SHA3_224_NAME, _112bit),
            (SHA3_256_NAME, _128bit),
            (SHA3_384_NAME, _192bit),
            (SHA3_512_NAME, _256bit),
            (SHAKE128_NAME, _128bit),
            (SHAKE256_NAME, _256bit),
        ];
        for (name, strength) in table {
            let k = KDFFactory::new(name).unwrap();
            assert_eq!(k.alg_name(), name);
            assert_eq!(k.max_security_strength(), strength, "{name}");
        }
    }

    #[test]
    fn sha3_kdf_tests() {
        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED[..32]).unwrap();

        // SHA3_224
        let derived_key =
            KDFFactory::new("SHA3-224").unwrap().derive_key(&key_material, &[0u8; 0], 28).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\xf6\xaa\xc1\x5e\x45\xb8\x1e\xb4\x12\x59\x32\x98\x4a\x6f\x1a\x90\xb4\x04\xb8\xcd\x64\xde\x5d\xfa\xd5\x63\x89\x4b").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        // assert!(KeyMaterialInternal::equals(&expected_key, derived_key.deref()));
        // assert!(keymaterial_equals(&derived_key, &expected_key));
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHA3_256
        let derived_key =
            KDFFactory::new("SHA3-256").unwrap().derive_key(&key_material, &[0u8; 0], 32).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\xee\x89\xda\x17\x73\x20\x7b\x04\x0e\xed\xd2\x72\x34\xd3\x20\x69\x2a\x86\x57\x26\x29\xb4\x92\x8f\x91\x2f\x74\xc6\xaf\xd8\x75\x8e").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHA3_384
        let derived_key =
            KDFFactory::new("SHA3-384").unwrap().derive_key(&key_material, &[0u8; 0], 48).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\xcf\x19\xcd\x2a\x68\xad\x33\xde\x78\x20\xe8\x0d\xcc\xa4\xa1\x2d\x13\xec\xe2\x3f\x67\x14\x15\xbc\xe8\xed\x90\xdd\xca\x84\x92\xa3\xb3\x06\xe5\xb5\xbd\x8c\x0a\xb8\x2e\xa7\x84\x26\xe3\xad\xb5\xcb").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHA3_512
        let derived_key =
            KDFFactory::new("SHA3-512").unwrap().derive_key(&key_material, &[0u8; 0], 64).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\xc7\x97\x5f\x83\xc1\xcc\x9b\x0b\x4a\x54\x69\x33\x2b\xbe\x3f\x90\x80\x3a\xf7\x24\xcb\x57\xfc\xea\x28\x39\x6a\x03\x6b\x58\xaa\x5b\xc0\x10\xc7\x93\xf6\x56\x62\x51\x97\x10\x68\x36\x73\xff\xb5\xd6\x6f\xf7\xde\x82\xd8\x73\x94\x1f\xbe\xc7\xa2\x42\x86\xa9\x1a\xf3").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHAKE128
        let derived_key =
            KDFFactory::new("SHAKE128").unwrap().derive_key(&key_material, &[0u8; 0], 32).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\xe0\x93\xd6\x47\x05\xb3\x60\x81\x2b\x05\xf1\xb8\xef\x17\x07\xa4\x16\x69\x84\xa3\x66\x4d\x31\xc5\x4e\x76\x1c\xdd\x57\x5d\x49\x44").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHAKE256
        let derived_key =
            KDFFactory::new("SHAKE256").unwrap().derive_key(&key_material, &[0u8; 0], 64).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\x7a\xe8\x3e\xf3\x7d\xd7\xf4\x2e\x02\x52\xde\x4e\xbd\x1e\xdc\xdf\xd3\x68\x9f\x1f\xf6\x5d\x4d\xb2\xf0\x22\x6b\xae\x8f\x18\x0f\x05\xbd\xc7\x05\x34\x4c\xbb\x9b\x4b\x7e\x5a\xf3\x5f\xfe\xda\xb7\x49\x23\x13\x7b\xe0\x75\x79\xdf\xbc\x63\xde\x43\x3e\x15\xec\x14\xb2").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));
    }

    #[test]
    fn hkdf_tests() {
        /* HKDF-SHA256 */
        // Note: this value is not checked against any external reference implementation,
        // The value is hard-coded to ensure consistency.
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();
        let derived_key = KDFFactory::new("HKDF-SHA256")
            .unwrap()
            .derive_key(&key_material, &[0u8; 0], 32)
            .unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\x37\xad\x29\x10\x9f\x43\x26\x52\x87\x80\x4b\x67\x4e\x26\x53\xd0\xa5\x13\x71\x89\x07\xf9\x7f\xca\x97\xc9\x5b\xde\xd8\x10\x4b\xbf").unwrap();
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        /* HKDF-SHA384 */
        // The factory must route to HKDF_SHA384 itself, which is checked against Wycheproof in
        // `bouncycastle-hkdf`; so here its output is compared with the alias used directly.
        let key_material = KeyMaterial512::from_bytes(&DUMMY_SEED[..48]).unwrap();
        let derived_key =
            KDFFactory::new("HKDF-SHA384").unwrap().derive_key(&key_material, b"info", 48).unwrap();
        let expected_key = HKDF_SHA384::new().derive_key(&key_material, b"info", 48).unwrap();
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), expected_key.ref_to_bytes()));
        assert_eq!(derived_key.key_len(), 48, "HKDF-SHA384 derives a hash-length key");

        /* HKDF-SM3 */
        // As for HKDF-SHA384: HKDF_SM3 is checked against known answers in bouncycastle-sm3, so
        // here the factory's output is compared with the alias used directly.
        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED[..32]).unwrap();
        let derived_key =
            KDFFactory::new("HKDF-SM3").unwrap().derive_key(&key_material, b"info", 32).unwrap();
        let expected_key = HKDF_SM3::new().derive_key(&key_material, b"info", 32).unwrap();
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), expected_key.ref_to_bytes()));
        assert_eq!(derived_key.key_len(), 32, "HKDF-SM3 derives a hash-length key");

        // The _out forms fill a longer buffer and report how much they wrote.
        let mut out = KeyMaterial512::new();
        let n = KDFFactory::new("HKDF-SM3")
            .unwrap()
            .derive_key_out(&key_material, b"info", 64, &mut out)
            .unwrap();
        let mut expected_out = KeyMaterial512::new();
        let expected_n =
            HKDF_SM3::new().derive_key_out(&key_material, b"info", 64, &mut expected_out).unwrap();
        assert_eq!(n, 64);
        assert_eq!(n, expected_n);
        assert!(ct::ct_eq_bytes(out.ref_to_bytes(), expected_out.ref_to_bytes()));

        let salt =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[32..64], KeyType::MACKey).unwrap();
        let n = KDFFactory::new("HKDF-SM3")
            .unwrap()
            .derive_key_from_multiple_out(&[&salt, &key_material], b"info", 64, &mut out)
            .unwrap();
        let expected_n = HKDF_SM3::new()
            .derive_key_from_multiple_out(&[&salt, &key_material], b"info", 64, &mut expected_out)
            .unwrap();
        assert_eq!(n, 64);
        assert_eq!(n, expected_n);
        assert!(ct::ct_eq_bytes(out.ref_to_bytes(), expected_out.ref_to_bytes()));

        /* HKDF-SHA512 */
        // Note: this value is not checked against any external reference implementation,
        // The value is hard-coded to ensure consistency.
        let key_material = KeyMaterial512::from_bytes(&DUMMY_SEED[..64]).unwrap();
        let derived_key = KDFFactory::new("HKDF-SHA512")
            .unwrap()
            .derive_key(&key_material, &[0u8; 0], 64)
            .unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\x8f\x5a\x29\x79\xfe\x16\x4d\x3a\x01\x72\x02\x32\x6c\x61\x97\xae\xa2\x58\x56\x3d\x90\x9b\x01\x20\x12\x1c\x37\x22\x6c\xb3\xd3\x68\xf4\x31\xf9\x79\x9d\x33\x8c\xe3\x0e\xfc\x5f\x41\xaf\xfc\x3d\x38\x54\x44\xa0\x65\xae\x80\x78\x60\x59\x45\x79\x50\xa1\xe6\x5e\x57").unwrap();
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));
    }

    #[test]
    fn test_defaults() {
        let key = KeyMaterial256::from_bytes(&DUMMY_SEED[..32]).unwrap();

        // All the ways to get "default"
        let _ = KDFFactory::default().derive_key(&key, &[0u8; 0], 64).unwrap();

        let _ = KDFFactory::new("Default").unwrap().derive_key(&key, &[0u8; 0], 64).unwrap();

        let _ = KDFFactory::new(factory::DEFAULT).unwrap().derive_key(&key, &[0u8; 0], 64).unwrap();

        // All the ways to get "default_128_bit"
        assert_eq!(KDFFactory::default_128_bit().alg_name(), "HKDF-SHA256");
        assert_eq!(KDFFactory::default_256_bit().alg_name(), "HKDF-SHA512");
        let _ = KDFFactory::default_128_bit().derive_key(&key, &[0u8; 0], 32).unwrap();

        let _ = KDFFactory::new("Default128Bit").unwrap().derive_key(&key, &[0u8; 0], 32).unwrap();

        let _ = KDFFactory::new(factory::DEFAULT_128_BIT)
            .unwrap()
            .derive_key(&key, &[0u8; 0], 32)
            .unwrap();

        // All the ways to get "default_256_bit"
        let _ = KDFFactory::default_256_bit().derive_key(&key, &[0u8; 0], 64).unwrap();

        let _ = KDFFactory::new("Default256Bit").unwrap().derive_key(&key, &[0u8; 0], 64).unwrap();

        let _ = KDFFactory::new(factory::DEFAULT_256_BIT)
            .unwrap()
            .derive_key(&key, &[0u8; 0], 64)
            .unwrap();
    }
}
