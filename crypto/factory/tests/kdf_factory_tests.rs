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
        use bouncycastle_sm3::hkdf::HKDF_SM3_NAME;
        let table = [
            (HKDF_SHA256_NAME, _128bit),
            (HKDF_SHA384_NAME, _192bit),
            (HKDF_SHA512_NAME, _256bit),
            (HKDF_SM3_NAME, _128bit),
        ];
        for (name, strength) in table {
            let k = KDFFactory::new(name).unwrap();
            assert_eq!(k.alg_name(), name);
            assert_eq!(k.max_security_strength(), strength, "{name}");
        }
    }

    /// Each concatenation KDF name selects its own instantiation: the factory's name, strength
    /// and output, through both `_out` forms, are the alias's (whose vectors live in
    /// `bouncycastle-concatkdf`).
    #[test]
    fn concat_kdf_variants_route_to_their_instantiation() {
        use bouncycastle_concatkdf::{
            ConcatKDF_SHA3_256, ConcatKDF_SHA3_384, ConcatKDF_SHA3_512, ConcatKDF_SHA256,
            ConcatKDF_SHA384, ConcatKDF_SHA512,
        };
        let z = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::CryptographicRandom)
            .unwrap();
        let direct: [(&dyn KDF, SecurityStrength); 6] = [
            (&ConcatKDF_SHA256::new(), SecurityStrength::_128bit),
            (&ConcatKDF_SHA384::new(), SecurityStrength::_192bit),
            (&ConcatKDF_SHA512::new(), SecurityStrength::_256bit),
            (&ConcatKDF_SHA3_256::new(), SecurityStrength::_128bit),
            (&ConcatKDF_SHA3_384::new(), SecurityStrength::_192bit),
            (&ConcatKDF_SHA3_512::new(), SecurityStrength::_256bit),
        ];
        for (kdf, strength) in direct {
            let name = kdf.alg_name();
            let f = KDFFactory::new(name).unwrap();
            assert_eq!(f.alg_name(), name);
            assert_eq!(f.max_security_strength(), strength, "{name}");

            let (mut out, mut expected) = (KeyMaterial512::new(), KeyMaterial512::new());
            assert_eq!(f.derive_key_out(&z, b"info", 40, &mut out).unwrap(), 40);
            kdf.derive_key_out(&z, b"info", 40, &mut expected).unwrap();
            assert!(ct::ct_eq_bytes(out.ref_to_bytes(), expected.ref_to_bytes()), "{name}");

            let keys: [&dyn KeyMaterialTrait; 2] = [&z, &z];
            assert_eq!(f.derive_key_from_multiple_out(&keys, b"info", 40, &mut out).unwrap(), 40);
            kdf.derive_key_from_multiple_out(&keys, b"info", 40, &mut expected).unwrap();
            assert!(ct::ct_eq_bytes(out.ref_to_bytes(), expected.ref_to_bytes()), "{name}");
        }
    }

    /// Each X9.63 KDF name selects its own instantiation, checked against a known answer per
    /// arm: NIST CAVP `ansx963_2001.rsp` (the file `bouncycastle-x963kdf` reads from
    /// bc-test-data), the first record of the `[SHA-256]`, `[SHA-384]` and `[SHA-512]` sections
    /// with a 192-bit shared secret, no SharedInfo and 128 bits of key data.
    #[test]
    fn x963_kdf_variants_route_to_their_instantiation() {
        use bouncycastle_hex::decode as hex_decode;
        use bouncycastle_x963kdf::{X963KDF_SHA256_NAME, X963KDF_SHA384_NAME, X963KDF_SHA512_NAME};
        let table = [
            (
                X963KDF_SHA256_NAME,
                SecurityStrength::_128bit,
                "96c05619d56c328ab95fe84b18264b08725b85e33fd34f08",
                "443024c3dae66b95e6f5670601558f71",
            ),
            (
                X963KDF_SHA384_NAME,
                SecurityStrength::_192bit,
                "d8554db1b392cd55c3fe957bed76af09c13ac2a9392f88f6",
                "671a46aada145162f8ddf1ca586a1cda",
            ),
            (
                X963KDF_SHA512_NAME,
                SecurityStrength::_256bit,
                "87fc0d8c4477485bb574f5fcea264b30885dc8d90ad82782",
                "947665fbb9152153ef460238506a0245",
            ),
        ];
        for (name, strength, z, key_data) in table {
            let f = KDFFactory::new(name).unwrap();
            assert_eq!(f.alg_name(), name);
            assert_eq!(f.max_security_strength(), strength, "{name}");

            let z =
                KeyMaterial256::from_bytes_as_type(&hex_decode(z).unwrap(), KeyType::SharedSecret)
                    .unwrap();
            let expected = hex_decode(key_data).unwrap();
            let mut out = KeyMaterial256::new();
            assert_eq!(f.derive_key_out(&z, b"", 16, &mut out).unwrap(), 16, "{name}");
            assert!(ct::ct_eq_bytes(out.ref_to_bytes(), &expected), "{name}");
            let keys: [&dyn KeyMaterialTrait; 1] = [&z];
            assert_eq!(f.derive_key_from_multiple_out(&keys, b"", 16, &mut out).unwrap(), 16);
            assert!(ct::ct_eq_bytes(out.ref_to_bytes(), &expected), "{name}");
        }
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
