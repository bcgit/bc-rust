#[cfg(test)]
mod kdf_factory_tests {
    use bouncycastle_factory::AlgorithmFactory;
    use bouncycastle_factory::kdf_factory::{KDFFactory};
    use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyMaterial512, KeyType};
    use bouncycastle_core_interface::traits::{KeyMaterial, KDF};
    use bouncycastle_core_test_framework::DUMMY_SEED_512;
    use bouncycastle_utils::ct;
    use bouncycastle_factory as factory;

    #[test]
    fn sha3_kdf_tests() {
        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED_512[..32]).unwrap();

        // SHA3_224
        let derived_key = KDFFactory::new("SHA3-224").unwrap().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\xbf\xc9\xc1\xe8\x93\x9a\xee\x95\x3c\xa0\xd4\x25\xa2\xf0\xcb\xdd\x2d\x18\x02\x5d\x5d\x6b\x79\x8f\x1c\x81\x50\xb9").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        // assert!(KeyMaterialInternal::equals(&expected_key, derived_key.deref()));
        // assert!(keymaterial_equals(&derived_key, &expected_key));
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHA3_256
        let derived_key = KDFFactory::new("SHA3-256").unwrap().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\x05\x0a\x48\x73\x3b\xd5\xc2\x75\x6b\xa9\x5c\x58\x28\xcc\x83\xee\x16\xfa\xbc\xd3\xc0\x86\x88\x5b\x77\x44\xf8\x4a\x0f\x9e\x0d\x94").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHA3_384
        let derived_key = KDFFactory::new("SHA3-384").unwrap().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\xe0\x86\xa2\xb6\xa6\x9b\xb6\xfa\xe3\x7c\xaa\x70\x73\x57\x23\xe7\xcc\x8a\xe2\x18\x37\x88\xfb\xb4\xa5\xf1\xcc\xac\xd8\x32\x26\x85\x2c\xa6\xfa\xff\x50\x3e\x12\xff\x95\x42\x3f\x94\xf8\x72\xdd\xa3").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHA3_512
        let derived_key = KDFFactory::new("SHA3-512").unwrap().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\xcb\xd3\xf6\xee\xba\x67\x6b\x21\xe0\xf2\xc4\x75\x22\x29\x24\x82\xfd\x83\x0f\x33\x0c\x1d\x84\xa7\x94\xbb\x94\x72\x8b\x2d\x93\xfe\xbe\x4c\x18\xea\xe5\xa7\xe0\x17\xe3\x5f\xa0\x90\xde\x24\x26\x2e\x70\x95\x1a\xd1\xd7\xdf\xb3\xa8\xc9\x6d\x11\x34\xfb\x18\x79\xf2").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHAKE128
        let derived_key = KDFFactory::new("SHAKE128").unwrap().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10\xce\xc0\xce\xcf\x79\x85\x9e\xc0\xfe\xc3\xd4\x09\xe5\x84\x7a\x92").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));

        // SHAKE256
        let derived_key = KDFFactory::new("SHAKE256").unwrap().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\x69\xf0\x7c\x88\x40\xce\x80\x02\x4d\xb3\x09\x39\x88\x2c\x3d\x5b\xbc\x9c\x98\xb3\xe3\x1e\x45\x13\xeb\xd2\xca\x9b\x45\x03\xcd\xd3\xc9\xc9\x07\x42\x45\x2c\x71\x73\xd4\xa7\x5a\xc4\x91\x63\xe1\x4e\xe0\xcc\x24\xef\x70\x35\xb2\x72\xd1\x9a\x7a\xf1\x09\x9b\x33\x3f").unwrap();
        // assert_eq!(&derived_key, &expected_key);
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));
    }
    
    #[test]
    fn hkdf_tests() {
        /* HKDF-SHA256 */
        // Note: this value is not checked against any external reference implementation,
        // I just hard-coded the value to make sure it stays consistent.
        let key_material = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::MACKey).unwrap();
        let derived_key = KDFFactory::new("HKDF-SHA256").unwrap().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\x37\xad\x29\x10\x9f\x43\x26\x52\x87\x80\x4b\x67\x4e\x26\x53\xd0\xa5\x13\x71\x89\x07\xf9\x7f\xca\x97\xc9\x5b\xde\xd8\x10\x4b\xbf").unwrap();
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));


        /* HKDF-SHA512 */
        // Note: this value is not checked against any external reference implementation,
        // I just hard-coded the value to make sure it stays consistent.
        let key_material = KeyMaterial512::from_bytes(&DUMMY_SEED_512[..64]).unwrap();
        let derived_key = KDFFactory::new("HKDF-SHA512").unwrap().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\x8f\x5a\x29\x79\xfe\x16\x4d\x3a\x01\x72\x02\x32\x6c\x61\x97\xae\xa2\x58\x56\x3d\x90\x9b\x01\x20\x12\x1c\x37\x22\x6c\xb3\xd3\x68\xf4\x31\xf9\x79\x9d\x33\x8c\xe3\x0e\xfc\x5f\x41\xaf\xfc\x3d\x38\x54\x44\xa0\x65\xae\x80\x78\x60\x59\x45\x79\x50\xa1\xe6\x5e\x57").unwrap();
        assert!(ct::ct_eq_bytes(derived_key.ref_to_bytes(), &expected_key.ref_to_bytes()));
    }

    #[test]
    fn test_defaults() {
        let key = KeyMaterial256::from_bytes(&DUMMY_SEED_512[..32]).unwrap();

        // All the ways to get "default"
        let _ = KDFFactory::default().derive_key(&key, &[0u8; 0]).unwrap();

        let _ = KDFFactory::new("Default").unwrap().derive_key(&key, &[0u8; 0]).unwrap();

        let _ = KDFFactory::new(factory::DEFAULT).unwrap().derive_key(&key, &[0u8; 0]).unwrap();

        // All the ways to get "default_128_bit"
        let _ = KDFFactory::default_128_bit().derive_key(&key, &[0u8; 0]).unwrap();

        let _ = KDFFactory::new("Default128Bit").unwrap().derive_key(&key, &[0u8; 0]).unwrap();

        let _ = KDFFactory::new(factory::DEFAULT_128_BIT).unwrap().derive_key(&key, &[0u8; 0]).unwrap();


        // All the ways to get "default_256_bit"
        let _ = KDFFactory::default_256_bit().derive_key(&key, &[0u8; 0]).unwrap();

        let _ = KDFFactory::new("Default256Bit").unwrap().derive_key(&key, &[0u8; 0]).unwrap();

        let _ = KDFFactory::new(factory::DEFAULT_256_BIT).unwrap().derive_key(&key, &[0u8; 0]).unwrap();
    }
}