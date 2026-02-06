#[cfg(test)]
mod test_key_material {
    use bouncycastle_core_interface::errors::KeyMaterialError;
    use bouncycastle_core_interface::key_material::{
        KeyMaterial0, KeyMaterial128, KeyMaterial256, KeyMaterial512, KeyMaterialInternal, KeyType,
    };
    use bouncycastle_core_interface::traits::{KeyMaterial, SecurityStrength};

    const DUMMY_KEY: &[u8; 64] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
                                   \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\
                                   \x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\
                                   \x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F";

    #[test]
    fn source_data_too_long() {
        const DUMMY_KEY_TOO_LONG: &[u8; 66] =
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
                                   \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\
                                   \x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\
                                   \x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3A\x3B\x3C\x3D\x3E\x3F\
                                   \x40\x41";

        match KeyMaterial512::from_bytes(DUMMY_KEY_TOO_LONG) {
            Err(KeyMaterialError::InputDataLongerThanKeyCapacity) => { /* good */ }
            _ => panic!("Expected InvalidLength"),
        }

        // But you can slice it down.
        match KeyMaterial512::from_bytes(&DUMMY_KEY_TOO_LONG[..64]) {
            Ok(key) => assert_eq!(key.key_len(), 64),
            _ => panic!("Expected InvalidLength"),
        }
    }

    #[test]
    fn test_set_bytes_as_type() {
        let key_bytes = [0u8; 16];
        let mut key = KeyMaterial256::new();
        let res = key.set_bytes_as_type(&key_bytes, KeyType::BytesLowEntropy);
        match res {
            Ok(_) => {
                panic!("should have thrown a KeyMaterialError::ActingOnZeroizedKey error.")
            }
            Err(KeyMaterialError::ActingOnZeroizedKey) => {
                // it correctly succeeded and threw an error
                assert_eq!(key.key_type(), KeyType::Zeroized);
                assert_eq!(key.key_len(), 16);

                // ... but we can force it.
                key.allow_hazardous_operations();
                key.set_key_type(KeyType::BytesLowEntropy).unwrap();
                key.drop_hazardous_operations();
            }
            Err(_) => {
                panic!("should have thrown a KeyMaterialError::ActingOnZeroizedKey error.")
            }
        }
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::None);

        // but it'll allow it if you allow hazardous operations first.
        let key_bytes = [0u8; 16];
        let mut key = KeyMaterial256::new();
        key.allow_hazardous_operations();
        key.set_bytes_as_type(&key_bytes, KeyType::BytesLowEntropy).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);

        // nothing else requires setting hazardous operations.
    }

    #[test]
    fn test_refs() {
        let mut key = KeyMaterial256::from_bytes(&[1u8; 16]).unwrap();
        assert_eq!(key.capacity(), 32);
        assert_eq!(key.ref_to_bytes(), &[1u8; 16]); // note: this is also testing that even though the internal buffer is larger than 16 bytes, it slices it down to length.

        match key.mut_ref_to_bytes() {
            Ok(_) => {
                panic!("getting a mut ref should require setting hazardous operations.")
            }
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            Err(_) => {
                panic!("getting a mut ref should require setting hazardous operations.")
            }
        }
        key.allow_hazardous_operations();
        assert_eq!(key.mut_ref_to_bytes().unwrap().len(), 32);
        assert_eq!(key.mut_ref_to_bytes().unwrap()[..16], [1u8; 16]);
        assert_eq!(key.mut_ref_to_bytes().unwrap()[16..], [0u8; 16]);

        // and I can set them
        key.mut_ref_to_bytes().unwrap().copy_from_slice(&[2u8; 32]);
        key.set_key_len(32).unwrap();
        assert_eq!(key.ref_to_bytes(), &[2u8; 32]);
        assert_eq!(key.key_len(), 32);
    }

    #[test]
    fn test_variable_length() {
        let key = KeyMaterial128::new();
        assert_eq!(key.capacity(), 16);

        let key = KeyMaterial256::new();
        assert_eq!(key.capacity(), 32);

        let key = KeyMaterial512::new();
        assert_eq!(key.capacity(), 64);

        let key16 = KeyMaterialInternal::<16>::new();
        assert_eq!(key16.capacity(), 16);
        match KeyMaterialInternal::<16>::from_bytes(&[1u8; 17]) {
            Ok(_) => {
                panic!("should have thrown a KeyMaterialError::InputDataLongerThanMaxKeyLen error.")
            }
            Err(KeyMaterialError::InputDataLongerThanKeyCapacity) => { /*** good ***/ }
            Err(_) => {
                panic!(
                    "should have thrown a KeyMaterialError::InputDataLongerThanMaxKeyLen error, but it threw something different."
                )
            }
        }

        let key1024 = KeyMaterialInternal::<1024>::new();
        assert_eq!(key1024.capacity(), 1024);
        assert_eq!(key1024.key_len(), 0);
        let key1024 = KeyMaterialInternal::<1024>::from_bytes(&[1u8; 1024]).unwrap();
        assert_eq!(key1024.key_len(), 1024);

        match KeyMaterialInternal::<1024>::from_bytes(&[1u8; 1025]) {
            Ok(_) => {
                panic!("should have thrown a KeyMaterialError::InputDataLongerThanMaxKeyLen error.")
            }
            Err(KeyMaterialError::InputDataLongerThanKeyCapacity) => { /*** good ***/ }
            Err(_) => {
                panic!(
                    "should have thrown a KeyMaterialError::InputDataLongerThanMaxKeyLen error, but it threw something different."
                )
            }
        }
    }

    #[test]
    fn from_bytes() {
        let key = KeyMaterial512::from_bytes(&DUMMY_KEY[..64]).unwrap();
        assert_eq!(key.key_len(), 64);
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);

        // Basic success case
        let key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::BytesFullEntropy).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::_128bit);

        // Success case: KeyType::BytesLowEntropy gets tagged with SecurityStrength::None.
        let key = KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::BytesLowEntropy);
        assert_eq!(key.unwrap().security_strength(), SecurityStrength::None);
    }

    #[test]
    fn new_from_rng() {
        use bouncycastle_rng as rng;

        let key = KeyMaterial256::from_rng(&mut rng::DefaultRNG::default()).unwrap();
        assert_eq!(key.key_len(), 32);
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);

        let key = KeyMaterial512::from_rng(&mut rng::DefaultRNG::default()).unwrap();
        assert_eq!(key.key_len(), 64);
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
    }

    #[test]
    fn zeroize() {
        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.zeroize();
        let key_len = key.key_len();
        assert_eq!(key_len, 0);
        assert_eq!(key.key_type(), KeyType::Zeroized);

        key.allow_hazardous_operations();
        let mut buf = vec![0u8; key_len];
        buf.copy_from_slice(key.ref_to_bytes());
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_truncate() {
        let mut key = KeyMaterial512::from_bytes(&DUMMY_KEY[..64]).unwrap();
        assert_eq!(key.key_len(), 64);

        // This should be no change
        match key.truncate(64) {
            Ok(()) => { /* good */ }
            _ => panic!("Expected Ok(())"),
        }
        assert_eq!(key.key_len(), 64);

        key.truncate(32).unwrap();
        assert_eq!(key.key_len(), 32);

        match key.truncate(64) {
            Err(KeyMaterialError::InvalidLength) => { /* good */ }
            _ => panic!("Expected InvalidLength"),
        }

        key.truncate(16).unwrap();
        assert_eq!(key.key_len(), 16);

        key.allow_hazardous_operations();
        let key_len = key.key_len();
        let mut buf = vec![0u8; key_len];
        buf.copy_from_slice(key.ref_to_bytes());
        const DUMMY_KEY_16: &[u8; 16] =
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        assert_eq!(buf, DUMMY_KEY_16);

        // Test truncating a key to zero length
        let mut key_zero = KeyMaterial512::from_bytes(&DUMMY_KEY[..64]).unwrap();
        key_zero.truncate(0).unwrap();
        assert_eq!(key_zero.key_len(), 0);
        assert_eq!(key_zero.key_type(), KeyType::Zeroized);

        // test security strength interactions with truncation
        let mut key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 64], KeyType::BytesFullEntropy).unwrap();
        assert_eq!(key.security_strength(), SecurityStrength::_256bit);
        key.truncate(16).unwrap();
        assert_eq!(key.security_strength(), SecurityStrength::_128bit);
        key.truncate(14).unwrap();
        assert_eq!(key.security_strength(), SecurityStrength::_112bit);
        key.truncate(11).unwrap();
        assert_eq!(key.security_strength(), SecurityStrength::None);

        // truncate should not raise the security level
        let mut key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 64], KeyType::BytesFullEntropy).unwrap();
        key.set_security_strength(SecurityStrength::_112bit).unwrap();
        key.drop_hazardous_operations();
        key.truncate(64).unwrap();
        assert_eq!(key.security_strength(), SecurityStrength::_112bit);
    }

    #[test]
    fn test_conversions() {
        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);
        assert!(!key.is_full_entropy());

        // Note: can't use the usual assert_eq!() here because that requires PartialEq, but we're in a no_std context here.
        match key.key_type() {
            KeyType::BytesLowEntropy => { /* good */ }
            _ => panic!("Expected BytesLowEntropy"),
        }

        // This should fail.
        match key.convert_key_type(KeyType::BytesFullEntropy) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }

        key.allow_hazardous_operations();
        key.convert_key_type(KeyType::BytesFullEntropy).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert!(key.is_full_entropy());

        key.drop_hazardous_operations();
        match key.convert_key_type(KeyType::SymmetricCipherKey) {
            Ok(()) => { /* good */ }
            _ => panic!("Expected Ok(())"),
        }
        match key.convert_key_type(KeyType::BytesFullEntropy) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }

        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.convert_key_type(KeyType::BytesFullEntropy).unwrap();
        match key.convert_key_type(KeyType::Seed) {
            Ok(()) => { /* good */ }
            _ => panic!("Expected Ok(())"),
        }

        // each KeyType can convert to itself

        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.set_key_type(KeyType::BytesLowEntropy).unwrap();
        key.drop_hazardous_operations();
        key.convert_key_type(KeyType::BytesLowEntropy).unwrap();

        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.set_key_type(KeyType::BytesFullEntropy).unwrap();
        key.drop_hazardous_operations();
        key.convert_key_type(KeyType::BytesFullEntropy).unwrap();

        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.set_key_type(KeyType::MACKey).unwrap();
        key.drop_hazardous_operations();
        key.convert_key_type(KeyType::MACKey).unwrap();

        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.set_key_type(KeyType::SymmetricCipherKey).unwrap();
        key.drop_hazardous_operations();
        key.convert_key_type(KeyType::SymmetricCipherKey).unwrap();

        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.set_key_type(KeyType::Seed).unwrap();
        key.drop_hazardous_operations();
        key.convert_key_type(KeyType::Seed).unwrap();
    }

    #[test]
    fn test_zeroized_key() {
        let mut zeroized_key = KeyMaterial256::default();
        assert_eq!(zeroized_key.key_type(), KeyType::Zeroized);

        /* All conversions should fail. */
        match zeroized_key.convert_key_type(KeyType::BytesLowEntropy) {
            Err(KeyMaterialError::ActingOnZeroizedKey) => { /* good */ }
            _ => panic!("Expected ActingOnZeroizedKey"),
        }
        match zeroized_key.convert_key_type(KeyType::BytesFullEntropy) {
            Err(KeyMaterialError::ActingOnZeroizedKey) => { /* good */ }
            _ => panic!("Expected ActingOnZeroizedKey"),
        }
        match zeroized_key.convert_key_type(KeyType::MACKey) {
            Err(KeyMaterialError::ActingOnZeroizedKey) => { /* good */ }
            _ => panic!("Expected ActingOnZeroizedKey"),
        }
        match zeroized_key.convert_key_type(KeyType::Seed) {
            Err(KeyMaterialError::ActingOnZeroizedKey) => { /* good */ }
            _ => panic!("Expected ActingOnZeroizedKey"),
        }
        match zeroized_key.convert_key_type(KeyType::SymmetricCipherKey) {
            Err(KeyMaterialError::ActingOnZeroizedKey) => { /* good */ }
            _ => panic!("Expected ActingOnZeroizedKey"),
        }

        let zero_key = KeyMaterial256::from_bytes(&[0u8; 19]).unwrap();
        // it should have set the key bytes and length, but also set the key type to Zeroized.
        assert_eq!(zero_key.key_type(), KeyType::Zeroized);
        assert_eq!(zero_key.key_len(), 19);
        assert_eq!(zero_key.ref_to_bytes(), &[0u8; 19]);

        // But it's totally fine if you give it non-zero input data.
        let not_zero_key = KeyMaterial256::from_bytes(&[1u8; 19]).unwrap();
        assert_eq!(not_zero_key.key_type(), KeyType::BytesLowEntropy);

        // test .set_bytes_as_type()
        // it should detect if you give it all zero input data.
        let mut zero_key = KeyMaterial256::new();
        match zero_key.set_bytes_as_type(&[0u8; 19], KeyType::MACKey) {
            Ok(_) => {
                panic!("should have thrown a KeyMaterialError::ActingOnZeroizedKey error.")
            }
            Err(KeyMaterialError::ActingOnZeroizedKey) => { /*** good ***/ }
            Err(_) => {
                panic!("should have thrown a KeyMaterialError::ActingOnZeroizedKey error.")
            }
        }
        // but it should still have set the key bytes; it's just giving you a friendly warning
        assert_eq!(zero_key.key_type(), KeyType::Zeroized);

        // ... but will allow it if you set .allow_hazardous_operations() first.
        let mut zero_key = KeyMaterial256::new();
        zero_key.allow_hazardous_operations();
        zero_key.set_bytes_as_type(&[0u8; 19], KeyType::MACKey).unwrap();
        zero_key.drop_hazardous_operations();
        assert_eq!(zero_key.key_type(), KeyType::MACKey);
    }

    #[test]
    /// Tests the conversions that should only be allowed if hazardous_conversions() has been set.
    fn test_hazardous_conversions_from_bytes() {
        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);

        /* All the non-hazardous conversions should work. */
        // ... none

        /* All the hazardous conversions should fail. */
        match key.convert_key_type(KeyType::BytesFullEntropy) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }
        match key.convert_key_type(KeyType::MACKey) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }
        match key.convert_key_type(KeyType::SymmetricCipherKey) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }
        match key.convert_key_type(KeyType::Seed) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }

        /* Should work if you allow hazardous conversions. */
        key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.convert_key_type(KeyType::BytesFullEntropy).unwrap();

        key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.convert_key_type(KeyType::MACKey).unwrap();

        key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.convert_key_type(KeyType::SymmetricCipherKey).unwrap();

        key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.convert_key_type(KeyType::Seed).unwrap();
    }

    #[test]
    /// impl Display for KeyMaterial to not print the key data.
    fn test_display() {
        let key = KeyMaterial256::from_bytes_as_type(&DUMMY_KEY[..32], KeyType::MACKey).unwrap();
        // println!("{:?}", key);

        // test fmt
        assert_eq!(
            format!("{}", key),
            "KeyMaterial { len: 32, key_type: MACKey, security_strength: _256bit }"
        );

        // test debug
        assert_eq!(
            format!("{:?}", key),
            "KeyMaterial { len: 32, key_type: MACKey, security_strength: _256bit }"
        );
    }

    #[test]
    fn from_keymaterial() {
        let key1 = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();

        // success case: same size using default From impl; only works if the sizes are the same (ie the compiler knows that they are the same type.
        let key2 = KeyMaterial256::from(key1.clone());
        assert_eq!(key1.key_len(), key2.key_len());
        assert_eq!(key1.key_type(), key2.key_type());
        assert_eq!(key1, key2);

        // success case: same size
        let key2 = KeyMaterial256::from_key(&key1).unwrap();
        assert_eq!(key1.key_len(), key2.key_len());
        assert_eq!(key1.key_type(), key2.key_type());
        assert_eq!(key1, key2);

        // success case: bigger
        let key2 = KeyMaterial512::from_key(&key1).unwrap();
        assert_eq!(key1.key_len(), key2.key_len());
        assert_eq!(key1.key_type(), key2.key_type());
        assert_eq!(key1.ref_to_bytes(), &key2.ref_to_bytes()[..key1.key_len()]);
    }

    #[test]
    /// Not exhaustive, cargo mutants will probably not be satisfied.
    fn test_hazardous_conversions_cast_types() {
        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key.allow_hazardous_operations();
        key.convert_key_type(KeyType::MACKey).unwrap();
        key.drop_hazardous_operations();

        // converting to self should work (idempotency)
        key.convert_key_type(KeyType::MACKey).unwrap();

        /* All the hazardous conversions should fail. */
        match key.convert_key_type(KeyType::BytesFullEntropy) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }
        match key.convert_key_type(KeyType::SymmetricCipherKey) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }
        match key.convert_key_type(KeyType::Seed) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected HazardousConversion"),
        }

        // should work if you allow hazardous conversions.
        key.allow_hazardous_operations();
        key.convert_key_type(KeyType::SymmetricCipherKey).unwrap();
    }

    #[test]
    fn test_security_strength() {
        let key = KeyMaterial512::from_bytes(DUMMY_KEY).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::None);

        let key = KeyMaterial512::from_bytes_as_type(DUMMY_KEY, KeyType::BytesFullEntropy).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::_256bit);

        let key = KeyMaterial512::from_bytes_as_type(&DUMMY_KEY[..32], KeyType::BytesFullEntropy)
            .unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::_256bit);

        let key = KeyMaterial512::from_bytes_as_type(&DUMMY_KEY[..31], KeyType::BytesFullEntropy)
            .unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::_192bit);

        let key = KeyMaterial512::from_bytes_as_type(&DUMMY_KEY[..24], KeyType::BytesFullEntropy)
            .unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::_192bit);

        let key = KeyMaterial512::from_bytes_as_type(&DUMMY_KEY[..16], KeyType::BytesFullEntropy)
            .unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::_128bit);

        let key = KeyMaterial512::from_bytes_as_type(&DUMMY_KEY[..15], KeyType::BytesFullEntropy)
            .unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::_112bit);

        let key = KeyMaterial512::from_bytes_as_type(&DUMMY_KEY[..14], KeyType::BytesFullEntropy)
            .unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::_112bit);

        let key = KeyMaterial512::from_bytes_as_type(&DUMMY_KEY[..13], KeyType::BytesFullEntropy)
            .unwrap();
        assert_eq!(key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(key.security_strength(), SecurityStrength::None);

        // even if it's long enough, BytesLowEntropy or Zeroized always get ::None
        let key = KeyMaterial512::from_bytes_as_type(DUMMY_KEY, KeyType::BytesLowEntropy).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(key.key_len(), 64);
        assert_eq!(key.security_strength(), SecurityStrength::None);

        let key = KeyMaterial512::from_bytes_as_type(DUMMY_KEY, KeyType::Zeroized).unwrap();
        assert_eq!(key.key_type(), KeyType::Zeroized);
        assert_eq!(key.key_len(), 64);
        assert_eq!(key.security_strength(), SecurityStrength::None);

        // test set_security_strength()
        // Can't increase the security level without setting .allow_hazardous_operations() first.
        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);
        match key.set_security_strength(SecurityStrength::_128bit) {
            Err(KeyMaterialError::HazardousOperationNotPermitted) => { /* good */ }
            _ => panic!("Expected KeyMaterialError::HazardousOperationNotPermitted"),
        }
        key.allow_hazardous_operations();
        match key.set_security_strength(SecurityStrength::_128bit) {
            Err(KeyMaterialError::SecurityStrength(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError::SecurityStrength"),
        }

        // So let's set it to a full-entropy type
        key.set_key_type(KeyType::BytesFullEntropy).unwrap();
        // now it should work
        key.set_security_strength(SecurityStrength::_128bit).unwrap();
        assert_eq!(key.security_strength(), SecurityStrength::_128bit);

        // BytesLowEntropy keys cannot have a security strength other than None.
        // success
        let mut key = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        assert_eq!(key.key_type(), KeyType::BytesLowEntropy);
        // setting to ::None should work .. even without setting .allow_hazardous_operations()
        key.set_security_strength(SecurityStrength::None).unwrap();
        // but to ::_128bit should fail
        key.allow_hazardous_operations();
        match key.set_security_strength(SecurityStrength::_128bit) {
            Err(KeyMaterialError::SecurityStrength(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError::SecurityStrength"),
        }

        // Zeroized keys cannot have a security strength other than None.
        // success
        let mut key = KeyMaterial256::new();
        key.allow_hazardous_operations();
        key.set_key_len(32).unwrap(); // still zeroized
        assert_eq!(key.key_type(), KeyType::Zeroized);
        // setting to ::None should work .. even without setting .allow_hazardous_operations()
        key.set_security_strength(SecurityStrength::None).unwrap();
        // but to ::_128bit should fail
        key.allow_hazardous_operations();
        match key.set_security_strength(SecurityStrength::_128bit) {
            Err(KeyMaterialError::SecurityStrength(_)) => { /* good */ }
            _ => panic!("Expected KeyMaterialError::SecurityStrength"),
        }
    }

    #[test]
    fn test_concatenate() {
        // intentionally half-full
        let mut key1 = KeyMaterial256::from_bytes(&[1u8; 16]).unwrap();
        let key2 = KeyMaterial256::from_bytes(&[2u8; 16]).unwrap();
        assert_eq!(key1.key_len(), 16);
        assert_eq!(key2.key_len(), 16);

        key1.concatenate(&key2).unwrap();
        assert_eq!(key1.key_len(), 32);
        assert_eq!(key1.ref_to_bytes()[..16], [1u8; 16]);
        assert_eq!(key1.ref_to_bytes()[16..], [2u8; 16]);

        let mut zeroized_key = KeyMaterial256::default();
        zeroized_key.allow_hazardous_operations();
        zeroized_key.set_key_len(8).unwrap();
        zeroized_key.drop_hazardous_operations();
        assert_eq!(zeroized_key.key_type(), KeyType::Zeroized);
        assert_eq!(zeroized_key.key_len(), 8);
        zeroized_key.concatenate(&key2).unwrap();
        assert_eq!(zeroized_key.key_len(), 24);
        // should take max(Zeroized, BytesLowEntropy)
        assert_eq!(zeroized_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(zeroized_key.security_strength(), SecurityStrength::None);

        // This should be symmetric, so test it in the other direction too.
        let mut zeroized_key = KeyMaterial256::default();
        zeroized_key.allow_hazardous_operations();
        zeroized_key.set_key_len(8).unwrap();
        zeroized_key.drop_hazardous_operations();
        assert_eq!(zeroized_key.key_type(), KeyType::Zeroized);
        assert_eq!(zeroized_key.key_len(), 8);
        let mut key2 = KeyMaterial256::from_bytes(&[1u8; 16]).unwrap();
        key2.concatenate(&zeroized_key).unwrap();
        assert_eq!(key2.key_len(), 24);
        // should take max(Zeroized, BytesLowEntropy)
        assert_eq!(key2.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(key2.security_strength(), SecurityStrength::None);

        // now try it with keys of different key types
        let mut low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::BytesLowEntropy).unwrap();
        let full_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[2u8; 16], KeyType::BytesFullEntropy).unwrap();
        low_entropy_key.concatenate(&full_entropy_key).unwrap();
        // should take max(BytesLowEntropy, BytesFullEntropy)
        assert_eq!(low_entropy_key.key_type(), KeyType::BytesFullEntropy);
        // should take max(None, _128Bit)
        assert_eq!(low_entropy_key.security_strength(), SecurityStrength::_128bit);

        // and in the other direction too
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::BytesLowEntropy).unwrap();
        let mut full_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[2u8; 16], KeyType::BytesFullEntropy).unwrap();
        full_entropy_key.concatenate(&low_entropy_key).unwrap();
        // should take max(BytesLowEntropy, BytesFullEntropy)
        assert_eq!(full_entropy_key.key_type(), KeyType::BytesFullEntropy);
        // should take max(None, _128Bit)
        assert_eq!(full_entropy_key.security_strength(), SecurityStrength::_128bit);

        // now with full entropy keys at different security levels
        let mut low_entropy_key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 16], KeyType::BytesFullEntropy).unwrap();
        // Now we're gonna explictly tag it at the 112bit security level -- does not require allow_hazardous_operations().
        low_entropy_key.set_security_strength(SecurityStrength::_112bit).unwrap();
        let full_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[2u8; 32], KeyType::BytesFullEntropy).unwrap();
        low_entropy_key.concatenate(&full_entropy_key).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::BytesFullEntropy);
        // should take max(_112Bit, _256Bit)
        assert_eq!(low_entropy_key.security_strength(), SecurityStrength::_256bit);
    }

    #[test]
    fn eq() {
        // On instances of the same exact type (size).
        let key1 = KeyMaterial256::from_bytes(
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        )
        .unwrap();
        let key2 = KeyMaterial256::from_bytes(
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
        )
        .unwrap();
        assert_eq!(key1, key2);

        let key3 = KeyMaterial256::from_bytes(
            b"\x0F\x0E\x0D\x0C\x0B\x0A\x10\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00",
        )
        .unwrap();
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_equals() {
        // This differs from eq in that it doesn't have to be the same size (ie the same type)

        // success case -- zero keys -- same type
        let key1 = KeyMaterial0::new();
        let key2 = KeyMaterial0::new();
        assert!(key1.equals(&key2));
        assert!(key2.equals(&key1));

        // success case -- zero keys -- different type
        let key1 = KeyMaterial0::new();
        let key2 = KeyMaterial256::new();
        assert!(key1.equals(&key2));
        assert!(key2.equals(&key1));

        // success case -- zero keys -- different type and different KeyType
        let key1 = KeyMaterial0::new();
        let mut key2 = KeyMaterial256::new();
        key2.allow_hazardous_operations();
        key2.convert_key_type(KeyType::SymmetricCipherKey).unwrap();
        assert!(key1.equals(&key2));
        assert!(key2.equals(&key1));

        // success case -- non-zero keys -- different type
        let key1 = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        let key2 = KeyMaterial512::from_bytes(&DUMMY_KEY[..32]).unwrap();
        assert!(key1.equals(&key2));
        assert!(key2.equals(&key1));

        // success case -- non-zero keys -- different type and different KeyType
        let key1 = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        let mut key2 = KeyMaterial512::from_bytes(&DUMMY_KEY[..32]).unwrap();
        key2.allow_hazardous_operations();
        key2.convert_key_type(KeyType::SymmetricCipherKey).unwrap();
        assert!(key1.equals(&key2));
        assert!(key2.equals(&key1));

        // error case -- different key_len
        let key1 = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        let key2 = KeyMaterial512::from_bytes(&DUMMY_KEY[..64]).unwrap();
        assert!(!key1.equals(&key2));
        assert!(!key2.equals(&key1));

        // error case -- different buf
        let key1 = KeyMaterial256::from_bytes(&DUMMY_KEY[..32]).unwrap();
        let key2 = KeyMaterial512::from_bytes(&DUMMY_KEY[32..64]).unwrap();
        assert!(!key1.equals(&key2));
        assert!(!key2.equals(&key1));
    }

    #[test]
    fn partial_ord() {
        use KeyType::*;
        use std::cmp::Ordering;

        fn rank(kt: KeyType) -> u8 {
            match kt {
                Zeroized => 0,
                BytesLowEntropy => 1,
                BytesFullEntropy => 2,
                Seed | MACKey | SymmetricCipherKey => 3,
            }
        }

        let all_types =
            [Zeroized, BytesLowEntropy, BytesFullEntropy, Seed, MACKey, SymmetricCipherKey];

        for &a in &all_types {
            for &b in &all_types {
                let expected = if rank(a) < rank(b) {
                    Ordering::Less
                } else if rank(a) > rank(b) {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                };
                assert_eq!(
                    a.partial_cmp(&b),
                    Some(expected),
                    "{:?} cmp {:?} should be {:?}",
                    a,
                    b,
                    expected
                );
            }
        }
    }
}
