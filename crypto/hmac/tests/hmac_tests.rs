#[cfg(test)]
mod hmac_tests {
    use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyMaterial512, KeyMaterialInternal, KeyType};
    use bouncycastle_core_interface::traits::{Algorithm, Hash, KeyMaterial, SecurityStrength, MAC};
    use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
    use bouncycastle_hex as hex;
    use bouncycastle_core_interface::errors::{KeyMaterialError, MACError};
    use bouncycastle_core_test_framework::DUMMY_SEED_512;
    use bouncycastle_hmac::*;
    use bouncycastle_sha2::*;
    use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

    #[test]
    fn simple_tests() {
        // Simple test with zero-length key
        let mut zero_length_key = KeyMaterial256::default();
        zero_length_key.allow_hazardous_operations();
        zero_length_key.convert_key_type(KeyType::MACKey).unwrap();
        assert_eq!(zero_length_key.key_len(), 0);
        assert_eq!(zero_length_key.key_type(), KeyType::MACKey);

        let mut mac = HMAC::<SHA256>::new_allow_weak_key(&zero_length_key).unwrap();
        mac.do_update("Hi There".as_bytes());
        let output = mac.do_final();
        assert_eq!(output, b"\xe4\x84\x11\x26\x27\x15\xc8\x37\x0c\xd5\xe7\xbf\x8e\x82\xbe\xf5\x3b\xd5\x37\x12\xd0\x07\xf3\x42\x93\x51\x84\x3b\x77\xc7\xbb\x9b");

        // RFC4231 Test Case 1 for SHA224
        let key = KeyMaterial256::from_bytes_as_type(
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            KeyType::MACKey,
        ).unwrap();
        let mut mac = HMAC::<SHA224>::new(&key).unwrap();
        mac.do_update(b"Hi There");
        let output = mac.do_final();
        assert_eq!(output, b"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22");

        // success case: do_final without do_update (ie empty content)
        let key = KeyMaterial256::from_bytes_as_type(
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            KeyType::MACKey,
        ).unwrap();
        let mac = HMAC::<SHA256>::new(&key).unwrap();
        // mac.do_update(b"").unwrap();
        let output = mac.do_final();
        assert_eq!(&output, &hex::decode("999a901219f032cd497cadb5e6051e97b6a29ab297bd6ae722bd6062a2f59542").unwrap());
    }

    #[test]
    fn test_type_aliases() {
        let key = KeyMaterial512::from_bytes_as_type(
                    b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
                    KeyType::MACKey).unwrap();

        _ = HMAC::<SHA224>::new(&key).unwrap();
        _ = HMAC_SHA224::new(&key).unwrap();

        _ = HMAC::<SHA256>::new(&key).unwrap();
        _ = HMAC_SHA256::new(&key).unwrap();

        _ = HMAC::<SHA384>::new(&key).unwrap();
        _ = HMAC_SHA384::new(&key).unwrap();

        _ = HMAC::<SHA512>::new(&key).unwrap();
        _ = HMAC_SHA512::new(&key).unwrap();


        _ = HMAC::<SHA3_224>::new(&key).unwrap();
        _ = HMAC_SHA3_224::new(&key).unwrap();

        _ = HMAC::<SHA3_256>::new(&key).unwrap();
        _ = HMAC_SHA3_256::new(&key).unwrap();

        _ = HMAC::<SHA3_384>::new(&key).unwrap();
        _ = HMAC_SHA3_384::new(&key).unwrap();

        _ = HMAC::<SHA3_512>::new(&key).unwrap();
        _ = HMAC_SHA3_512::new(&key).unwrap();
    }

    #[test]
    fn constructor_tests() {
        let short_key = KeyMaterial256::from_bytes_as_type(
            &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            KeyType::MACKey,
        ).unwrap();
        assert_eq!(short_key.security_strength(), SecurityStrength::_112bit);
        // key is too short, so we expect it to fail
        match HMAC::<SHA256>::new(&short_key) {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* good */ },
            _ => panic!("This should have thrown a KeyMaterialError::SecurityStrength error but it didn't"),
        }

        // but this'll work fine
        HMAC::<SHA256>::new_allow_weak_key(&short_key).unwrap();

        // as will a long enough key
        let key = KeyMaterial256::from_bytes_as_type(
            &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
            KeyType::MACKey,
        ).unwrap();
        HMAC::<SHA256>::new(&key).unwrap();
    }

    #[test]
    fn test_block_bitlen() {
        // give it a key that is exactly the block size
        let key = KeyMaterialInternal::<1000>::from_bytes_as_type(&vec![0x3cu8; SHA256::new().block_bitlen()/8], KeyType::MACKey).unwrap();
        assert!(HMAC_SHA256::new(&key).unwrap().verify(b"Hi There", &hex::decode("4da0a0bb56f010db147b8f6e5f2dbecf7bb35ff00c8b9da31c9b94cc81815873").unwrap()));

        // Now give it a key that is larger than the block size and needs to be hashed down
        let key = KeyMaterialInternal::<1000>::from_bytes_as_type(&vec![0x3cu8; SHA256::new().block_bitlen()/8 + 1], KeyType::MACKey).unwrap();
        HMAC_SHA256::new(&key).unwrap().verify(b"Hi There", &hex::decode("5cb9475aba606afe8c82c2d1b3e1cfb1c814e8a72ce5a7b4fe43b0a0aac45144").unwrap());
    }

    #[test]
    fn security_strength_tests() {
        // test: provided key has the correct length, but insufficient tagged security strength
        // HMAC should still work, but should return an error

        // it works with a zero key (as new_allow_weak_key)
        // zero-len ey
        let mut zero_key = KeyMaterial256::default();
        HMAC_SHA256::new_allow_weak_key(&zero_key).unwrap();

        // non-zero len key of all-zero bytes
        zero_key.allow_hazardous_operations();
        zero_key.set_key_len(32).unwrap();
        HMAC_SHA256::new_allow_weak_key(&zero_key).unwrap();

        // but we don't allow zero-len keys that are not Zeroized or MACKey


        // init
        let mut key = KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::MACKey).unwrap();
        assert_eq!(key.security_strength(), SecurityStrength::_256bit);
        key.set_security_strength(SecurityStrength::_128bit).unwrap();
        // complains at first
        match HMAC::<SHA512>::new(&key) {
            Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => { /* fine */ },
            _ => { panic!("This should have thrown a KeyMaterialError::SecurityStrength error but it didn't") },
        }
        // but fine if you set .allow_weak_keys()
        let mut hmac = HMAC::<SHA512>::new_allow_weak_key(&key).unwrap();
        hmac.do_update(b"Hi There");
        hmac.do_final();

        // one-shot APIs still work with a weak key
        let out = HMAC::<SHA512>::new_allow_weak_key(&key).unwrap().mac(b"Hi There");
        assert!(HMAC::<SHA512>::new_allow_weak_key(&key).unwrap().verify(b"Hi There", &out));
        // but fine if you set .allow_weak_keys()
        let mut out = [0u8; 64];
        HMAC::<SHA512>::new_allow_weak_key(&key).unwrap().mac_out(b"Hi There", &mut out).unwrap();
        assert!(HMAC::<SHA512>::new_allow_weak_key(&key).unwrap().verify(b"Hi There", &out));
    }

    #[test]
    fn negative_tests() {
        let key = KeyMaterial256::from_bytes_as_type(
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            KeyType::MACKey,
        ).unwrap();

        // get the known-good output
        let out = HMAC::<SHA224>::new(&key).unwrap().mac(b"Hi There");

        // test output that's the wrong length, should simply return False
        let mut mac = HMAC::<SHA224>::new(&key).unwrap();
        mac.do_update(b"Hi There");
        assert!( ! mac.do_verify_final(&out[..out.len() - 1]));

        // test output that's the right length but wrong value -- do_verify
        let mut mac = HMAC::<SHA224>::new(&key).unwrap();
        mac.do_update(b"Hi There");
        assert!( ! mac.do_verify_final(&[0x01_u8; 28]));

        // test output that's the right length but wrong value -- static verify
        assert!( ! HMAC_SHA224::new(&key).unwrap().verify( b"Hi There", &[0x01_u8; 28]));

        // error case: test that it'll refuse to truncate below MIN_FIPS_DIGEST_LEN
        let mut mac = HMAC::<SHA224>::new(&key).unwrap();
        mac.do_update(b"Hi There");
        let mut out = vec![0u8; MIN_FIPS_DIGEST_LEN - 1];
        match mac.do_final_out(&mut out) {
            Ok(_) => { panic!("This should have throw an InvalidLength error")}
            Err(MACError::InvalidLength(_)) => { /*** good **/ },
            Err(_) => { panic!("This should have throw an InvalidLength error but it threw something else")},
        }

        // success case: ... but it will truncate to exactly MIN_FIPS_DIGEST_LEN
        let mut mac = HMAC::<SHA224>::new(&key).unwrap();
        mac.do_update(b"Hi There");
        let mut out = vec![0u8; MIN_FIPS_DIGEST_LEN];
        let bytes_written = mac.do_final_out(&mut out).unwrap();
        assert_eq!(bytes_written, MIN_FIPS_DIGEST_LEN);
        assert_eq!(&out, b"\x89\x6f\xb1\x12");

        // fail case: mac value is correct but truncated
        let mac = HMAC_SHA3_224::new(&key).unwrap();
        let mut mac_val = mac.mac(b"Polly want a cracker?");
        let verifier =  HMAC_SHA3_224::new(&key).unwrap();
        assert!(verifier.verify(b"Polly want a cracker?", &mac_val));

        // truncation of the mac value is considered a fail
        let verifier =  HMAC_SHA3_224::new(&key).unwrap();
        assert!(! verifier.verify(b"Polly want a cracker?", &mac_val[..mac_val.len() - 1]) );

        // .. as is some extra bytes at the end
        let verifier =  HMAC_SHA3_224::new(&key).unwrap();
        mac_val.extend_from_slice(&[0u8; 4]);
        assert!(! verifier.verify(b"Polly want a cracker?", &mac_val) );
    }

    #[test]
    fn algorithm_tests() {
        // Test the type aliases and string constants
        assert_eq!(HMAC_SHA224::ALG_NAME, HMAC_SHA224_NAME);
        assert_eq!(HMAC_SHA256::ALG_NAME, HMAC_SHA256_NAME);
        assert_eq!(HMAC_SHA384::ALG_NAME, HMAC_SHA384_NAME);
        assert_eq!(HMAC_SHA512::ALG_NAME, HMAC_SHA512_NAME);
        assert_eq!(HMAC_SHA3_224::ALG_NAME, HMAC_SHA3_224_NAME);
        assert_eq!(HMAC_SHA3_256::ALG_NAME, HMAC_SHA3_256_NAME);
        assert_eq!(HMAC_SHA3_384::ALG_NAME, HMAC_SHA3_384_NAME);
        assert_eq!(HMAC_SHA3_512::ALG_NAME, HMAC_SHA3_512_NAME);
    }

    #[cfg(test)]
    mod core_test_framework_rfc4231 {
        use bouncycastle_core_interface::key_material::KeyMaterialInternal;
        use super::*;

        #[test]
        fn hmac_sha224() {
            let test_framework = TestFrameworkMAC::new();
            let mut zero_length_key = KeyMaterial256::default();
            zero_length_key.allow_hazardous_operations();
            zero_length_key.convert_key_type(KeyType::MACKey).unwrap();
            assert_eq!(zero_length_key.key_len(), 0);
            assert_eq!(zero_length_key.key_type(), KeyType::MACKey);

            test_framework.test_mac::<HMAC<SHA224>>(
                &zero_length_key,
                b"Hello, world",
                &hex::decode("57454372e6a8780b11150274d7056c6fbcffef902f9c23f24fbbfee9").unwrap(),
            );

            // RFC4231 Test Case 1
            let test_framework = TestFrameworkMAC::new();
            test_framework.test_mac::<HMAC<SHA224>>(
                &KeyMaterial256::from_bytes_as_type(
                    &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                    KeyType::MACKey,
                )
                .unwrap(),
                b"Hi There",
                &hex::decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22").unwrap(),
            );

            // RFC4231 Test Case 2 -- Test with a key shorter than the length of the HMAC output.
            test_framework.test_mac::<HMAC<SHA224>>(
                &KeyMaterial256::from_bytes_as_type(b"Jefe", KeyType::MACKey).unwrap(),
                b"what do ya want for nothing?",
                &hex::decode("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44").unwrap(),
            );

            // RFC4231 Test Case 3 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA224>>(&KeyMaterial256::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    &hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap(),
                                                    &hex::decode("7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea").unwrap()
            );

            // RFC4231 Test Case 4 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA224>>(&KeyMaterial256::from_bytes_as_type(&hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(), KeyType::MACKey).unwrap(),
                                                    &hex::decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
                                                    &hex::decode("6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a").unwrap()
            );

            // RFC4231 Test Case 5 -- Test with a truncation of output to 128 bits.
            let key = KeyMaterial256::from_bytes_as_type(
                &hex::decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            let mut out = [0u8; 128 / 8];
            HMAC::<SHA224>::new(&key).unwrap().mac_out(b"Test With Truncation", &mut out).unwrap();
            assert_eq!(&Vec::from(out), &hex::decode("0e2aea68a90c8d37c988bcdb9fca6fa8").unwrap());

            // RFC4231 Test Case 6 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            let key = KeyMaterialInternal::<131>::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap();
            test_framework.test_mac::<HMAC<SHA224>>(&key,
                                                    b"Test Using Larger Than Block-Size Key - Hash Key First",
                                                    &hex::decode("95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e").unwrap()
            );

            // RFC4231 Test Case 7 -- Test with a key and data that is larger than 128 bytes (= block-size
            //    of SHA-384 and SHA-512)
            test_framework.test_mac::<HMAC<SHA224>>(&KeyMaterialInternal::<131>::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                                                    &hex::decode("3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1").unwrap()
            );
        }

        #[test]
        fn hmac_sha256() {
            // test with zero-length key
            let test_framework = TestFrameworkMAC::new();
            let mut zero_length_key = KeyMaterial256::default();
            zero_length_key.allow_hazardous_operations();
            zero_length_key.convert_key_type(KeyType::MACKey).unwrap();
            assert_eq!(zero_length_key.key_len(), 0);
            assert_eq!(zero_length_key.key_type(), KeyType::MACKey);

            test_framework.test_mac::<HMAC<SHA256>>(
                &zero_length_key,
                b"Hello, world",
                &hex::decode("c0fa4c55880318c31c1020e7a2cf830c2c695716387795c7a0eb918ba84e4bf0").unwrap(),
            );

            // RFC4231 Test Case 1
            let test_framework = TestFrameworkMAC::new();
            test_framework.test_mac::<HMAC<SHA256>>(
                &KeyMaterial256::from_bytes_as_type(
                    &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                    KeyType::MACKey,
                )
                    .unwrap(),
                b"Hi There",
                &hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap(),
            );

            // RFC4231 Test Case 2 -- Test with a key shorter than the length of the HMAC output.
            test_framework.test_mac::<HMAC<SHA256>>(
                &KeyMaterial256::from_bytes_as_type(b"Jefe", KeyType::MACKey).unwrap(),
                b"what do ya want for nothing?",
                &hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843").unwrap(),
            );

            // RFC4231 Test Case 3 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA256>>(&KeyMaterial256::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    &hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap(),
                                                    &hex::decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe").unwrap()
            );

            // RFC4231 Test Case 4 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA256>>(&KeyMaterial256::from_bytes_as_type(&hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(), KeyType::MACKey).unwrap(),
                                                    &hex::decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
                                                    &hex::decode("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b").unwrap()
            );

            // RFC4231 Test Case 5 -- Test with a truncation of output to 128 bits.
            let key = KeyMaterial256::from_bytes_as_type(
                &hex::decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
                KeyType::MACKey,
            )
                .unwrap();
            let mut out = [0u8; 128 / 8];
            HMAC::<SHA256>::new(&key).unwrap().mac_out(b"Test With Truncation", &mut out).unwrap();
            assert_eq!(&Vec::from(out), &hex::decode("a3b6167473100ee06e0c796c2955552b").unwrap());

            // RFC4231 Test Case 6 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA256>>(&KeyMaterialInternal::<131>::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    b"Test Using Larger Than Block-Size Key - Hash Key First",
                                                    &hex::decode("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54").unwrap()
            );

            // RFC4231 Test Case 7 -- Test with a key and data that is larger than 128 bytes (= block-size
            //    of SHA-384 and SHA-512)
            test_framework.test_mac::<HMAC<SHA256>>(&KeyMaterialInternal::<131>::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                                                    &hex::decode("9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2").unwrap()
            );
        }

        #[test]
        fn hmac_sha384() {
            // test with zero-length key
            let test_framework = TestFrameworkMAC::new();
            let mut zero_length_key = KeyMaterial256::default();
            zero_length_key.allow_hazardous_operations();
            zero_length_key.convert_key_type(KeyType::MACKey).unwrap();
            assert_eq!(zero_length_key.key_len(), 0);
            assert_eq!(zero_length_key.key_type(), KeyType::MACKey);

            test_framework.test_mac::<HMAC<SHA384>>(
                &zero_length_key,
                b"Hello, world",
                &hex::decode("fbd41442f749049355175277afbaff610539e5bfa874c9cf86ef867a43a30b09a5eac6578d5c0cb1ceddc95f97598af7").unwrap(),
            );

            // RFC4231 Test Case 1
            let test_framework = TestFrameworkMAC::new();
            test_framework.test_mac::<HMAC<SHA384>>(
                &KeyMaterial256::from_bytes_as_type(
                    &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                    KeyType::MACKey,
                ).unwrap(),
                b"Hi There",
                &hex::decode("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6").unwrap(),
            );

            // RFC4231 Test Case 2 -- Test with a key shorter than the length of the HMAC output.
            test_framework.test_mac::<HMAC<SHA384>>(
                &KeyMaterial256::from_bytes_as_type(b"Jefe", KeyType::MACKey).unwrap(),
                b"what do ya want for nothing?",
                &hex::decode("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649").unwrap(),
            );

            // RFC4231 Test Case 3 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA384>>(&KeyMaterial256::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    &hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap(),
                                                    &hex::decode("88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27").unwrap()
            );

            // RFC4231 Test Case 4 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA384>>(&KeyMaterial256::from_bytes_as_type(&hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(), KeyType::MACKey).unwrap(),
                                                    &hex::decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
                                                    &hex::decode("3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb").unwrap()
            );

            // RFC4231 Test Case 5 -- Test with a truncation of output to 128 bits.
            let key = KeyMaterial256::from_bytes_as_type(
                &hex::decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
                KeyType::MACKey,
            )
                .unwrap();
            let mut out = [0u8; 128 / 8];
            // Key is shorter than HMAC security strength, so need to use new_allow_weak_keys()
            let hmac = HMAC::<SHA384>::new_allow_weak_key(&key).unwrap();
            hmac.mac_out(b"Test With Truncation", &mut out).unwrap();
            assert_eq!(&Vec::from(out), &hex::decode("3abf34c3503b2a23a46efc619baef897").unwrap());

            // RFC4231 Test Case 6 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA384>>(&KeyMaterialInternal::<131>::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    b"Test Using Larger Than Block-Size Key - Hash Key First",
                                                    &hex::decode("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952").unwrap()
            );

            // RFC4231 Test Case 7 -- Test with a key and data that is larger than 128 bytes (= block-size
            //    of SHA-384 and SHA-512)
            test_framework.test_mac::<HMAC<SHA384>>(&KeyMaterialInternal::<131>::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                                                    &hex::decode("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e").unwrap()
            );
        }

        #[test]
        fn hmac_sha512() {
            // test with zero-length key
            let test_framework = TestFrameworkMAC::new();
            let mut zero_length_key = KeyMaterial256::default();
            zero_length_key.allow_hazardous_operations();
            zero_length_key.convert_key_type(KeyType::MACKey).unwrap();
            assert_eq!(zero_length_key.key_len(), 0);
            assert_eq!(zero_length_key.key_type(), KeyType::MACKey);

            test_framework.test_mac::<HMAC<SHA512>>(
                &zero_length_key,
                b"Hello, world",
                &hex::decode("e8f7176e01bf9bb883f71f42c143681e86cfafe0b61f3bc0d824e2cde13b5f80199e82d865aebb725461c86a54086aeacac37a86a9f1cf07db567ba5a10f1cc1").unwrap(),
            );

            // RFC4231 Test Case 1
            let test_framework = TestFrameworkMAC::new();
            test_framework.test_mac::<HMAC<SHA512>>(
                &KeyMaterial256::from_bytes_as_type(
                    &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                    KeyType::MACKey,
                )
                    .unwrap(),
                b"Hi There",
                &hex::decode("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854").unwrap(),
            );

            // RFC4231 Test Case 2 -- Test with a key shorter than the length of the HMAC output.
            test_framework.test_mac::<HMAC<SHA512>>(
                &KeyMaterial256::from_bytes_as_type(b"Jefe", KeyType::MACKey).unwrap(),
                b"what do ya want for nothing?",
                &hex::decode("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737").unwrap(),
            );

            // RFC4231 Test Case 3 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA512>>(&KeyMaterial256::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    &hex::decode("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd").unwrap(),
                                                    &hex::decode("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb").unwrap()
            );

            // RFC4231 Test Case 4 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA512>>(&KeyMaterial256::from_bytes_as_type(&hex::decode("0102030405060708090a0b0c0d0e0f10111213141516171819").unwrap(), KeyType::MACKey).unwrap(),
                                                    &hex::decode("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
                                                    &hex::decode("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd").unwrap()
            );

            // RFC4231 Test Case 5 -- Test with a truncation of output to 128 bits.
            let key = KeyMaterial256::from_bytes_as_type(
                &hex::decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c").unwrap(),
                KeyType::MACKey,
            )
                .unwrap();
            let mut out = [0u8; 128 / 8];
            // Key is shorter than HMAC security strength, so need to use new_allow_weak_keys()
            let hmac = HMAC::<SHA512>::new_allow_weak_key(&key).unwrap();
            hmac.mac_out(b"Test With Truncation", &mut out).unwrap();
            assert_eq!(&Vec::from(out), &hex::decode("415fad6271580a531d4179bc891d87a6").unwrap());

            // RFC4231 Test Case 6 -- Test with a combined length of key and data that is larger than 64
            //    bytes (= block-size of SHA-224 and SHA-256).
            test_framework.test_mac::<HMAC<SHA512>>(&KeyMaterialInternal::<131>::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    b"Test Using Larger Than Block-Size Key - Hash Key First",
                                                    &hex::decode("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598").unwrap()
            );

            // RFC4231 Test Case 7 -- Test with a key and data that is larger than 128 bytes (= block-size
            //    of SHA-384 and SHA-512)
            test_framework.test_mac::<HMAC<SHA512>>(&KeyMaterialInternal::<131>::from_bytes_as_type(&hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(), KeyType::MACKey).unwrap(),
                                                    b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                                                    &hex::decode("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58").unwrap()
            );
        }
    }
}
