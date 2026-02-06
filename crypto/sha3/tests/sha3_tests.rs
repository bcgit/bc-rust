#[cfg(test)]
mod sha3_tests {
    use super::sha3_test_helpers::*;
    use bouncycastle_core_interface::key_material::{
        KeyMaterial256, KeyMaterial512, KeyMaterialInternal, KeyType,
    };
    use bouncycastle_core_interface::traits::{Hash, HashAlgParams, KDF, KeyMaterial, SecurityStrength};
    use bouncycastle_core_test_framework::DUMMY_SEED_512;
    use bouncycastle_core_test_framework::hash::TestFrameworkHash;
    use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
    use bouncycastle_sha3::{SHA3_224, SHA3_256, SHA3_384, SHA3_512};

    #[test]
    fn test_constants() {
        assert_eq!(SHA3_224::OUTPUT_LEN, 28);
        assert_eq!(SHA3_256::OUTPUT_LEN, 32);
        assert_eq!(SHA3_384::OUTPUT_LEN, 48);
        assert_eq!(SHA3_512::OUTPUT_LEN, 64);

        assert_eq!(SHA3_224::BLOCK_LEN, 144);
        assert_eq!(SHA3_256::BLOCK_LEN, 136);
        assert_eq!(SHA3_384::BLOCK_LEN, 104);
        assert_eq!(SHA3_512::BLOCK_LEN, 72);

        assert_eq!(SHA3_224::new().block_bitlen(), 144*8);
        assert_eq!(SHA3_256::new().block_bitlen(), 136*8);
        assert_eq!(SHA3_384::new().block_bitlen(), 104*8);
        assert_eq!(SHA3_512::new().block_bitlen(), 72*8);
    }

    #[test]
    fn test_framework_hash() {
        let test_framework = TestFrameworkHash::new();
        test_framework.test_hash::<SHA3_224>(DUMMY_SEED_512, b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");
        test_framework.test_hash::<SHA3_256>(DUMMY_SEED_512, b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");
        test_framework.test_hash::<SHA3_384>(DUMMY_SEED_512, b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");
        test_framework.test_hash::<SHA3_512>(DUMMY_SEED_512, b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");
    }

    #[test]
    fn test_static_hash() {
        // success case -- return vec version
        assert_eq!(SHA3_224::new().hash(DUMMY_SEED_512), b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");
        assert_eq!(SHA3_256::new().hash(DUMMY_SEED_512), b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");
        assert_eq!(SHA3_384::new().hash(DUMMY_SEED_512), b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");
        assert_eq!(SHA3_512::new().hash(DUMMY_SEED_512), b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");

        // success case -- output slice version
        // We're just gonna hand an output slice that's too big and the result had better get written to the beginning of it.
        let mut out: [u8; 64] = [0; 64];
        assert_eq!(SHA3_224::new().output_len(), 28);
        let bytes_written = SHA3_224::new().hash_out(DUMMY_SEED_512, &mut out);
        assert_eq!(bytes_written, 28);
        assert_eq!(&out[..28], b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");

        assert_eq!(SHA3_256::new().output_len(), 32);
        let bytes_written = SHA3_256::new().hash_out(DUMMY_SEED_512, &mut out);
        assert_eq!(&out[..32], b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");
        assert_eq!(bytes_written, 32);

        assert_eq!(SHA3_384::new().output_len(), 48);
        let bytes_written = SHA3_384::new().hash_out(DUMMY_SEED_512, &mut out);
        assert_eq!(&out[..48], b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");
        assert_eq!(bytes_written, 48);

        assert_eq!(SHA3_512::new().output_len(), 64);
        let bytes_written = SHA3_512::new().hash_out(DUMMY_SEED_512, &mut out);
        assert_eq!(&out, b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");
        assert_eq!(bytes_written, 64);

        // check that if you feed it an output slice that's bigger than it needs, that it doesn't touch the extra bytes.
        let mut out = DUMMY_SEED_512.clone();
        SHA3_256::new().hash_out(DUMMY_SEED_512, &mut out);
        assert_eq!(&out[32..], &DUMMY_SEED_512[32..]);
    }

    #[test]
    fn test_do_update() {
        // success case -- return vec version
        let output1 = SHA3_224::new().hash(DUMMY_SEED_512);

        let mut sha3 = SHA3_224::new();
        for i in (0..DUMMY_SEED_512.len()).step_by(8) {
            sha3.do_update(&DUMMY_SEED_512[i..(i + 8)]);
        }
        let output2 = sha3.do_final();

        assert_eq!(output1, output2);

        // success case -- output slice version
        // let output1 = SHA3_224::new().hashes(DUMMY_SEED);  // already have this above

        let mut sha3 = SHA3_224::new();
        for i in (0..DUMMY_SEED_512.len()).step_by(8) {
            sha3.do_update(&DUMMY_SEED_512[i..(i + 8)]);
        }
        let mut output2 = [0u8; SHA3_224::OUTPUT_LEN];
        sha3.do_final_out(&mut output2);

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_partial_input() {
        let input_byte = 0xFFu8;

        let output = SHA3_224::new()
            .do_final_partial_bits(input_byte, 1)
            .expect("Failed to finalize partial input");
        assert_eq!(output, b"\x6f\x2f\xc5\x4a\x6b\x11\xa6\xda\x61\x1e\xd7\x34\x50\x5b\x9c\xab\x89\xee\xcc\x1d\xc7\xdd\x2d\xeb\xd2\x7b\xd1\xc9");

        let output = SHA3_224::new()
            .do_final_partial_bits(input_byte, 2)
            .expect("Failed to finalize partial input");
        assert_eq!(output, b"\xdf\xeb\x54\xcd\x8a\x7a\x54\x90\x89\xae\x37\x09\x30\x79\x23\xb4\x91\x16\xdb\xa1\xad\x3c\xbc\x3f\xe4\x03\xb6\xe8");

        // ..

        let output = SHA3_224::new()
            .do_final_partial_bits(input_byte, 7)
            .expect("Failed to finalize partial input");
        assert_eq!(output, b"\x81\x67\x07\x1f\xfc\x12\xaf\x71\x65\x06\x01\x4e\x99\x49\xe9\xa8\x9d\x11\x26\x04\x93\xf9\x88\x09\x8c\xbb\x7f\x35");
        // println!("{:2x?}", output);

        // success case -- output slice version
        let mut output = vec![0u8; SHA3_224::OUTPUT_LEN];
        SHA3_224::new()
            .do_final_partial_bits_out(input_byte, 7, &mut *output)
            .expect("Failed to finalize partial input");
        assert_eq!(output, b"\x81\x67\x07\x1f\xfc\x12\xaf\x71\x65\x06\x01\x4e\x99\x49\xe9\xa8\x9d\x11\x26\x04\x93\xf9\x88\x09\x8c\xbb\x7f\x35");

        //output slice too small -- should just truncate
        let mut expected_output = vec![0u8; SHA3_224::new().output_len()];
        SHA3_224::new()
            .do_final_partial_bits_out(input_byte, 7, &mut *expected_output)
            .expect("Failed to finalize partial input");
        let mut output = vec![0u8; SHA3_224::OUTPUT_LEN - 1];
        SHA3_224::new().do_final_partial_bits_out(input_byte, 7, &mut *output).unwrap();
        assert_eq!(output, expected_output[..SHA3_224::OUTPUT_LEN - 1]);
    }

    #[test]
    fn test_do_final_out_truncation() {
        let expected_output =  b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47";

        for len in 0..SHA3_224::OUTPUT_LEN {
            let mut output = vec![0u8; len];
            let mut sha3 = SHA3_224::new();
            sha3.do_update(DUMMY_SEED_512);
            let bytes_written = sha3.do_final_out(&mut output);
            assert_eq!(bytes_written, len);
            assert_eq!(output, expected_output[..len]);
        }
    }

    #[test]
    fn test_kdf() {
        let testframework = TestFrameworkKDF::new();

        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED_512[..32]).unwrap();

        // Without additional input
        let derived_key = SHA3_256::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_len(), 32);
        let expected_key = KeyMaterial256::from_bytes(b"\x05\x0a\x48\x73\x3b\xd5\xc2\x75\x6b\xa9\x5c\x58\x28\xcc\x83\xee\x16\xfa\xbc\xd3\xc0\x86\x88\x5b\x77\x44\xf8\x4a\x0f\x9e\x0d\x94").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHA3_256>(&key_material, &[0u8; 0], &expected_key);

        // With additional input
        let derived_key = SHA3_256::new().derive_key(&key_material, &[0u8; 8]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\xe9\x50\x00\xce\x8a\xbd\x3e\x3f\x21\x01\xcd\xee\x5c\x97\xc0\x69\xa9\x34\x2c\x2e\x2c\x5d\x4b\xd1\x9b\x61\x06\xfc\x52\x43\x33\x4a").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHA3_256>(&key_material, &[0u8; 8], &expected_key);

        // derive_key_from_multiple
        let keys = [&key_material, &key_material];
        let derived_key = SHA3_256::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        let mut expected_key = KeyMaterial256::from_bytes(b"\x5d\x22\x75\xda\x43\xad\x31\xf6\xef\x5c\x26\x4f\xb2\x6b\x99\x6a\x49\x2b\x77\x56\x19\xdd\x5a\x23\x27\x06\xb3\x94\xa0\x9f\xe2\xa7").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_multiple_key::<SHA3_256>(&keys, &[0u8; 0], &mut expected_key);

        // test SHA3_224
        let derived_key = SHA3_224::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\xbf\xc9\xc1\xe8\x93\x9a\xee\x95\x3c\xa0\xd4\x25\xa2\xf0\xcb\xdd\x2d\x18\x02\x5d\x5d\x6b\x79\x8f\x1c\x81\x50\xb9").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHA3_224>(&key_material, &[0u8; 0], &expected_key);

        // test SHA3_256
        let derived_key = SHA3_256::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\x05\x0a\x48\x73\x3b\xd5\xc2\x75\x6b\xa9\x5c\x58\x28\xcc\x83\xee\x16\xfa\xbc\xd3\xc0\x86\x88\x5b\x77\x44\xf8\x4a\x0f\x9e\x0d\x94").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHA3_256>(&key_material, &[0u8; 0], &expected_key);

        // test SHA3_384
        let derived_key = SHA3_384::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\xe0\x86\xa2\xb6\xa6\x9b\xb6\xfa\xe3\x7c\xaa\x70\x73\x57\x23\xe7\xcc\x8a\xe2\x18\x37\x88\xfb\xb4\xa5\xf1\xcc\xac\xd8\x32\x26\x85\x2c\xa6\xfa\xff\x50\x3e\x12\xff\x95\x42\x3f\x94\xf8\x72\xdd\xa3").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHA3_384>(&key_material, &[0u8; 0], &expected_key);

        // test SHA3_512
        let derived_key = SHA3_512::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial512::from_bytes(b"\xcb\xd3\xf6\xee\xba\x67\x6b\x21\xe0\xf2\xc4\x75\x22\x29\x24\x82\xfd\x83\x0f\x33\x0c\x1d\x84\xa7\x94\xbb\x94\x72\x8b\x2d\x93\xfe\xbe\x4c\x18\xea\xe5\xa7\xe0\x17\xe3\x5f\xa0\x90\xde\x24\x26\x2e\x70\x95\x1a\xd1\xd7\xdf\xb3\xa8\xc9\x6d\x11\x34\xfb\x18\x79\xf2").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHA3_512>(&key_material, &[0u8; 0], &expected_key);

        // success case -- output slice version
        let mut derived_key = KeyMaterial256::new();
        SHA3_256::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 32);
        let expected_key = KeyMaterial256::from_bytes(b"\x05\x0a\x48\x73\x3b\xd5\xc2\x75\x6b\xa9\x5c\x58\x28\xcc\x83\xee\x16\xfa\xbc\xd3\xc0\x86\x88\x5b\x77\x44\xf8\x4a\x0f\x9e\x0d\x94").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
    }

    #[test]
    fn test_kdf_undersized_and_oversized() {
        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED_512[..32]).unwrap();

        // at size
        let mut derived_key = KeyMaterialInternal::<32>::new();
        SHA3_256::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 32);
        let expected_key = KeyMaterial256::from_bytes(b"\x05\x0a\x48\x73\x3b\xd5\xc2\x75\x6b\xa9\x5c\x58\x28\xcc\x83\xee\x16\xfa\xbc\xd3\xc0\x86\x88\x5b\x77\x44\xf8\x4a\x0f\x9e\x0d\x94").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // undersized -- should truncate
        let mut derived_key = KeyMaterialInternal::<16>::new();
        SHA3_256::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 16);
        let expected_key = KeyMaterial256::from_bytes(
            b"\x05\x0a\x48\x73\x3b\xd5\xc2\x75\x6b\xa9\x5c\x58\x28\xcc\x83\xee",
        )
        .unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // oversized -- SHA3 is a fixed-length KDF, so it should leave the back of the buffer as 0's
        let mut derived_key = KeyMaterialInternal::<200>::new();
        SHA3_256::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 32);
        let expected_key = KeyMaterial256::from_bytes(b"\x05\x0a\x48\x73\x3b\xd5\xc2\x75\x6b\xa9\x5c\x58\x28\xcc\x83\xee\x16\xfa\xbc\xd3\xc0\x86\x88\x5b\x77\x44\xf8\x4a\x0f\x9e\x0d\x94").unwrap();
        assert_eq!(&derived_key.ref_to_bytes()[..32], expected_key.ref_to_bytes());
        // since the KeyMaterial was set to len 32, if you ask for more, it'll just be empty
        assert_eq!(&derived_key.ref_to_bytes()[32..], &[0u8; 0]);
    }

    #[test]
    fn kdf_input_entropy() {
        // This is essentially testing the bounds in FIPS 202 Table 3

        // Exact entropy
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHA3_256::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\x05\x0a\x48\x73\x3b\xd5\xc2\x75\x6b\xa9\x5c\x58\x28\xcc\x83\xee\x16\xfa\xbc\xd3\xc0\x86\x88\x5b\x77\x44\xf8\x4a\x0f\x9e\x0d\x94").unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::_128bit);
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // more entropy than needed -- single input key
        let key_material =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHA3_256::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::_128bit);

        // more entropy than needed -- single input key
        // but if you use SHA512 then you get SecurityStrength::_256bit
        let key_material =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHA3_512::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::_256bit);

        // more entropy than needed -- multiple input keys
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::BytesFullEntropy)
                .unwrap();
        let keys = [&key_material, &key_material];
        let derived_key = SHA3_256::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesFullEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::_128bit);

        // more entropy than needed -- multiple input keys of different full-entropy types;
        // should get the type of the first one
        let key_material1 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::MACKey).unwrap();
        let key_material2 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::SymmetricCipherKey)
                .unwrap();
        let keys = [&key_material1, &key_material2];
        let derived_key = SHA3_256::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::MACKey);
        assert_eq!(derived_key.security_strength(), SecurityStrength::_128bit);

        // test zeorized
        let key_material = KeyMaterial256::new();
        assert_eq!(key_material.key_type(), KeyType::Zeroized);
        // it should do it, but return a zeroized output key, regardless of the additional_input
        let derived_key = SHA3_256::new().derive_key(&key_material, &[1u8; 100]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::None);

        // less entropy than needed -- various permutations, but not exhaustive
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHA3_256::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::None);

        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::BytesFullEntropy)
                .unwrap();
        let keys = [&key_material, &key_material];
        let derived_key = SHA3_512::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::None);

        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..8], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHA3_224::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::None);

        let key_low_entropy =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::BytesLowEntropy)
                .unwrap();
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::BytesFullEntropy)
                .unwrap();
        let keys = [&key_material, &key_low_entropy];
        let derived_key = SHA3_256::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(derived_key.security_strength(), SecurityStrength::None);
    }

    #[test]
    fn kdf_key_type_conversions() {
        // This will fail because the input is automatically tagged as BytesLowEntropy,
        // which is preserved by a call to KDF::new().derive_key(), and cannot by safely converted to MACKey.
        let input_seed = KeyMaterial256::from_bytes(&DUMMY_SEED_512[..32]).expect("Error happened");
        let mut output_seed =
            SHA3_256::new().derive_key(&input_seed, b"nytimes.com").expect("Error happened");
        match output_seed.convert_key_type(KeyType::MACKey) {
            Ok(_) => {
                panic!(
                    "Should have failed to convert key type because the input was BytesLowEntropy"
                );
            }
            Err(_) => { /* good */ }
        }

        // This works because we allow hazardous conversions before doing the conversion.
        let input_seed = KeyMaterial256::from_bytes(&DUMMY_SEED_512[..32]).expect("Error happened");
        let mut output_seed = SHA3_256::new()
            .derive_key(&input_seed, b"some addtional input to the KDF")
            .expect("Error happened");
        output_seed.allow_hazardous_operations();
        output_seed.convert_key_type(KeyType::MACKey).unwrap();
        output_seed.drop_hazardous_operations(); // not strictly necessary because KeyMaterial
        // will automatically drop allow_hazardous_conversions() after performing one.
        assert_eq!(output_seed.key_type(), KeyType::MACKey);

        // This works because we explicitly tag the input data as BytesFullEntropy.
        // This is the preferred and better way to do it.
        let input_seed =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::BytesFullEntropy)
                .expect("Error happened");
        let output_seed =
            SHA3_256::new().derive_key(&input_seed, b"nytimes.com").expect("Error happened");
        assert_eq!(output_seed.key_type(), KeyType::BytesFullEntropy);
    }

    #[test]
    fn test_security_strength() {
        assert_eq!(Hash::max_security_strength(&SHA3_224::default()), SecurityStrength::_112bit);
        assert_eq!(KDF::max_security_strength(&SHA3_224::default()), SecurityStrength::_112bit);

        assert_eq!(Hash::max_security_strength(&SHA3_256::default()), SecurityStrength::_128bit);
        assert_eq!(KDF::max_security_strength(&SHA3_256::default()), SecurityStrength::_128bit);

        assert_eq!(Hash::max_security_strength(&SHA3_384::default()), SecurityStrength::_192bit);
        assert_eq!(KDF::max_security_strength(&SHA3_384::default()), SecurityStrength::_192bit);

        assert_eq!(Hash::max_security_strength(&SHA3_512::default()), SecurityStrength::_256bit);
        assert_eq!(KDF::max_security_strength(&SHA3_512::default()), SecurityStrength::_256bit);
    }

    #[test]
    fn run_kats() {
        run_test_vectors(read_test_vectors("tests/data/SHA3TestVectors.txt"));
    }

    fn run_test_vectors(test_vectors: Vec<TestCase>) {
        for tc in test_vectors {
            match tc.algorithm {
                224 => run_test_case(tc, SHA3_224::new()),
                256 => run_test_case(tc, SHA3_256::new()),
                384 => run_test_case(tc, SHA3_384::new()),
                512 => run_test_case(tc, SHA3_512::new()),
                _ => panic!("Unsupported algorithm {}", tc.algorithm),
            }
        }
    }

    fn run_test_case(tc: TestCase, mut sha3: impl Hash) {
        let partial_bits = tc.bits % 8;
        let output: Vec<u8>;

        if partial_bits == 0 {
            sha3.do_update(tc.msg.as_slice());
            output = sha3.do_final();
        } else {
            sha3.do_update(&tc.msg[..(tc.msg.len() - 1)]);
            output = sha3.do_final_partial_bits(tc.msg[tc.msg.len() - 1], partial_bits).unwrap();
        }

        assert_eq!(tc.hash, output);
    }
}

/** Constant helpers **/

pub(crate) mod sha3_test_helpers {
    use bouncycastle_hex as hex;
    use std::fs;

    const SAMPLE_OF: &str = " sample of ";
    const MSG_HEADER: &str = "Msg as bit string";
    const HASH_HEADER: &str = "Hash val is";

    pub(crate) struct TestCase {
        pub(crate) algorithm: usize,
        pub(crate) bits: usize,
        pub(crate) msg: Vec<u8>,
        pub(crate) hash: Vec<u8>,
    }

    pub(crate) fn read_test_vectors(path: &str) -> Vec<TestCase> {
        let mut test_vectors: Vec<TestCase> = vec![];
        let string_content: Vec<String> =
            fs::read_to_string(path).unwrap().lines().map(String::from).collect();

        let mut i = 0;
        while i < string_content.len() {
            if string_content[i].contains(SAMPLE_OF) {
                let header = string_content[i].split(SAMPLE_OF).collect::<Vec<&str>>();

                let algorithm =
                    header[0].split("-").collect::<Vec<&str>>()[1].parse::<usize>().unwrap();
                let bits = header[1].split("-").collect::<Vec<&str>>()[0].parse::<usize>().unwrap();

                i += 2;
                if !string_content[i].contains(MSG_HEADER) {
                    panic!("Missing header {}", MSG_HEADER);
                }

                i += 1;
                let mut block: Vec<u8> = vec![];
                while string_content[i].len() != 0 {
                    if string_content[i].trim().eq("#(empty message)") {
                        i += 1;
                        break;
                    }
                    let line = string_content[i].replace(" ", "");
                    block.append(&mut Vec::from(line));
                    i += 1;
                }
                if block.len() != bits {
                    panic!(
                        "Test vector length mismatch: block len = {}, bits = {}",
                        block.len(),
                        bits
                    )
                }
                let msg = decode_binary(&mut block);

                i += 1;
                if !string_content[i].contains(HASH_HEADER) {
                    panic!("Missing header {}", HASH_HEADER);
                }

                i += 1;
                let mut block: Vec<u8> = vec![];
                while string_content[i].len() != 0 {
                    let line = string_content[i].replace(" ", "");
                    block.append(&mut Vec::from(line));
                    i += 1;
                }
                let hash = hex::decode(&*String::from_utf8(block).unwrap()).unwrap();

                let v = TestCase { algorithm, bits, msg, hash };
                test_vectors.push(v);
            }
            i += 1;
        }

        test_vectors
    }

    fn decode_binary(block: &mut Vec<u8>) -> Vec<u8> {
        let bits = block.len();
        let full_bytes = bits / 8;
        let total_bytes = (bits + 7) / 8;
        let mut result = vec![0u8; total_bytes];

        for i in 0..full_bytes {
            let index = i * 8;
            block[index..(index + 8)].reverse();
            result[i] = parse_binary(&block[index..(index + 8)]);
        }

        if total_bytes > full_bytes {
            block[(full_bytes * 8)..].reverse();
            result[full_bytes] = parse_binary(&block[(full_bytes * 8)..]);
        }

        result
    }

    fn parse_binary(block: &[u8]) -> u8 {
        let str = std::str::from_utf8(block).unwrap();
        isize::from_str_radix(str, 2).unwrap() as u8
    }
}
