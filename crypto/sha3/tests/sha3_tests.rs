#[cfg(test)]
mod sha3_tests {
    use bouncycastle_core::errors::HashError;
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{AlgorithmInfo, Hash, HashAlgParams, HashOneShot};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::hash::TestFrameworkHash;
    use bouncycastle_sha3::{
        SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE256, SUSPENDED_SHA3_STATE_LEN,
    };

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

        assert_eq!(SHA3_224::new().block_bitlen(), 144 * 8);
        assert_eq!(SHA3_256::new().block_bitlen(), 136 * 8);
        assert_eq!(SHA3_384::new().block_bitlen(), 104 * 8);
        assert_eq!(SHA3_512::new().block_bitlen(), 72 * 8);
    }

    #[test]
    fn test_framework_hash() {
        let test_framework = TestFrameworkHash::new();
        test_framework.test_hash::<SHA3_224>(&DUMMY_SEED[..512], b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");
        test_framework.test_hash::<SHA3_256>(&DUMMY_SEED[..512], b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");
        test_framework.test_hash::<SHA3_384>(&DUMMY_SEED[..512], b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");
        test_framework.test_hash::<SHA3_512>(&DUMMY_SEED[..512], b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");
    }

    #[test]
    fn test_static_hash() {
        // success case -- return vec version
        assert_eq!(SHA3_224::hash(&DUMMY_SEED[..512]), b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");
        assert_eq!(SHA3_256::hash(&DUMMY_SEED[..512]), b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");
        assert_eq!(SHA3_384::hash(&DUMMY_SEED[..512]), b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");
        assert_eq!(SHA3_512::hash(&DUMMY_SEED[..512]), b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");

        // success case -- output slice version
        // We're just gonna hand an output slice that's too big and the result had better get written to the beginning of it.
        let mut out: [u8; 64] = [0; 64];
        assert_eq!(SHA3_224::new().output_len(), 28);
        let bytes_written = SHA3_224::hash_out(&DUMMY_SEED[..512], &mut out);
        assert_eq!(bytes_written, 28);
        assert_eq!(&out[..28], b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");

        assert_eq!(SHA3_256::new().output_len(), 32);
        let bytes_written = SHA3_256::hash_out(&DUMMY_SEED[..512], &mut out);
        assert_eq!(&out[..32], b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");
        assert_eq!(bytes_written, 32);

        assert_eq!(SHA3_384::new().output_len(), 48);
        let bytes_written = SHA3_384::hash_out(&DUMMY_SEED[..512], &mut out);
        assert_eq!(&out[..48], b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");
        assert_eq!(bytes_written, 48);

        assert_eq!(SHA3_512::new().output_len(), 64);
        let bytes_written = SHA3_512::hash_out(&DUMMY_SEED[..512], &mut out);
        assert_eq!(&out, b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");
        assert_eq!(bytes_written, 64);

        // check that the bytes of an oversized output buffer past the digest length get zeroized.
        let mut out = *DUMMY_SEED;
        SHA3_256::hash_out(DUMMY_SEED, &mut out);
        assert!(out[32..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_do_update() {
        // success case -- return vec version
        let output1 = SHA3_224::hash(DUMMY_SEED);

        let mut sha3 = SHA3_224::new();
        for i in (0..DUMMY_SEED.len()).step_by(8) {
            sha3.do_update(&DUMMY_SEED[i..(i + 8)]);
        }
        let output2 = sha3.do_final();

        assert_eq!(output1, output2);

        // success case -- output slice version
        // let output1 = SHA3_224::new().hashes(DUMMY_SEED);  // already have this above

        let mut sha3 = SHA3_224::new();
        for i in (0..DUMMY_SEED.len()).step_by(8) {
            sha3.do_update(&DUMMY_SEED[i..(i + 8)]);
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
            .do_final_partial_bits_out(input_byte, 7, &mut output)
            .expect("Failed to finalize partial input");
        assert_eq!(output, b"\x81\x67\x07\x1f\xfc\x12\xaf\x71\x65\x06\x01\x4e\x99\x49\xe9\xa8\x9d\x11\x26\x04\x93\xf9\x88\x09\x8c\xbb\x7f\x35");

        //output slice too small -- should just truncate
        let mut expected_output = vec![0u8; SHA3_224::new().output_len()];
        SHA3_224::new()
            .do_final_partial_bits_out(input_byte, 7, &mut expected_output)
            .expect("Failed to finalize partial input");
        let mut output = vec![0u8; SHA3_224::OUTPUT_LEN - 1];
        SHA3_224::new().do_final_partial_bits_out(input_byte, 7, &mut output).unwrap();
        assert_eq!(output, expected_output[..SHA3_224::OUTPUT_LEN - 1]);
    }

    /// do_final_partial_bits() must validate num_partial_bits before shifting: 0 is equivalent to
    /// do_final(), 8+ is rejected with InvalidLength rather than panicking (16+ used to overflow a shift).
    #[test]
    fn partial_bits_range_is_validated() {
        for bad in [8usize, 9, 15, 16, 64, usize::MAX] {
            let mut h = SHA3_256::new();
            h.do_update(b"abc");
            assert!(
                matches!(h.do_final_partial_bits(0xFF, bad), Err(HashError::InvalidLength(_))),
                "num_partial_bits={bad}"
            );
            let mut out = [0u8; 32];
            assert!(matches!(
                SHA3_256::new().do_final_partial_bits_out(0xFF, bad, &mut out),
                Err(HashError::InvalidLength(_))
            ));
        }
        let mut h = SHA3_256::new();
        h.do_update(b"abc");
        assert_eq!(h.do_final_partial_bits(0xFF, 0).unwrap(), SHA3_256::hash(b"abc"));
    }

    #[test]
    fn test_do_final_out_truncation() {
        let expected_output =  b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47";

        for len in 0..SHA3_224::OUTPUT_LEN {
            let mut output = vec![0u8; len];
            let mut sha3 = SHA3_224::new();
            sha3.do_update(&DUMMY_SEED[..512]);
            let bytes_written = sha3.do_final_out(&mut output);
            assert_eq!(bytes_written, len);
            assert_eq!(output, expected_output[..len]);
        }
    }

    #[test]
    fn test_security_strength() {
        assert_eq!(SHA3_224::default().max_security_strength(), SecurityStrength::_112bit);

        assert_eq!(SHA3_256::default().max_security_strength(), SecurityStrength::_128bit);

        assert_eq!(SHA3_384::default().max_security_strength(), SecurityStrength::_192bit);

        assert_eq!(SHA3_512::default().max_security_strength(), SecurityStrength::_256bit);
    }

    #[test]
    fn serializable_state() {
        use bouncycastle_core::errors::SuspendableError;
        use bouncycastle_core::traits::Suspendable;
        use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

        let str = "Colorless green ideas sleep furiously";

        // A helper that exercises the full round-trip for one SHA3 variant.
        fn round_trip<const N: usize, H: Hash + Suspendable<N> + Clone>(mut hash: H, input: &[u8]) {
            hash.do_update(input);

            // do the default trait-conformance tests
            TestFrameworkSuspendableState::new().test(&hash);

            // serialize the in-progress state, then finish the original
            let serialized_state = hash.clone().suspend();
            assert_eq!(serialized_state.len(), SUSPENDED_SHA3_STATE_LEN);

            let expected = hash.do_final();

            // rebuild from the serialized state and confirm it produces the same digest
            let from_state = H::from_suspended(serialized_state).unwrap();
            assert_eq!(expected, from_state.do_final());

            // a corrupt `squeezing` byte (last byte of the keccak state) must be rejected.
            // Layout: 3 version bytes + variant tag(1) + [u64;25](200) + data_queue(192)
            //         + bits_in_queue(8) + squeezing(1)
            let mut busted = serialized_state;
            busted[3 + 1 + 400] = 42;
            match H::from_suspended(busted) {
                Err(SuspendableError::InvalidData) => { /* good */ }
                _ => panic!("Expected an error for a corrupt squeezing byte"),
            }

            // A well-formed phase byte that says "squeezing" is not a state a SHA3 produces
            // either: it is only ever suspended while absorbing, and every finalisation of a
            // squeezing one would fail. Refused on resume, as SHAKE refuses it.
            let mut squeezing = serialized_state;
            squeezing[3 + 1 + 400] = 1;
            assert!(
                matches!(H::from_suspended(squeezing), Err(SuspendableError::InvalidData)),
                "a squeezing phase byte must be rejected"
            );
        }

        round_trip(SHA3_224::new(), str.as_bytes());
        round_trip(SHA3_256::new(), str.as_bytes());
        round_trip(SHA3_384::new(), str.as_bytes());
        round_trip(SHA3_512::new(), str.as_bytes());

        // A state serialized by one variant must be rejected by a different variant (mismatched
        // variant tag). SHA3-256 and SHAKE256 share the same rate (1088), so this cross-family case
        // is only caught by the tag, not the rate -- it is the exact bug the tag exists to prevent.
        let mut sha3_256 = SHA3_256::new();
        sha3_256.do_update(str.as_bytes());
        let serialized_256 = sha3_256.suspend();
        match SHA3_512::from_suspended(serialized_256) {
            Err(SuspendableError::InvalidData) => { /* good */ }
            _ => panic!("Expected an error when loading a SHA3-256 state into SHA3-512"),
        }
        match SHAKE256::from_suspended(serialized_256) {
            Err(SuspendableError::InvalidData) => { /* good */ }
            _ => panic!("Expected an error when loading a SHA3-256 state into SHAKE256"),
        }
    }
}
