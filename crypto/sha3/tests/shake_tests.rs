extern crate core;

#[cfg(test)]
mod shake_tests {
    use super::shake_test_helpers::*;
    use bouncycastle_core::errors::HashError;
    use bouncycastle_core::key_material::{
        KeyMaterial, KeyMaterial256, KeyMaterial512, KeyMaterialTrait, KeyType,
    };
    use bouncycastle_core::traits::{Hash, KDF, SecurityStrength, XOF, XofOutput};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
    use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
    use bouncycastle_sha3::{SHA3_256, SHAKE128, SHAKE256};

    /// Regression: when the 4 trailing message bits plus the SHAKE "1111" suffix exactly fill a byte,
    /// the sponge must still switch to squeezing, otherwise the first squeeze appended a second suffix.
    /// Vector: NIST CAVP SHA3VS SHAKE128ShortMsg (bit-oriented), Len = 4, Msg = 08 (FIPS 202 B.1
    /// packing: message bits 0001 in the low nibble, first bit in the LSB), i.e. 0x10 in the API's
    /// MSB-first order.
    #[test]
    fn into_output_partial_bits_four_bits() {
        let shake = SHAKE128::new();
        let mut out = shake.into_output_partial_bits(0x10, 4).unwrap();
        assert_eq!(
            out.do_output(16),
            bouncycastle_hex::decode("d40238024b040a954d9c2c89daf480e5").unwrap(),
            "SHAKE128 of the 4-bit message 0001"
        );
    }

    /// into_output_partial_bits() must validate num_bits before shifting: 0 is allowed
    /// (finalize with no partial byte), 8+ is rejected with InvalidLength rather than panicking.
    #[test]
    fn into_output_partial_bits_validates_range() {
        for bad in [8usize, 9, 15, 16, 64, usize::MAX] {
            let mut shake = SHAKE128::new();
            shake.do_update(b"abc");
            assert!(
                matches!(
                    shake.into_output_partial_bits(0xFF, bad),
                    Err(HashError::InvalidLength(_))
                ),
                "num_bits={bad}"
            );
        }
        let mut a = SHAKE128::new();
        a.do_update(b"abc");
        let mut a = a.into_output_partial_bits(0xFF, 0).unwrap();
        assert_eq!(a.do_output(32), SHAKE128::new().hash_xof(b"abc", 32));

        // Upper boundary: 7 bits is the largest valid partial byte and must be accepted, and must
        // actually change the output relative to the byte-aligned message.
        let mut b = SHAKE128::new();
        b.do_update(b"abc");
        let mut b = b.into_output_partial_bits(0xFE, 7).unwrap();
        assert_ne!(b.do_output(32), SHAKE128::new().hash_xof(b"abc", 32));
    }

    /// The two `Hash` metadata methods, pinned to their actual values.
    ///
    /// The generic framework can only check that these are positive and byte-aligned, which every
    /// plausible mis-derivation also satisfies -- `cargo mutants` survived three separate mutations
    /// of them until this test existed.
    ///
    /// `block_bitlen` is the sponge rate, `1600 - 2c`: FIPS 202 Table 3 gives 1344 bits for
    /// SHAKE128 and 1088 for SHAKE256. `output_len` is the nominal digest size, which BC Java's
    /// `SHAKEDigest.getDigestSize()` defines as `fixedOutputLength / 4`: 32 and 64 bytes.
    #[test]
    fn metadata_matches_fips202_and_bc_java() {
        assert_eq!(SHAKE128::new().block_bitlen(), 1344, "SHAKE128 rate, FIPS 202 Table 3");
        assert_eq!(SHAKE256::new().block_bitlen(), 1088, "SHAKE256 rate, FIPS 202 Table 3");
        assert_eq!(SHAKE128::new().output_len(), 32, "SHAKEDigest.getDigestSize() for SHAKE128");
        assert_eq!(SHAKE256::new().output_len(), 64, "SHAKEDigest.getDigestSize() for SHAKE256");

        // and do_final actually produces that many bytes
        assert_eq!(SHAKE128::new().hash(b"abc").len(), 32);
        assert_eq!(SHAKE256::new().hash(b"abc").len(), 64);
    }

    #[test]
    fn test_update_bytes() {
        for tc in read_test_vectors("SHAKETestVectors.txt") {
            //println!("SHAKE-{} {}-bits", &tc.algorithm, &tc.bits);
            //println!("msg {}", hex::encode_upper(&tc.msg));
            //println!("hashes {}", hex::encode_upper(&tc.output));

            match tc.algorithm {
                128 => run_test_case(tc, SHAKE128::new()),
                256 => run_test_case(tc, SHAKE256::new()),
                _ => panic!("Unsupported algorithm {}", tc.algorithm),
            }
        }
    }

    #[test]
    fn test_kdf() {
        let testframework = TestFrameworkKDF::new();

        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED[..32]).unwrap();
        // println!("{:x?}", &DUMMY_SEED[..32]);

        // Without additional input -- SHAKE128
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_len(), 32);
        let expected_key = KeyMaterial256::from_bytes(b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10\xce\xc0\xce\xcf\x79\x85\x9e\xc0\xfe\xc3\xd4\x09\xe5\x84\x7a\x92").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHAKE128>(&key_material, &[0u8; 0], &expected_key);

        // Without additional input -- SHAKE256
        let derived_key = SHAKE256::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_len(), 64);
        let expected_key = KeyMaterial512::from_bytes(b"\x69\xf0\x7c\x88\x40\xce\x80\x02\x4d\xb3\x09\x39\x88\x2c\x3d\x5b\xbc\x9c\x98\xb3\xe3\x1e\x45\x13\xeb\xd2\xca\x9b\x45\x03\xcd\xd3\xc9\xc9\x07\x42\x45\x2c\x71\x73\xd4\xa7\x5a\xc4\x91\x63\xe1\x4e\xe0\xcc\x24\xef\x70\x35\xb2\x72\xd1\x9a\x7a\xf1\x09\x9b\x33\x3f").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHAKE256>(&key_material, &[0u8; 0], &expected_key);

        // With additional input
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 8]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\xfb\x4e\x8b\x67\xbb\xb8\xe1\x16\xa7\x76\x17\x2d\xb6\x64\xc9\xcd\x71\xad\x3b\xc0\xce\x45\xd3\xe8\xd0\x43\x43\x97\x79\xeb\x2d\xd1").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_single_key::<SHAKE128>(&key_material, &[0u8; 8], &expected_key);

        // derive_key_from_multiple
        let keys = [&key_material, &key_material];
        let derived_key = SHAKE128::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        let mut expected_key = KeyMaterial256::from_bytes(b"\xc2\x44\x60\x7f\x7b\x84\x3a\xe3\xc7\x69\x3d\x0b\x39\x9a\x3d\x50\x2e\x42\x58\x96\x33\xc7\x3a\xc1\x1f\xae\x0a\x04\x7b\x49\x1e\xf4").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        testframework.test_kdf_multiple_key::<SHAKE128>(&keys, &[0u8; 0], &mut expected_key);

        // success case -- output version
        let mut derived_key = KeyMaterial256::new();
        SHAKE128::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 32);
        let expected_key = KeyMaterial256::from_bytes(b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10\xce\xc0\xce\xcf\x79\x85\x9e\xc0\xfe\xc3\xd4\x09\xe5\x84\x7a\x92").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // test with a really long output key
        let mut derived_key = KeyMaterial::<10_000>::new();
        SHAKE128::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 10_000);
        // check that data was written to the end of the buffer
        assert_ne!(derived_key.ref_to_bytes()[10_000 - 10..10_000], [0u8; 10]);
    }

    #[test]
    fn test_kdf_undersized_and_oversized() {
        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED[..32]).unwrap();

        // at size
        let mut derived_key = KeyMaterial::<32>::new();
        SHAKE128::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 32);
        let expected_key = KeyMaterial256::from_bytes(b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10\xce\xc0\xce\xcf\x79\x85\x9e\xc0\xfe\xc3\xd4\x09\xe5\x84\x7a\x92").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // undersized -- should truncate
        let mut derived_key = KeyMaterial::<16>::new();
        SHAKE128::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 16);
        let expected_key = KeyMaterial256::from_bytes(
            b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10",
        )
        .unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // oversized -- SHAKE128 is an XOF, so it should fill the provided buffer
        let mut derived_key = KeyMaterial::<200>::new();
        SHAKE128::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 200);
        let expected_key = KeyMaterial256::from_bytes(b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10\xce\xc0\xce\xcf\x79\x85\x9e\xc0\xfe\xc3\xd4\x09\xe5\x84\x7a\x92").unwrap();
        assert_eq!(&derived_key.ref_to_bytes()[..32], expected_key.ref_to_bytes());
        // and there should be data all the way to the end, but I don't have a reference vector for it...
        assert_ne!(&derived_key.ref_to_bytes()[32..], [0u8; 200 - 32]);
    }

    #[test]
    fn kdf_input_entropy() {
        // Exact entropy
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
                .unwrap();
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10\xce\xc0\xce\xcf\x79\x85\x9e\xc0\xfe\xc3\xd4\x09\xe5\x84\x7a\x92").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        assert_eq!(derived_key.key_type(), KeyType::CryptographicRandom);

        // more entropy than needed -- single input key
        let key_material =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::CryptographicRandom)
                .unwrap();
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::CryptographicRandom);

        // // more entropy than needed -- multiple input keys
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::CryptographicRandom)
                .unwrap();
        let keys = [&key_material, &key_material];
        let derived_key = SHAKE128::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::CryptographicRandom);

        // more entropy than needed -- multiple input keys of different full-entropy types;
        // should get the type of the first one
        let key_material1 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::MACKey).unwrap();
        let key_material2 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::SymmetricCipherKey)
                .unwrap();
        let keys = [&key_material1, &key_material2];
        let derived_key = SHAKE128::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::MACKey);

        // // less entropy than needed -- various permutations, but not exhaustive

        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..31], KeyType::CryptographicRandom)
                .unwrap();
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::Unknown);

        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::CryptographicRandom)
                .unwrap();
        let keys = [&key_material, &key_material];
        let derived_key = SHAKE256::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::Unknown);

        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..8], KeyType::CryptographicRandom)
                .unwrap();
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::Unknown);

        let key_low_entropy =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Unknown).unwrap();
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..16], KeyType::CryptographicRandom)
                .unwrap();
        let keys = [&key_material, &key_low_entropy];
        let derived_key = SHAKE128::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::Unknown);
    }

    #[test]
    fn security_strength() {
        assert_eq!(KDF::max_security_strength(&SHAKE128::default()), SecurityStrength::_128bit);
        assert_eq!(Hash::max_security_strength(&SHAKE128::default()), SecurityStrength::_128bit);
        assert_eq!(KDF::max_security_strength(&SHAKE256::default()), SecurityStrength::_256bit);
        assert_eq!(Hash::max_security_strength(&SHAKE256::default()), SecurityStrength::_256bit);
    }

    #[test]
    fn run_kats() {
        run_test_vectors(read_test_vectors("SHAKETestVectors.txt"));
    }

    #[test]
    fn test_framework_xof() {
        let test_framework = TestFrameworkXOF::new();
        test_framework.test_xof::<SHAKE128>(&DUMMY_SEED[..512], b"\x88\x90\xED\x20\x4D\x22\x89\xE1\x72\xE9\xAE\x68\x48\x18\x23\x77\x08\x20\x90\x80\x60\xA4\xDF\x33\x51\xA3\xF1\x84\xEB\xB6\xDD\x0F\x9D\x23\x15\x60\x68\x0F\x2C\x65\x8A\xC4\x84\x97\xAD\xB5\xA4\x83\x99\x36\xA3\x16\x55\x16\xFA\x5E\x13\xBF\x8A\x15\xBA\xBC\x14\x1F");
        test_framework.test_xof::<SHAKE256>(&DUMMY_SEED[..512], b"\xA1\xD7\x18\x85\xB0\xA8\x41\xF0\x3D\x1D\xC7\xF2\x73\x8A\x15\xCC\x98\x40\x71\xA1\x7F\xFE\xD5\xEC\xAC\xB9\xF5\x87\x20\xA4\x73\xBE\x1F\x2D\x28\xB9\x6D\x54\x3A\x36\x7C\x81\x11\x42\x06\xF5\xAF\x37\x18\xE7\x31\x5B\x57\xF2\x90\xB6\x4D\x8D\x29\xCF\x43\x7E\x40\x4C");
    }

    #[test]
    fn suspendable_state() {
        use bouncycastle_core::errors::SuspendableError;
        use bouncycastle_core::traits::Suspendable;
        use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

        let str = "Colorless green ideas sleep furiously";

        // A helper that exercises the full round-trip for one SHAKE variant.
        // Each phase suspends as its own type: an absorbing state resumes as `X`, a squeezing one
        // as `X::Output`, and each rejects the other's phase.
        fn round_trip<const N: usize, X>(mut shake: X, input: &[u8])
        where
            X: XOF + Suspendable<N> + Clone,
            X::Output: Suspendable<N> + Clone,
        {
            shake.do_update(input);

            // do the default trait-conformance tests
            TestFrameworkSuspendableState::new().test(&shake);

            // Test #1
            // serialize the in-progress (absorbing) state, then read from the original and compare
            let absorbing_state = shake.clone().suspend();
            let mut out = shake.into_output();
            let expected = out.do_output(64);

            // rebuild from the serialized state and confirm it produces the same output
            let from_state =
                X::from_suspended(absorbing_state).expect("an absorbing state resumes as the XOF");
            assert_eq!(expected, from_state.into_output().do_output(64));

            // Test #2
            // serialize the in-progress (squeezing) state, then read more from the original and compare
            let squeezing_state = out.clone().suspend();
            let expected = out.do_output(64);

            // rebuild from the serialized state and confirm it produces the same output
            let mut from_state = X::Output::from_suspended(squeezing_state)
                .expect("a squeezing state resumes as the output");
            assert_eq!(expected, from_state.do_output(64));

            // The phase is part of the state, so each type refuses the other's.
            assert!(
                matches!(X::from_suspended(squeezing_state), Err(SuspendableError::InvalidData)),
                "a squeezing state must not resume as an absorbing XOF"
            );
            assert!(
                matches!(
                    X::Output::from_suspended(absorbing_state),
                    Err(SuspendableError::InvalidData)
                ),
                "an absorbing state must not resume as an output"
            );

            // a corrupt `squeezing` byte (last byte of the keccak state) must be rejected.
            // Layout: 3 version bytes + variant tag(1) + [u64;25](200) + data_queue(192)
            //         + bits_in_queue(8) + squeezing(1)
            let mut busted = squeezing_state;
            busted[3 + 1 + 400] = 42;
            match X::Output::from_suspended(busted) {
                Err(SuspendableError::InvalidData) => { /* good */ }
                _ => panic!("Expected an error for a corrupt squeezing byte"),
            }
        }

        round_trip(SHAKE128::new(), str.as_bytes());
        round_trip(SHAKE256::new(), str.as_bytes());

        // A state serialized by one variant must be rejected by a different variant (mismatched
        // variant tag). The SHAKE256 -> SHA3-256 case is the important one: they share the same rate
        // (1088), so only the variant tag distinguishes them.
        let mut shake128 = SHAKE128::new();
        shake128.do_update(str.as_bytes());
        let serialized_128 = shake128.suspend();
        match SHAKE256::from_suspended(serialized_128) {
            Err(SuspendableError::InvalidData) => { /* good */ }
            _ => panic!("Expected an error when loading a SHAKE128 state into SHAKE256"),
        }

        let mut shake256 = SHAKE256::new();
        shake256.do_update(str.as_bytes());
        let serialized_256 = shake256.suspend();
        match SHA3_256::from_suspended(serialized_256) {
            Err(SuspendableError::InvalidData) => { /* good */ }
            _ => panic!("Expected an error when loading a SHAKE256 state into SHA3-256"),
        }
    }

    fn run_test_vectors(test_vectors: Vec<TestCase>) {
        for tc in test_vectors {
            //println!("SHA3-{} {}-bits", &tc.algorithm, &tc.bits);
            //println!("msg {}", hex::encode_upper(&tc.msg));
            //println!("hashes {}", hex::encode_upper(&tc.hashes));

            match tc.algorithm {
                128 => run_test_case(tc, SHAKE128::new()),
                256 => run_test_case(tc, SHAKE256::new()),
                _ => panic!("Unsupported algorithm {}", tc.algorithm),
            }
        }
    }

    fn run_test_case(tc: TestCase, mut shake: impl XOF) {
        let partial_bits = tc.bits % 8;
        let output: Vec<u8>;

        if partial_bits == 0 {
            shake.do_update(tc.msg.as_slice());
            let mut shake = shake.into_output();
            output = shake.do_output(tc.output.len());
        } else {
            shake.do_update(&tc.msg[..(tc.msg.len() - 1)]);
            let mut shake = shake
                .into_output_partial_bits(tc.msg[tc.msg.len() - 1], partial_bits)
                .expect("partial_bits is in 1..=7");
            output = shake.do_output(tc.output.len());
        }

        assert_eq!(tc.output, output);
    }
}

/** Constant helpers **/

pub(crate) mod shake_test_helpers {
    use bouncycastle_hex as hex;
    use std::fs;
    use std::path::Path;
    use std::sync::Once;

    // Test vectors are read from the bc-test-data repo (https://github.com/bcgit/bc-test-data),
    // which must be cloned alongside this repo at "../bc-test-data" (same convention as the mldsa
    // and mlkem crates). If it is not present the vector tests print a warning and pass vacuously.
    const TEST_DATA_PATH_RELATIVE: &str = "../../../bc-test-data/crypto";
    const TEST_DATA_PATH: &str = "../bc-test-data/crypto";

    static TEST_DATA_CHECK: Once = Once::new();

    /// Returns the contents of `filename` from bc-test-data, or `None` (after a one-time warning)
    /// if the repo is not checked out.
    fn get_test_data(filename: &str) -> Option<String> {
        let dir =
            [TEST_DATA_PATH_RELATIVE, TEST_DATA_PATH].into_iter().find(|d| Path::new(d).exists());
        TEST_DATA_CHECK.call_once(|| match dir {
            Some(d) => println!("bc-test-data found at: {d:?}"),
            None => {
                println!("WARNING: bc-test-data directory not found; vector tests will be skipped")
            }
        });
        let dir = dir?;
        Some(
            fs::read_to_string(format!("{dir}/{filename}"))
                .expect("failed to read test vector file"),
        )
    }

    const SAMPLE_OF: &str = " sample of ";
    const MSG_HEADER: &str = "Msg as bit string";
    const OUTPUT_HEADER: &str = "Output val is";

    pub(crate) struct TestCase {
        pub(crate) algorithm: usize,
        pub(crate) bits: usize,
        pub(crate) msg: Vec<u8>,
        pub(crate) output: Vec<u8>,
    }

    /// Parses the named NIST FIPS 202 example-vector file from bc-test-data. Returns an empty list
    /// (skipping the test) if bc-test-data is not available.
    pub(crate) fn read_test_vectors(filename: &str) -> Vec<TestCase> {
        let mut test_vectors: Vec<TestCase> = vec![];
        let Some(content) = get_test_data(filename) else {
            return test_vectors;
        };
        let string_content: Vec<String> = content.lines().map(String::from).collect();

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
                if !string_content[i].contains(OUTPUT_HEADER) {
                    panic!("Missing header {}", OUTPUT_HEADER);
                }

                i += 1;
                let mut block: Vec<u8> = vec![];
                while string_content[i].len() != 0 {
                    let line = string_content[i].replace(" ", "");
                    block.append(&mut Vec::from(line));
                    i += 1;
                }
                let output = hex::decode(&*String::from_utf8(block).unwrap()).unwrap();

                let v = TestCase { algorithm, bits, msg, output };
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

        // Whole bytes are packed per FIPS 202 Appendix B.1 (Algorithm 11, b2h: message bit 8i + j has
        // weight 2^j in byte i, i.e. the first bit is the LSB), which is how SHA-3 reads a byte-oriented
        // message.
        for i in 0..full_bytes {
            let index = i * 8;
            block[index..(index + 8)].reverse();
            result[i] = parse_binary(&block[index..(index + 8)]);
        }

        // The trailing partial byte is packed the way the API takes it: the remaining message bits
        // in order from the most significant bit down (ASN.1 BIT STRING order, X.690 s. 8.6.2.1),
        // with the unused low bits zero.
        if total_bytes > full_bytes {
            let partial_bits = bits - full_bytes * 8;
            result[full_bytes] = parse_binary(&block[(full_bytes * 8)..]) << (8 - partial_bits);
        }

        result
    }

    fn parse_binary(block: &[u8]) -> u8 {
        let str = std::str::from_utf8(block).unwrap();
        isize::from_str_radix(str, 2).unwrap() as u8
    }
}
