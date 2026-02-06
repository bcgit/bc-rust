#![feature(unwrap_infallible)]
extern crate core;

#[cfg(test)]
mod shake_tests {
    use super::shake_test_helpers::*;
    use bouncycastle_core_interface::key_material::{
        KeyMaterial256, KeyMaterial512, KeyMaterialInternal, KeyType,
    };
    use bouncycastle_core_interface::traits::{KDF, KeyMaterial, SecurityStrength, XOF};
    use bouncycastle_core_test_framework::DUMMY_SEED_512;
    use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
    use bouncycastle_sha3::{SHAKE128, SHAKE256};

    #[test]
    fn test_xof_partial_bit_output() {
        // we know that the 4th ([3]) byte of the output of SHA128(\x00\x01\x02\x03\x04) is 0xFF
        // So we'll play with that to test partial byte output.

        let output = SHAKE128::new().hash_xof(&[0u8, 1u8, 2u8, 3u8, 4u8], 4);
        assert_eq!(output[3], 0xFF);

        // just for comparison
        let mut output2 = vec![0u8; 4];
        SHAKE128::new().hash_xof_out(&[0u8, 1u8, 2u8, 3u8, 4u8], &mut output2);
        assert_eq!(output, output2);

        // test bounds
        let mut shake = SHAKE128::new();
        shake.absorb(&[0u8, 1u8, 2u8, 3u8, 4u8]).expect("Absorb failed");
        let _throwaway = shake.squeeze(3);
        match shake.squeeze_partial_byte_final(0) {
            Err(_) => { /* good */ }
            _ => {
                panic!("Should have failed")
            }
        }

        let mut shake = SHAKE128::new();
        shake.absorb(&[0u8, 1u8, 2u8, 3u8, 4u8]).expect("Absorb failed");
        let _throwaway = shake.squeeze(3);
        match shake.squeeze_partial_byte_final(8) {
            Err(_) => { /* good */ }
            _ => {
                panic!("Should have failed")
            }
        }

        for i in 1..7 {
            let mut shake = SHAKE128::new();
            shake.absorb(&[0u8, 1u8, 2u8, 3u8, 4u8]).expect("Absorb failed");
            _ = shake.squeeze(3);
            let out: u8 = shake.squeeze_partial_byte_final(i).expect("Squeeze failed");
            assert_eq!(out, 0xFF >> (8 - i));
        }

        // success case -- output slice version
        let mut shake = SHAKE128::new();
        shake.absorb(&[0u8, 1u8, 2u8, 3u8, 4u8]).expect("Absorb failed");
        _ = shake.squeeze(3);
        let mut out = 0u8;
        shake.squeeze_partial_byte_final_out(1, &mut out).expect("Squeeze failed");
        assert_eq!(out, 0x01);
    }

    #[test]
    fn test_update_bytes() {
        for tc in read_test_vectors("tests/data/SHAKETestVectors.txt") {
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

        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED_512[..32]).unwrap();
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
        let mut derived_key = KeyMaterialInternal::<10_000>::new();
        SHAKE128::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 10_000);
        // check that data was written to the end of the buffer
        assert_ne!(derived_key.ref_to_bytes()[10_000 - 10..10_000], [0u8; 10]);
    }

    #[test]
    fn test_kdf_undersized_and_oversized() {
        let key_material = KeyMaterial256::from_bytes(&DUMMY_SEED_512[..32]).unwrap();

        // at size
        let mut derived_key = KeyMaterialInternal::<32>::new();
        SHAKE128::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 32);
        let expected_key = KeyMaterial256::from_bytes(b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10\xce\xc0\xce\xcf\x79\x85\x9e\xc0\xfe\xc3\xd4\x09\xe5\x84\x7a\x92").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // undersized -- should truncate
        let mut derived_key = KeyMaterialInternal::<16>::new();
        SHAKE128::new().derive_key_out(&key_material, &[0u8; 0], &mut derived_key).unwrap();
        assert_eq!(derived_key.key_len(), 16);
        let expected_key = KeyMaterial256::from_bytes(
            b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10",
        )
        .unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());

        // oversized -- SHAKE128 is an XOF, so it should fill the provided buffer
        let mut derived_key = KeyMaterialInternal::<200>::new();
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
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        let expected_key = KeyMaterial256::from_bytes(b"\x06\x6a\x36\x1d\xc6\x75\xf8\x56\xce\xcd\xc0\x2b\x25\x21\x8a\x10\xce\xc0\xce\xcf\x79\x85\x9e\xc0\xfe\xc3\xd4\x09\xe5\x84\x7a\x92").unwrap();
        assert_eq!(derived_key.ref_to_bytes(), expected_key.ref_to_bytes());
        assert_eq!(derived_key.key_type(), KeyType::BytesFullEntropy);

        // more entropy than needed -- single input key
        let key_material =
            KeyMaterial512::from_bytes_as_type(&DUMMY_SEED_512[..64], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesFullEntropy);

        // // more entropy than needed -- multiple input keys
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::BytesFullEntropy)
                .unwrap();
        let keys = [&key_material, &key_material];
        let derived_key = SHAKE128::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesFullEntropy);

        // more entropy than needed -- multiple input keys of different full-entropy types;
        // should get the type of the first one
        let key_material1 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::MACKey).unwrap();
        let key_material2 =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::SymmetricCipherKey)
                .unwrap();
        let keys = [&key_material1, &key_material2];
        let derived_key = SHAKE128::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::MACKey);

        // // less entropy than needed -- various permutations, but not exhaustive

        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..31], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);

        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::BytesFullEntropy)
                .unwrap();
        let keys = [&key_material, &key_material];
        let derived_key = SHAKE256::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);

        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..8], KeyType::BytesFullEntropy)
                .unwrap();
        let derived_key = SHAKE128::new().derive_key(&key_material, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);

        let key_low_entropy =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..32], KeyType::BytesLowEntropy)
                .unwrap();
        let key_material =
            KeyMaterial256::from_bytes_as_type(&DUMMY_SEED_512[..16], KeyType::BytesFullEntropy)
                .unwrap();
        let keys = [&key_material, &key_low_entropy];
        let derived_key = SHAKE128::new().derive_key_from_multiple(&keys, &[0u8; 0]).unwrap();
        assert_eq!(derived_key.key_type(), KeyType::BytesLowEntropy);
    }

    #[test]
    fn test_security_strength() {
        assert_eq!(KDF::max_security_strength(&SHAKE128::default()), SecurityStrength::_128bit);
        assert_eq!(XOF::max_security_strength(&SHAKE128::default()), SecurityStrength::_128bit);
        assert_eq!(KDF::max_security_strength(&SHAKE256::default()), SecurityStrength::_256bit);
        assert_eq!(XOF::max_security_strength(&SHAKE256::default()), SecurityStrength::_256bit);
    }

    #[test]
    fn run_kats() {
        run_test_vectors(read_test_vectors("tests/data/SHAKETestVectors.txt"));
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
            shake.absorb(tc.msg.as_slice()).expect("Absorb failed");
            output = shake.squeeze(tc.output.len()).expect("Squeeze failed.");
        } else {
            shake.absorb(&tc.msg[..(tc.msg.len() - 1)]).expect("Absorb failed");
            shake
                .absorb_last_partial_byte(tc.msg[tc.msg.len() - 1], partial_bits)
                .expect("Absorb failed");
            output = shake.squeeze(tc.output.len()).expect("Squeeze failed.");
        }

        assert_eq!(tc.output, output);
    }
}

/** Constant helpers **/

pub(crate) mod shake_test_helpers {
    use bouncycastle_hex as hex;
    use std::fs;

    const SAMPLE_OF: &str = " sample of ";
    const MSG_HEADER: &str = "Msg as bit string";
    const OUTPUT_HEADER: &str = "Output val is";

    pub(crate) struct TestCase {
        pub(crate) algorithm: usize,
        pub(crate) bits: usize,
        pub(crate) msg: Vec<u8>,
        pub(crate) output: Vec<u8>,
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
