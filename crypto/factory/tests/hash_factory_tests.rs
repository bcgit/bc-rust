#[cfg(test)]
mod hash_factory_tests {
    use bouncycastle_core::errors::HashError;
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{Hash, XOF};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_factory::hash_factory::HashFactory;
    use bouncycastle_factory::xof_factory::XOFFactory;
    use bouncycastle_factory::{AlgorithmFactory, FactoryError};

    mod sha3_tests {
        use super::*;
        use bouncycastle_factory as factory;
        use bouncycastle_sha2 as sha2;
        use bouncycastle_sha2::SHA224;
        use bouncycastle_sha3 as sha3;

        #[test]
        fn sha2_hash_tests() {
            // SHA224

            let h = SHA224::new();
            h.hash(&DUMMY_SEED[..24]);

            let sha2 = HashFactory::new("SHA224").unwrap();
            assert_eq!(sha2.output_len(), 28);
            assert_eq!(sha2.hash(&DUMMY_SEED[..512]), b"\xb8\x06\x0c\xcc\x82\xd4\x0c\x57\x61\x56\xf7\xca\x03\x33\xe4\x38\x9e\x41\x0d\xf0\x27\xd2\xfb\x8f\x76\x4f\xa6\x03");

            let sha2 = HashFactory::new(sha2::SHA224_NAME).unwrap();
            assert_eq!(sha2.output_len(), 28);
            assert_eq!(sha2.hash(&DUMMY_SEED[..512]), b"\xb8\x06\x0c\xcc\x82\xd4\x0c\x57\x61\x56\xf7\xca\x03\x33\xe4\x38\x9e\x41\x0d\xf0\x27\xd2\xfb\x8f\x76\x4f\xa6\x03");

            // SHA256
            let sha2 = HashFactory::new("SHA256").unwrap();
            assert_eq!(sha2.output_len(), 32);
            assert_eq!(sha2.hash(&DUMMY_SEED[..512]), b"\x11\x00\x09\xdc\xee\x21\x62\x0b\x16\x6f\x3a\xbf\xec\xb5\xef\xf7\xa8\x73\xbe\x72\x9d\x1c\x2d\x53\x82\x2e\x7a\xcc\x5f\x34\xeb\x9b");

            let sha2 = HashFactory::new(sha2::SHA256_NAME).unwrap();
            assert_eq!(sha2.output_len(), 32);
            assert_eq!(sha2.hash(&DUMMY_SEED[..512]), b"\x11\x00\x09\xdc\xee\x21\x62\x0b\x16\x6f\x3a\xbf\xec\xb5\xef\xf7\xa8\x73\xbe\x72\x9d\x1c\x2d\x53\x82\x2e\x7a\xcc\x5f\x34\xeb\x9b");

            // SHA384
            let sha2 = HashFactory::new("SHA384").unwrap();
            assert_eq!(sha2.output_len(), 48);
            assert_eq!(sha2.hash(&DUMMY_SEED[..512]), b"\x45\x82\xfc\x82\x43\x0e\x52\x68\x86\xa1\x85\x34\x11\xe6\x06\x45\xfe\xf7\xe8\xea\x0c\x85\x46\xb7\xc9\xba\x0c\x84\x16\xd9\xa9\x8f\xb5\x2e\xbd\x0c\x60\x5f\xbb\x70\x74\x9c\x4e\x3e\x5d\xa3\xdb\xac");

            let sha2 = HashFactory::new(sha2::SHA384_NAME).unwrap();
            assert_eq!(sha2.output_len(), 48);
            assert_eq!(sha2.hash(&DUMMY_SEED[..512]), b"\x45\x82\xfc\x82\x43\x0e\x52\x68\x86\xa1\x85\x34\x11\xe6\x06\x45\xfe\xf7\xe8\xea\x0c\x85\x46\xb7\xc9\xba\x0c\x84\x16\xd9\xa9\x8f\xb5\x2e\xbd\x0c\x60\x5f\xbb\x70\x74\x9c\x4e\x3e\x5d\xa3\xdb\xac");

            // SHA512
            let sha2 = HashFactory::new("SHA512").unwrap();
            assert_eq!(sha2.output_len(), 64);
            assert_eq!(sha2.hash(&DUMMY_SEED[..512]), b"\xed\xb9\xbe\xd7\x21\xaa\x6a\x5f\x6f\xbc\x66\x19\xd3\xa3\xc2\xbe\x3d\x04\x30\x43\xf0\x5a\x9a\xeb\xc7\xb1\x19\x7a\x2a\xa9\xc4\x9a\x57\xd5\xdd\xd4\x67\x4c\x17\x85\x78\x50\x88\xd9\xf1\xff\x42\xc7\x97\xa0\x2a\xdc\x9b\x81\x7a\x13\x9a\x50\x97\x0d\xa6\xc9\x95\x24");

            let sha2 = HashFactory::new(sha2::SHA512_NAME).unwrap();
            assert_eq!(sha2.output_len(), 64);
            assert_eq!(sha2.hash(&DUMMY_SEED[..512]), b"\xed\xb9\xbe\xd7\x21\xaa\x6a\x5f\x6f\xbc\x66\x19\xd3\xa3\xc2\xbe\x3d\x04\x30\x43\xf0\x5a\x9a\xeb\xc7\xb1\x19\x7a\x2a\xa9\xc4\x9a\x57\xd5\xdd\xd4\x67\x4c\x17\x85\x78\x50\x88\xd9\xf1\xff\x42\xc7\x97\xa0\x2a\xdc\x9b\x81\x7a\x13\x9a\x50\x97\x0d\xa6\xc9\x95\x24");

            // SHA512/224 -- "abc" vector from the NIST example file SHA512_224.pdf
            let sha2 = HashFactory::new("SHA512/224").unwrap();
            assert_eq!(sha2.output_len(), 28);
            assert_eq!(sha2.hash(b"abc"), b"\x46\x34\x27\x0f\x70\x7b\x6a\x54\xda\xae\x75\x30\x46\x08\x42\xe2\x0e\x37\xed\x26\x5c\xee\xe9\xa4\x3e\x89\x24\xaa");

            let sha2 = HashFactory::new(sha2::SHA512_224_NAME).unwrap();
            assert_eq!(sha2.output_len(), 28);
            assert_eq!(sha2.hash(b"abc"), b"\x46\x34\x27\x0f\x70\x7b\x6a\x54\xda\xae\x75\x30\x46\x08\x42\xe2\x0e\x37\xed\x26\x5c\xee\xe9\xa4\x3e\x89\x24\xaa");

            // SHA512/256 -- "abc" vector from the NIST example file SHA512_256.pdf
            let sha2 = HashFactory::new("SHA512/256").unwrap();
            assert_eq!(sha2.output_len(), 32);
            assert_eq!(sha2.hash(b"abc"), b"\x53\x04\x8e\x26\x81\x94\x1e\xf9\x9b\x2e\x29\xb7\x6b\x4c\x7d\xab\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46\xe0\xe2\xf1\x31\x07\xe7\xaf\x23");

            let sha2 = HashFactory::new(sha2::SHA512_256_NAME).unwrap();
            assert_eq!(sha2.output_len(), 32);
            assert_eq!(sha2.hash(b"abc"), b"\x53\x04\x8e\x26\x81\x94\x1e\xf9\x9b\x2e\x29\xb7\x6b\x4c\x7d\xab\xe4\xc2\xd0\xc6\x34\xfc\x6d\x46\xe0\xe2\xf1\x31\x07\xe7\xaf\x23");

            // The remaining pass-throughs, on the same "abc" vectors: streaming, the _out variants
            // and block_bitlen.
            let expected_224 = HashFactory::new("SHA512/224").unwrap().hash(b"abc");
            let expected_256 = HashFactory::new("SHA512/256").unwrap().hash(b"abc");
            for (name, expected) in [("SHA512/224", &expected_224), ("SHA512/256", &expected_256)] {
                let mut sha2 = HashFactory::new(name).unwrap();
                assert_eq!(sha2.block_bitlen(), 1024);
                sha2.do_update(b"a");
                sha2.do_update(b"bc");
                assert_eq!(&sha2.do_final(), expected);

                let mut sha2 = HashFactory::new(name).unwrap();
                sha2.do_update(b"abc");
                let mut out = vec![0xffu8; expected.len()];
                assert_eq!(sha2.do_final_out(&mut out), expected.len());
                assert_eq!(&out, expected);

                let mut out = vec![0xffu8; expected.len()];
                assert_eq!(
                    HashFactory::new(name).unwrap().hash_out(b"abc", &mut out),
                    expected.len()
                );
                assert_eq!(&out, expected);
            }
        }

        #[test]
        fn sm3_hash_tests() {
            use bouncycastle_sm3 as sm3;
            // Expected values: GB/T 32905-2016 Appendix A ("abc") and openssl dgst -sm3 (DUMMY_SEED[..512]).
            for name in ["SM3", sm3::SM3_NAME] {
                let h = HashFactory::new(name).unwrap();
                assert_eq!(h.output_len(), 32);
                assert_eq!(h.block_bitlen(), 512);
                assert_eq!(
                    h.hash(&DUMMY_SEED[..512]),
                    b"\xb2\x1f\x83\x0d\xca\x06\xbe\x8b\x67\x8c\xf9\x87\xf2\x6b\x9a\x43\x6e\x1b\x42\x79\x63\xb4\x45\x03\x32\xf0\x12\x70\xbd\x2d\xf7\x5c"
                );
                let h = HashFactory::new(name).unwrap();
                assert_eq!(
                    h.hash(b"abc"),
                    b"\x66\xc7\xf0\xf4\x62\xee\xed\xd9\xd1\xf2\xd4\x6b\xdc\x10\xe4\xe2\x41\x67\xc4\x87\x5c\xf2\xf7\xa2\x29\x7d\xa0\x2b\x8f\x4b\xa8\xe0"
                );
            }
        }

        #[test]
        fn sha3_hash_tests() {
            // SHA3-224
            let sha3 = HashFactory::new("SHA3-224").unwrap();
            assert_eq!(sha3.output_len(), 28);
            assert_eq!(sha3.hash(&DUMMY_SEED[..512]), b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");

            let sha3 = HashFactory::new(sha3::SHA3_224_NAME).unwrap();
            assert_eq!(sha3.output_len(), 28);
            assert_eq!(sha3.hash(&DUMMY_SEED[..512]), b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");

            // SHA3-256
            let sha3 = HashFactory::new("SHA3-256").unwrap();
            assert_eq!(sha3.output_len(), 32);
            assert_eq!(sha3.hash(&DUMMY_SEED[..512]), b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");

            let sha3 = HashFactory::new(sha3::SHA3_256_NAME).unwrap();
            assert_eq!(sha3.output_len(), 32);
            assert_eq!(sha3.hash(&DUMMY_SEED[..512]), b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");

            // SHA3-384
            let sha3 = HashFactory::new("SHA3-384").unwrap();
            assert_eq!(sha3.output_len(), 48);
            assert_eq!(sha3.hash(&DUMMY_SEED[..512]), b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");

            let sha3 = HashFactory::new(sha3::SHA3_384_NAME).unwrap();
            assert_eq!(sha3.output_len(), 48);
            assert_eq!(sha3.hash(&DUMMY_SEED[..512]), b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");

            // SHA3-512
            let sha3 = HashFactory::new("SHA3-512").unwrap();
            assert_eq!(sha3.output_len(), 64);
            assert_eq!(sha3.hash(&DUMMY_SEED[..512]), b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");

            let sha3 = HashFactory::new(sha3::SHA3_512_NAME).unwrap();
            assert_eq!(sha3.output_len(), 64);
            assert_eq!(sha3.hash(&DUMMY_SEED[..512]), b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");
        }

        #[test]
        fn sha3_xof_tests() {
            assert_eq!(XOFFactory::new("SHAKE128").unwrap().xof(&DUMMY_SEED[..512], 32), b"\x88\x90\xed\x20\x4d\x22\x89\xe1\x72\xe9\xae\x68\x48\x18\x23\x77\x08\x20\x90\x80\x60\xa4\xdf\x33\x51\xa3\xf1\x84\xeb\xb6\xdd\x0f");
            assert_eq!(XOFFactory::new("SHAKE256").unwrap().xof(&DUMMY_SEED[..512], 32), b"\xa1\xd7\x18\x85\xb0\xa8\x41\xf0\x3d\x1d\xc7\xf2\x73\x8a\x15\xcc\x98\x40\x71\xa1\x7f\xfe\xd5\xec\xac\xb9\xf5\x87\x20\xa4\x73\xbe");
        }

        #[test]
        fn ascon_hash_tests() {
            use bouncycastle_ascon::ASCON_HASH256_NAME;
            use bouncycastle_ascon::AsconHash256;

            let direct = AsconHash256::new().hash(&DUMMY_SEED[..512]);

            // Construct by literal name and by the crate's name constant; both must match the
            // direct implementation.
            let by_name = HashFactory::new("Ascon-Hash256").unwrap();
            assert_eq!(by_name.output_len(), 32);
            assert_eq!(by_name.hash(&DUMMY_SEED[..512]), direct);

            let by_const = HashFactory::new(ASCON_HASH256_NAME).unwrap();
            assert_eq!(by_const.hash(&DUMMY_SEED[..512]), direct);

            // Unknown algorithm names are still rejected.
            assert!(matches!(
                HashFactory::new("Ascon-Hash999"),
                Err(FactoryError::UnsupportedAlgorithm(_))
            ));
        }

        /// Checks every `Hash` pass-through of the `name` variant against `expected`, the digest of
        /// `msg`; and the byte-oriented partial-bit policy of the BLAKE crates (0 bits is the
        /// whole-byte digest, 1..=7 is `InvalidInput`, more than 7 is `InvalidLength`).
        fn check_blake_hash(
            name: &str,
            msg: &[u8],
            expected: &[u8],
            block_bitlen: usize,
            strength: SecurityStrength,
        ) {
            let make = || HashFactory::new(name).unwrap();

            assert_eq!(make().output_len(), expected.len(), "{name}: output_len");
            assert_eq!(make().block_bitlen(), block_bitlen, "{name}: block_bitlen");
            assert_eq!(make().max_security_strength(), strength, "{name}: max_security_strength");

            assert_eq!(make().hash(msg), expected, "{name}: hash");

            let mut out = vec![0xffu8; expected.len()];
            assert_eq!(make().hash_out(msg, &mut out), expected.len(), "{name}: hash_out length");
            assert_eq!(out, expected, "{name}: hash_out");

            let mut h = make();
            msg.chunks(7).for_each(|c| h.do_update(c));
            assert_eq!(h.do_final(), expected, "{name}: do_update then do_final");

            let mut h = make();
            h.do_update(msg);
            let mut out = vec![0xffu8; expected.len()];
            assert_eq!(h.do_final_out(&mut out), expected.len(), "{name}: do_final_out length");
            assert_eq!(out, expected, "{name}: do_final_out");

            let mut h = make();
            h.do_update(msg);
            assert_eq!(h.do_final_partial_bits(0x00, 0).unwrap(), expected, "{name}: 0 bits");

            let mut h = make();
            h.do_update(msg);
            let mut out = vec![0xffu8; expected.len()];
            assert_eq!(
                h.do_final_partial_bits_out(0x00, 0, &mut out).unwrap(),
                expected.len(),
                "{name}: do_final_partial_bits_out length"
            );
            assert_eq!(out, expected, "{name}: do_final_partial_bits_out");

            let mut h = make();
            h.do_update(msg);
            assert!(
                matches!(h.do_final_partial_bits(0x05, 3), Err(HashError::InvalidInput(_))),
                "{name}: BLAKE is byte-oriented"
            );
            let mut out = vec![0u8; expected.len()];
            assert!(
                matches!(
                    make().do_final_partial_bits_out(0x05, 3, &mut out),
                    Err(HashError::InvalidInput(_))
                ),
                "{name}: BLAKE is byte-oriented (_out)"
            );
            assert!(
                matches!(make().do_final_partial_bits(0xff, 8), Err(HashError::InvalidLength(_))),
                "{name}: eight partial bits is not a partial byte"
            );
        }

        /// BLAKE2b-512, BLAKE2s-256 and BLAKE3 through the factory, by name constant and by string.
        ///
        /// Expected values are copied from the vectors embedded in the algorithm crates' tests:
        /// - BLAKE2b-512 / BLAKE2s-256 of "abc": RFC 7693 Appendix A / B (`RFC_ABC` in
        ///   crypto/blake2/tests/blake2{b,s}_tests.rs);
        /// - BLAKE2b-512 / BLAKE2s-256 of the 255 bytes 0, 1, ..., 254: the official BLAKE2 KAT,
        ///   blake2-kat.json (the `KAT` entry for length 255 in the same files);
        /// - BLAKE3 of the 1025-byte input `i % 251`: the official BLAKE3 test_vectors.json (the
        ///   first 32 bytes of the `hash` field of the 1025 case in
        ///   crypto/blake3/tests/vectors/mod.rs).
        #[test]
        fn blake_hash_tests() {
            use bouncycastle_blake2::{BLAKE2B_512_NAME, BLAKE2S_256_NAME};
            use bouncycastle_blake3::BLAKE3_NAME;
            use bouncycastle_hex as hex;

            let blake2b_abc = hex::decode("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923").unwrap();
            let blake2b_255 = hex::decode("5b21c5fd8868367612474fa2e70e9cfa2201ffeee8fafab5797ad58fefa17c9b5b107da4a3db6320baaf2c8617d5a51df914ae88da3867c2d41f0cc14fa67928").unwrap();
            let blake2s_abc =
                hex::decode("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
                    .unwrap();
            let blake2s_255 =
                hex::decode("f03f5789d3336b80d002d59fdf918bdb775b00956ed5528e86aa994acb38fe2d")
                    .unwrap();
            let blake3_1025 =
                hex::decode("d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444")
                    .unwrap();
            let blake3_input: Vec<u8> = (0..1025).map(|i| (i % 251) as u8).collect();

            for name in ["BLAKE2b-512", BLAKE2B_512_NAME] {
                check_blake_hash(name, b"abc", &blake2b_abc, 1024, SecurityStrength::_256bit);
                check_blake_hash(
                    name,
                    &DUMMY_SEED[..255],
                    &blake2b_255,
                    1024,
                    SecurityStrength::_256bit,
                );
            }
            for name in ["BLAKE2s-256", BLAKE2S_256_NAME] {
                check_blake_hash(name, b"abc", &blake2s_abc, 512, SecurityStrength::_128bit);
                check_blake_hash(
                    name,
                    &DUMMY_SEED[..255],
                    &blake2s_255,
                    512,
                    SecurityStrength::_128bit,
                );
            }
            for name in ["BLAKE3", BLAKE3_NAME] {
                check_blake_hash(name, &blake3_input, &blake3_1025, 512, SecurityStrength::_128bit);
            }

            // Names are case-sensitive, and the MAC names are not hashes.
            for name in
                ["blake2b-512", "BLAKE2b-256", "BLAKE2b-512-MAC", "blake3", "BLAKE3-KeyedHash"]
            {
                assert!(
                    matches!(HashFactory::new(name), Err(FactoryError::UnsupportedAlgorithm(_))),
                    "{name:?} must not construct a Hash"
                );
            }
        }

        #[test]
        fn test_defaults() {
            // All the ways to get "default"
            let hash = HashFactory::default();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new("Default").unwrap();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new(factory::DEFAULT).unwrap();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);

            // All the ways to get "default_128_bit"
            let hash = HashFactory::default_128_bit();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new("Default128Bit").unwrap();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new(factory::DEFAULT_128_BIT).unwrap();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);

            // All the ways to get "default_256_bit"
            let hash = HashFactory::default_256_bit();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new("Default256Bit").unwrap();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new(factory::DEFAULT_256_BIT).unwrap();
            let out = hash.hash(DUMMY_SEED);
            assert_ne!(out, vec![0u8; out.len()]);
        }
    }
}
