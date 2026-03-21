#[cfg(test)]
mod hash_factory_tests {
    use bouncycastle_factory::AlgorithmFactory;
    use bouncycastle_factory::hash_factory::{HashFactory};
    use bouncycastle_factory::xof_factory::{XOFFactory};
    use bouncycastle_core_interface::traits::{Hash, XOF};
    use bouncycastle_core_test_framework::DUMMY_SEED_512;

    mod sha3_tests {
        use super::*;
        use bouncycastle_sha2::SHA224;
        use bouncycastle_sha2 as sha2;
        use bouncycastle_sha3 as sha3;
        use bouncycastle_factory as factory;

        #[test]
        fn sha2_hash_tests() {
            // SHA224

            let h = SHA224::new();
            h.hash(&DUMMY_SEED_512[..24]);


            let sha2 = HashFactory::new("SHA224").unwrap();
            assert_eq!(sha2.output_len(), 28);
            assert_eq!(sha2.hash(DUMMY_SEED_512), b"\xb8\x06\x0c\xcc\x82\xd4\x0c\x57\x61\x56\xf7\xca\x03\x33\xe4\x38\x9e\x41\x0d\xf0\x27\xd2\xfb\x8f\x76\x4f\xa6\x03");

            let sha2 = HashFactory::new(sha2::SHA224_NAME).unwrap();
            assert_eq!(sha2.output_len(), 28);
            assert_eq!(sha2.hash(DUMMY_SEED_512), b"\xb8\x06\x0c\xcc\x82\xd4\x0c\x57\x61\x56\xf7\xca\x03\x33\xe4\x38\x9e\x41\x0d\xf0\x27\xd2\xfb\x8f\x76\x4f\xa6\x03");


            // SHA256
            let sha2 = HashFactory::new("SHA256").unwrap();
            assert_eq!(sha2.output_len(), 32);
            assert_eq!(sha2.hash(DUMMY_SEED_512), b"\x11\x00\x09\xdc\xee\x21\x62\x0b\x16\x6f\x3a\xbf\xec\xb5\xef\xf7\xa8\x73\xbe\x72\x9d\x1c\x2d\x53\x82\x2e\x7a\xcc\x5f\x34\xeb\x9b");

            let sha2 = HashFactory::new(sha2::SHA256_NAME).unwrap();
            assert_eq!(sha2.output_len(), 32);
            assert_eq!(sha2.hash(DUMMY_SEED_512), b"\x11\x00\x09\xdc\xee\x21\x62\x0b\x16\x6f\x3a\xbf\xec\xb5\xef\xf7\xa8\x73\xbe\x72\x9d\x1c\x2d\x53\x82\x2e\x7a\xcc\x5f\x34\xeb\x9b");

            // SHA384
            let sha2 = HashFactory::new("SHA384").unwrap();
            assert_eq!(sha2.output_len(), 48);
            assert_eq!(sha2.hash(DUMMY_SEED_512), b"\x45\x82\xfc\x82\x43\x0e\x52\x68\x86\xa1\x85\x34\x11\xe6\x06\x45\xfe\xf7\xe8\xea\x0c\x85\x46\xb7\xc9\xba\x0c\x84\x16\xd9\xa9\x8f\xb5\x2e\xbd\x0c\x60\x5f\xbb\x70\x74\x9c\x4e\x3e\x5d\xa3\xdb\xac");

            let sha2 = HashFactory::new(sha2::SHA384_NAME).unwrap();
            assert_eq!(sha2.output_len(), 48);
            assert_eq!(sha2.hash(DUMMY_SEED_512), b"\x45\x82\xfc\x82\x43\x0e\x52\x68\x86\xa1\x85\x34\x11\xe6\x06\x45\xfe\xf7\xe8\xea\x0c\x85\x46\xb7\xc9\xba\x0c\x84\x16\xd9\xa9\x8f\xb5\x2e\xbd\x0c\x60\x5f\xbb\x70\x74\x9c\x4e\x3e\x5d\xa3\xdb\xac");

            // SHA512
            let sha2 = HashFactory::new("SHA512").unwrap();
            assert_eq!(sha2.output_len(), 64);
            assert_eq!(sha2.hash(DUMMY_SEED_512), b"\xed\xb9\xbe\xd7\x21\xaa\x6a\x5f\x6f\xbc\x66\x19\xd3\xa3\xc2\xbe\x3d\x04\x30\x43\xf0\x5a\x9a\xeb\xc7\xb1\x19\x7a\x2a\xa9\xc4\x9a\x57\xd5\xdd\xd4\x67\x4c\x17\x85\x78\x50\x88\xd9\xf1\xff\x42\xc7\x97\xa0\x2a\xdc\x9b\x81\x7a\x13\x9a\x50\x97\x0d\xa6\xc9\x95\x24");

            let sha2 = HashFactory::new(sha2::SHA512_NAME).unwrap();
            assert_eq!(sha2.output_len(), 64);
            assert_eq!(sha2.hash(DUMMY_SEED_512), b"\xed\xb9\xbe\xd7\x21\xaa\x6a\x5f\x6f\xbc\x66\x19\xd3\xa3\xc2\xbe\x3d\x04\x30\x43\xf0\x5a\x9a\xeb\xc7\xb1\x19\x7a\x2a\xa9\xc4\x9a\x57\xd5\xdd\xd4\x67\x4c\x17\x85\x78\x50\x88\xd9\xf1\xff\x42\xc7\x97\xa0\x2a\xdc\x9b\x81\x7a\x13\x9a\x50\x97\x0d\xa6\xc9\x95\x24");
        }

        #[test]
        fn sha3_hash_tests() {
            // SHA3-224
            let sha3 = HashFactory::new("SHA3-224").unwrap();
            assert_eq!(sha3.output_len(), 28);
            assert_eq!(sha3.hash(DUMMY_SEED_512), b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");

            let sha3 = HashFactory::new(sha3::SHA3_224_NAME).unwrap();
            assert_eq!(sha3.output_len(), 28);
            assert_eq!(sha3.hash(DUMMY_SEED_512), b"\xFE\x51\xC5\xD7\x62\x48\xE1\xE9\xD3\x01\x29\x6A\xE8\xAB\x94\x69\xD2\x86\x34\xB4\xAD\x3E\x9E\x78\xC8\xB0\x9D\x47");


            // SHA3-256
            let sha3 = HashFactory::new("SHA3-256").unwrap();
            assert_eq!(sha3.output_len(), 32);
            assert_eq!(sha3.hash(DUMMY_SEED_512), b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");

            let sha3 = HashFactory::new(sha3::SHA3_256_NAME).unwrap();
            assert_eq!(sha3.output_len(), 32);
            assert_eq!(sha3.hash(DUMMY_SEED_512), b"\xD4\x72\x8E\xA5\xE9\xF3\x81\x9F\x2B\x47\x60\x15\x1A\x8F\x80\x2D\xBE\x9F\x94\x1F\xD6\xFB\x59\xB3\x71\x58\x92\x43\x65\x55\x77\x2A");

            // SHA3-384
            let sha3 = HashFactory::new("SHA3-384").unwrap();
            assert_eq!(sha3.output_len(), 48);
            assert_eq!(sha3.hash(DUMMY_SEED_512), b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");

            let sha3 = HashFactory::new(sha3::SHA3_384_NAME).unwrap();
            assert_eq!(sha3.output_len(), 48);
            assert_eq!(sha3.hash(DUMMY_SEED_512), b"\xd5\x3b\x51\x68\x53\xf5\xac\xb4\xaa\xfd\xa5\x9d\x6f\x74\x0f\x69\x99\xc9\xe5\x21\x1c\x51\x03\x9c\x6d\x64\x5b\xf9\x83\xd7\xba\x0b\xdf\x12\x31\xb5\x50\x90\xb5\x5e\x35\x99\xee\x7a\xaa\x62\xd3\xbf");

            // SHA3-512
            let sha3 = HashFactory::new("SHA3-512").unwrap();
            assert_eq!(sha3.output_len(), 64);
            assert_eq!(sha3.hash(DUMMY_SEED_512), b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");

            let sha3 = HashFactory::new(sha3::SHA3_512_NAME).unwrap();
            assert_eq!(sha3.output_len(), 64);
            assert_eq!(sha3.hash(DUMMY_SEED_512), b"\x58\x4c\xc7\x02\xc2\x22\x9a\x0a\xbc\x78\x9b\xfa\x64\xb4\x27\x1f\xb8\xf0\xbb\x78\x67\x15\x88\xb9\xef\x1d\x09\x3e\xa3\xd4\x72\x58\x4c\x6d\x43\xb5\x68\x33\x59\x47\x2f\x44\x1b\x33\x85\x6f\x68\x28\x59\xf0\xc3\x95\x4b\x56\x80\x8f\xd1\xfb\xa0\xb5\x9c\x9d\x19\x54");
        }

        #[test]
        fn sha3_xof_tests() {
            assert_eq!(XOFFactory::new("SHAKE128").unwrap().hash_xof(DUMMY_SEED_512, 32), b"\x88\x90\xed\x20\x4d\x22\x89\xe1\x72\xe9\xae\x68\x48\x18\x23\x77\x08\x20\x90\x80\x60\xa4\xdf\x33\x51\xa3\xf1\x84\xeb\xb6\xdd\x0f");
            assert_eq!(XOFFactory::new("SHAKE256").unwrap().hash_xof(DUMMY_SEED_512, 32), b"\xa1\xd7\x18\x85\xb0\xa8\x41\xf0\x3d\x1d\xc7\xf2\x73\x8a\x15\xcc\x98\x40\x71\xa1\x7f\xfe\xd5\xec\xac\xb9\xf5\x87\x20\xa4\x73\xbe");

        }

        #[test]
        fn test_defaults() {
            // All the ways to get "default"
            let hash = HashFactory::default();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new("Default").unwrap();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new(factory::DEFAULT).unwrap();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);

            // All the ways to get "default_128_bit"
            let hash = HashFactory::default_128_bit();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new("Default128Bit").unwrap();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new(factory::DEFAULT_128_BIT).unwrap();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);

            // All the ways to get "default_256_bit"
            let hash = HashFactory::default_256_bit();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new("Default256Bit").unwrap();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);

            let hash = HashFactory::new(factory::DEFAULT_256_BIT).unwrap();
            let out = hash.hash(DUMMY_SEED_512);
            assert_ne!(out, vec![0u8; out.len()]);
        }
    }
}