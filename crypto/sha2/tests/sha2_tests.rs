#[cfg(test)]
mod sha2_tests {
    use bouncycastle_core::errors::{HashError, SuspendableError};
    use bouncycastle_core::traits::{Algorithm, Hash, HashAlgParams, SecurityStrength};
    use bouncycastle_core_test_framework::hash::TestFrameworkHash;
    use bouncycastle_sha2::*;

    #[cfg(test)]
    mod core_test_framework_hash {
        use super::*;
        use bouncycastle_core_test_framework::DUMMY_SEED;

        #[test]
        fn sha224() {
            let test_framework = TestFrameworkHash::new();
            test_framework.test_hash::<SHA224>(b"", b"\xd1\x4a\x02\x8c\x2a\x3a\x2b\xc9\x47\x61\x02\xbb\x28\x82\x34\xc4\x15\xa2\xb0\x1f\x82\x8e\xa6\x2a\xc5\xb3\xe4\x2f");
            test_framework.test_hash::<SHA224>(b"a", b"\xab\xd3\x75\x34\xc7\xd9\xa2\xef\xb9\x46\x5d\xe9\x31\xcd\x70\x55\xff\xdb\x88\x79\x56\x3a\xe9\x80\x78\xd6\xd6\xd5");
            test_framework.test_hash::<SHA224>(b"abc", b"\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2\x55\xb3\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7");
            test_framework.test_hash::<SHA224>(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", b"\x75\x38\x8b\x16\x51\x27\x76\xcc\x5d\xba\x5d\xa1\xfd\x89\x01\x50\xb0\xc6\x45\x5c\xb4\xf5\x8b\x19\x52\x52\x25\x25");
            test_framework.test_hash::<SHA224>(&DUMMY_SEED[..512], b"\xb8\x06\x0c\xcc\x82\xd4\x0c\x57\x61\x56\xf7\xca\x03\x33\xe4\x38\x9e\x41\x0d\xf0\x27\xd2\xfb\x8f\x76\x4f\xa6\x03");
            test_framework.test_hash::<SHA224>(DUMMY_SEED, b"\x62\x90\x81\x7f\x60\x01\x43\x2c\xd4\x41\x05\x8d\x2b\xb8\x2d\x88\xb3\xf3\x24\x25\xad\xe4\xc9\x3d\x56\x20\x78\x38");
        }

        #[test]
        fn sha256() {
            let test_framework = TestFrameworkHash::new();
            test_framework.test_hash::<SHA256>(b"", b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55");
            test_framework.test_hash::<SHA256>(b"a", b"\xca\x97\x81\x12\xca\x1b\xbd\xca\xfa\xc2\x31\xb3\x9a\x23\xdc\x4d\xa7\x86\xef\xf8\x14\x7c\x4e\x72\xb9\x80\x77\x85\xaf\xee\x48\xbb");
            test_framework.test_hash::<SHA256>(b"abc", b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad");
            test_framework.test_hash::<SHA256>(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", b"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1");
            test_framework.test_hash::<SHA256>(&DUMMY_SEED[..512], b"\x11\x00\x09\xdc\xee\x21\x62\x0b\x16\x6f\x3a\xbf\xec\xb5\xef\xf7\xa8\x73\xbe\x72\x9d\x1c\x2d\x53\x82\x2e\x7a\xcc\x5f\x34\xeb\x9b");
        }

        #[test]
        fn sha384() {
            let test_framework = TestFrameworkHash::new();
            test_framework.test_hash::<SHA384>(b"", b"\x38\xb0\x60\xa7\x51\xac\x96\x38\x4c\xd9\x32\x7e\xb1\xb1\xe3\x6a\x21\xfd\xb7\x11\x14\xbe\x07\x43\x4c\x0c\xc7\xbf\x63\xf6\xe1\xda\x27\x4e\xde\xbf\xe7\x6f\x65\xfb\xd5\x1a\xd2\xf1\x48\x98\xb9\x5b");
            test_framework.test_hash::<SHA384>(b"a", b"\x54\xa5\x9b\x9f\x22\xb0\xb8\x08\x80\xd8\x42\x7e\x54\x8b\x7c\x23\xab\xd8\x73\x48\x6e\x1f\x03\x5d\xce\x9c\xd6\x97\xe8\x51\x75\x03\x3c\xaa\x88\xe6\xd5\x7b\xc3\x5e\xfa\xe0\xb5\xaf\xd3\x14\x5f\x31");
            test_framework.test_hash::<SHA384>(b"abc", b"\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7");
            test_framework.test_hash::<SHA384>(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", b"\x09\x33\x0c\x33\xf7\x11\x47\xe8\x3d\x19\x2f\xc7\x82\xcd\x1b\x47\x53\x11\x1b\x17\x3b\x3b\x05\xd2\x2f\xa0\x80\x86\xe3\xb0\xf7\x12\xfc\xc7\xc7\x1a\x55\x7e\x2d\xb9\x66\xc3\xe9\xfa\x91\x74\x60\x39");
            test_framework.test_hash::<SHA384>(&DUMMY_SEED[..512], b"\x45\x82\xfc\x82\x43\x0e\x52\x68\x86\xa1\x85\x34\x11\xe6\x06\x45\xfe\xf7\xe8\xea\x0c\x85\x46\xb7\xc9\xba\x0c\x84\x16\xd9\xa9\x8f\xb5\x2e\xbd\x0c\x60\x5f\xbb\x70\x74\x9c\x4e\x3e\x5d\xa3\xdb\xac");
        }

        #[test]
        fn sha512() {
            let test_framework = TestFrameworkHash::new();
            test_framework.test_hash::<SHA512>(b"", b"\xcf\x83\xe1\x35\x7e\xef\xb8\xbd\xf1\x54\x28\x50\xd6\x6d\x80\x07\xd6\x20\xe4\x05\x0b\x57\x15\xdc\x83\xf4\xa9\x21\xd3\x6c\xe9\xce\x47\xd0\xd1\x3c\x5d\x85\xf2\xb0\xff\x83\x18\xd2\x87\x7e\xec\x2f\x63\xb9\x31\xbd\x47\x41\x7a\x81\xa5\x38\x32\x7a\xf9\x27\xda\x3e");
            test_framework.test_hash::<SHA512>(b"a", b"\x1f\x40\xfc\x92\xda\x24\x16\x94\x75\x09\x79\xee\x6c\xf5\x82\xf2\xd5\xd7\xd2\x8e\x18\x33\x5d\xe0\x5a\xbc\x54\xd0\x56\x0e\x0f\x53\x02\x86\x0c\x65\x2b\xf0\x8d\x56\x02\x52\xaa\x5e\x74\x21\x05\x46\xf3\x69\xfb\xbb\xce\x8c\x12\xcf\xc7\x95\x7b\x26\x52\xfe\x9a\x75");
            test_framework.test_hash::<SHA512>(b"abc", b"\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f");
            test_framework.test_hash::<SHA512>(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", b"\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09");
            test_framework.test_hash::<SHA512>(&DUMMY_SEED[..512], b"\xed\xb9\xbe\xd7\x21\xaa\x6a\x5f\x6f\xbc\x66\x19\xd3\xa3\xc2\xbe\x3d\x04\x30\x43\xf0\x5a\x9a\xeb\xc7\xb1\x19\x7a\x2a\xa9\xc4\x9a\x57\xd5\xdd\xd4\x67\x4c\x17\x85\x78\x50\x88\xd9\xf1\xff\x42\xc7\x97\xa0\x2a\xdc\x9b\x81\x7a\x13\x9a\x50\x97\x0d\xa6\xc9\x95\x24");
        }
    }

    /// FIPS 180-4 s. 5.1: bit-oriented messages. Zero partial bits must equal the byte-oriented
    /// digest; more than 7 partial bits is rejected; only the low bits of the partial byte matter;
    /// and the pad byte spilling into a second block must not break. Known answers are in
    /// `partial_bits_known_answers`.
    #[test]
    fn partial_bits() {
        fn check<H: Hash + Default>() {
            // 0 partial bits == do_final
            let mut a = H::default();
            a.do_update(b"abc");
            assert_eq!(a.do_final_partial_bits(0xFF, 0).unwrap(), H::default().hash(b"abc"));

            // out of range -> InvalidLength, never a panic
            for bad in [8usize, 9, 16, 64, usize::MAX] {
                let mut h = H::default();
                h.do_update(b"abc");
                assert!(matches!(h.do_final_partial_bits(0xFF, bad), Err(HashError::InvalidLength(_))));
            }

            // only the low num_partial_bits bits of partial_byte may influence the result
            for n in 1..=7usize {
                let mask = ((1u16 << n) - 1) as u8;
                let x = H::default().do_final_partial_bits(0xA5, n).unwrap();
                let y = H::default().do_final_partial_bits(0xA5 & mask, n).unwrap();
                let z = H::default().do_final_partial_bits(0xA5 ^ 1, n).unwrap();
                assert_eq!(x, y, "n={n}");
                assert_ne!(x, z, "n={n}: low bit must change the digest");
                // and a bit-message is distinct from byte-messages of nearby length
                assert_ne!(x, H::default().hash(&[]), "n={n}");
                assert_ne!(x, H::default().hash(&[0xA5 & mask]), "n={n}");
            }

            // the partial-bit path must also work when the pad byte spills into a second block
            for len in [55usize, 56, 63, 64, 111, 112, 119, 127, 128] {
                let msg = vec![0x5Au8; len];
                let mut h = H::default();
                h.do_update(&msg);
                let mut out = vec![0u8; 64];
                let written = h.do_final_partial_bits_out(0x03, 2, &mut out).unwrap();
                assert!(written > 0);
            }
        }
        check::<SHA224>();
        check::<SHA256>();
        check::<SHA384>();
        check::<SHA512>();
    }

    /// Bit-oriented known answers (FIPS 180-4 s. 5.1). Expected values were produced by an
    /// independent pure-Python implementation of FIPS 180-4 with bit-length padding, itself checked
    /// against `hashlib` for byte-aligned inputs. `(prefix_len, fill, partial_byte, bits, digest)`.
    #[test]
    fn partial_bits_known_answers() {
        fn hex(s: &str) -> Vec<u8> {
            (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
        }
        fn check<H: Hash + Default>(cases: &[(usize, u8, u8, usize, &str)]) {
            for &(prefix_len, fill, partial_byte, bits, expected) in cases {
                let mut h = H::default();
                h.do_update(&vec![fill; prefix_len]);
                assert_eq!(h.do_final_partial_bits(partial_byte, bits).unwrap(), hex(expected), "{prefix_len}/{bits}");
            }
        }
        check::<SHA256>(&[
            (0, 0, 0x01, 1, "b9debf7d52f36e6468a54817c1fa071166c3a63d384850e1575b42f702dc5aa1"),
            (0, 0, 0x15, 5, "9a6eb6cad1c1017a060c4cc9d1be5c9404397e4d05c8e6c91f6347db8591c1a9"),
            (55, 0x5a, 0x03, 2, "f9f22d1e48f4d6fe0f84db4a04bef65d4be116e4f182845b8a827c897b05723a"),
            (111, 0x5a, 0x05, 3, "bf63c89e04968fba3fc26ccf8908e0b2d05221834a17f912b48d9816d821be6d"),
        ]);
        let mut h = SHA256::new();
        h.do_update(b"abc");
        assert_eq!(h.do_final_partial_bits(0x7f, 7).unwrap(), hex("9f5893e1b85faf8d646489927b5bc22b7394e2a14bbd47da00bbce3a1b27a5ba"));

        check::<SHA512>(&[
            (0, 0, 0x01, 1, "5f72ee8494a425ba13fc8c48ac0a05cbaae7e932e471e948cb524333745aa432c1851c0c43682b0e67d64626f8f45cf165f6b538a94c63be98224e969e75d7ed"),
            (0, 0, 0x15, 5, "dcaab1be5ce172f510ebe2da22f6488bd2f706c8124d6bb16de5cfb3432f0dd6e7262dd35206d500180b70563c419e142c354b6ac155ca8a3f0f0fdb88d567e9"),
            (55, 0x5a, 0x03, 2, "4fe3a857ce5d8abc5dcc7ea0d3f97ff7bb0db06001e1f37c2c2c9d48bd4c609af169b0f5d200d1b9033af31819095a4679b62d87b15673a85ac75c8ecbc2bd57"),
            (111, 0x5a, 0x05, 3, "f0af9c9852d733b024e097ae6aa9e7959c84c05a666b04f3c0df368e2ea93bcccf9136aefa54b0c4db432217742dec7d77365b3f5a6b63fe46c9fc259b8f0101"),
        ]);
        let mut h = SHA512::new();
        h.do_update(b"abc");
        assert_eq!(h.do_final_partial_bits(0x7f, 7).unwrap(), hex("ec168db3beb4379ddd4dd854461ac533f047f69ebf4770dec59442994a8320a4f240eeb0d808f8b7dc8d23d0428af5f095cc2ded70c516aef86ca68e99f8ffe6"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(SHA224::OUTPUT_LEN, 28);
        assert_eq!(SHA256::OUTPUT_LEN, 32);
        assert_eq!(SHA384::OUTPUT_LEN, 48);
        assert_eq!(SHA512::OUTPUT_LEN, 64);

        assert_eq!(SHA224::BLOCK_LEN, 64);
        assert_eq!(SHA256::BLOCK_LEN, 64);
        assert_eq!(SHA384::BLOCK_LEN, 128);
        assert_eq!(SHA512::BLOCK_LEN, 128);

        assert_eq!(SHA224::new().block_bitlen(), 512);
        assert_eq!(SHA256::new().block_bitlen(), 512);
        assert_eq!(SHA384::new().block_bitlen(), 1024);
        assert_eq!(SHA512::new().block_bitlen(), 1024);
    }

    #[test]
    fn test_algorithm() {
        assert_eq!(SHA224::ALG_NAME, SHA224_NAME);
        assert_eq!(SHA256::ALG_NAME, SHA256_NAME);
        assert_eq!(SHA384::ALG_NAME, SHA384_NAME);
        assert_eq!(SHA512::ALG_NAME, SHA512_NAME);
    }

    #[test]
    fn test_security_strength() {
        assert_eq!(SHA224::default().max_security_strength(), SecurityStrength::_112bit);
        assert_eq!(SHA256::default().max_security_strength(), SecurityStrength::_128bit);
        assert_eq!(SHA384::default().max_security_strength(), SecurityStrength::_192bit);
        assert_eq!(SHA512::default().max_security_strength(), SecurityStrength::_256bit);
    }

    #[test]
    fn suspendable_state() {
        use bouncycastle_core::traits::Suspendable;
        use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

        let str = "Colorless green ideas sleep furiously";

        // SHA256
        let mut sha256 = SHA256::new();
        sha256.do_update(str.as_bytes());

        // do the default tests
        let test_framework = TestFrameworkSuspendableState::new();
        test_framework.test(&sha256);

        // now let's serialize the in-progress state
        let serialized_state = sha256.clone().suspend();
        assert_eq!(serialized_state.len(), SUSPENDED_SHA256_STATE_LEN);

        // finish the hash
        let output = sha256.do_final();

        // then load from state and finish the hash and make sure we get the same thing
        let sha2_from_state = SHA256::from_suspended(serialized_state).unwrap();
        let output2 = sha2_from_state.do_final();
        assert_eq!(output, output2);

        // also, give it a busted x_buf_off, just to satisfy mutants that that's been tested
        let mut busted_state = serialized_state;
        busted_state[3 + 104] = 65;
        match SHA256::from_suspended(busted_state) {
            Err(SuspendableError::InvalidData) => { /* good */ }
            _ => panic!("Expected an error"),
        }

        // SHA512
        let mut sha512 = SHA512::new();
        sha512.do_update(str.as_bytes());

        // do the default tests
        let test_framework = TestFrameworkSuspendableState::new();
        test_framework.test(&sha512);

        // now let's serialize the in-progress state
        let serialized_state = sha512.clone().suspend();
        assert_eq!(serialized_state.len(), SUSPENDED_SHA512_STATE_LEN);

        // finish the hash
        let output = sha512.do_final();

        // then load from state and finish the hash and make sure we get the same thing
        let sha2_from_state = SHA512::from_suspended(serialized_state).unwrap();
        let output2 = sha2_from_state.do_final();
        assert_eq!(output, output2);

        // also, give it a busted x_buf_off, just to satisfy mutants that that's been tested
        let mut busted_state = serialized_state;
        busted_state[3 + 200] = 129;
        match SHA512::from_suspended(busted_state) {
            Err(SuspendableError::InvalidData) => { /* good */ }
            _ => panic!("Expected an error"),
        }
    }
}
