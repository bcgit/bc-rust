//! Known-answer and conformance tests for the four RIPEMD functions.
//!
//! The vectors are the nine the designers publish for each function on
//! <https://homes.esat.kuleuven.be/~bosselae/ripemd160.html> ("", "a", "abc", "message digest",
//! "a...z", "abcdbcde...nopq", "A...Za...z0...9", eight times "1234567890", one million times
//! "a"); BC Java's `RIPEMD*DigestTest` classes use the same nine. Each is run through the `Hash`
//! conformance suite of `core-test-framework`, which exercises every trait method and every output
//! truncation.

#[cfg(test)]
mod ripemd_tests {
    use bouncycastle_core::errors::{HashError, SuspendableError};
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{
        Algorithm, AlgorithmInfo, AlgorithmOID, Hash, HashAlgParams, HashOneShot,
    };
    use bouncycastle_core_test_framework::hash::TestFrameworkHash;
    use bouncycastle_hex as hex;
    use bouncycastle_ripemd::*;

    /// The designers' eight short messages, in the order of their table.
    const MESSAGES: [&[u8]; 8] = [
        b"",
        b"a",
        b"abc",
        b"message digest",
        b"abcdefghijklmnopqrstuvwxyz",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
    ];

    const RIPEMD128_DIGESTS: [&str; 8] = [
        "cdf26213a150dc3ecb610f18f6b38b46",
        "86be7afa339d0fc7cfc785e72f578d33",
        "c14a12199c66e4ba84636b0f69144c77",
        "9e327b3d6e523062afc1132d7df9d1b8",
        "fd2aa607f71dc8f510714922b371834e",
        "a1aa0689d0fafa2ddc22e88b49133a06",
        "d1e959eb179c911faea4624c60c5c702",
        "3f45ef194732c2dbb2c4a2c769795fa3",
    ];
    const RIPEMD128_MILLION_A: &str = "4a7f5723f954eba1216c9d8f6320431f";

    const RIPEMD160_DIGESTS: [&str; 8] = [
        "9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
        "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
        "5d0689ef49d2fae572b881b123a85ffa21595f36",
        "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
        "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
    ];
    const RIPEMD160_MILLION_A: &str = "52783243c1697bdbe16d37f97f68f08325dc1528";

    const RIPEMD256_DIGESTS: [&str; 8] = [
        "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
        "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
        "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
        "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
        "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133",
        "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
        "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8",
        "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd",
    ];
    const RIPEMD256_MILLION_A: &str =
        "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978";

    const RIPEMD320_DIGESTS: [&str; 8] = [
        "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
        "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d",
        "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
        "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197",
        "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009",
        "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac",
        "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4",
        "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42",
    ];
    const RIPEMD320_MILLION_A: &str =
        "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66";

    fn framework() -> TestFrameworkHash {
        TestFrameworkHash::new()
    }

    fn check_vectors<H: HashOneShot + HashAlgParams + Clone>(digests: &[&str; 8], million_a: &str) {
        let framework = framework();
        for (msg, digest) in MESSAGES.iter().zip(digests.iter()) {
            framework.test_hash::<H>(msg, &hex::decode(digest).unwrap());
        }
        // "1 million times 'a'", streamed in 1000-byte chunks.
        let mut h = H::default();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.do_update(&chunk);
        }
        assert_eq!(h.do_final(), hex::decode(million_a).unwrap(), "million a");
    }

    #[test]
    fn ripemd128() {
        check_vectors::<RIPEMD128>(&RIPEMD128_DIGESTS, RIPEMD128_MILLION_A);
    }

    #[test]
    fn ripemd160() {
        check_vectors::<RIPEMD160>(&RIPEMD160_DIGESTS, RIPEMD160_MILLION_A);
    }

    #[test]
    fn ripemd256() {
        check_vectors::<RIPEMD256>(&RIPEMD256_DIGESTS, RIPEMD256_MILLION_A);
    }

    #[test]
    fn ripemd320() {
        check_vectors::<RIPEMD320>(&RIPEMD320_DIGESTS, RIPEMD320_MILLION_A);
    }

    /// The same digests reached through every chunking of the input: one byte at a time, and in
    /// pieces that straddle the block boundary.
    #[test]
    fn chunking_does_not_matter() {
        let msg: Vec<u8> = (0..300u32).map(|i| (i * 7 % 251) as u8).collect();
        for sizes in [[1usize, 1, 1], [63, 1, 64], [64, 64, 64], [65, 3, 200], [7, 57, 100]] {
            let whole = RIPEMD320::hash(&msg);
            let mut h = RIPEMD320::new();
            let mut rest = &msg[..];
            let mut i = 0;
            while !rest.is_empty() {
                let n = sizes[i % 3].min(rest.len());
                h.do_update(&rest[..n]);
                rest = &rest[n..];
                i += 1;
            }
            assert_eq!(h.do_final(), whole, "{sizes:?}");
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(RIPEMD128::OUTPUT_LEN, 16);
        assert_eq!(RIPEMD160::OUTPUT_LEN, 20);
        assert_eq!(RIPEMD256::OUTPUT_LEN, 32);
        assert_eq!(RIPEMD320::OUTPUT_LEN, 40);
        for block in
            [RIPEMD128::BLOCK_LEN, RIPEMD160::BLOCK_LEN, RIPEMD256::BLOCK_LEN, RIPEMD320::BLOCK_LEN]
        {
            assert_eq!(block, 64);
        }
        assert_eq!(RIPEMD128::new().block_bitlen(), 512);
        assert_eq!(RIPEMD160::new().block_bitlen(), 512);
        assert_eq!(RIPEMD256::new().block_bitlen(), 512);
        assert_eq!(RIPEMD320::new().block_bitlen(), 512);
        assert_eq!(RIPEMD128::new().output_len(), 16);
        assert_eq!(RIPEMD160::new().output_len(), 20);
        assert_eq!(RIPEMD256::new().output_len(), 32);
        assert_eq!(RIPEMD320::new().output_len(), 40);
    }

    #[test]
    fn test_algorithm() {
        assert_eq!(RIPEMD128::ALG_NAME, RIPEMD128_NAME);
        assert_eq!(RIPEMD160::ALG_NAME, RIPEMD160_NAME);
        assert_eq!(RIPEMD256::ALG_NAME, RIPEMD256_NAME);
        assert_eq!(RIPEMD320::ALG_NAME, RIPEMD320_NAME);
        assert_eq!(RIPEMD160_NAME, "RIPEMD160");
        assert_eq!(RIPEMD320_NAME, "RIPEMD320");
    }

    /// All four sit below the library's 112-bit floor; see the crate docs.
    #[test]
    fn test_security_strength() {
        for s in [
            RIPEMD128::default().max_security_strength(),
            RIPEMD160::default().max_security_strength(),
            RIPEMD256::default().max_security_strength(),
            RIPEMD320::default().max_security_strength(),
            RIPEMD128::MAX_SECURITY_STRENGTH,
            RIPEMD160::MAX_SECURITY_STRENGTH,
            RIPEMD256::MAX_SECURITY_STRENGTH,
            RIPEMD320::MAX_SECURITY_STRENGTH,
        ] {
            assert_eq!(s, SecurityStrength::None);
        }
    }

    /// TeleTrusT hashAlgorithm arc: ripemd160 {1}, ripemd128 {2}, ripemd256 {3}.
    #[test]
    fn test_oids() {
        assert_eq!(RIPEMD160::OID, &[1, 3, 36, 3, 2, 1]);
        assert_eq!(RIPEMD128::OID, &[1, 3, 36, 3, 2, 2]);
        assert_eq!(RIPEMD256::OID, &[1, 3, 36, 3, 2, 3]);
        // DER: 06 05, then 1.3 -> 2b, 36 -> 24, 3, 2, and the last arc.
        assert_eq!(RIPEMD160::OID_DER, &[0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x01]);
        assert_eq!(RIPEMD128::OID_DER, &[0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x02]);
        assert_eq!(RIPEMD256::OID_DER, &[0x06, 0x05, 0x2b, 0x24, 0x03, 0x02, 0x03]);
    }

    #[test]
    fn suspendable_state() {
        use bouncycastle_core::traits::Suspendable;
        use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

        fn check<const N: usize, H: Hash + Suspendable<N> + Default + Clone>(expected_len: usize) {
            let msg = b"Colorless green ideas sleep furiously";
            assert_eq!(N, expected_len);
            let mut h = H::default();
            h.do_update(msg);
            TestFrameworkSuspendableState::new().test(&h);
            let state = h.clone().suspend();
            assert_eq!(state.len(), N);
            let output = h.do_final();
            let resumed = H::from_suspended(state).unwrap();
            assert_eq!(resumed.do_final(), output);
            // A buffer fill at or past the block length is rejected.
            let mut busted = state;
            busted[N - 1] = 64;
            assert!(matches!(H::from_suspended(busted), Err(SuspendableError::InvalidData)));
            // The byte count must agree with the buffer fill modulo the block length; the
            // count itself is not limited (RFC 1320 Sec 3.2 takes it modulo 2^64).
            let with_count = |byte_count: u64| {
                let mut state = state;
                state[N - 73..N - 65].copy_from_slice(&byte_count.to_le_bytes());
                H::from_suspended(state)
            };
            let fill = msg.len() as u64;
            assert!(with_count(fill + 64).is_ok());
            assert!(with_count(u64::MAX - 63 + fill).is_ok());
            assert!(matches!(with_count(fill + 1), Err(SuspendableError::InvalidData)));
            assert!(matches!(with_count(0), Err(SuspendableError::InvalidData)));
            // The same message prefix reached two ways has one encoding, and it carries no
            // byte of the block already compressed: the buffer field is zero past its fill.
            let block: Vec<u8> = (1..=64u8).collect();
            let mut one = H::default();
            one.do_update(&block);
            let mut two = H::default();
            two.do_update(&block[..10]);
            two.do_update(&block[10..]);
            let (one, two) = (one.suspend(), two.suspend());
            assert_eq!(one, two);
            assert_eq!(one[N - 65..N - 1], [0u8; 64]);
            assert_eq!(one[N - 1], 0);
            // and a partial block: the 37 buffered bytes, then zeros
            assert_eq!(state[N - 65..N - 65 + 37], msg[..]);
            assert_eq!(state[N - 65 + 37..N - 1], [0u8; 27]);
            // which `from_suspended` requires: a byte past the fill is refused
            for at in [N - 65 + 37, N - 2] {
                let mut dirty = state;
                dirty[at] = 1;
                assert!(matches!(H::from_suspended(dirty), Err(SuspendableError::InvalidData)));
            }
            // Suspending after exactly one block (fill 0) round-trips too.
            let mut h = H::default();
            h.do_update(&[0x5A; 64]);
            let state = h.clone().suspend();
            assert_eq!(H::from_suspended(state).unwrap().do_final(), h.do_final());
        }
        check::<SUSPENDED_RIPEMD128_STATE_LEN, RIPEMD128>(92);
        check::<SUSPENDED_RIPEMD160_STATE_LEN, RIPEMD160>(96);
        check::<SUSPENDED_RIPEMD256_STATE_LEN, RIPEMD256>(108);
        check::<SUSPENDED_RIPEMD320_STATE_LEN, RIPEMD320>(116);
    }

    /// RFC 1320 s. 3.1: bit-oriented messages. Zero partial bits must equal the byte-oriented
    /// digest; more than 7 partial bits is rejected, leaving the output buffer zeroed; and only the
    /// top bits of the partial byte matter (ASN.1 BIT STRING order). Known answers, including the
    /// pad byte spilling into a second block, are in `partial_bits_known_answers`.
    #[test]
    fn partial_bits() {
        fn check<H: HashOneShot>() {
            // 0 partial bits == do_final
            let mut a = H::default();
            a.do_update(b"abc");
            assert_eq!(a.do_final_partial_bits(0xFF, 0).unwrap(), H::hash(b"abc"));

            // out of range -> InvalidLength, never a panic
            for bad in [8usize, 9, 16, 64, usize::MAX] {
                let mut h = H::default();
                h.do_update(b"abc");
                assert!(matches!(
                    h.do_final_partial_bits(0xFF, bad),
                    Err(HashError::InvalidLength(_))
                ));
                // a refused call clears the caller's buffer, a longer one in full
                let mut out = [0xA5u8; 48];
                assert!(matches!(
                    H::default().do_final_partial_bits_out(0xFF, bad, &mut out),
                    Err(HashError::InvalidLength(_))
                ));
                assert_eq!(out, [0u8; 48]);
            }

            // only the top num_partial_bits bits of partial_byte may influence the result
            for n in 1..=7usize {
                let mask = (0xFF00u16 >> n) as u8;
                let x = H::default().do_final_partial_bits(0xA5, n).unwrap();
                let y = H::default().do_final_partial_bits(0xA5 & mask, n).unwrap();
                let z = H::default().do_final_partial_bits(0xA5 ^ 0x80, n).unwrap();
                assert_eq!(x, y, "n={n}");
                assert_ne!(x, z, "n={n}: the leading bit must change the digest");
                // and a bit-message is distinct from byte-messages of nearby length
                assert_ne!(x, H::hash(&[]), "n={n}");
                assert_ne!(x, H::hash(&[0xA5 & mask]), "n={n}");
            }
        }
        check::<RIPEMD128>();
        check::<RIPEMD160>();
        check::<RIPEMD256>();
        check::<RIPEMD320>();
    }

    /// Bit-oriented known answers for RIPEMD-160. The designers publish no bit-length vectors, so
    /// the expected values were produced by an independent pure-Python RIPEMD-160 with the RFC 1320
    /// s. 3.1 bit-level padding, which reproduces the designers' published digests and agrees with
    /// `openssl dgst -ripemd160` on byte-aligned inputs. The padding is shared by all four functions
    /// (`Buffer::finish`), so these also pin it for RIPEMD-128/256/320.
    /// `(prefix_len, fill, partial_byte, bits, digest)`, where the `bits` message bits are the top
    /// bits of `partial_byte` (ASN.1 BIT STRING order).
    #[test]
    fn partial_bits_known_answers() {
        let cases: [(usize, u8, u8, usize, &str); 6] = [
            (0, 0, 0x80, 1, "4cd9629a69fdd5fa1520047fa19b4b10480041c2"),
            (0, 0, 0xA8, 5, "35c0fd00ad8956b4e8a125d1b4de2c8821250243"),
            (3, b'a', 0xFE, 7, "cc16f93f66f42b786299b2c3cc545b7735cb6626"), // prefix "abc"
            (55, 0x5a, 0xC0, 2, "959618ed1011ec04f7e8fe2dfdcb10a8b56b76ba"),
            (111, 0x5a, 0xA0, 3, "c69fbe216862101834faf961cf8830e05ca852d3"),
            (64, 0, 0xF0, 4, "6627e673c83542496cf9e3228e3f50dfa6cdbba8"), // prefix 0x00..=0x3F
        ];
        for (prefix_len, fill, partial_byte, bits, expected) in cases {
            let prefix: Vec<u8> = match (prefix_len, fill) {
                (3, _) => b"abc".to_vec(),
                (64, 0) => (0u8..64).collect(),
                _ => vec![fill; prefix_len],
            };
            let mut h = RIPEMD160::new();
            h.do_update(&prefix);
            assert_eq!(
                h.do_final_partial_bits(partial_byte, bits).unwrap(),
                hex::decode(expected).unwrap(),
                "{prefix_len}/{bits}"
            );
        }
    }
}
