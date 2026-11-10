extern crate core;

#[cfg(test)]
mod shake_tests {
    use bouncycastle_core::errors::HashError;
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::{
        AlgorithmInfo, Hash, HashAlgParams, HashOneShot, XOF, XOFSqueezer,
    };
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::hash::TestFrameworkHash;
    use bouncycastle_core_test_framework::xof::TestFrameworkXOF;
    use bouncycastle_sha3::{SHA3_256, SHAKE128, SHAKE256};

    /// Regression: when the 4 trailing message bits plus the SHAKE "1111" suffix exactly fill a byte,
    /// the sponge must still switch to squeezing, otherwise the first squeeze appended a second suffix.
    /// Vector: NIST CAVP SHA3VS SHAKE128ShortMsg (bit-oriented), Len = 4, Msg = 08 (FIPS 202 B.1
    /// packing: message bits 0001 in the low nibble, first bit in the LSB), i.e. 0x10 in the API's
    /// MSB-first order.
    /// The low `8 - num_bits` bits of the partial byte are the BIT STRING's unused bits (X.690
    /// s. 8.6.2.1) and must not reach the sponge: all ones there and all zeros there give the
    /// same output.
    #[test]
    fn the_unused_bits_of_a_partial_byte_are_ignored() {
        for num_bits in 1..=7usize {
            let mut all_ones = SHAKE128::new();
            all_ones.do_update(b"abc");
            let mut all_zeros = SHAKE128::new();
            all_zeros.do_update(b"abc");
            let used_mask = 0xffu8 << (8 - num_bits);
            let a = all_ones.into_squeezer_partial_bits(0xff, num_bits).unwrap().do_output(32);
            let b =
                all_zeros.into_squeezer_partial_bits(used_mask, num_bits).unwrap().do_output(32);
            assert_eq!(a, b, "num_bits = {num_bits}");
        }
    }

    #[test]
    fn into_squeezer_partial_bits_four_bits() {
        let shake = SHAKE128::new();
        let mut out = shake.into_squeezer_partial_bits(0x10, 4).unwrap();
        assert_eq!(
            out.do_output(16),
            bouncycastle_hex::decode("d40238024b040a954d9c2c89daf480e5").unwrap(),
            "SHAKE128 of the 4-bit message 0001"
        );
    }

    /// into_squeezer_partial_bits() must validate num_bits before shifting: 0 is allowed
    /// (finalize with no partial byte), 8+ is rejected with InvalidLength rather than panicking.
    #[test]
    fn into_squeezer_partial_bits_validates_range() {
        for bad in [8usize, 9, 15, 16, 64, usize::MAX] {
            let mut shake = SHAKE128::new();
            shake.do_update(b"abc");
            assert!(
                matches!(
                    shake.into_squeezer_partial_bits(0xFF, bad),
                    Err(HashError::InvalidLength(_))
                ),
                "num_bits={bad}"
            );
        }
        let mut a = SHAKE128::new();
        a.do_update(b"abc");
        let mut a = a.into_squeezer_partial_bits(0xFF, 0).unwrap();
        assert_eq!(a.do_output(32), SHAKE128::new().xof(b"abc", 32));

        // Upper boundary: 7 bits is the largest valid partial byte and must be accepted, and must
        // actually change the output relative to the byte-aligned message.
        let mut b = SHAKE128::new();
        b.do_update(b"abc");
        let mut b = b.into_squeezer_partial_bits(0xFE, 7).unwrap();
        assert_ne!(b.do_output(32), SHAKE128::new().xof(b"abc", 32));
    }

    /// The two `Hash` metadata methods, pinned to their actual values.
    ///
    /// The generic framework can only check that these are positive and byte-aligned, which every
    /// plausible mis-derivation also satisfies -- `cargo mutants` survived three separate mutations
    /// of them until this test existed.
    ///
    /// `block_bitlen` is the sponge rate, `1600 - 2c`: FIPS 202 Table 3 gives 1344 bits for
    /// SHAKE128 and 1088 for SHAKE256. `output_len` is the nominal digest size, twice the security
    /// strength: 32 and 64 bytes.
    #[test]
    fn metadata_matches_fips202() {
        assert_eq!(SHAKE128::new().block_bitlen(), 1344, "SHAKE128 rate, FIPS 202 Table 3");
        assert_eq!(SHAKE256::new().block_bitlen(), 1088, "SHAKE256 rate, FIPS 202 Table 3");
        assert_eq!(SHAKE128::new().output_len(), 32, "nominal digest size for SHAKE128");
        assert_eq!(SHAKE256::new().output_len(), 64, "nominal digest size for SHAKE256");

        // and do_final actually produces that many bytes
        assert_eq!(SHAKE128::hash(b"abc").len(), 32);
        assert_eq!(SHAKE256::hash(b"abc").len(), 64);
    }

    /// The `Hash` view writes [`Hash::output_len`] bytes and zeroizes the rest of the buffer; the
    /// XOF spelling is what fills a buffer of the caller's choosing.
    ///
    /// FIPS 202 binds no length, so the two readings agree on the bytes they share -- the hash is
    /// the first `output_len` bytes of the same stream -- and differ only in how much they write.
    /// Before this, the `Hash` entry points took their length from the buffer, so a long one came
    /// back full of XOF output and `output_len` meant nothing.
    #[test]
    fn the_hash_view_writes_output_len_bytes_and_zeroes_the_rest() {
        let mut hash_view = [0xFFu8; 100];
        assert_eq!(SHAKE128::hash_out(b"abc", &mut hash_view), 32, "the nominal length");
        assert_eq!(&hash_view[..32], &SHAKE128::hash(b"abc")[..], "... written in full");
        assert_eq!(&hash_view[32..], &[0u8; 68][..], "everything past output_len is zeroized");

        // do_final_out and the byte-aligned partial-bit spelling follow the same rule.
        let mut buf = [0xFFu8; 100];
        let mut h = SHAKE128::new();
        h.do_update(b"abc");
        assert_eq!(h.do_final_out(&mut buf), 32);
        assert_eq!(buf, hash_view, "do_final_out must agree with hash_out");

        let mut buf = [0xFFu8; 100];
        let mut h = SHAKE128::new();
        h.do_update(b"abc");
        assert_eq!(h.do_final_partial_bits_out(0, 0, &mut buf).expect("0 is in range"), 32);
        assert_eq!(buf, hash_view, "a zero-bit partial byte is the same call");

        // A short buffer truncates, as it always did.
        let mut short = [0xFFu8; 16];
        assert_eq!(SHAKE128::hash_out(b"abc", &mut short), 16);
        assert_eq!(&short[..], &hash_view[..16], "a short buffer truncates the same output");

        // The XOF spelling takes its length from the buffer and keeps reading past output_len.
        let mut xof_view = [0xFFu8; 100];
        assert_eq!(SHAKE128::new().xof_out(b"abc", &mut xof_view), 100, "the XOF fills it");
        assert_eq!(&xof_view[..32], &hash_view[..32], "the same stream, read further");
        assert_ne!(&xof_view[32..], &[0u8; 68][..], "... rather than stopping at output_len");

        // SHAKE256's nominal length is 64, so its split lands elsewhere.
        let mut hash_view = [0xFFu8; 100];
        assert_eq!(SHAKE256::hash_out(b"abc", &mut hash_view), 64, "the nominal length");
        assert_eq!(&hash_view[64..], &[0u8; 36][..], "everything past output_len is zeroized");
    }

    #[test]
    fn security_strength() {
        assert_eq!(SHAKE128::default().max_security_strength(), SecurityStrength::_128bit);
        assert_eq!(SHAKE256::default().max_security_strength(), SecurityStrength::_256bit);
    }

    #[test]
    fn test_framework_xof() {
        let test_framework = TestFrameworkXOF::new();
        test_framework.test_xof(SHAKE128::new, &DUMMY_SEED[..512], b"\x88\x90\xED\x20\x4D\x22\x89\xE1\x72\xE9\xAE\x68\x48\x18\x23\x77\x08\x20\x90\x80\x60\xA4\xDF\x33\x51\xA3\xF1\x84\xEB\xB6\xDD\x0F\x9D\x23\x15\x60\x68\x0F\x2C\x65\x8A\xC4\x84\x97\xAD\xB5\xA4\x83\x99\x36\xA3\x16\x55\x16\xFA\x5E\x13\xBF\x8A\x15\xBA\xBC\x14\x1F");
        test_framework.test_xof(SHAKE256::new, &DUMMY_SEED[..512], b"\xA1\xD7\x18\x85\xB0\xA8\x41\xF0\x3D\x1D\xC7\xF2\x73\x8A\x15\xCC\x98\x40\x71\xA1\x7F\xFE\xD5\xEC\xAC\xB9\xF5\x87\x20\xA4\x73\xBE\x1F\x2D\x28\xB9\x6D\x54\x3A\x36\x7C\x81\x11\x42\x06\xF5\xAF\x37\x18\xE7\x31\x5B\x57\xF2\x90\xB6\x4D\x8D\x29\xCF\x43\x7E\x40\x4C");
    }

    #[test]
    fn suspendable_state() {
        use bouncycastle_core::errors::SuspendableError;
        use bouncycastle_core::traits::Suspendable;
        use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

        let str = "Colorless green ideas sleep furiously";

        // A helper that exercises the full round-trip for one SHAKE variant.
        // Each phase suspends as its own type: an absorbing state resumes as `X`, a squeezing one
        // as `X::Squeezer`, and each rejects the other's phase.
        fn round_trip<const N: usize, X>(mut shake: X, input: &[u8])
        where
            X: XOF + Suspendable<N> + Clone,
            X::Squeezer: Suspendable<N> + Clone,
        {
            shake.do_update(input);

            // do the default trait-conformance tests
            TestFrameworkSuspendableState::new().test(&shake);

            // Test #1
            // serialize the in-progress (absorbing) state, then read from the original and compare
            let absorbing_state = shake.clone().suspend();
            let mut out = shake.into_squeezer();
            let expected = out.do_output(64);

            // rebuild from the serialized state and confirm it produces the same output
            let from_state =
                X::from_suspended(absorbing_state).expect("an absorbing state resumes as the XOF");
            assert_eq!(expected, from_state.into_squeezer().do_output(64));

            // Test #2
            // serialize the in-progress (squeezing) state, then read more from the original and compare
            let squeezing_state = out.clone().suspend();
            let expected = out.do_output(64);

            // rebuild from the serialized state and confirm it produces the same output
            let mut from_state = X::Squeezer::from_suspended(squeezing_state)
                .expect("a squeezing state resumes as the output");
            assert_eq!(expected, from_state.do_output(64));

            // The phase is part of the state, so each type refuses the other's.
            assert!(
                matches!(X::from_suspended(squeezing_state), Err(SuspendableError::InvalidData)),
                "a squeezing state must not resume as an absorbing XOF"
            );
            assert!(
                matches!(
                    X::Squeezer::from_suspended(absorbing_state),
                    Err(SuspendableError::InvalidData)
                ),
                "an absorbing state must not resume as an output"
            );

            // a corrupt `squeezing` byte (last byte of the keccak state) must be rejected.
            // Layout: 3 version bytes + variant tag(1) + [u64;25](200) + data_queue(192)
            //         + bits_in_queue(8) + squeezing(1)
            let mut busted = squeezing_state;
            busted[3 + 1 + 400] = 42;
            match X::Squeezer::from_suspended(busted) {
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

    /// RFC 8702 Section 3.1's fixed digests, which `HashAlgParams` carries: 32 bytes for SHAKE128
    /// and 64 for SHAKE256, the sponge rate as the block length (FIPS 202 Table 3), and the same
    /// bytes as the XOF at that length, through the framework's hash suite.
    #[test]
    fn shake_as_a_fixed_length_digest() {
        assert_eq!(SHAKE128::OUTPUT_LEN, 32);
        assert_eq!(SHAKE256::OUTPUT_LEN, 64);
        assert_eq!(SHAKE128::BLOCK_LEN, 168);
        assert_eq!(SHAKE256::BLOCK_LEN, 136);
        let tf = TestFrameworkHash::new();
        tf.test_hash::<SHAKE128>(&DUMMY_SEED[..512], &SHAKE128::new().xof(&DUMMY_SEED[..512], 32));
        tf.test_hash::<SHAKE256>(&DUMMY_SEED[..512], &SHAKE256::new().xof(&DUMMY_SEED[..512], 64));
    }
}
