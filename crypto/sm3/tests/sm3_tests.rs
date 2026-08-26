#[cfg(test)]
mod sm3_tests {
    use bouncycastle_core::errors::{HashError, SuspendableError};
    use bouncycastle_core::traits::{Algorithm, AlgorithmOID, Hash, HashAlgParams, SecurityStrength};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::hash::TestFrameworkHash;
    use bouncycastle_hex as hex;
    use bouncycastle_sm3::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// Runs the shared Hash-trait conformance suite against known answers.
    /// The first two are the standard vectors from GB/T 32905-2016 Appendix A; the rest are the
    /// bc-java SM3DigestTest vectors and digests of DUMMY_SEED generated with openssl and confirmed
    /// with bc-java's `SM3Digest`.
    #[test]
    fn core_test_framework_hash() {
        let mut test_framework = TestFrameworkHash::new();
        test_framework.enable_partial_final_input_tests = false;

        test_framework.test_hash::<SM3>(b"abc", &h("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"));
        test_framework.test_hash::<SM3>(
            b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
            &h("debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
        );
        test_framework.test_hash::<SM3>(b"", &h("1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"));
        test_framework.test_hash::<SM3>(b"a", &h("623476ac18f65a2909e43c7fec61b49c7e764a91a18ccb82f1917a29c86c5e88"));
        test_framework.test_hash::<SM3>(
            b"abcdefghijklmnopqrstuvwxyz",
            &h("b80fe97a4da24afc277564f66a359ef440462ad28dcc6d63adb24d5c20a61595"),
        );
        test_framework.test_hash::<SM3>(&DUMMY_SEED[..512], &h("b21f830dca06be8b678cf987f26b9a436e1b427963b4450332f01270bd2df75c"));
        test_framework.test_hash::<SM3>(DUMMY_SEED, &h("1f00bad6a72e851e0f6e94fd317f97b74d5fbc4c090aefb91e7554e3f9c8c7fb"));
    }

    /// bc-java SM3DigestTest "Additional vectors for GMSSL": the SM2 Z_A value from GM/T 0003.5 (also
    /// checked against openssl `dgst -sm3`).
    #[test]
    fn bc_java_vectors() {
        let msg = h(concat!(
            "0090",
            "414C494345313233405941484F4F2E434F4D",
            "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498",
            "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A",
            "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D",
            "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2",
            "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A",
            "7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857",
        ));
        assert_eq!(SM3::new().hash(&msg), h("f4a38489e32b45b6f876e3ac2168ca392362dc8f23459c1d1146fc3dbfb7bc9a"));
    }

    /// Padding boundaries (GB/T 32905-2016 s. 5.2): message lengths around the 56- and 64-byte
    /// points where the length field does / does not fit in the current block. Expected values
    /// generated with openssl `dgst -sm3` over prefixes of DUMMY_SEED and confirmed with bc-java's
    /// `SM3Digest`.
    #[test]
    fn padding_boundaries() {
        for (len, expected) in [
            (55, "a79cf9dcee3404abf7f769698201647fd9d3ff61d629d0f58bb4b5579a427db8"),
            (56, "62f7363b15f4de76dd925c493b9d6d00d4ba0ef2a1f334c1d0f13b293aeb40d1"),
            (63, "6165e4cbb15cde01c6226e0015a47f710f8f8e1f2c296700033bb34d9212109c"),
            (64, "93566f236d157aae078d1ddb5cebdbba1520b5142e22a8915564345ba2ae1d63"),
            (65, "c886e6814be748285a10b28ae62ddacd85db830cd2cf3a2bfa2f729c15f63618"),
            (119, "8f3ea392a89a7119982d6634660db1a95f35d68267a2235e3255998a857f4fbf"),
            (128, "a9e7985473ca09df1510d83b572f72375430756c4a661b00724afeb8b75dd0a5"),
        ] {
            assert_eq!(SM3::new().hash(&DUMMY_SEED[..len]), h(expected), "len={len}");

            // and the same via byte-at-a-time streaming, which exercises every x_buf_off value
            let mut sm3 = SM3::new();
            for b in &DUMMY_SEED[..len] {
                sm3.do_update(core::slice::from_ref(b));
            }
            assert_eq!(sm3.do_final(), h(expected), "streaming len={len}");
        }
    }

    #[test]
    fn test_constants() {
        assert_eq!(SM3::OUTPUT_LEN, 32);
        assert_eq!(SM3::BLOCK_LEN, 64);
        assert_eq!(SM3::new().block_bitlen(), 512);
        assert_eq!(SM3::new().output_len(), 32);
    }

    #[test]
    fn test_algorithm() {
        assert_eq!(SM3::ALG_NAME, SM3_NAME);
        assert_eq!(SM3_NAME, "SM3");
        assert_eq!(SM3::OID, &[1, 2, 156, 10197, 1, 401]);
        assert_eq!(SM3::OID_DER, &[0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x11]);
    }

    #[test]
    fn test_security_strength() {
        assert_eq!(SM3::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
        assert_eq!(SM3::default().max_security_strength(), SecurityStrength::_128bit);
    }

    /// Bit-oriented messages are not supported: 0 partial bits must equal do_final(); 1..=7 returns
    /// InvalidInput; more than 7 returns InvalidLength. None of them panic.
    #[test]
    fn partial_bits_are_rejected() {
        let mut a = SM3::new();
        a.do_update(b"abc");
        assert_eq!(a.do_final_partial_bits(0xFF, 0).unwrap(), SM3::new().hash(b"abc"));

        for n in 1..=7usize {
            let mut sm3 = SM3::new();
            sm3.do_update(b"abc");
            assert!(matches!(sm3.do_final_partial_bits(0xFF, n), Err(HashError::InvalidInput(_))), "n={n}");
            let mut out = [0u8; 32];
            assert!(matches!(
                SM3::new().do_final_partial_bits_out(0xFF, n, &mut out),
                Err(HashError::InvalidInput(_))
            ));
        }
        for bad in [8usize, 9, 16, 64, usize::MAX] {
            let mut sm3 = SM3::new();
            sm3.do_update(b"abc");
            assert!(matches!(sm3.do_final_partial_bits(0xFF, bad), Err(HashError::InvalidLength(_))), "n={bad}");
        }
    }

    #[test]
    fn suspendable_state() {
        use bouncycastle_core::traits::Suspendable;
        use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableState;

        let str = "Colorless green ideas sleep furiously";

        let mut sm3 = SM3::new();
        sm3.do_update(str.as_bytes());

        // do the default tests
        let test_framework = TestFrameworkSuspendableState::new();
        test_framework.test(&sm3);

        // now let's serialize the in-progress state
        let serialized_state = sm3.clone().suspend();
        assert_eq!(serialized_state.len(), SUSPENDED_SM3_STATE_LEN);

        // finish the hash
        let output = sm3.do_final();

        // then load from state and finish the hash and make sure we get the same thing
        let sm3_from_state = SM3::from_suspended(serialized_state).unwrap();
        let output2 = sm3_from_state.do_final();
        assert_eq!(output, output2);

        // also, give it a busted x_buf_off, just to satisfy mutants that that's been tested
        let mut busted_state = serialized_state;
        busted_state[3 + 104] = 65;
        match SM3::from_suspended(busted_state) {
            Err(SuspendableError::InvalidData) => { /* good */ }
            _ => panic!("Expected an error"),
        }
    }
}
