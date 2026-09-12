#[cfg(test)]
mod hmac_sha3_tests {
    use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
    use bouncycastle_core::traits::{Algorithm, AlgorithmOID, MAC, SecurityStrength};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_rng::HashDRBG_SHA512;
    use bouncycastle_sha3::hmac::*;

    #[test]
    fn long_key() {
        // Regression test: a key just under the maximum length before HMAC will hash it down.
        // (RFC 2104 only pre-hashes keys *longer* than the block).
        // This test is designed to detect an overflow-write and panic on HMAC's internal key buffer.

        // SHA3-224 has the largest block (144 bytes); a 143-byte key exercises the top of the range.
        let key = KeyMaterial::<200>::from_bytes_as_type(&[0x0B; 143], KeyType::MACKey).unwrap();
        let mut mac = HMAC_SHA3_224::new(&key).unwrap();
        mac.do_update(b"Hi There");
        let tag = mac.do_final();
        assert!(HMAC_SHA3_224::new(&key).unwrap().verify(b"Hi There", &tag));
    }

    #[test]
    fn negative_tests() {
        let key = KeyMaterial256::from_bytes_as_type(
            b"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            KeyType::MACKey,
        )
        .unwrap();

        // fail case: mac value is correct but truncated
        let mac = HMAC_SHA3_224::new(&key).unwrap();
        let mut mac_val = mac.mac(b"Polly want a cracker?");
        let verifier = HMAC_SHA3_224::new(&key).unwrap();
        assert!(verifier.verify(b"Polly want a cracker?", &mac_val));

        // truncation of the mac value is considered a fail
        let verifier = HMAC_SHA3_224::new(&key).unwrap();
        assert!(!verifier.verify(b"Polly want a cracker?", &mac_val[..mac_val.len() - 1]));

        // .. as is some extra bytes at the end
        let verifier = HMAC_SHA3_224::new(&key).unwrap();
        mac_val.extend_from_slice(&[0u8; 4]);
        assert!(!verifier.verify(b"Polly want a cracker?", &mac_val));
    }

    #[test]
    fn algorithm_tests() {
        // Test the type aliases and string constants
        assert_eq!(HMAC_SHA3_224::ALG_NAME, HMAC_SHA3_224_NAME);
        assert_eq!(HMAC_SHA3_256::ALG_NAME, HMAC_SHA3_256_NAME);
        assert_eq!(HMAC_SHA3_384::ALG_NAME, HMAC_SHA3_384_NAME);
        assert_eq!(HMAC_SHA3_512::ALG_NAME, HMAC_SHA3_512_NAME);

        assert_eq!(HMAC_SHA3_224::OID, [2, 16, 840, 1, 101, 3, 4, 2, 13]);
        assert_eq!(HMAC_SHA3_256::OID, [2, 16, 840, 1, 101, 3, 4, 2, 14]);
        assert_eq!(HMAC_SHA3_384::OID, [2, 16, 840, 1, 101, 3, 4, 2, 15]);
        assert_eq!(HMAC_SHA3_512::OID, [2, 16, 840, 1, 101, 3, 4, 2, 16]);

        assert_eq!(HMAC_SHA3_224::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
        assert_eq!(HMAC_SHA3_256::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
        assert_eq!(HMAC_SHA3_384::MAX_SECURITY_STRENGTH, SecurityStrength::_192bit);
        assert_eq!(HMAC_SHA3_512::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
    }

    #[test]
    fn suspendable_keyed_state() {
        use bouncycastle_core::errors::SuspendableError;
        use bouncycastle_core::suspendable_state::LIB_VERSION;
        use bouncycastle_core::traits::SuspendableKeyed;
        use bouncycastle_core_test_framework::suspendable_state::TestFrameworkSuspendableKeyedState;

        let key = KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();
        let msg = b"Colorless green ideas sleep furiously";

        // A helper that exercises the full round-trip for one HMAC variant. HMAC is keyed, so the
        // key is NOT in the serialized state -- it is re-supplied (by reference) to
        // from_serialized_state.
        // The `+ 'static` on the trait object matches the associated type `type Key = dyn
        // KeyMaterialTrait` (a bare `dyn` in an associated type defaults to `'static`). The concrete
        // key types are owned, so they satisfy it.
        fn round_trip<const N: usize, H>(
            mut hmac: H,
            key: &(dyn KeyMaterialTrait + 'static),
            input: &[u8],
        ) where
            H: MAC + Clone + SuspendableKeyed<N, Key = dyn KeyMaterialTrait>,
        {
            hmac.do_update(&input[..10]);

            // do the default trait-conformance tests
            TestFrameworkSuspendableKeyedState::new().test(&hmac, key);

            // serialize the in-progress state (on a clone), then finish the original
            let serialized_state = hmac.clone().suspend();

            // the serialized state carries the library version header (from the inner hash)
            let header: [u8; 3] = serialized_state[..3].try_into().unwrap();
            assert_eq!(header, <[u8; 3]>::from(LIB_VERSION));

            hmac.do_update(&input[10..]);
            let expected = hmac.do_final();

            // rebuild from the serialized state (re-supplying the key), feed the identical remaining
            // input, and confirm the MAC matches
            let mut from_state = H::from_suspended(serialized_state, key).unwrap();
            from_state.do_update(&input[10..]);
            assert_eq!(expected, from_state.do_final());

            // a state whose version header is zeroed must be rejected (delegated to the hash's impl)
            let mut busted = serialized_state;
            busted[..3].copy_from_slice(&[0, 0, 0]);
            match H::from_suspended(busted, key) {
                Err(SuspendableError::IncompatibleVersion) => { /* good */ }
                _ => panic!("Expected IncompatibleVersion for a zeroed version header"),
            }
        }

        round_trip(HMAC_SHA3_256::new(&key).unwrap(), &key, msg);
    }

    /// Exercises the `keygen_from_rng()` function of each HMAC type alias:
    ///   * the generated key must not be the all-zero array,
    ///   * `keygen_from_rng()` returns a ready-to-use `KeyType::MACKey` key, so that
    ///   * `HMAC::new(&key)` accepts the freshly generated key, without error.
    ///
    /// HashDRBG_SHA512 is used throughout because it is the only built-in DRBG that meets the
    /// 256-bit strength that HMAC-SHA3-512 claims.
    macro_rules! keygen_test {
        ($test_name:ident, $hmac:ident, $n:literal) => {
            #[test]
            fn $test_name() {
                let mut rng = HashDRBG_SHA512::new_from_os();
                let key = $hmac::keygen_from_rng(&mut rng).expect("keygen_from_rng should succeed");

                assert_eq!(key.key_len(), $n, "key should be the hash's output length");
                assert_eq!(key.key_type(), KeyType::MACKey, "keygen should return a MAC key");
                assert!(
                    key.ref_to_bytes().iter().any(|&b| b != 0),
                    "keygen produced an all-zero key"
                );

                $hmac::new(&key).expect("HMAC::new should accept a freshly generated key");
            }
        };
    }

    keygen_test!(keygen_hmac_sha3_224, HMAC_SHA3_224, 28);
    keygen_test!(keygen_hmac_sha3_256, HMAC_SHA3_256, 32);
    keygen_test!(keygen_hmac_sha3_384, HMAC_SHA3_384, 48);
    keygen_test!(keygen_hmac_sha3_512, HMAC_SHA3_512, 64);
}
