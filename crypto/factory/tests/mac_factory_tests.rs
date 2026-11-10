#[cfg(test)]
mod hash_factory_tests {
    use bouncycastle_core::errors::MACError;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::traits::AlgorithmInfo;
    use bouncycastle_factory::FactoryError;
    use bouncycastle_factory::mac_factory::MACFactory;
    use bouncycastle_hex as hex;

    /// `AlgorithmInfo` answers for the algorithm the factory selected, not for the factory.
    /// Each default is at least as strong as its name says, and so refuses a key below that.
    #[test]
    fn defaults_meet_their_strength() {
        use bouncycastle_factory::mac_factory::{
            DEFAULT_128BIT_MAC_NAME, DEFAULT_256BIT_MAC_NAME, DEFAULT_MAC_NAME,
        };
        let key32 = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
        let key16 = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::MACKey).unwrap();

        let k = MACFactory::default_256_bit(&key32).unwrap();
        let m = k.create_generator();
        assert_eq!(m.max_security_strength(), SecurityStrength::_256bit);
        assert_eq!(m.alg_name(), DEFAULT_256BIT_MAC_NAME);
        assert!(MACFactory::default_256_bit(&key16).is_err());
        assert!(MACFactory::new("Default256Bit", &key16).is_err());

        let k = MACFactory::default_128_bit(&key16).unwrap();
        let m = k.create_generator();
        assert!(m.max_security_strength() >= SecurityStrength::_128bit);
        assert_eq!(m.alg_name(), DEFAULT_128BIT_MAC_NAME);

        let k = MACFactory::default(&key16).unwrap();
        let m = k.create_generator();
        assert!(m.max_security_strength() >= SecurityStrength::_128bit);
        assert_eq!(m.alg_name(), DEFAULT_MAC_NAME);
    }

    /// Both workers report the variant's name, strength and tag length, and the tag length is
    /// the key's.
    #[test]
    fn alg_name_strength_and_length_follow_the_variant() {
        use SecurityStrength::*;
        use bouncycastle_sha2::hmac::*;
        use bouncycastle_sha3::hmac::*;
        use bouncycastle_sha3::kmac::{KMAC128_NAME, KMAC256_NAME};
        use bouncycastle_sm3::hmac::HMAC_SM3_NAME;
        let key = KeyMaterial::<64>::from_bytes_as_type(&[0x42; 64], KeyType::MACKey).unwrap();
        let table = [
            (KMAC128_NAME, _128bit, 32),
            (KMAC256_NAME, _256bit, 64),
            (HMAC_SHA224_NAME, _112bit, 28),
            (HMAC_SHA256_NAME, _128bit, 32),
            (HMAC_SHA384_NAME, _192bit, 48),
            (HMAC_SHA512_NAME, _256bit, 64),
            (HMAC_SHA512_224_NAME, _112bit, 28),
            (HMAC_SHA512_256_NAME, _128bit, 32),
            (HMAC_SHA3_224_NAME, _112bit, 28),
            (HMAC_SHA3_256_NAME, _128bit, 32),
            (HMAC_SHA3_384_NAME, _192bit, 48),
            (HMAC_SHA3_512_NAME, _256bit, 64),
            (HMAC_SM3_NAME, _128bit, 32),
        ];
        for (name, strength, len) in table {
            let key = MACFactory::new(name, &key).unwrap();
            assert_eq!(key.output_len(), len, "{name}");
            let generator = key.create_generator();
            assert_eq!(generator.alg_name(), name);
            assert_eq!(generator.max_security_strength(), strength, "{name}");
            assert_eq!(generator.output_len(), len, "{name}");
            let verifier = key.create_verifier();
            assert_eq!(verifier.alg_name(), name);
            assert_eq!(verifier.max_security_strength(), strength, "{name}");
            assert_eq!(verifier.output_len(), len, "{name}");
            assert_eq!(key.mac(b"abc").len(), len, "{name}");
        }
    }

    /// Every variant's one-shots and workers agree with each other and with the underlying key,
    /// and the run-time-length forms check their lengths.
    #[test]
    fn every_variant_round_trips() {
        use bouncycastle_sha2::hmac::*;
        use bouncycastle_sha3::hmac::*;
        use bouncycastle_sha3::kmac::{KMAC128_NAME, KMAC256_NAME};
        use bouncycastle_sm3::hmac::HMAC_SM3_NAME;
        let material = KeyMaterial::<64>::from_bytes_as_type(&[0x42; 64], KeyType::MACKey).unwrap();
        for name in [
            KMAC128_NAME, KMAC256_NAME, HMAC_SHA224_NAME, HMAC_SHA256_NAME, HMAC_SHA384_NAME,
            HMAC_SHA512_NAME, HMAC_SHA512_224_NAME, HMAC_SHA512_256_NAME, HMAC_SHA3_224_NAME,
            HMAC_SHA3_256_NAME, HMAC_SHA3_384_NAME, HMAC_SHA3_512_NAME, HMAC_SM3_NAME,
        ] {
            let key = MACFactory::new(name, &material).unwrap();
            let n = key.output_len();
            let msg = b"a message that arrives in pieces";
            let tag = key.mac(msg);
            assert_eq!(tag.len(), n, "{name}");

            // the streaming generator, in pieces, into a Vec and into an oversized buffer
            let mut g = key.create_generator();
            g.do_update(b"a message that arrives ");
            g.do_update(b"in pieces");
            assert_eq!(g.do_final(), tag, "{name}");
            let mut g = key.create_generator();
            g.do_update(msg);
            let mut out = vec![0xFFu8; n + 5];
            assert_eq!(g.do_final_out(&mut out).unwrap(), n, "{name}");
            assert_eq!(out[..n], tag[..], "{name}");
            assert_eq!(out[n..], [0u8; 5], "{name}: zeroized past the tag");

            // a short buffer is refused, zeroized, by both run-time-length forms
            let mut out = vec![0xFFu8; n - 1];
            assert!(
                matches!(key.mac_out(msg, &mut out), Err(MACError::InvalidLength(_))),
                "{name}"
            );
            assert!(out.iter().all(|&b| b == 0), "{name}");
            let mut out = vec![0xFFu8; n - 1];
            let g = key.create_generator();
            assert!(matches!(g.do_final_out(&mut out), Err(MACError::InvalidLength(_))), "{name}");
            let mut out = vec![0xFFu8; n];
            assert_eq!(key.mac_out(msg, &mut out).unwrap(), n);
            assert_eq!(out, tag);

            // verification: the one-shot and the streaming verifier, right, wrong and misshapen
            assert_eq!(key.verify(msg, &tag), Ok(()), "{name}");
            let mut v = key.create_verifier();
            v.do_update(b"a message that arrives ");
            v.do_update(b"in pieces");
            assert_eq!(v.do_verify_final(&tag), Ok(()), "{name}");
            let mut wrong = tag.clone();
            wrong[0] ^= 1;
            assert_eq!(key.verify(msg, &wrong), Err(MACError::VerificationFailed), "{name}");
            let mut v = key.create_verifier();
            v.do_update(msg);
            assert_eq!(v.do_verify_final(&wrong), Err(MACError::VerificationFailed), "{name}");
            assert_eq!(key.verify(b"another message", &tag), Err(MACError::VerificationFailed));
            assert!(
                matches!(key.verify(msg, &tag[..n - 1]), Err(MACError::InvalidLength(_))),
                "{name}: a truncated tag is the wrong length"
            );
            let mut long = tag.clone();
            long.push(0);
            assert!(matches!(key.verify(msg, &long), Err(MACError::InvalidLength(_))), "{name}");
        }
    }

    mod sha3_tests {
        use super::*;

        #[test]
        fn sha2_hash_tests() {
            // HMAC-SHA224
            let key = KeyMaterial::<32>::from_bytes_as_type(
                &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            let hmac = MACFactory::new("HMAC-SHA224", &key).unwrap();
            assert_eq!(
                hmac.verify(
                    b"Hi There",
                    &hex::decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22")
                        .unwrap(),
                ),
                Ok(())
            );

            // HMAC-SHA512/224 -- NIST ACVP HMAC-SHA2-512/224 2.0, tgId 1, tcId 106 (MAC truncated to 160 bits)
            let key = KeyMaterial::<45>::from_bytes_as_type(
                &hex::decode("a0b7276557f6880d151ea5e147fa2c29daf3104fda96ff8ee440f69e2c07a74b6eb38751fe54b08f9f4a84d1d7").unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            let msg = hex::decode("2579f5df03e0fccde2b515944d88dc81ca3b4a20517cdc54170559f0d2f889e2f543eacf8a84b34563d0139351ea9a77399d274c5c6c1b0f488063b7255f9df648667fe800151ef288a68d6c8c24d57abd7e4f70eed149752beae4a9763cebf03c").unwrap();
            let expected = hex::decode("6e927067f724d4fedc96b310c5115979e8dde8a4").unwrap();
            let hmac = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
            assert_eq!(hmac.output_len(), 28);
            assert_eq!(&hmac.mac(&msg)[..20], &expected[..]);
            let hmac =
                MACFactory::new(bouncycastle_sha2::hmac::HMAC_SHA512_224_NAME, &key).unwrap();
            assert_eq!(&hmac.mac(&msg)[..20], &expected[..]);

            // HMAC-SHA512/256 -- NIST ACVP HMAC-SHA2-512/256 2.0, tgId 1, tcId 147 (MAC truncated to 160 bits)
            let key = KeyMaterial::<55>::from_bytes_as_type(
                &hex::decode("4915691891f05dec5569ca75819daac897aaeeebb2fb04e7fc696d076feccef399f0eea660a7de4b7bb6ef7829a5f82feed70b35b40458").unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            let msg = hex::decode("").unwrap();
            let expected = hex::decode("7857d4737760e127f1533185c6ad183ac4e10bd9").unwrap();
            let hmac = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
            assert_eq!(hmac.output_len(), 32);
            assert_eq!(&hmac.mac(&msg)[..20], &expected[..]);
            let hmac =
                MACFactory::new(bouncycastle_sha2::hmac::HMAC_SHA512_256_NAME, &key).unwrap();
            assert_eq!(&hmac.mac(&msg)[..20], &expected[..]);
        }

        #[test]
        fn hmac_sm3_tests() {
            // RFC4231 Test Case 1 key/message; expected value from `openssl dgst -sm3 -mac HMAC`,
            // confirmed with bc-java's HMac(new SM3Digest()).
            let key = KeyMaterial::<32>::from_bytes_as_type(
                &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            for name in ["HMAC-SM3", bouncycastle_sm3::hmac::HMAC_SM3_NAME] {
                let hmac = MACFactory::new(name, &key).unwrap();
                assert_eq!(hmac.output_len(), 32);
                assert_eq!(
                    hmac.verify(
                        b"Hi There",
                        &hex::decode(
                            "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"
                        )
                        .unwrap(),
                    ),
                    Ok(())
                );
            }
        }

        /// A factory key authenticates any number of messages, which a Poly1305 key must never
        /// do, so the name is refused even with a key every other MAC here accepts.
        #[test]
        fn poly1305_is_not_offered() {
            let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
            assert!(MACFactory::new(bouncycastle_sm3::hmac::HMAC_SM3_NAME, &key).is_ok());
            assert!(matches!(
                MACFactory::new("Poly1305", &key),
                Err(FactoryError::UnsupportedAlgorithm(_))
            ));
        }
    }
}
