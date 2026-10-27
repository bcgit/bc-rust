#[cfg(test)]
mod hash_factory_tests {
    use bouncycastle_core::errors::MACError;
    use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
    use bouncycastle_core::security_strength::SecurityStrength;
    use bouncycastle_core::symmetric_key::{MacGenerationKey, MacVerificationKey};
    use bouncycastle_core::traits::MAC;
    use bouncycastle_factory::FactoryError;
    use bouncycastle_factory::mac_factory::MACFactory;
    use bouncycastle_hex as hex;

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
            assert!(hmac.verify(
                b"Hi There",
                &hex::decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22").unwrap(),
            ));

            // HMAC-SHA512/224 -- NIST ACVP HMAC-SHA2-512/224 2.0, tgId 1, tcId 106 (MAC truncated to 160 bits)
            let key = KeyMaterial::<45>::from_bytes_as_type(
                &hex::decode("a0b7276557f6880d151ea5e147fa2c29daf3104fda96ff8ee440f69e2c07a74b6eb38751fe54b08f9f4a84d1d7").unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            let msg = hex::decode("2579f5df03e0fccde2b515944d88dc81ca3b4a20517cdc54170559f0d2f889e2f543eacf8a84b34563d0139351ea9a77399d274c5c6c1b0f488063b7255f9df648667fe800151ef288a68d6c8c24d57abd7e4f70eed149752beae4a9763cebf03c").unwrap();
            let expected = hex::decode("6e927067f724d4fedc96b310c5115979e8dde8a4").unwrap();
            let hmac = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
            assert_eq!(hmac.create_generator().output_len(), 28);
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
            assert_eq!(hmac.create_generator().output_len(), 32);
            assert_eq!(&hmac.mac(&msg)[..20], &expected[..]);
            let hmac =
                MACFactory::new(bouncycastle_sha2::hmac::HMAC_SHA512_256_NAME, &key).unwrap();
            assert_eq!(&hmac.mac(&msg)[..20], &expected[..]);

            // HMAC-SHA512/224 pass-throughs: streaming, mac_out, verify and do_verify_final.
            let key = KeyMaterial::<45>::from_bytes_as_type(
                &hex::decode("a0b7276557f6880d151ea5e147fa2c29daf3104fda96ff8ee440f69e2c07a74b6eb38751fe54b08f9f4a84d1d7").unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            let msg = hex::decode("2579f5df03e0fccde2b515944d88dc81ca3b4a20517cdc54170559f0d2f889e2f543eacf8a84b34563d0139351ea9a77399d274c5c6c1b0f488063b7255f9df648667fe800151ef288a68d6c8c24d57abd7e4f70eed149752beae4a9763cebf03c").unwrap();
            let full = MACFactory::new("HMAC-SHA512/224", &key).unwrap().mac(&msg);
            assert_eq!(full.len(), 28);
            assert_eq!(
                &full[..20],
                &hex::decode("6e927067f724d4fedc96b310c5115979e8dde8a4").unwrap()[..]
            );

            let hmac_key = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
            let mut hmac = hmac_key.create_generator();
            for chunk in msg.chunks(7) {
                hmac.do_update(chunk);
            }
            assert_eq!(hmac.do_final(), full);

            let mut out = vec![0xffu8; 28];
            assert_eq!(
                MACFactory::new("HMAC-SHA512/224", &key).unwrap().mac_out(&msg, &mut out).unwrap(),
                28
            );
            assert_eq!(out, full);

            let mut out = vec![0xffu8; 28];
            let hmac_key = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
            let mut hmac = hmac_key.create_generator();
            hmac.do_update(&msg);
            assert_eq!(hmac.do_final_out(&mut out).unwrap(), 28);
            assert_eq!(out, full);

            let mut wrong = full.clone();
            wrong[0] ^= 1;
            assert!(MACFactory::new("HMAC-SHA512/224", &key).unwrap().verify(&msg, &full));
            assert!(!MACFactory::new("HMAC-SHA512/224", &key).unwrap().verify(&msg, &wrong));
            let hmac_key = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
            let mut hmac = hmac_key.create_generator();
            hmac.do_update(&msg);
            assert!(hmac.do_verify_final(&full));
            let hmac_key = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
            let mut hmac = hmac_key.create_generator();
            hmac.do_update(&msg);
            assert!(!hmac.do_verify_final(&wrong));

            // HMAC-SHA512/256 pass-throughs: streaming, mac_out, verify and do_verify_final.
            let key = KeyMaterial::<55>::from_bytes_as_type(
                &hex::decode("4915691891f05dec5569ca75819daac897aaeeebb2fb04e7fc696d076feccef399f0eea660a7de4b7bb6ef7829a5f82feed70b35b40458").unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            let msg = hex::decode("").unwrap();
            let full = MACFactory::new("HMAC-SHA512/256", &key).unwrap().mac(&msg);
            assert_eq!(full.len(), 32);
            assert_eq!(
                &full[..20],
                &hex::decode("7857d4737760e127f1533185c6ad183ac4e10bd9").unwrap()[..]
            );

            let hmac_key = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
            let mut hmac = hmac_key.create_generator();
            for chunk in msg.chunks(7) {
                hmac.do_update(chunk);
            }
            assert_eq!(hmac.do_final(), full);

            let mut out = vec![0xffu8; 32];
            assert_eq!(
                MACFactory::new("HMAC-SHA512/256", &key).unwrap().mac_out(&msg, &mut out).unwrap(),
                32
            );
            assert_eq!(out, full);

            let mut out = vec![0xffu8; 32];
            let hmac_key = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
            let mut hmac = hmac_key.create_generator();
            hmac.do_update(&msg);
            assert_eq!(hmac.do_final_out(&mut out).unwrap(), 32);
            assert_eq!(out, full);

            let mut wrong = full.clone();
            wrong[0] ^= 1;
            assert!(MACFactory::new("HMAC-SHA512/256", &key).unwrap().verify(&msg, &full));
            assert!(!MACFactory::new("HMAC-SHA512/256", &key).unwrap().verify(&msg, &wrong));
            let hmac_key = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
            let mut hmac = hmac_key.create_generator();
            hmac.do_update(&msg);
            assert!(hmac.do_verify_final(&full));
            let hmac_key = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
            let mut hmac = hmac_key.create_generator();
            hmac.do_update(&msg);
            assert!(!hmac.do_verify_final(&wrong));

            // TODO: at least one test for each type
        }

        /// Checks every pass-through of the `name` key and its workers against `expected`, the tag
        /// of `msg` under `key`: the key's one-shots, and each `MAC` method on a fresh worker.
        fn check_blake_mac(
            name: &str,
            key: &impl KeyMaterialTrait,
            msg: &[u8],
            expected: &[u8],
            strength: SecurityStrength,
        ) {
            let mac_key = MACFactory::new(name, key).unwrap();
            let make = || mac_key.create_generator();

            assert_eq!(make().output_len(), expected.len(), "{name}: output_len");
            assert_eq!(make().max_security_strength(), strength, "{name}: max_security_strength");

            assert_eq!(make().mac(msg), expected, "{name}: mac");
            assert_eq!(mac_key.mac(msg), expected, "{name}: the key's mac");

            let mut out = vec![0xffu8; expected.len()];
            assert_eq!(make().mac_out(msg, &mut out).unwrap(), expected.len(), "{name}: mac_out");
            assert_eq!(out, expected, "{name}: mac_out");

            let mut mac = make();
            msg.chunks(7).for_each(|c| mac.do_update(c));
            assert_eq!(mac.do_final(), expected, "{name}: do_update then do_final");

            let mut mac = make();
            mac.do_update(msg);
            let mut out = vec![0xffu8; expected.len()];
            assert_eq!(mac.do_final_out(&mut out).unwrap(), expected.len(), "{name}: do_final_out");
            assert_eq!(out, expected, "{name}: do_final_out");

            let mut wrong = expected.to_vec();
            wrong[0] ^= 1;
            assert!(make().verify(msg, expected), "{name}: verify");
            assert!(!make().verify(msg, &wrong), "{name}: verify a wrong tag");
            assert!(mac_key.verify(msg, expected), "{name}: the key's verify");
            assert!(!mac_key.verify(msg, &wrong), "{name}: the key's verify, wrong tag");
            let mut mac = mac_key.create_verifier();
            mac.do_update(msg);
            assert!(mac.do_verify_final(expected), "{name}: do_verify_final");
            let mut mac = mac_key.create_verifier();
            mac.do_update(msg);
            assert!(!mac.do_verify_final(&wrong), "{name}: do_verify_final a wrong tag");
        }

        /// The keyed modes of BLAKE2b-512, BLAKE2s-256 and BLAKE3 through the factory, by name
        /// constant and by string.
        ///
        /// Expected values are copied from the vectors embedded in the algorithm crates' tests:
        /// - BLAKE2b-512-MAC / BLAKE2s-256-MAC: the official BLAKE2 KAT, blake2-kat.json, keyed
        ///   with the bytes 0, 1, ..., kk - 1 (kk = 64 / 32) over the message 0, 1, ..., len - 1
        ///   (the `KAT` entries for lengths 3 and 255 in crypto/blake2/tests/blake2{b,s}_tests.rs);
        /// - BLAKE3-KeyedHash: the official BLAKE3 test_vectors.json, key
        ///   "whats the Elvish word for friend", input `i % 251` of 1025 bytes (the first 32 bytes
        ///   of the `keyed_hash` field of the 1025 case in crypto/blake3/tests/vectors/mod.rs).
        #[test]
        fn blake_mac_tests() {
            use bouncycastle_blake2::{BLAKE2B_512_MAC_NAME, BLAKE2S_256_MAC_NAME};
            use bouncycastle_blake3::BLAKE3_KEYED_HASH_NAME;
            use bouncycastle_core_test_framework::DUMMY_SEED;

            let key64 =
                KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::MACKey).unwrap();
            let key32 =
                KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::MACKey).unwrap();
            let blake3_key = KeyMaterial::<32>::from_bytes_as_type(
                b"whats the Elvish word for friend",
                KeyType::MACKey,
            )
            .unwrap();
            let blake3_input: Vec<u8> = (0..1025).map(|i| (i % 251) as u8).collect();

            for name in ["BLAKE2b-512-MAC", BLAKE2B_512_MAC_NAME] {
                check_blake_mac(
                    name,
                    &key64,
                    &DUMMY_SEED[..3],
                    &hex::decode("33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1").unwrap(),
                    SecurityStrength::_256bit,
                );
                check_blake_mac(
                    name,
                    &key64,
                    &DUMMY_SEED[..255],
                    &hex::decode("142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461").unwrap(),
                    SecurityStrength::_256bit,
                );
            }
            for name in ["BLAKE2s-256-MAC", BLAKE2S_256_MAC_NAME] {
                check_blake_mac(
                    name,
                    &key32,
                    &DUMMY_SEED[..3],
                    &hex::decode(
                        "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b",
                    )
                    .unwrap(),
                    SecurityStrength::_128bit,
                );
                check_blake_mac(
                    name,
                    &key32,
                    &DUMMY_SEED[..255],
                    &hex::decode(
                        "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd",
                    )
                    .unwrap(),
                    SecurityStrength::_128bit,
                );
            }
            for name in ["BLAKE3-KeyedHash", BLAKE3_KEYED_HASH_NAME] {
                check_blake_mac(
                    name,
                    &blake3_key,
                    &blake3_input,
                    &hex::decode(
                        "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
                    )
                    .unwrap(),
                    SecurityStrength::_128bit,
                );
            }

            // The factory builds keys with `from_key_material`, so the key objects' checks surface as
            // `FactoryError::MACError`: BLAKE3 keyed_hash needs exactly 32 bytes (BLAKE3 spec
            // s. 2.3, "a 256-bit key"); BLAKE2s takes at most 32 and BLAKE2b at most 64 (RFC 7693
            // s. 2.1 table, "Key bytes": "0 <= kk <= 64" / "0 <= kk <= 32").
            let key33 =
                KeyMaterial::<64>::from_bytes_as_type(&DUMMY_SEED[..33], KeyType::MACKey).unwrap();
            for name in [BLAKE3_KEYED_HASH_NAME, BLAKE2S_256_MAC_NAME] {
                assert!(
                    matches!(
                        MACFactory::new(name, &key33),
                        Err(FactoryError::MACError(MACError::InvalidLength(_)))
                    ),
                    "{name}: a 33-byte key must be refused"
                );
            }
            assert!(MACFactory::new(BLAKE2B_512_MAC_NAME, &key33).is_ok());

            // Names are case-sensitive, and the hash names are not MACs.
            for name in ["blake2b-512-mac", "BLAKE2b-512", "BLAKE3", "blake3-keyedhash"] {
                assert!(
                    matches!(
                        MACFactory::new(name, &key32),
                        Err(FactoryError::UnsupportedAlgorithm(_))
                    ),
                    "{name:?} must not construct a MAC"
                );
            }
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
                assert_eq!(hmac.create_generator().output_len(), 32);
                assert!(
                    hmac.verify(
                        b"Hi There",
                        &hex::decode(
                            "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70"
                        )
                        .unwrap(),
                    )
                );
            }
        }
    }
}
