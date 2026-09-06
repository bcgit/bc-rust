#[cfg(test)]
mod hash_factory_tests {
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::traits::MAC;
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
            assert_eq!(hmac.output_len(), 28);
            assert_eq!(&hmac.mac(&msg)[..20], &expected[..]);
            let hmac = MACFactory::new(bouncycastle_hmac::HMAC_SHA512_224_NAME, &key).unwrap();
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
            let hmac = MACFactory::new(bouncycastle_hmac::HMAC_SHA512_256_NAME, &key).unwrap();
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

            let mut hmac = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
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
            let mut hmac = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
            hmac.do_update(&msg);
            assert_eq!(hmac.do_final_out(&mut out).unwrap(), 28);
            assert_eq!(out, full);

            let mut wrong = full.clone();
            wrong[0] ^= 1;
            assert!(MACFactory::new("HMAC-SHA512/224", &key).unwrap().verify(&msg, &full));
            assert!(!MACFactory::new("HMAC-SHA512/224", &key).unwrap().verify(&msg, &wrong));
            let mut hmac = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
            hmac.do_update(&msg);
            assert!(hmac.do_verify_final(&full));
            let mut hmac = MACFactory::new("HMAC-SHA512/224", &key).unwrap();
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

            let mut hmac = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
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
            let mut hmac = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
            hmac.do_update(&msg);
            assert_eq!(hmac.do_final_out(&mut out).unwrap(), 32);
            assert_eq!(out, full);

            let mut wrong = full.clone();
            wrong[0] ^= 1;
            assert!(MACFactory::new("HMAC-SHA512/256", &key).unwrap().verify(&msg, &full));
            assert!(!MACFactory::new("HMAC-SHA512/256", &key).unwrap().verify(&msg, &wrong));
            let mut hmac = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
            hmac.do_update(&msg);
            assert!(hmac.do_verify_final(&full));
            let mut hmac = MACFactory::new("HMAC-SHA512/256", &key).unwrap();
            hmac.do_update(&msg);
            assert!(!hmac.do_verify_final(&wrong));

            // TODO: at least one test for each type
        }
    }
}
