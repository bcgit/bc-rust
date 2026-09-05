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

            // TODO: at least one test for each type
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
            for name in ["HMAC-SM3", bouncycastle_hmac::HMAC_SM3_NAME] {
                let hmac = MACFactory::new(name, &key).unwrap();
                assert_eq!(hmac.output_len(), 32);
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
