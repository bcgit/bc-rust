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
            // HMAC-SHA224, RFC 4231 Test Case 6. MACFactory has no weak-key constructor, so this
            // needs a vector whose key reaches the strength HMAC-SHA224 claims; Test Case 1's
            // 20-byte key does not.
            let key = KeyMaterial::<131>::from_bytes_as_type(
                &hex::decode("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                    .unwrap(),
                KeyType::MACKey,
            )
            .unwrap();
            let hmac = MACFactory::new("HMAC-SHA224", &key).unwrap();
            assert!(hmac.verify(
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                &hex::decode("95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e").unwrap(),
            ));

            // TODO: at least one test for each type
        }
    }
}
