#[cfg(test)]
mod hash_factory_tests {
    use bouncycastle_hex as hex;
    use bouncycastle_factory::mac_factory::{MACFactory};
    use bouncycastle_core_interface::traits::{MAC};
    use bouncycastle_core_interface::key_material::{KeyMaterialInternal, KeyType};

    mod sha3_tests {
        use super::*;

        #[test]
        fn sha2_hash_tests() {
            // HMAC-SHA224
            let key = KeyMaterialInternal::<32>::from_bytes_as_type(
                &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
                KeyType::MACKey,
            ).unwrap();
            let hmac = MACFactory::new("HMAC-SHA224", &key).unwrap();
            assert!(hmac.verify(
                b"Hi There",
                &hex::decode("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22").unwrap(),
            ));

            // TODO: at least one test for each type
        }
    }
}