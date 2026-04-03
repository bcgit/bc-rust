#[cfg(test)]
mod mldsa_tests {
    #![allow(dead_code)]
    #![allow(unused_imports)]

    use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyType};
    use bouncycastle_core_interface::traits::{Signature, SignaturePrivateKey, SignaturePublicKey};
    use bouncycastle_core_test_framework::signature::{TestFrameworkSignatureKeys};
    use bouncycastle_mldsa_lowmemory::{MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87PrivateKey, MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MLDSATrait, MLDSA44, MLDSA65, MLDSA87};
    use bouncycastle_mldsa_lowmemory::{MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA87_PK_LEN, MLDSA87_SK_LEN};
    use bouncycastle_hex as hex;


    #[test]
    fn core_framework_tests() {
        let tf = TestFrameworkSignatureKeys::new();

        tf.test_keys::<MLDSA44PublicKey, MLDSA44PrivateKey, MLDSA44, MLDSA44_PK_LEN, MLDSA44_SK_LEN>();
        tf.test_keys::<MLDSA65PublicKey, MLDSA65PrivateKey, MLDSA65, MLDSA65_PK_LEN, MLDSA65_SK_LEN>();
        tf.test_keys::<MLDSA87PublicKey, MLDSA87PrivateKey, MLDSA87, MLDSA87_PK_LEN, MLDSA87_SK_LEN>();
    }

    #[test]
    fn encode_decode() {
        let seed = KeyMaterial256::from_bytes_as_type(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
            KeyType::Seed,
        ).unwrap();

        let (pk1, sk1) = MLDSA44::keygen_from_seed(&seed).unwrap();
        let pk1_bytes = pk1.encode();
        let sk1_bytes = sk1.encode();

        let (pk2, sk2) = MLDSA44::keygen_from_seed(&seed).unwrap();
        let mut pk2_bytes = [1u8; MLDSA44_PK_LEN];
        let bytes_written = pk2.encode_out(&mut pk2_bytes).unwrap();
        assert_eq!(bytes_written, MLDSA44_PK_LEN);
        assert_eq!(pk1_bytes, pk2_bytes);

        let mut sk2_bytes = [1u8; MLDSA44_SK_LEN];
        let bytes_written = sk2.encode_out(&mut sk2_bytes).unwrap();
        assert_eq!(bytes_written, MLDSA44_SK_LEN);
        assert_eq!(sk1_bytes, sk2_bytes);
    }

    #[test]
    fn seed() {
        let seed = KeyMaterial256::from_bytes_as_type(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap(),
            KeyType::Seed,
        ).unwrap();

        let (_pk, sk) = MLDSA44::keygen_from_seed(&seed).unwrap();

        assert_eq!(sk.seed(), &seed);
    }

    #[test]
    fn test_eq() {

        // MLDSA-44

        let (pk, sk) = MLDSA44::keygen().unwrap();

        // basic equality checks
        assert_eq!(pk, pk);
        assert_eq!(pk, pk.clone());
        assert_eq!(pk, MLDSA44PublicKey::from_bytes(&pk.encode()).unwrap());

        assert_eq!(sk, sk);
        assert_eq!(sk, sk.clone());
        assert_eq!(sk, MLDSA44PrivateKey::from_bytes(&sk.sk_encode()).unwrap());

        // inequality checks
        let mut bytes = pk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(pk, MLDSA44PublicKey::from_bytes(&bytes).unwrap());

        let mut bytes = sk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(sk, MLDSA44PrivateKey::from_bytes(&bytes).unwrap());


        // MLDSA-65

        let (pk, sk) = MLDSA65::keygen().unwrap();

        // basic equality checks
        assert_eq!(pk, pk);
        assert_eq!(pk, pk.clone());
        assert_eq!(pk, MLDSA65PublicKey::from_bytes(&pk.pk_encode()).unwrap());

        assert_eq!(sk, sk);
        assert_eq!(sk, sk.clone());
        assert_eq!(sk, MLDSA65PrivateKey::from_bytes(&sk.sk_encode()).unwrap());

        // inequality checks
        let mut bytes = pk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(pk, MLDSA65PublicKey::from_bytes(&bytes).unwrap());

        let mut bytes = sk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(sk, MLDSA65PrivateKey::from_bytes(&bytes).unwrap());


        // MLDSA-87

        let (pk, sk) = MLDSA87::keygen().unwrap();

        // basic equality checks
        assert_eq!(pk, pk);
        assert_eq!(pk, pk.clone());
        assert_eq!(pk, MLDSA87PublicKey::from_bytes(&pk.pk_encode()).unwrap());

        assert_eq!(sk, sk);
        assert_eq!(sk, sk.clone());
        assert_eq!(sk, MLDSA87PrivateKey::from_bytes(&sk.sk_encode()).unwrap());

        // inequality checks
        let mut bytes = pk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(pk, MLDSA87PublicKey::from_bytes(&bytes).unwrap());

        let mut bytes = sk.encode();
        bytes[17] ^= 0x01;
        assert_ne!(sk, MLDSA87PrivateKey::from_bytes(&bytes).unwrap());
    }

    /// Tests that no private data is displayed
    #[test]
    fn test_display() {
        let (pk44, sk44) = MLDSA44::keygen().unwrap();
        let (pk65, sk65) = MLDSA65::keygen().unwrap();
        let (pk87, sk87) = MLDSA87::keygen().unwrap();


        /*** MLDSAPublicKey ***/
        // fmt

        let pk_str = format!("{}", pk44);
        assert!(pk_str.contains("MLDSAPublicKey { alg: ML-DSA-44, pub_key_hash (tr):"));

        let pk_str = format!("{}", pk65);
        assert!(pk_str.contains("MLDSAPublicKey { alg: ML-DSA-65, pub_key_hash (tr):"));

        let pk_str = format!("{}", pk87);
        assert!(pk_str.contains("MLDSAPublicKey { alg: ML-DSA-87, pub_key_hash (tr):"));

        // debug
        let pk_str = format!("{:?}", pk44);
        assert!(pk_str.contains("MLDSAPublicKey { alg: ML-DSA-44, pub_key_hash (tr):"));

        let pk_str = format!("{:?}", pk65);
        assert!(pk_str.contains("MLDSAPublicKey { alg: ML-DSA-65, pub_key_hash (tr):"));

        let pk_str = format!("{:?}", pk87);
        assert!(pk_str.contains("MLDSAPublicKey { alg: ML-DSA-87, pub_key_hash (tr):"));



        /*** MLDSAPrivateKey ***/
        // fmt
        let sk_str = format!("{}", sk44);
        assert!(sk_str.contains("MLDSASeedPrivateKey { alg: ML-DSA-44, pub_key_hash (tr):"));

        let sk_str = format!("{}", sk65);
        assert!(sk_str.contains("MLDSASeedPrivateKey { alg: ML-DSA-65, pub_key_hash (tr):"));

        let sk_str = format!("{}", sk87);
        assert!(sk_str.contains("MLDSASeedPrivateKey { alg: ML-DSA-87, pub_key_hash (tr):"));

        // debug
        let sk_str = format!("{:?}", sk44);
        assert!(sk_str.contains("MLDSASeedPrivateKey { alg: ML-DSA-44, pub_key_hash (tr):"));

        let sk_str = format!("{:?}", sk65);
        assert!(sk_str.contains("MLDSASeedPrivateKey { alg: ML-DSA-65, pub_key_hash (tr):"));

        let sk_str = format!("{:?}", sk87);
        assert!(sk_str.contains("MLDSASeedPrivateKey { alg: ML-DSA-87, pub_key_hash (tr):"));
    }
}