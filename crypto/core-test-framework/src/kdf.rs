use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyMaterial512, KeyMaterialInternal, KeyType};
use bouncycastle_core_interface::traits::{KDF, KeyMaterial, SecurityStrength};

pub struct TestFrameworkKDF {}

impl TestFrameworkKDF {
    pub fn new() -> Self {
        Self {}
    }

    pub fn test_kdf_single_key<H: KDF + Default>(
        &self,
        key: &impl KeyMaterial,
        additional_input: &[u8],
        expected_output: &impl KeyMaterial,
    ) {
        /*** Test derive_key() ***/
        let kdf = H::default();
        let output = kdf.derive_key(key, additional_input).unwrap();
        // TODO: will need to handle the fact that this API might return a truncated version of the expected output
        // TODO: IE if output_len < expected; then check that the bit you have is equal
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** Test derive_key_out() ***/
        let kdf = H::default();
        let mut output = KeyMaterial512::new();
        let bytes_written = kdf.derive_key_out(key, additional_input, &mut output).unwrap();
        // account for the fact that XOF style KDFs will will the provided buffer.
        assert!(bytes_written >= expected_output.key_len());
        assert_eq!(output.key_len(), bytes_written);
        output.truncate(expected_output.key_len()).unwrap();
        assert_eq!(output.key_len(), expected_output.key_len());
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** Test that additional_input changes the output ***/
        let out_key1 = H::default().derive_key(key, &[0u8; 0]).unwrap();
        let out_key2 = H::default().derive_key(key, b"some additional input").unwrap();
        assert_ne!(out_key1.ref_to_bytes(), out_key2.ref_to_bytes());

        /*** Test truncation -- all KDFs should support this ***/

        let kdf = H::default();
        // Give it a KeyMaterial with a capacity of 10 bytes
        let mut output = KeyMaterialInternal::<10>::new();
        let bytes_written = kdf.derive_key_out(key, additional_input, &mut output).unwrap();
        assert_eq!(bytes_written, 10);
        assert_eq!(output.key_len(), 10);
        assert_eq!(output.ref_to_bytes(), &expected_output.ref_to_bytes()[..10]);

        // Some KDFs (such as HKDF) are XOFs underneath and will support longer outputs, but not all are (such as SHA3),
        // so we can't test extendable output generically for all KDFs.

        /*** Test entropy mapping ***/

        // Zeroized -> Zeroized
        let zeroized_key = KeyMaterial256::new();
        assert_eq!(zeroized_key.key_type(), KeyType::Zeroized);
        let out_key = H::default().derive_key(&zeroized_key, &[0u8; 10]).unwrap();
        // since we've done some computation, the result will not actually be zeroized, even if all input key material was zeroized.
        assert_eq!(out_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // BytesLowEntropy -> BytesLowEntropy
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::BytesLowEntropy).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::BytesLowEntropy);
        let out_key = H::default().derive_key(&low_entropy_key, &[0u8; 10]).unwrap();
        assert_eq!(out_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // BytesFullEntropy -> BytesLowEntropy if not enough to fill the hash block
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 6], KeyType::BytesFullEntropy).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::BytesFullEntropy);
        let out_key = H::default().derive_key(&low_entropy_key, &[0u8; 10]).unwrap();
        assert_eq!(out_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // BytesFullEntropy -> BytesFullEntropy
        let full_entropy_key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 64], KeyType::BytesFullEntropy).unwrap();
        assert_eq!(full_entropy_key.key_type(), KeyType::BytesFullEntropy);
        let out_key = H::default().derive_key(&full_entropy_key, &[0u8; 10]).unwrap();
        assert_eq!(out_key.key_type(), KeyType::BytesFullEntropy);
        assert!(out_key.security_strength() > SecurityStrength::None);
    }

    pub fn test_kdf_multiple_key<H: KDF + Default>(
        &self,
        keys: &[&impl KeyMaterial],
        additional_input: &[u8],
        expected_output: &mut impl KeyMaterial,
    ) {
        /*** test derive_key_from_multiple() ***/
        let kdf = H::default();

        let output = kdf.derive_key_from_multiple(keys, additional_input).unwrap();
        // This is sortof a hack since the rust language won't easily allow me to make the KeyMaterials the same length
        if output.key_len() < expected_output.key_len() {
            expected_output.truncate(output.key_len()).unwrap();
        }
        assert_eq!(output.key_len(), expected_output.key_len());
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** test derive_key_from_multiple_out() ***/
        let kdf = H::default();
        let mut output = KeyMaterial512::new();
        let bytes_written =
            kdf.derive_key_from_multiple_out(keys, additional_input, &mut output).unwrap();
        // account for the fact that XOF style KDFs will will the provided buffer.
        assert!(bytes_written >= expected_output.key_len());
        assert_eq!(output.key_len(), bytes_written);
        output.truncate(expected_output.key_len()).unwrap();
        assert_eq!(output.key_len(), expected_output.key_len());
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** Test that additional_input changes the output ***/
        let out_key1 = H::default().derive_key_from_multiple(keys, &[0u8; 0]).unwrap();
        let out_key2 =
            H::default().derive_key_from_multiple(keys, b"some additional input").unwrap();
        assert_ne!(out_key1.ref_to_bytes(), out_key2.ref_to_bytes());

        /*** Test trunctation -- all KDFs should support this ***/

        let kdf = H::default();
        // Give it a KeyMaterial with a capacity of 10 bytes
        let mut output = KeyMaterialInternal::<10>::new();
        let bytes_written =
            kdf.derive_key_from_multiple_out(keys, additional_input, &mut output).unwrap();
        assert_eq!(bytes_written, 10);
        assert_eq!(output.key_len(), 10);
        assert_eq!(output.ref_to_bytes(), &expected_output.ref_to_bytes()[..10]);

        /*** Test entropy mapping ***/

        // Zeroized -> Zeroized
        let zeroized_key = KeyMaterial256::new();
        assert_eq!(zeroized_key.key_type(), KeyType::Zeroized);
        assert_eq!(zeroized_key.security_strength(), SecurityStrength::None);
        let keys = [&zeroized_key, &zeroized_key];
        let out_key = H::default().derive_key_from_multiple(&keys, &[0u8; 10]).unwrap();
        assert_eq!(out_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // BytesLowEntropy -> BytesLowEntropy
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::BytesLowEntropy).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::BytesLowEntropy);
        let keys = [&zeroized_key, &low_entropy_key];
        let out_key = H::default().derive_key_from_multiple(&keys, &[0u8; 10]).unwrap();
        assert_eq!(out_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // BytesFullEntropy -> BytesLowEntropy if not enough to fill the hash block
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 6], KeyType::BytesFullEntropy).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::BytesFullEntropy);
        let keys = [&zeroized_key, &low_entropy_key];
        let out_key = H::default().derive_key_from_multiple(&keys, &[0u8; 10]).unwrap();
        assert_eq!(out_key.key_type(), KeyType::BytesLowEntropy);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // BytesFullEntropy -> BytesFullEntropy
        let zeroized64_key = KeyMaterial512::new();
        let full_entropy_key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 64], KeyType::BytesFullEntropy).unwrap();
        assert_eq!(full_entropy_key.key_type(), KeyType::BytesFullEntropy);
        let keys = [&zeroized64_key, &full_entropy_key];
        let out_key = H::default().derive_key_from_multiple(&keys, &[0u8; 10]).unwrap();
        assert_eq!(out_key.key_type(), KeyType::BytesFullEntropy);
        assert!(out_key.security_strength() > SecurityStrength::None);
    }
}
