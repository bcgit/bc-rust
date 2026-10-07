//! Generic behaviour tests for anything that implements [`KDF`].

// Imports needed for std
#[allow(unused_imports)]
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterial256, KeyMaterial512, KeyMaterialTrait, KeyType,
};
#[allow(unused_imports)]
use bouncycastle_core::traits::{KDF, SecurityStrength};
// end imports needed for std

/// Instance of the test framework.
pub struct TestFrameworkKDF {
    // Put any config options here
}

impl TestFrameworkKDF {
    ///
    pub fn new() -> Self {
        Self {}
    }
    ///
    pub fn test_kdf_single_key<H: KDF + Default>(
        &self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        expected_output: &impl KeyMaterialTrait,
    ) {
        /*** Test derive_key_out() ***/
        let kdf = H::default();
        let mut output = KeyMaterial512::new();
        let bytes_written = kdf.derive_key_out(key, additional_input, &mut output).unwrap();
        // account for the fact that XOF style KDFs will fill the provided buffer.
        assert!(bytes_written >= expected_output.key_len());
        assert_eq!(output.key_len(), bytes_written);
        output.set_key_len(expected_output.key_len()).unwrap(); // truncates should be infallible
        assert_eq!(output.key_len(), expected_output.key_len());
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** Test derive_key() ***/
        #[cfg(feature = "std")]
        {
            let kdf = H::default();
            let output = kdf.derive_key(key, additional_input).unwrap();
            // TODO: will need to handle the fact that this API might return a truncated version of the expected output
            // TODO: IE if output_len < expected; then check that the bit you have is equal
            assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());
        }

        /*** Test that additional_input changes the output ***/
        let mut output1 = KeyMaterial512::new();
        let mut output2 = KeyMaterial512::new();
        _ = H::default().derive_key_out(key, &[0u8; 0], &mut output1).unwrap();
        _ = H::default().derive_key_out(key, b"some additional input", &mut output2).unwrap();
        assert_ne!(output1.ref_to_bytes(), output2.ref_to_bytes());

        // ... and the same via derive_key()
        #[cfg(feature = "std")]
        {
            let out_key1 = H::default().derive_key(key, &[0u8; 0]).unwrap();
            let out_key2 = H::default().derive_key(key, b"some additional input").unwrap();
            assert_ne!(out_key1.ref_to_bytes(), out_key2.ref_to_bytes());
        }

        /*** Test truncation -- all KDFs should support this ***/

        let kdf = H::default();
        // Give it a KeyMaterial with a capacity of 10 bytes
        let mut output = KeyMaterial::<10>::new();
        let bytes_written = kdf.derive_key_out(key, additional_input, &mut output).unwrap();
        assert_eq!(bytes_written, 10);
        assert_eq!(output.key_len(), 10);
        assert_eq!(output.ref_to_bytes(), &expected_output.ref_to_bytes()[..10]);

        // Some KDFs (such as HKDF) are XOFs underneath and will support longer outputs, but not all are (such as SHA3),
        // so we can't test extendable output generically for all KDFs.

        /*** Test entropy mapping ***/
        // Each case is checked via derive_key_out(), and then the same via derive_key().

        // Zeroized -> Zeroized
        let zeroized_key = KeyMaterial256::new();
        assert_eq!(zeroized_key.key_type(), KeyType::Zeroized);
        let mut out_key = KeyMaterial512::new();
        _ = H::default().derive_key_out(&zeroized_key, &[0u8; 10], &mut out_key).unwrap();
        // since we've done some computation, the result will not actually be zeroized, even if all input key material was zeroized.
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);
        #[cfg(feature = "std")]
        {
            let out_key = H::default().derive_key(&zeroized_key, &[0u8; 10]).unwrap();
            assert_eq!(out_key.key_type(), KeyType::Unknown);
            assert_eq!(out_key.security_strength(), SecurityStrength::None);
        }

        // BytesLowEntropy -> BytesLowEntropy
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::Unknown).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::Unknown);
        let mut out_key = KeyMaterial512::new();
        _ = H::default().derive_key_out(&low_entropy_key, &[0u8; 10], &mut out_key).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);
        #[cfg(feature = "std")]
        {
            let out_key = H::default().derive_key(&low_entropy_key, &[0u8; 10]).unwrap();
            assert_eq!(out_key.key_type(), KeyType::Unknown);
            assert_eq!(out_key.security_strength(), SecurityStrength::None);
        }

        // BytesFullEntropy -> BytesLowEntropy if not enough to fill the hash block
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 6], KeyType::CryptographicRandom).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::CryptographicRandom);
        let mut out_key = KeyMaterial512::new();
        _ = H::default().derive_key_out(&low_entropy_key, &[0u8; 10], &mut out_key).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);
        #[cfg(feature = "std")]
        {
            let out_key = H::default().derive_key(&low_entropy_key, &[0u8; 10]).unwrap();
            assert_eq!(out_key.key_type(), KeyType::Unknown);
            assert_eq!(out_key.security_strength(), SecurityStrength::None);
        }

        // BytesFullEntropy -> BytesFullEntropy
        let full_entropy_key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 64], KeyType::CryptographicRandom).unwrap();
        assert_eq!(full_entropy_key.key_type(), KeyType::CryptographicRandom);
        let mut out_key = KeyMaterial512::new();
        _ = H::default().derive_key_out(&full_entropy_key, &[0u8; 10], &mut out_key).unwrap();
        assert_eq!(out_key.key_type(), KeyType::CryptographicRandom);
        assert!(out_key.security_strength() > SecurityStrength::None);
        #[cfg(feature = "std")]
        {
            let out_key = H::default().derive_key(&full_entropy_key, &[0u8; 10]).unwrap();
            assert_eq!(out_key.key_type(), KeyType::CryptographicRandom);
            assert!(out_key.security_strength() > SecurityStrength::None);
        }
    }
    ///
    pub fn test_kdf_multiple_key<H: KDF + Default>(
        &self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
        expected_output: &mut impl KeyMaterialTrait,
    ) {
        /*** test derive_key_from_multiple_out() ***/
        let kdf = H::default();
        let mut output = KeyMaterial512::new();
        let bytes_written =
            kdf.derive_key_from_multiple_out(keys, additional_input, &mut output).unwrap();
        // This is sortof a hack since the rust language won't easily allow me to make the KeyMaterials the same length.
        // Callers may supply an expected_output longer than this KDF produces (e.g. an expanded HKDF vector),
        // so compare on the common prefix. This must happen here, before any of the comparisons below,
        // so that it applies equally with and without the `std` feature.
        if bytes_written < expected_output.key_len() {
            expected_output.set_key_len(bytes_written).unwrap(); // truncates should be infallible
        }
        // account for the fact that XOF style KDFs will fill the provided buffer.
        assert!(bytes_written >= expected_output.key_len());
        assert_eq!(output.key_len(), bytes_written);
        output.set_key_len(expected_output.key_len()).unwrap(); // truncates should be infallible
        assert_eq!(output.key_len(), expected_output.key_len());
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** test derive_key_from_multiple() ***/
        #[cfg(feature = "std")]
        {
            let kdf = H::default();

            let output = kdf.derive_key_from_multiple(keys, additional_input).unwrap();
            // This is sortof a hack since the rust language won't easily allow me to make the KeyMaterials the same length
            if output.key_len() < expected_output.key_len() {
                expected_output.set_key_len(output.key_len()).unwrap(); // truncates should be infallible
            }
            assert_eq!(output.key_len(), expected_output.key_len());
            assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());
        }

        /*** Test that additional_input changes the output ***/
        let mut out_key1 = KeyMaterial512::new();
        let mut out_key2 = KeyMaterial512::new();
        _ = H::default().derive_key_from_multiple_out(keys, &[0u8; 0], &mut out_key1).unwrap();
        _ = H::default()
            .derive_key_from_multiple_out(keys, b"some additional input", &mut out_key2)
            .unwrap();
        assert_ne!(out_key1.ref_to_bytes(), out_key2.ref_to_bytes());

        // ... and the same via derive_key_from_multiple()
        #[cfg(feature = "std")]
        {
            let out_key1 = H::default().derive_key_from_multiple(keys, &[0u8; 0]).unwrap();
            let out_key2 =
                H::default().derive_key_from_multiple(keys, b"some additional input").unwrap();
            assert_ne!(out_key1.ref_to_bytes(), out_key2.ref_to_bytes());
        }

        /*** Test trunctation -- all KDFs should support this ***/

        let kdf = H::default();
        // Give it a KeyMaterial with a capacity of 10 bytes
        let mut output = KeyMaterial::<10>::new();
        let bytes_written =
            kdf.derive_key_from_multiple_out(keys, additional_input, &mut output).unwrap();
        assert_eq!(bytes_written, 10);
        assert_eq!(output.key_len(), 10);
        assert_eq!(output.ref_to_bytes(), &expected_output.ref_to_bytes()[..10]);

        /*** Test entropy mapping ***/
        // Each case is checked via derive_key_from_multiple_out(), and then the same via
        // derive_key_from_multiple().

        // Zeroized -> Zeroized
        let zeroized_key = KeyMaterial256::new();
        assert_eq!(zeroized_key.key_type(), KeyType::Zeroized);
        assert_eq!(zeroized_key.security_strength(), SecurityStrength::None);
        let keys = [&zeroized_key, &zeroized_key];
        let mut out_key = KeyMaterial512::new();
        _ = H::default().derive_key_from_multiple_out(&keys, &[0u8; 10], &mut out_key).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);
        #[cfg(feature = "std")]
        {
            let out_key = H::default().derive_key_from_multiple(&keys, &[0u8; 10]).unwrap();
            assert_eq!(out_key.key_type(), KeyType::Unknown);
            assert_eq!(out_key.security_strength(), SecurityStrength::None);
        }

        // BytesLowEntropy -> BytesLowEntropy
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::Unknown).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::Unknown);
        let keys = [&zeroized_key, &low_entropy_key];
        let mut out_key = KeyMaterial512::new();
        _ = H::default().derive_key_from_multiple_out(&keys, &[0u8; 10], &mut out_key).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);
        #[cfg(feature = "std")]
        {
            let out_key = H::default().derive_key_from_multiple(&keys, &[0u8; 10]).unwrap();
            assert_eq!(out_key.key_type(), KeyType::Unknown);
            assert_eq!(out_key.security_strength(), SecurityStrength::None);
        }

        // BytesFullEntropy -> BytesLowEntropy if not enough to fill the hash block
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 6], KeyType::CryptographicRandom).unwrap();
        assert_eq!(low_entropy_key.key_type(), KeyType::CryptographicRandom);
        let keys = [&zeroized_key, &low_entropy_key];
        let mut out_key = KeyMaterial512::new();
        _ = H::default().derive_key_from_multiple_out(&keys, &[0u8; 10], &mut out_key).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);
        #[cfg(feature = "std")]
        {
            let out_key = H::default().derive_key_from_multiple(&keys, &[0u8; 10]).unwrap();
            assert_eq!(out_key.key_type(), KeyType::Unknown);
            assert_eq!(out_key.security_strength(), SecurityStrength::None);
        }

        // BytesFullEntropy -> BytesFullEntropy
        let zeroized64_key = KeyMaterial512::new();
        let full_entropy_key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 64], KeyType::CryptographicRandom).unwrap();
        assert_eq!(full_entropy_key.key_type(), KeyType::CryptographicRandom);
        let keys = [&zeroized64_key, &full_entropy_key];
        let mut out_key = KeyMaterial512::new();
        _ = H::default().derive_key_from_multiple_out(&keys, &[0u8; 10], &mut out_key).unwrap();
        assert_eq!(out_key.key_type(), KeyType::CryptographicRandom);
        assert!(out_key.security_strength() > SecurityStrength::None);
        #[cfg(feature = "std")]
        {
            let out_key = H::default().derive_key_from_multiple(&keys, &[0u8; 10]).unwrap();
            assert_eq!(out_key.key_type(), KeyType::CryptographicRandom);
            assert!(out_key.security_strength() > SecurityStrength::None);
        }
    }
}
