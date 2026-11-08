//! Generic behaviour tests for anything that implements [`KDF`].

use bouncycastle_core::errors::KDFError;
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterial256, KeyMaterial512, KeyMaterialTrait, KeyType,
};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KDF, KDF_ONE_SHOT_MAX_LEN};

/// Instance of the test framework.
pub struct TestFrameworkKDF {
    // Put any config options here
}

impl TestFrameworkKDF {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Every member of [`KDF`] on `kdf` with one input key, an instance holding no credited keying
    /// material of its own (an HKDF with a secret `MACKey` salt does; one with a public salt or
    /// none does not), since the entropy checks below run on it: the one-shot and the `_out` form give
    /// `expected_output` at its length, a shorter length is its prefix, `fixed_info` changes the
    /// output, the length bounds are refused with the buffer zeroized, the entropy accounting
    /// follows the trait's rule, and the instance works as `&dyn KDF`.
    pub fn test_kdf_single_key(
        &self,
        kdf: &impl KDF,
        key: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        expected_output: &dyn KeyMaterialTrait,
    ) {
        let len = expected_output.key_len();

        /*** derive_key() ***/
        let output = kdf.derive_key(key, fixed_info, len).unwrap();
        assert_eq!(output.key_len(), len);
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** derive_key_out() ***/
        let mut output = KeyMaterial::<KDF_ONE_SHOT_MAX_LEN>::new();
        let bytes_written = kdf.derive_key_out(key, fixed_info, len, &mut output).unwrap();
        assert_eq!(bytes_written, len);
        assert_eq!(output.key_len(), len);
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** a shorter length is a prefix: every KDF supports truncation ***/
        let mut output = KeyMaterial::<10>::new();
        let bytes_written = kdf.derive_key_out(key, fixed_info, 10, &mut output).unwrap();
        assert_eq!(bytes_written, 10);
        assert_eq!(output.key_len(), 10);
        assert_eq!(output.ref_to_bytes(), &expected_output.ref_to_bytes()[..10]);

        /*** fixed_info changes the output ***/
        let out_key1 = kdf.derive_key(key, &[0u8; 0], len).unwrap();
        let out_key2 = kdf.derive_key(key, b"some additional input", len).unwrap();
        assert_ne!(out_key1.ref_to_bytes(), out_key2.ref_to_bytes());

        /*** a length the buffer cannot hold is refused and the buffer left zeroized ***/
        let mut output = KeyMaterial::<10>::new();
        output.set_bytes_as_type(&[0xAA; 10], KeyType::CryptographicRandom).unwrap();
        match kdf.derive_key_out(key, fixed_info, 11, &mut output) {
            Err(KDFError::InvalidLength(_)) => {}
            other => panic!("a length beyond the buffer must be refused, got {other:?}"),
        }
        assert_eq!(output.key_len(), 0);
        assert_eq!(output.key_type(), KeyType::Zeroized);

        /*** the instance works as a trait object ***/
        let dyn_kdf: &dyn KDF = kdf;
        let output = dyn_kdf.derive_key(key, fixed_info, len).unwrap();
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** entropy accounting ***/
        // Zeroized -> Unknown: computation happened, so the result is not zeroized, but nothing
        // was credited
        let zeroized_key = KeyMaterial256::new();
        assert_eq!(zeroized_key.key_type(), KeyType::Zeroized);
        let out_key = kdf.derive_key(&zeroized_key, &[0u8; 10], 10).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // Unknown -> Unknown
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::Unknown).unwrap();
        let out_key = kdf.derive_key(&low_entropy_key, &[0u8; 10], 10).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // full entropy, but too little of it to seed the function -> Unknown
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 6], KeyType::CryptographicRandom).unwrap();
        let out_key = kdf.derive_key(&low_entropy_key, &[0u8; 10], 10).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // enough full entropy -> CryptographicRandom at some strength
        let full_entropy_key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 64], KeyType::CryptographicRandom).unwrap();
        let out_key = kdf.derive_key(&full_entropy_key, &[0u8; 10], len).unwrap();
        assert_eq!(out_key.key_type(), KeyType::CryptographicRandom);
        assert!(out_key.security_strength() > SecurityStrength::None);

        // the output is the KDF's, not the input's: a Seed, a MACKey or a SharedSecret with a
        // strength in gives CryptographicRandom out
        for key_type in [KeyType::Seed, KeyType::MACKey, KeyType::SharedSecret] {
            let mut typed = KeyMaterial512::from_bytes_as_type(&[2u8; 64], key_type).unwrap();
            if key_type == KeyType::SharedSecret {
                do_hazardous_operations(&mut typed, |z| {
                    z.set_security_strength(SecurityStrength::_128bit)
                })
                .unwrap();
            }
            let out_key = kdf.derive_key(&typed, &[0u8; 10], len).unwrap();
            assert_eq!(out_key.key_type(), KeyType::CryptographicRandom, "{key_type:?} in");
            assert!(out_key.security_strength() > SecurityStrength::None, "{key_type:?} in");
        }

        // a full-entropy key with no strength credits nothing: a SharedSecret whose producer
        // stated none
        let z = KeyMaterial512::from_bytes_as_type(&[3u8; 64], KeyType::SharedSecret).unwrap();
        assert_eq!(z.security_strength(), SecurityStrength::None);
        let out_key = kdf.derive_key(&z, &[0u8; 10], len).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        /*** a zero-length derivation is refused, and the one-shot refuses a length past its cap ***/
        assert!(matches!(kdf.derive_key(key, fixed_info, 0), Err(KDFError::InvalidLength(_))));
        let mut zero = KeyMaterial::<10>::new();
        assert!(matches!(
            kdf.derive_key_out(key, fixed_info, 0, &mut zero),
            Err(KDFError::InvalidLength(_))
        ));
        assert!(matches!(
            kdf.derive_key(key, fixed_info, KDF_ONE_SHOT_MAX_LEN + 1),
            Err(KDFError::InvalidLength(_))
        ));
    }

    /// The multi-key members of [`KDF`] on `kdf`: `keys` concatenated must give
    /// `expected_output` at its length through both forms, a shorter length is a prefix,
    /// `fixed_info` changes the output, and the entropy credited is the keys' sum.
    pub fn test_kdf_multiple_key(
        &self,
        kdf: &impl KDF,
        keys: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        expected_output: &dyn KeyMaterialTrait,
    ) {
        let len = expected_output.key_len();

        /*** derive_key_from_multiple() ***/
        let output = kdf.derive_key_from_multiple(keys, fixed_info, len).unwrap();
        assert_eq!(output.key_len(), len);
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** derive_key_from_multiple_out() ***/
        let mut output = KeyMaterial::<KDF_ONE_SHOT_MAX_LEN>::new();
        let bytes_written =
            kdf.derive_key_from_multiple_out(keys, fixed_info, len, &mut output).unwrap();
        assert_eq!(bytes_written, len);
        assert_eq!(output.key_len(), len);
        assert_eq!(output.ref_to_bytes(), expected_output.ref_to_bytes());

        /*** a shorter length is a prefix ***/
        let mut output = KeyMaterial::<10>::new();
        let bytes_written =
            kdf.derive_key_from_multiple_out(keys, fixed_info, 10, &mut output).unwrap();
        assert_eq!(bytes_written, 10);
        assert_eq!(output.ref_to_bytes(), &expected_output.ref_to_bytes()[..10]);

        /*** fixed_info changes the output ***/
        let out_key1 = kdf.derive_key_from_multiple(keys, &[0u8; 0], len).unwrap();
        let out_key2 = kdf.derive_key_from_multiple(keys, b"some additional input", len).unwrap();
        assert_ne!(out_key1.ref_to_bytes(), out_key2.ref_to_bytes());

        /*** a derivation from no keys is refused ***/
        assert!(matches!(
            kdf.derive_key_from_multiple(&[], fixed_info, len),
            Err(KDFError::InvalidLength(_))
        ));
        let mut none = KeyMaterial::<KDF_ONE_SHOT_MAX_LEN>::new();
        assert!(matches!(
            kdf.derive_key_from_multiple_out(&[], fixed_info, len, &mut none),
            Err(KDFError::InvalidLength(_))
        ));

        /*** entropy accounting ***/
        // two zeroized keys -> Unknown
        let zeroized_key = KeyMaterial256::new();
        let keys: [&dyn KeyMaterialTrait; 2] = [&zeroized_key, &zeroized_key];
        let out_key = kdf.derive_key_from_multiple(&keys, &[0u8; 10], 10).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // zeroized and Unknown -> Unknown
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 16], KeyType::Unknown).unwrap();
        let keys: [&dyn KeyMaterialTrait; 2] = [&zeroized_key, &low_entropy_key];
        let out_key = kdf.derive_key_from_multiple(&keys, &[0u8; 10], 10).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // zeroized and too little full entropy -> Unknown
        let low_entropy_key =
            KeyMaterial256::from_bytes_as_type(&[1u8; 6], KeyType::CryptographicRandom).unwrap();
        let keys: [&dyn KeyMaterialTrait; 2] = [&zeroized_key, &low_entropy_key];
        let out_key = kdf.derive_key_from_multiple(&keys, &[0u8; 10], 10).unwrap();
        assert_eq!(out_key.key_type(), KeyType::Unknown);
        assert_eq!(out_key.security_strength(), SecurityStrength::None);

        // zeroized and enough full entropy -> CryptographicRandom
        let zeroized64_key = KeyMaterial512::new();
        let full_entropy_key =
            KeyMaterial512::from_bytes_as_type(&[1u8; 64], KeyType::CryptographicRandom).unwrap();
        let keys: [&dyn KeyMaterialTrait; 2] = [&zeroized64_key, &full_entropy_key];
        let out_key = kdf.derive_key_from_multiple(&keys, &[0u8; 10], len).unwrap();
        assert_eq!(out_key.key_type(), KeyType::CryptographicRandom);
        assert!(out_key.security_strength() > SecurityStrength::None);

        // two halves credit as their sum: 32 + 32 bytes seed what one 64-byte key does
        let half_a =
            KeyMaterial256::from_bytes_as_type(&[1u8; 32], KeyType::CryptographicRandom).unwrap();
        let half_b =
            KeyMaterial256::from_bytes_as_type(&[2u8; 32], KeyType::CryptographicRandom).unwrap();
        let keys: [&dyn KeyMaterialTrait; 2] = [&half_a, &half_b];
        let out_key = kdf.derive_key_from_multiple(&keys, &[0u8; 10], len).unwrap();
        assert_eq!(out_key.key_type(), KeyType::CryptographicRandom);
    }
}
