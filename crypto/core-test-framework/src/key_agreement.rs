//! Generic behaviour tests for anything that implements [`KeyAgreement`].

use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::traits::{KeyAgreement, KeyAgreementPrivateKey, KeyAgreementPublicKey};

/// Instance of the test framework.
pub struct TestFrameworkKeyAgreement {
    // Put any config options here
}

impl TestFrameworkKeyAgreement {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test the members of trait [`KeyAgreement`].
    ///
    /// Since key generation is not part of the trait, the caller supplies a
    /// `keygen` function pointer (the inherent `keygen` associated function on the algorithm struct).
    pub fn test_key_agreement<
        PK: KeyAgreementPublicKey<PK_LEN>,
        SK: KeyAgreementPrivateKey<SK_LEN>,
        KAAlg: KeyAgreement<PK, SK, PK_LEN, SK_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), KeyAgreementError>,
    ) where
        KAAlg::DerivedKey: AsRef<[u8]>,
    {
        let (pk_a, sk_a) = keygen().unwrap();
        let (pk_b, sk_b) = keygen().unwrap();

        // Symmetry test -- basic correctness
        // KA(&pk_a, &sk_b) == KA(&pk_b, &sk_a)
        let k_ab = KAAlg::key_agreement(&pk_a, &sk_b).unwrap();
        let k_ba = KAAlg::key_agreement(&pk_b, &sk_a).unwrap();
        assert_eq!(k_ba.as_ref(), k_ab.as_ref());

        // Determinism
        // The same (pk, sk) twice gives the same output
        let k_1 = KAAlg::key_agreement(&pk_a, &sk_b).unwrap();
        let k_2 = KAAlg::key_agreement(&pk_a, &sk_b).unwrap();
        assert_eq!(k_1.as_ref(), k_2.as_ref());

        // Output decodes as a usable PK
        let k = KAAlg::key_agreement(&pk_a, &sk_b).unwrap();
        _ = KAAlg::key_agreement(&PK::from_bytes(k.as_ref()).unwrap(), &sk_a).unwrap();

        // Decoded keys behave the same
        // KA on PK::from_bytes(&pk.encode()) and SK::from_bytes(&sk.encode()) equals KA on the originals
        let k = KAAlg::key_agreement(&pk_a, &sk_b).unwrap();
        let k1 = KAAlg::key_agreement(&PK::from_bytes(&pk_a.encode()).unwrap(), &sk_b).unwrap();
        assert_eq!(k.as_ref(), k1.as_ref());
        let k2 = KAAlg::key_agreement(&pk_a, &SK::from_bytes(&sk_b.encode()).unwrap()).unwrap();
        assert_eq!(k.as_ref(), k2.as_ref());
    }
}

/// Instance of the test framework.
pub struct TestFrameworkKeyAgreementKeys {}

impl TestFrameworkKeyAgreementKeys {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test the members of traits [`KeyAgreementPublicKey`] and [`KeyAgreementPrivateKey`].
    ///
    /// Since key generation is not part of either key trait, the caller supplies a
    /// `keygen` function pointer (the inherent `keygen` associated function on the algorithm struct).
    pub fn test_keys<
        PK: KeyAgreementPublicKey<PK_LEN>,
        SK: KeyAgreementPrivateKey<SK_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), KeyAgreementError>,
    ) {
        let (pk, sk) = keygen().unwrap();

        // Check encoded lengths
        assert_eq!(pk.encode().len(), PK_LEN);
        assert_eq!(sk.encode().len(), SK_LEN);

        // AsRef matches encode
        assert_eq!(pk.as_ref(), &pk.encode());

        // encode_out matches encode
        let mut pk_buf = [0u8; PK_LEN];
        let bytes_written = pk.encode_out(&mut pk_buf);
        assert_eq!(bytes_written, PK_LEN);
        assert_eq!(pk_buf, pk.encode());

        let mut sk_buf = [0u8; SK_LEN];
        let bytes_written = sk.encode_out(&mut sk_buf);
        assert_eq!(bytes_written, SK_LEN);
        assert_eq!(sk_buf, sk.encode());

        // encode_out overwrites
        let mut pk_buf = [0xff; PK_LEN];
        let bytes_written = pk.encode_out(&mut pk_buf);
        assert_eq!(bytes_written, PK_LEN);
        assert_eq!(pk_buf, pk.encode());

        let mut sk_buf = [0xff; SK_LEN];
        let bytes_written = sk.encode_out(&mut sk_buf);
        assert_eq!(bytes_written, SK_LEN);
        assert_eq!(sk_buf, sk.encode());

        // Encoding round trips
        assert_eq!(PK::from_bytes(&pk.encode()).unwrap().encode(), pk.encode());
        assert_eq!(SK::from_bytes(&sk.encode()).unwrap().encode(), sk.encode());

        // Wrong length throws Err(DecodingError(_))
        // pk too small
        assert!(matches!(
            PK::from_bytes(&pk.encode()[..PK_LEN - 1]),
            Err(KeyAgreementError::DecodingError(_))
        ));
        // sk too large
        let mut pk_buf_too_large = [0xff; 1000];
        pk_buf_too_large[..PK_LEN].copy_from_slice(&pk.encode());
        assert!(matches!(
            PK::from_bytes(&pk_buf_too_large),
            Err(KeyAgreementError::DecodingError(_))
        ));

        // sk too small
        assert!(matches!(
            SK::from_bytes(&sk.encode()[..SK_LEN - 1]),
            Err(KeyAgreementError::DecodingError(_))
        ));
        // sk too large
        let mut sk_buf_too_large = [0xff; 1000];
        sk_buf_too_large[..SK_LEN].copy_from_slice(&sk.encode());
        assert!(matches!(
            SK::from_bytes(&sk_buf_too_large),
            Err(KeyAgreementError::DecodingError(_))
        ));
    }
}
