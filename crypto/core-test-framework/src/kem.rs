use crate::FixedSeedRNG;
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::traits::{
    KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, RNG, SecurityStrength,
};

pub struct TestFrameworkKEM {
    // Put any config options here
    /// Should the test framework expect that repeated calls to encaps() will produce the same CT?
    alg_is_deterministic: bool,

    /// True if the KEM is based on the implicitly-rejecting FO design and decaps failures will still return a ss,
    /// False if it is explicitly-rejecting and decaps failures will throw an error.
    is_implicitly_rejecting: bool,
}

impl TestFrameworkKEM {
    pub fn new(alg_is_deterministic: bool, is_implicitly_rejecting: bool) -> Self {
        Self { alg_is_deterministic, is_implicitly_rejecting }
    }

    /// Test all the members of traits [KEMEncapsulator] and [KEMDecapsulator] against the given input-output pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    ///
    /// Since key generation is not part of either KEM trait, the caller supplies a
    /// `keygen` function pointer (the inherent `keygen` associated function on the algorithm struct).
    pub fn test_kem<
        PK: KEMPublicKey<PK_LEN>,
        SK: KEMPrivateKey<SK_LEN>,
        KEMAlg: KEMEncapsulator<PK, PK_LEN, CT_LEN, SS_LEN> + KEMDecapsulator<SK, SK_LEN, CT_LEN, SS_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
        const CT_LEN: usize,
        const SS_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), KEMError>,
        run_full_bitflipping_tests: bool,
    ) {
        // Basic test
        let (pk, sk) = keygen().unwrap();
        let (ss, ct) = KEMAlg::encaps(&pk).unwrap();
        let ss1 = KEMAlg::decaps(&sk, &ct).unwrap();
        assert_eq!(ss, ss1);

        // Test that encaps_rng is deterministic in its RNG input: two encapsulations against the
        // same public key, each fed an RNG that emits identical bytes, must produce the same
        // shared secret and ciphertext.
        {
            let mut rng_a = FixedSeedRNG::new([0x5A; 64]);
            let mut rng_b = FixedSeedRNG::new([0x5A; 64]);
            let (ss_a, ct_a) = KEMAlg::encaps_rng(&pk, &mut rng_a).unwrap();
            let (ss_b, ct_b) = KEMAlg::encaps_rng(&pk, &mut rng_b).unwrap();
            assert_eq!(
                ss_a, ss_b,
                "encaps_rng shared secret must be deterministic given fixed RNG output"
            );
            assert_eq!(
                ct_a, ct_b,
                "encaps_rng ciphertext must be deterministic given fixed RNG output"
            );
        }

        // Test non-determinism
        if !self.alg_is_deterministic {
            let (ss1, ct1) = KEMAlg::encaps(&pk).unwrap();
            let (ss2, ct2) = KEMAlg::encaps(&pk).unwrap();
            assert_ne!(ss1, ss2);
            assert_ne!(ct1, ct2);
        }

        // Test that decaps fails for broken ct value
        let (pk, sk) = keygen().unwrap();
        let (ss, mut ct) = KEMAlg::encaps(&pk).unwrap();
        ct[17] ^= 0xFF;
        if self.is_implicitly_rejecting {
            let ss2 = KEMAlg::decaps(&sk, &ct).unwrap();
            assert_ne!(ss, ss2);
        } else {
            match KEMAlg::decaps(&sk, &ct) {
                Err(KEMError::DecapsulationFailed) =>
                /* good */
                {
                    ()
                }
                _ => panic!("This should have thrown an error but it didn't."),
            }
        }

        // test flipping every bit ... this will take some time to run
        if run_full_bitflipping_tests {
            for i in 0..ct.len() {
                for j in 0..8 {
                    let mut ct_copy = ct.clone();
                    ct_copy[i] ^= 1 << j;

                    // should throw an Err
                    if self.is_implicitly_rejecting {
                        let ss2 = KEMAlg::decaps(&sk, &ct_copy).unwrap();
                        assert_ne!(ss, ss2);
                    } else {
                        match KEMAlg::decaps(&sk, &ct) {
                            Err(KEMError::DecapsulationFailed) =>
                            /* good */
                            {
                                ()
                            }
                            _ => panic!("This should have thrown an error but it didn't."),
                        }
                    }
                }
            }
        }

        // test ct the wrong length
        let (pk, sk) = keygen().unwrap();
        let (_ss, ct) = KEMAlg::encaps(&pk).unwrap();
        // too short
        match KEMAlg::decaps(&sk, &ct[..CT_LEN - 1]) {
            Err(KEMError::LengthError(_)) => { /* good */ }
            _ => panic!("This should have thrown an error but it didn't."),
        };

        // too long
        let mut long_ct = vec![1u8; CT_LEN + 2];
        long_ct.as_mut_slice()[..CT_LEN].copy_from_slice(&ct);
        match KEMAlg::decaps(&sk, &long_ct) {
            Err(KEMError::LengthError(_)) => { /* good */ }
            _ => panic!("This should have thrown an error but it didn't."),
        };

        // encaps_rng should reject an RNG at a lower security level than the KEM
        let mut no_security_rng = FixedSeedRNG::new([0x00; 64]);
        no_security_rng.set_security_strength(SecurityStrength::None);
        assert_eq!(no_security_rng.security_strength(), SecurityStrength::None);
        match KEMAlg::encaps_rng(&pk, &mut no_security_rng) {
            Err(KEMError::RNGError(_)) => { /* good */ }
            _ => panic!("This should have thrown an error but it didn't."),
        }
    }
}

pub struct TestFrameworkKEMKeys {}

impl TestFrameworkKEMKeys {
    pub fn new() -> Self {
        Self {}
    }

    /// Since key generation is not part of either KEM trait, the caller supplies a
    /// `keygen` function pointer (the inherent `keygen` associated function on the algorithm struct).
    pub fn test_keys<
        PK: KEMPublicKey<PK_LEN>,
        SK: KEMPrivateKey<SK_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), KEMError>,
    ) {
        self.test_boundary_conditions::<PK, SK, PK_LEN, SK_LEN>(keygen);
    }

    /// Tests the correct behaviour on buffers too large / too small.
    fn test_boundary_conditions<
        PK: KEMPublicKey<PK_LEN>,
        SK: KEMPrivateKey<SK_LEN>,
        const PK_LEN: usize,
        const SK_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), KEMError>,
    ) {
        let (pk, sk) = keygen().unwrap();

        let pk_bytes = pk.encode();
        assert_eq!(pk_bytes.len(), PK_LEN);
        // too short
        match PK::from_bytes(&pk_bytes[..PK_LEN - 1]) {
            Err(KEMError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::with_capacity(PK_LEN + 1);
        bytes_too_long.append(&mut Vec::from(&pk_bytes[..PK_LEN]));
        bytes_too_long.push(0xFF);
        match PK::from_bytes(&bytes_too_long) {
            Err(KEMError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }

        let sk_bytes = sk.encode();
        assert_eq!(sk_bytes.len(), SK_LEN);
        // too short
        match SK::from_bytes(&sk_bytes[..SK_LEN - 1]) {
            Err(KEMError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::with_capacity(SK_LEN + 1);
        bytes_too_long.append(&mut Vec::from(&sk_bytes[..SK_LEN]));
        bytes_too_long.push(0xFF);
        match SK::from_bytes(&bytes_too_long) {
            Err(KEMError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
    }
}
