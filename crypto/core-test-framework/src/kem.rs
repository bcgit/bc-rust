//! Generic behaviour tests for the KEM role traits of `bouncycastle_core::kem_key` and the
//! workers they produce.

use bouncycastle_core::errors::KEMError;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
use bouncycastle_core::traits::{
    AlgorithmInfo, KEMDecapsulator, KEMEncapsulator, KEMPrivateKey, KEMPublicKey, RNG,
};
use bouncycastle_rng::FixedSeedRNG;

/// Instance of the test framework.
pub struct TestFrameworkKEM {
    // Put any config options here
    /// Should the test framework expect that repeated calls to encaps() will produce the same CT?
    alg_is_deterministic: bool,

    /// True if the KEM is based on the implicitly-rejecting FO design and decaps failures will still return a ss,
    /// False if it is explicitly-rejecting and decaps failures will throw an error.
    is_implicitly_rejecting: bool,
}

impl TestFrameworkKEM {
    ///
    pub fn new(alg_is_deterministic: bool, is_implicitly_rejecting: bool) -> Self {
        Self { alg_is_deterministic, is_implicitly_rejecting }
    }

    /// Every member of [`EncapsulatingKey`] and [`DecapsulatingKey`], and of the workers they
    /// produce, for the algorithm the key pair `keygen` returns implements over the parameter
    /// type of `params`, which every construction takes a copy of. The randomness comes from a
    /// [`FixedSeedRNG`] whose consecutive draws differ, so the run is repeatable and two
    /// encapsulations still differ.
    ///
    /// Key generation is not part of the traits, so the caller supplies it. A damaged ciphertext
    /// is checked at byte 17, so a ciphertext must be longer than that.
    /// `run_full_bitflipping_tests` decapsulates the ciphertext with each of its bits flipped in
    /// turn, which takes a while for a large ciphertext.
    pub fn test_kem<
        Params: Copy,
        PK: EncapsulatingKey<Params, CT_LEN, SS_LEN>,
        SK: DecapsulatingKey<Params, CT_LEN, SS_LEN>,
        const CT_LEN: usize,
        const SS_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), KEMError>,
        params: Params,
        run_full_bitflipping_tests: bool,
    ) {
        // Both roles must name the same algorithm.
        assert_eq!(PK::Algorithm::ALG_NAME, SK::Algorithm::ALG_NAME);
        assert_eq!(PK::Algorithm::MAX_SECURITY_STRENGTH, SK::Algorithm::MAX_SECURITY_STRENGTH);

        // The seed cycles, so it is longer than one draw: a 32-byte encapsulation message drawn
        // twice from a 32-byte constant seed would repeat, and the "two encapsulations differ"
        // check below would fail.
        let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 256, _>(|i| i as u8));
        let (pk, sk) = keygen().unwrap();

        // one-shots
        let (ss, ct) = pk.encaps(&mut rng, params).unwrap();
        let ss1 = sk.decaps(&ct, params).unwrap();
        assert_eq!(ss, ss1);

        // the shared secret is typed, full-entropy material at the algorithm's strength
        assert_eq!(ss.key_len(), SS_LEN);
        assert!(ss.is_full_entropy(), "the shared secret must be full-entropy material");
        assert_eq!(ss.security_strength(), PK::Algorithm::MAX_SECURITY_STRENGTH);

        // the workers carry the algorithm's metadata
        let encapsulator = pk.create_encapsulator(params).unwrap();
        let decapsulator = sk.create_decapsulator(params).unwrap();
        assert_eq!(encapsulator.alg_name(), PK::Algorithm::ALG_NAME);
        assert_eq!(encapsulator.max_security_strength(), PK::Algorithm::MAX_SECURITY_STRENGTH);
        assert_eq!(decapsulator.alg_name(), PK::Algorithm::ALG_NAME);
        assert_eq!(decapsulator.max_security_strength(), PK::Algorithm::MAX_SECURITY_STRENGTH);

        // the worker path, the `_out` path and the one-shot agree on the same RNG bytes, and
        // `_out` reports the whole ciphertext written
        {
            let seed = [0x5A; 64];
            let (ss_a, ct_a) = pk.encaps(&mut FixedSeedRNG::new(seed), params).unwrap();
            let (ss_b, ct_b) = encapsulator.encaps(&mut FixedSeedRNG::new(seed)).unwrap();
            // the `_out` buffers are prefilled: whatever was there is gone
            let stale = || {
                KeyMaterial::<SS_LEN>::from_bytes_as_type(&[0xFF; SS_LEN], KeyType::Seed).unwrap()
            };
            let mut ct_c = [0xFFu8; CT_LEN];
            let mut ss_c = stale();
            let written = encapsulator
                .encaps_out(&mut FixedSeedRNG::new(seed), &mut ct_c, &mut ss_c)
                .unwrap();
            let mut ct_d = [0xFFu8; CT_LEN];
            let mut ss_d = stale();
            let written_d =
                pk.encaps_out(&mut FixedSeedRNG::new(seed), params, &mut ct_d, &mut ss_d).unwrap();
            assert_eq!(ss_a, ss_b, "encaps must be deterministic given fixed RNG output");
            assert_eq!(ct_a, ct_b, "encaps must be deterministic given fixed RNG output");
            assert_eq!(ss_a, ss_c);
            assert_eq!(ct_a, ct_c);
            assert_eq!(written, CT_LEN);
            assert_eq!(ss_a, ss_d);
            assert_eq!(ct_a, ct_d);
            assert_eq!(written_d, CT_LEN);

            // the decapsulator is reusable, and its result is the one-shot's; the `_out` forms
            // write the same secret over a prefilled buffer
            assert_eq!(decapsulator.decaps(&ct_a).unwrap(), ss_a);
            assert_eq!(decapsulator.decaps(&ct_a).unwrap(), ss_a);
            assert_eq!(sk.decaps(&ct_a, params).unwrap(), ss_a);
            let mut ss_e = stale();
            assert_eq!(decapsulator.decaps_out(&ct_a, &mut ss_e).unwrap(), SS_LEN);
            assert_eq!(ss_e, ss_a);
            let mut ss_f = stale();
            assert_eq!(sk.decaps_out(&ct_a, params, &mut ss_f).unwrap(), SS_LEN);
            assert_eq!(ss_f, ss_a);
        }

        // the workers are usable as trait objects
        {
            let dyn_enc: &dyn KEMEncapsulator<CT_LEN, SS_LEN> = &encapsulator;
            let dyn_dec: &dyn KEMDecapsulator<CT_LEN, SS_LEN> = &decapsulator;
            let (ss_e, ct_e) = dyn_enc.encaps(&mut rng).unwrap();
            assert_eq!(dyn_dec.decaps(&ct_e).unwrap(), ss_e);
            let mut ss_g = KeyMaterial::<SS_LEN>::new();
            assert_eq!(dyn_dec.decaps_out(&ct_e, &mut ss_g).unwrap(), SS_LEN);
            assert_eq!(ss_g, ss_e);
        }

        // Test non-determinism
        if !self.alg_is_deterministic {
            let (ss1, ct1) = pk.encaps(&mut rng, params).unwrap();
            let (ss2, ct2) = encapsulator.encaps(&mut rng).unwrap();
            assert_ne!(ss1, ss2);
            assert_ne!(ct1, ct2);
        }

        // Test that decaps fails for a damaged ciphertext
        let (pk, sk) = keygen().unwrap();
        let (ss, mut ct) = pk.encaps(&mut rng, params).unwrap();
        const { assert!(CT_LEN > 17, "the suite damages byte 17, so a ciphertext must be longer") };
        ct[17] ^= 0xFF;
        self.check_rejection(&sk, params, &ss, &ct);

        // test flipping every bit ... this will take some time to run
        if run_full_bitflipping_tests {
            for i in 0..ct.len() {
                for j in 0..8 {
                    let mut ct_copy = ct;
                    ct_copy[i] ^= 1 << j;
                    self.check_rejection(&sk, params, &ss, &ct_copy);
                }
            }
        }

        // an RNG at a lower security level than the KEM is refused, by both paths
        let mut no_security_rng = FixedSeedRNG::new([0x00; 64]);
        no_security_rng.set_security_strength(SecurityStrength::None);
        assert_eq!(no_security_rng.security_strength(), SecurityStrength::None);
        match pk.encaps(&mut no_security_rng, params) {
            Err(KEMError::RNGError(_)) => { /* good */ }
            _ => panic!("This should have thrown an error but it didn't."),
        }
        match encapsulator.encaps(&mut no_security_rng) {
            Err(KEMError::RNGError(_)) => { /* good */ }
            _ => panic!("This should have thrown an error but it didn't."),
        }
    }

    /// A damaged ciphertext decapsulates to a different secret (implicit rejection) or to
    /// [`KEMError::DecapsulationFailed`] (explicit rejection).
    fn check_rejection<
        Params: Copy,
        SK: DecapsulatingKey<Params, CT_LEN, SS_LEN>,
        const CT_LEN: usize,
        const SS_LEN: usize,
    >(
        &self,
        sk: &SK,
        params: Params,
        ss: &impl KeyMaterialTrait,
        damaged_ct: &[u8; CT_LEN],
    ) {
        match sk.decaps(damaged_ct, params) {
            Ok(ss2) if self.is_implicitly_rejecting => {
                assert!(!ss.equals(&ss2), "a damaged ciphertext must not give the same secret")
            }
            Err(KEMError::DecapsulationFailed) if !self.is_implicitly_rejecting => { /* good */ }
            other => panic!("unexpected decapsulation result for a damaged ciphertext: {other:?}"),
        }
    }
}

/// Instance of the test framework.
pub struct TestFrameworkKEMKeys {}

impl TestFrameworkKEMKeys {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Since key generation is not part of the KEM traits, the caller supplies a
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

#[cfg(test)]
mod tests {
    //! Exercises the framework itself against a mock KEM whose marker takes a parameter, so that
    //! the parameter plumbing of the role traits, and both rejection branches of the suite, are
    //! known to work before any real parameterised KEM exists.

    use super::*;
    use bouncycastle_core::errors::RNGError;
    use bouncycastle_core::hazmat::do_hazardous_operations;
    use bouncycastle_core::kem_key::KEMAlgorithm;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use core::marker::PhantomData;

    const KEY_LEN: usize = 32;
    const TAG_LEN: usize = 4;
    const CT_LEN: usize = KEY_LEN + TAG_LEN;

    /// NOT CRYPTOGRAPHY. Stands in for a configured KDF: the shared secret is a function of the
    /// primitive's output and this label, so two sides with different labels disagree.
    struct MockKdf {
        label: u8,
    }

    /// NOT CRYPTOGRAPHY. A "KEM" whose ciphertext is `r XOR key || tag(key, r)`, with `r` drawn
    /// from the RNG, and whose shared secret is `kdf(key, r)`. `REJECT_EXPLICITLY` selects
    /// whether a bad tag is an error or a different secret.
    struct MockKEM<const REJECT_EXPLICITLY: bool>;

    impl<const E: bool> Algorithm for MockKEM<E> {
        const ALG_NAME: &'static str = "MockKEM-NOT-CRYPTOGRAPHY";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    }

    impl<const E: bool> KEMAlgorithm for MockKEM<E> {}

    /// The keys carry the rejection mode too: one key type can implement a role only once per
    /// parameter type, and both mocks take `&MockKdf`.
    struct MockPublicKey<const E: bool> {
        key: [u8; KEY_LEN],
    }
    struct MockPrivateKey<const E: bool> {
        key: [u8; KEY_LEN],
    }

    /// Both workers: the key bytes and the KDF, borrowed separately.
    struct MockWorker<'k, 'p, const E: bool> {
        key: &'k [u8; KEY_LEN],
        kdf: &'p MockKdf,
        _alg: PhantomData<MockKEM<E>>,
    }

    impl<const E: bool> Algorithm for MockWorker<'_, '_, E> {
        const ALG_NAME: &'static str = MockKEM::<E>::ALG_NAME;
        const MAX_SECURITY_STRENGTH: SecurityStrength = MockKEM::<E>::MAX_SECURITY_STRENGTH;
    }

    /// 32-bit FNV-1a over `key || r`.
    fn tag(key: &[u8], r: &[u8]) -> [u8; TAG_LEN] {
        let mut hash: u32 = 0x811c9dc5;
        for b in key.iter().chain(r.iter()) {
            hash ^= *b as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        hash.to_be_bytes()
    }

    fn shared_secret(
        key: &[u8; KEY_LEN],
        r: &[u8; KEY_LEN],
        kdf: &MockKdf,
    ) -> KeyMaterial<KEY_LEN> {
        let mut ss = [0u8; KEY_LEN];
        for i in 0..KEY_LEN {
            ss[i] = (key[i] ^ r[i]).wrapping_mul(3).wrapping_add(kdf.label).wrapping_add(i as u8);
        }
        let mut ss = KeyMaterial::from_bytes_as_type(&ss, KeyType::CryptographicRandom).unwrap();
        do_hazardous_operations(&mut ss, |ss| ss.set_security_strength(SecurityStrength::_128bit))
            .unwrap();
        ss
    }

    impl<const E: bool> KEMEncapsulator<CT_LEN, KEY_LEN> for MockWorker<'_, '_, E> {
        fn encaps_out(
            &self,
            rng: &mut dyn RNG,
            ct: &mut [u8; CT_LEN],
            ss: &mut KeyMaterial<KEY_LEN>,
        ) -> Result<usize, KEMError> {
            ct.fill(0);
            ss.zeroize();
            if rng.security_strength() < Self::MAX_SECURITY_STRENGTH {
                return Err(RNGError::SecurityStrengthInsufficientForAlgorithm.into());
            }
            let mut r = [0u8; KEY_LEN];
            rng.next_bytes_out(&mut r)?;
            for i in 0..KEY_LEN {
                ct[i] = r[i] ^ self.key[i];
            }
            ct[KEY_LEN..].copy_from_slice(&tag(self.key, &r));
            *ss = shared_secret(self.key, &r, self.kdf);
            Ok(CT_LEN)
        }
    }

    impl<const E: bool> KEMDecapsulator<CT_LEN, KEY_LEN> for MockWorker<'_, '_, E> {
        fn decaps_out(
            &self,
            ct: &[u8; CT_LEN],
            ss: &mut KeyMaterial<KEY_LEN>,
        ) -> Result<usize, KEMError> {
            ss.zeroize();
            let mut r = [0u8; KEY_LEN];
            for i in 0..KEY_LEN {
                r[i] = ct[i] ^ self.key[i];
            }
            if ct[KEY_LEN..] != tag(self.key, &r) {
                if E {
                    return Err(KEMError::DecapsulationFailed);
                }
                // implicit rejection: a secret that depends on the whole damaged ciphertext
                let mut rejected = [0u8; KEY_LEN];
                for (i, b) in rejected.iter_mut().enumerate() {
                    *b = ct[i] ^ ct[KEY_LEN + (i % TAG_LEN)] ^ 0xA5;
                }
                *ss = shared_secret(self.key, &rejected, self.kdf);
                return Ok(KEY_LEN);
            }
            *ss = shared_secret(self.key, &r, self.kdf);
            Ok(KEY_LEN)
        }
    }

    impl<'p, const E: bool> EncapsulatingKey<&'p MockKdf, CT_LEN, KEY_LEN> for MockPublicKey<E> {
        type Algorithm = MockKEM<E>;
        type Encapsulator<'k> = MockWorker<'k, 'p, E>;

        fn create_encapsulator<'k>(
            &'k self,
            params: &'p MockKdf,
        ) -> Result<Self::Encapsulator<'k>, KEMError> {
            Ok(MockWorker { key: &self.key, kdf: params, _alg: PhantomData })
        }
    }

    impl<'p, const E: bool> DecapsulatingKey<&'p MockKdf, CT_LEN, KEY_LEN> for MockPrivateKey<E> {
        type Algorithm = MockKEM<E>;
        type Decapsulator<'k> = MockWorker<'k, 'p, E>;

        fn create_decapsulator<'k>(
            &'k self,
            params: &'p MockKdf,
        ) -> Result<Self::Decapsulator<'k>, KEMError> {
            Ok(MockWorker { key: &self.key, kdf: params, _alg: PhantomData })
        }
    }

    fn keygen<const E: bool>() -> Result<(MockPublicKey<E>, MockPrivateKey<E>), KEMError> {
        let key = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(0x42));
        Ok((MockPublicKey { key }, MockPrivateKey { key }))
    }

    #[test]
    fn framework_runs_over_a_parameterised_implicitly_rejecting_kem() {
        let kdf = MockKdf { label: 0x11 };
        TestFrameworkKEM::new(false, true).test_kem(keygen::<false>, &kdf, true);
    }

    #[test]
    fn framework_runs_over_a_parameterised_explicitly_rejecting_kem() {
        let kdf = MockKdf { label: 0x22 };
        TestFrameworkKEM::new(false, false).test_kem(keygen::<true>, &kdf, true);
    }

    /// The parameters are the KDF: two sides configured differently derive different secrets
    /// from one ciphertext, which is the property the shared `Params` type exists to make
    /// visible. The parameter type selects the impl, so the calls need no annotation.
    #[test]
    fn different_params_give_different_secrets() {
        let (pk, sk) = keygen::<false>().unwrap();
        let mut rng = FixedSeedRNG::new([0x33u8; 64]);
        let (ss, ct) = pk.encaps(&mut rng, &MockKdf { label: 1 }).unwrap();
        assert_eq!(sk.decaps(&ct, &MockKdf { label: 1 }).unwrap(), ss);
        assert_ne!(sk.decaps(&ct, &MockKdf { label: 2 }).unwrap(), ss);
    }
}
