//! Generic behaviour tests for the key-agreement role trait of
//! `bouncycastle_core::agreement_key` and the workers it produces.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{
    Algorithm, AlgorithmInfo, KeyAgreement, KeyAgreementPrivateKey, KeyAgreementPublicKey,
};

/// Instance of the test framework.
pub struct TestFrameworkKeyAgreement {}

impl Default for TestFrameworkKeyAgreement {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkKeyAgreement {
    /// A framework instance; it holds no configuration.
    pub fn new() -> Self {
        Self {}
    }

    /// Every member of [`AgreementKey`] and of the workers it produces, for the algorithm the
    /// keys `keygen` returns implement over the parameter type of `params`, which every
    /// construction takes a copy of. Key generation is not part of the trait, so the caller
    /// supplies it, and it must return a fresh pair on each call. The secret's `KeyType` is not
    /// pinned here, since a raw primitive returns `SharedSecret` and a KDF-bearing algorithm its
    /// derived key; an implementor's own tests pin which.
    pub fn test_key_agreement<
        Params: Copy,
        PK,
        SK: AgreementKey<Params, SS_LEN, PublicKey = PK>,
        const SS_LEN: usize,
    >(
        &self,
        keygen: fn() -> Result<(PK, SK), KeyAgreementError>,
        params: Params,
    ) {
        let (pk_a, sk_a) = keygen().unwrap();
        let (pk_b, sk_b) = keygen().unwrap();

        // one-shots agree from both sides
        let z_ab = sk_a.agree(&pk_b, params).unwrap();
        let z_ba = sk_b.agree(&pk_a, params).unwrap();
        assert!(z_ab.equals(&z_ba), "both parties must compute the same shared secret");

        // the secret is typed full-entropy material at the algorithm's strength: the raw
        // primitive's `SharedSecret`, or a KDF-bearing algorithm's derived key
        assert_eq!(z_ab.key_len(), SS_LEN);
        assert_ne!(z_ab.key_type(), KeyType::Unknown);
        assert_eq!(z_ab.security_strength(), SK::Algorithm::MAX_SECURITY_STRENGTH);
        assert!(z_ab.is_full_entropy());

        // the worker path gives the one-shot's value, carries the metadata and is reusable
        let agreement = sk_a.create_agreement(params).unwrap();
        assert_eq!(agreement.alg_name(), SK::Algorithm::ALG_NAME);
        assert_eq!(agreement.max_security_strength(), SK::Algorithm::MAX_SECURITY_STRENGTH);
        assert!(agreement.agree(&pk_b).unwrap().equals(&z_ab));
        assert!(agreement.agree(&pk_b).unwrap().equals(&z_ab));

        // the `_out` forms write the same secret over a prefilled buffer, on the worker and
        // on the key
        let stale =
            || KeyMaterial::<SS_LEN>::from_bytes_as_type(&[0xFF; SS_LEN], KeyType::Seed).unwrap();
        let mut z_out = stale();
        assert_eq!(agreement.agree_out(&pk_b, &mut z_out).unwrap(), SS_LEN);
        assert!(z_out.equals(&z_ab));
        assert_eq!(z_out.key_type(), z_ab.key_type());
        assert_eq!(z_out.security_strength(), z_ab.security_strength());
        let mut z_out = stale();
        assert_eq!(sk_a.agree_out(&pk_b, params, &mut z_out).unwrap(), SS_LEN);
        assert!(z_out.equals(&z_ab));

        // a third party gives a different secret, from the same worker
        let (pk_c, sk_c) = keygen().unwrap();
        let z_ac = agreement.agree(&pk_c).unwrap();
        assert!(!z_ac.equals(&z_ab), "a different peer must give a different secret");
        assert!(sk_c.agree(&pk_a, params).unwrap().equals(&z_ac));

        // the worker is usable as a trait object
        let dyn_agreement: &dyn KeyAgreement<PK, SS_LEN> = &agreement;
        assert!(dyn_agreement.agree(&pk_b).unwrap().equals(&z_ab));
        let mut z_out = KeyMaterial::<SS_LEN>::new();
        assert_eq!(dyn_agreement.agree_out(&pk_b, &mut z_out).unwrap(), SS_LEN);
        assert!(z_out.equals(&z_ab));
    }
}

/// Instance of the test framework.
pub struct TestFrameworkKeyAgreementKeys {}

impl Default for TestFrameworkKeyAgreementKeys {
    fn default() -> Self {
        Self::new()
    }
}

impl TestFrameworkKeyAgreementKeys {
    /// A framework instance; it holds no configuration.
    pub fn new() -> Self {
        Self {}
    }

    /// Tests the correct behaviour of the key encodings on buffers too large / too small.
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

        let pk_bytes = pk.encode();
        assert_eq!(pk_bytes.len(), PK_LEN);
        assert_eq!(PK::from_bytes(&pk_bytes).unwrap(), pk);
        let mut out = [0xFFu8; PK_LEN];
        assert_eq!(pk.encode_out(&mut out), PK_LEN);
        assert_eq!(out, pk_bytes);
        // too short
        match PK::from_bytes(&pk_bytes[..PK_LEN - 1]) {
            Err(KeyAgreementError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::from(&pk_bytes[..]);
        bytes_too_long.push(0xFF);
        match PK::from_bytes(&bytes_too_long) {
            Err(KeyAgreementError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }

        let sk_bytes = sk.encode();
        assert_eq!(sk_bytes.len(), SK_LEN);
        assert!(SK::from_bytes(&sk_bytes).unwrap() == sk, "the private key must round-trip");
        let mut out = [0xFFu8; SK_LEN];
        assert_eq!(sk.encode_out(&mut out), SK_LEN);
        assert_eq!(out, sk_bytes);
        // too short
        match SK::from_bytes(&sk_bytes[..SK_LEN - 1]) {
            Err(KeyAgreementError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
        // too long
        let mut bytes_too_long: Vec<u8> = Vec::from(&sk_bytes[..]);
        bytes_too_long.push(0xFF);
        match SK::from_bytes(&bytes_too_long) {
            Err(KeyAgreementError::DecodingError(_)) => { /* good */ }
            _ => panic!("Should have failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Exercises the framework itself against a mock agreement whose marker takes a parameter,
    //! so that the parameter plumbing of the role trait is known to work before any real
    //! parameterised agreement exists.

    use super::*;
    use bouncycastle_core::agreement_key::KeyAgreementAlgorithm;
    use bouncycastle_core::hazmat::do_hazardous_operations;
    use bouncycastle_core::key_material::KeyMaterial;
    use bouncycastle_core::security_strength::SecurityStrength;
    use core::fmt;
    use core::sync::atomic::{AtomicU64, Ordering};

    /// NOT CRYPTOGRAPHY. Diffie-Hellman in the multiplicative group of the integers modulo the
    /// Mersenne prime 2^61 - 1 with generator 3: `pk = 3^sk`, `Z = pk_peer^sk`, which both
    /// parties compute alike. 61 bits is no security at all; the point is the trait plumbing.
    const P: u128 = (1u128 << 61) - 1;
    const G: u128 = 3;
    const SS_LEN: usize = 32;

    fn pow_mod(mut base: u128, mut exp: u128) -> u128 {
        let mut acc = 1u128;
        base %= P;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc * base % P;
            }
            base = base * base % P;
            exp >>= 1;
        }
        acc
    }

    /// Stands in for a configured KDF: a label mixed into the expansion of `Z` to 32 bytes.
    struct MockContext {
        label: u8,
    }

    struct MockDH;

    impl Algorithm for MockDH {
        const ALG_NAME: &'static str = "MockDH-NOT-CRYPTOGRAPHY";
        const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    }

    impl KeyAgreementAlgorithm for MockDH {}

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct MockPublicKey(u64);
    #[derive(Clone, PartialEq, Eq)]
    struct MockPrivateKey(u64);

    impl fmt::Display for MockPublicKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "MockPublicKey({})", self.0)
        }
    }

    impl KeyAgreementPublicKey<8> for MockPublicKey {
        fn encode(&self) -> [u8; 8] {
            self.0.to_be_bytes()
        }
        fn encode_out(&self, out: &mut [u8; 8]) -> usize {
            out.fill(0);
            *out = self.0.to_be_bytes();
            8
        }
        fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| KeyAgreementError::DecodingError("a public key is 8 bytes"))?;
            let value = u64::from_be_bytes(bytes);
            // the analogue of public-key validation: in the group, and not the identity
            if value as u128 >= P || value <= 1 {
                return Err(KeyAgreementError::DecodingError("not a group element"));
            }
            Ok(Self(value))
        }
    }

    impl KeyAgreementPrivateKey<8> for MockPrivateKey {
        fn encode(&self) -> [u8; 8] {
            self.0.to_be_bytes()
        }
        fn encode_out(&self, out: &mut [u8; 8]) -> usize {
            out.fill(0);
            *out = self.0.to_be_bytes();
            8
        }
        fn from_bytes(bytes: &[u8]) -> Result<Self, KeyAgreementError> {
            let bytes: [u8; 8] = bytes
                .try_into()
                .map_err(|_| KeyAgreementError::DecodingError("a private key is 8 bytes"))?;
            Ok(Self(u64::from_be_bytes(bytes)))
        }
    }

    /// The worker: the own key and the context, borrowed separately.
    struct MockAgreement<'k, 'p> {
        sk: &'k MockPrivateKey,
        ctx: &'p MockContext,
    }

    impl Algorithm for MockAgreement<'_, '_> {
        const ALG_NAME: &'static str = MockDH::ALG_NAME;
        const MAX_SECURITY_STRENGTH: SecurityStrength = MockDH::MAX_SECURITY_STRENGTH;
    }

    impl KeyAgreement<MockPublicKey, SS_LEN> for MockAgreement<'_, '_> {
        fn agree_out(
            &self,
            peer_pk: &MockPublicKey,
            ss: &mut KeyMaterial<SS_LEN>,
        ) -> Result<usize, KeyAgreementError> {
            ss.zeroize();
            let z = pow_mod(peer_pk.0 as u128, self.sk.0 as u128);
            if z == 1 {
                return Err(KeyAgreementError::AgreementFailed);
            }
            // expand the 61-bit z to 32 bytes under the context label (NOT a KDF)
            let mut out = [0u8; SS_LEN];
            let mut acc = z;
            for (i, b) in out.iter_mut().enumerate() {
                acc = acc
                    .wrapping_mul(0x9E3779B97F4A7C15)
                    .wrapping_add(self.ctx.label as u128 + i as u128)
                    % P;
                *b = (acc & 0xFF) as u8;
            }
            let mut z = KeyMaterial::<SS_LEN>::from_bytes_as_type(&out, KeyType::SharedSecret)?;
            do_hazardous_operations(&mut z, |z| {
                z.set_security_strength(SecurityStrength::_128bit)
            })?;
            *ss = z;
            Ok(SS_LEN)
        }
    }

    impl<'p> AgreementKey<&'p MockContext, SS_LEN> for MockPrivateKey {
        type Algorithm = MockDH;
        type PublicKey = MockPublicKey;
        type Agreement<'k> = MockAgreement<'k, 'p>;

        /// A label of `0` stands for parameters the algorithm rejects.
        fn create_agreement<'k>(
            &'k self,
            params: &'p MockContext,
        ) -> Result<Self::Agreement<'k>, KeyAgreementError> {
            if params.label == 0 {
                return Err(KeyAgreementError::GenericError("label 0 is not a context"));
            }
            Ok(MockAgreement { sk: self, ctx: params })
        }
    }

    /// Fresh keys from a counter: `sk` counts up from 2, so every pair differs.
    static NEXT_SK: AtomicU64 = AtomicU64::new(2);

    fn keygen() -> Result<(MockPublicKey, MockPrivateKey), KeyAgreementError> {
        let sk = NEXT_SK.fetch_add(0x1234_5678_9ABC, Ordering::Relaxed);
        let pk = pow_mod(G, sk as u128) as u64;
        Ok((MockPublicKey(pk), MockPrivateKey(sk)))
    }

    #[test]
    fn framework_runs_over_a_parameterised_agreement() {
        let ctx = MockContext { label: 0x11 };
        TestFrameworkKeyAgreement::new().test_key_agreement(keygen, &ctx);
        TestFrameworkKeyAgreementKeys::new()
            .test_keys::<MockPublicKey, MockPrivateKey, 8, 8>(keygen);
    }

    /// Two parties configured differently derive different secrets from the same keys, which
    /// is the property the shared `Params` type exists to make visible.
    #[test]
    fn different_params_give_different_secrets() {
        let (pk_a, sk_a) = keygen().unwrap();
        let (pk_b, sk_b) = keygen().unwrap();
        let z1 = sk_a.agree(&pk_b, &MockContext { label: 1 }).unwrap();
        assert!(sk_b.agree(&pk_a, &MockContext { label: 1 }).unwrap().equals(&z1));
        assert!(!sk_b.agree(&pk_a, &MockContext { label: 2 }).unwrap().equals(&z1));
    }

    /// The identity element has no secret: the mock's analogue of SP 800-56Ar3 Section 5.7.1.2
    /// step 2, reached only by bypassing the decoder's validation.
    #[test]
    fn identity_peer_fails() {
        let (_pk, sk) = keygen().unwrap();
        match sk.agree(&MockPublicKey(1), &MockContext { label: 1 }) {
            Err(KeyAgreementError::AgreementFailed) => {}
            other => panic!("expected AgreementFailed, got {other:?}"),
        }
    }

    /// `agree_out` leaves a prefilled buffer zeroized on every error: on the worker, and through
    /// the role's one-shots whether the worker fails (the identity peer) or `create_agreement`
    /// does (a rejected context), where only the role's own clearing reaches the buffer.
    #[test]
    fn agree_out_leaves_the_buffer_zeroized_on_error() {
        let (pk, sk) = keygen().unwrap();
        let ctx = MockContext { label: 1 };
        let stale =
            || KeyMaterial::<SS_LEN>::from_bytes_as_type(&[0xFF; SS_LEN], KeyType::Seed).unwrap();
        let zeroized =
            |ss: &KeyMaterial<SS_LEN>| ss.key_type() == KeyType::Zeroized && ss.key_len() == 0;

        let agreement = sk.create_agreement(&ctx).unwrap();
        let mut ss = stale();
        assert!(matches!(
            agreement.agree_out(&MockPublicKey(1), &mut ss),
            Err(KeyAgreementError::AgreementFailed)
        ));
        assert!(zeroized(&ss), "the worker's error leaves the buffer zeroized");

        let mut ss = stale();
        assert!(matches!(
            sk.agree_out(&MockPublicKey(1), &ctx, &mut ss),
            Err(KeyAgreementError::AgreementFailed)
        ));
        assert!(zeroized(&ss), "the role's one-shot passes the worker's error through");

        let rejected = MockContext { label: 0 };
        assert!(matches!(sk.create_agreement(&rejected), Err(KeyAgreementError::GenericError(_))));
        let mut ss = stale();
        assert!(matches!(
            sk.agree_out(&pk, &rejected, &mut ss),
            Err(KeyAgreementError::GenericError(_))
        ));
        assert!(zeroized(&ss), "a rejected construction leaves the buffer zeroized");
        assert!(matches!(sk.agree(&pk, &rejected), Err(KeyAgreementError::GenericError(_))));
    }
}
