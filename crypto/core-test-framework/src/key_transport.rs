//! Generic behaviour tests for the key-transport role traits of
//! `bouncycastle_core::key_transport_key`.

use bouncycastle_core::errors::{KeyMaterialError, KeyTransportError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::key_transport_key::{KeyTransportDecryptingKey, KeyTransportEncryptingKey};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
use bouncycastle_rng::FixedSeedRNG;
use bouncycastle_utils::min;

/// Instance of the test framework.
pub struct TestFrameworkKeyTransport {
    /// Whether two transports of one key give two ciphertexts.
    alg_is_randomized: bool,
}

impl TestFrameworkKeyTransport {
    ///
    pub fn new(alg_is_randomized: bool) -> Self {
        Self { alg_is_randomized }
    }

    /// Every member of [`KeyTransportEncryptingKey`] and [`KeyTransportDecryptingKey`] for the
    /// key pairs given, over the parameter type of `params`, which every call takes a copy of.
    /// `other_sk` is the private key of another pair. A damaged ciphertext is checked at byte
    /// 17, so a ciphertext must be longer than that, and the algorithm must carry a 32-byte
    /// key.
    pub fn test<Params, PK, SK, const CT_LEN: usize>(
        &self,
        pk: &PK,
        sk: &SK,
        other_sk: &SK,
        params: Params,
    ) where
        Params: Copy,
        PK: KeyTransportEncryptingKey<Params, CT_LEN>,
        SK: KeyTransportDecryptingKey<Params, CT_LEN>,
    {
        // Both roles must name the same algorithm.
        assert_eq!(PK::Algorithm::ALG_NAME, SK::Algorithm::ALG_NAME);
        assert_eq!(PK::Algorithm::MAX_SECURITY_STRENGTH, SK::Algorithm::MAX_SECURITY_STRENGTH);

        // A seed that does not repeat within itself, so consecutive draws differ.
        let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 4096, _>(|i| {
            ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8
        }));
        let key_bytes: [u8; 32] = core::array::from_fn(|i| 0xA0 ^ i as u8);
        let key =
            KeyMaterial::<32>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey).unwrap();
        let max = pk.max_key_len(params);
        assert!(max >= 32, "the algorithm must carry a 32-byte key");

        // A round trip, by value and into a stale buffer; the count is the ciphertext's length.
        let ct = pk.transport(&mut rng, params, &key).unwrap();
        let mut ct_out = [0xFFu8; CT_LEN];
        assert_eq!(pk.transport_out(&mut rng, params, &key, &mut ct_out), Ok(CT_LEN));
        if self.alg_is_randomized {
            assert_ne!(ct, ct_out, "two transports of one key must differ");
        } else {
            assert_eq!(ct, ct_out);
        }
        for ct in [&ct, &ct_out] {
            let mut recovered = KeyMaterial::<64>::from_bytes(&[0xEE; 64]).unwrap();
            assert_eq!(sk.recover_out(ct, params, &mut recovered), Ok(32));
            assert_eq!(recovered.ref_to_bytes(), key_bytes);
            // The key comes back as full-entropy material at the lesser of the algorithm's
            // strength and what 32 bytes carry.
            assert_eq!(recovered.key_type(), KeyType::CryptographicRandom);
            let expected =
                *min(&PK::Algorithm::MAX_SECURITY_STRENGTH, &SecurityStrength::from_bytes(32));
            assert_eq!(recovered.security_strength(), expected);
        }
        // Into a buffer of exactly the key's length.
        let mut exact = KeyMaterial::<32>::new();
        assert_eq!(sk.recover_out(&ct, params, &mut exact), Ok(32));
        assert_eq!(exact.ref_to_bytes(), key_bytes);

        // A key longer than the recipient's buffer, a damaged ciphertext and another private
        // key are the one error, with the buffer left zeroized.
        let failures: [(&SK, [u8; CT_LEN]); 2] = [(sk, damaged(&ct)), (other_sk, ct)];
        for (sk, ct) in failures {
            let mut recovered = KeyMaterial::<64>::from_bytes(&[0xEE; 64]).unwrap();
            assert_eq!(
                sk.recover_out(&ct, params, &mut recovered),
                Err(KeyTransportError::DecryptionFailed)
            );
            assert_eq!(recovered.key_type(), KeyType::Zeroized);
        }
        let mut short = KeyMaterial::<31>::from_bytes(&[0xEE; 31]).unwrap();
        assert_eq!(
            sk.recover_out(&ct, params, &mut short),
            Err(KeyTransportError::DecryptionFailed)
        );
        assert_eq!(short.key_type(), KeyType::Zeroized);

        // The longest key goes through; one byte more does not, and neither does a zeroized
        // key, each leaving the ciphertext buffer zeroized.
        let longest =
            KeyMaterial::<4096>::from_bytes_as_type(&vec![0x5A; max], KeyType::Seed).unwrap();
        let ct = pk.transport(&mut rng, params, &longest).unwrap();
        let mut recovered = KeyMaterial::<4096>::new();
        assert_eq!(sk.recover_out(&ct, params, &mut recovered), Ok(max));
        assert_eq!(recovered.ref_to_bytes(), longest.ref_to_bytes());
        let too_long =
            KeyMaterial::<4096>::from_bytes_as_type(&vec![0x5A; max + 1], KeyType::Seed).unwrap();
        let mut ct_out = [0xFFu8; CT_LEN];
        assert_eq!(
            pk.transport_out(&mut rng, params, &too_long, &mut ct_out),
            Err(KeyTransportError::KeyTooLong)
        );
        assert_eq!(ct_out, [0u8; CT_LEN]);
        let mut ct_out = [0xFFu8; CT_LEN];
        assert_eq!(
            pk.transport_out(&mut rng, params, &KeyMaterial::<32>::new(), &mut ct_out),
            Err(KeyTransportError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
        );
        assert_eq!(ct_out, [0u8; CT_LEN]);

        // An RNG below the algorithm's strength is refused.
        if PK::Algorithm::MAX_SECURITY_STRENGTH > SecurityStrength::None {
            let mut weak = FixedSeedRNG::new([0x5A; 64]);
            weak.set_security_strength(SecurityStrength::None);
            let mut ct_out = [0xFFu8; CT_LEN];
            assert!(matches!(
                pk.transport_out(&mut weak, params, &key, &mut ct_out),
                Err(KeyTransportError::RNGError(_))
            ));
            assert_eq!(ct_out, [0u8; CT_LEN]);
        }
    }
}

/// `ct` with one bit of byte 17 flipped.
fn damaged<const CT_LEN: usize>(ct: &[u8; CT_LEN]) -> [u8; CT_LEN] {
    let mut ct = *ct;
    ct[17] ^= 0x04;
    ct
}
