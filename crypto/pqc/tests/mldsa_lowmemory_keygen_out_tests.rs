//! `keygen_out` / `keygen_from_seed_out` of the low-memory module, the all-zero keys they write
//! into, and the refusal of a key that was never filled.

use bouncycastle_core::errors::{KeyMaterialError, RNGError, SignatureError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicPreHashSigningKey, DeterministicSigningKey,
    OneShotVerifyingKey, PreHashVerifyingKey, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_core_test_framework::FailingRNG;
use bouncycastle_digest::sha2::SHA512;
use bouncycastle_pqc::mldsa_lowmemory::{
    MLDSA44, MLDSA44_SIG_LEN, MLDSA44PrivateKey, MLDSA44PublicKey, MLDSA65, MLDSA65_SIG_LEN,
    MLDSA65PrivateKey, MLDSA65PublicKey, MLDSA87, MLDSA87_SIG_LEN, MLDSA87PrivateKey,
    MLDSA87PublicKey, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MLDSATrait,
};

const ZEROIZED: SignatureError =
    SignatureError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);

fn seed(first: u8) -> KeyMaterial256 {
    let bytes: [u8; 32] = core::array::from_fn(|i| first.wrapping_add(i as u8));
    KeyMaterial256::from_bytes_as_type(&bytes, KeyType::Seed).unwrap()
}

/// 64 distinct bytes, so that a second 32-byte draw differs from the first.
fn rng() -> FixedSeedRNG<[u8; 64]> {
    FixedSeedRNG::new(core::array::from_fn(|i| i as u8))
}

macro_rules! keygen_out_tests {
    ($name:ident, $alg:ident, $pk:ident, $sk:ident, $sig_len:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn from_seed_out_matches_from_seed() {
                let (pk, sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut pk_out = $pk::zeroized();
                let mut sk_out = $sk::zeroized();
                $alg::keygen_from_seed_out(&seed(1), &mut pk_out, &mut sk_out).unwrap();
                assert_eq!(pk_out, pk);
                assert!(sk_out == sk);
                assert_eq!(sk_out.encode(), sk.encode());
                assert_eq!(sk_out.tr(), sk.tr());
                assert!(sk_out.seed() == Some(&seed(1)));
                $alg::keypair_consistency_check(&pk_out, &sk_out).unwrap();
            }

            #[test]
            fn keygen_out_matches_keygen_and_signs() {
                let (pk, sk) = $alg::keygen(&mut rng()).unwrap();
                let mut pk_out = $pk::zeroized();
                let mut sk_out = $sk::zeroized();
                $alg::keygen_out(&mut rng(), &mut pk_out, &mut sk_out).unwrap();
                assert_eq!(pk_out.encode(), pk.encode());
                assert_eq!(sk_out.encode(), sk.encode());

                let sig = sk_out.sign_deterministic(b"msg", None).unwrap();
                pk_out.verify(b"msg", None, &sig).unwrap();
                pk.verify(b"msg", None, &sig).unwrap();
            }

            /// A key that already holds one key pair holds exactly the new one afterwards.
            #[test]
            fn refilling_replaces_every_field() {
                let (pk2, sk2) = $alg::keygen_from_seed(&seed(2)).unwrap();
                let (mut pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                $alg::keygen_from_seed_out(&seed(2), &mut pk, &mut sk).unwrap();
                assert_eq!(pk.encode(), pk2.encode());
                assert!(sk == sk2);
                assert_eq!(sk.tr(), sk2.tr());
            }

            #[test]
            fn an_error_leaves_both_keys_zeroized() {
                // A seed of the wrong type.
                let (mut pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let bad = KeyMaterial256::from_bytes_as_type(&[7u8; 32], KeyType::MACKey).unwrap();
                assert!(matches!(
                    $alg::keygen_from_seed_out(&bad, &mut pk, &mut sk),
                    Err(SignatureError::KeyGenError(_))
                ));
                assert_eq!(pk, $pk::zeroized());
                assert_eq!(sk.encode(), [0u8; 32]);
                assert!(sk.seed().is_none());
                assert_eq!(sk.sign_deterministic(b"msg", None).unwrap_err(), ZEROIZED);

                // An RNG weaker than the parameter set.
                let (mut pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut weak = rng();
                weak.set_security_strength(SecurityStrength::_112bit);
                assert_eq!(
                    $alg::keygen_out(&mut weak, &mut pk, &mut sk).unwrap_err(),
                    SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm)
                );
                assert_eq!(pk, $pk::zeroized());
                assert!(sk.seed().is_none());

                // The draw itself failing.
                let (mut pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                assert!(matches!(
                    $alg::keygen_out(&mut FailingRNG, &mut pk, &mut sk),
                    Err(SignatureError::RNGError(_))
                ));
                assert_eq!(pk, $pk::zeroized());
                assert!(sk.seed().is_none());
            }

            #[test]
            fn the_consistency_check_refuses_unfilled_keys() {
                let (pk, sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let (zero_pk, zero_sk) = ($pk::zeroized(), $sk::zeroized());
                assert_eq!($alg::keypair_consistency_check(&zero_pk, &zero_sk), Err(ZEROIZED));
                assert_eq!($alg::keypair_consistency_check(&zero_pk, &sk), Err(ZEROIZED));
                assert_eq!($alg::keypair_consistency_check(&pk, &zero_sk), Err(ZEROIZED));
                assert_eq!($alg::keypair_consistency_check(&pk, &sk), Ok(()));
            }

            #[test]
            fn a_zeroized_private_key_does_not_sign_or_encode() {
                let sk = $sk::zeroized();
                let mu = [0x5Au8; 64];
                let ph = [0x33u8; 64];
                let mut out = [0xFFu8; $sig_len];

                assert!(sk.seed().is_none());
                assert_eq!(sk.encode(), [0u8; 32]);
                assert_eq!(sk.create_signer(&mut rng(), None).err(), Some(ZEROIZED));
                assert_eq!(sk.create_signer_deterministic(None).err(), Some(ZEROIZED));
                assert_eq!(sk.sign_deterministic(b"msg", None).unwrap_err(), ZEROIZED);
                assert_eq!(sk.sign_mu_deterministic_out(&mu, &mut out).unwrap_err(), ZEROIZED);
                assert_eq!(out, [0u8; $sig_len]);
                assert_eq!(sk.sign_mu(&mu, &mut rng()).unwrap_err(), ZEROIZED);
                assert_eq!(
                    sk.as_prehash::<SHA512>().sign_ph_deterministic(&ph, None).unwrap_err(),
                    ZEROIZED
                );
            }

            #[test]
            fn a_zeroized_public_key_does_not_verify() {
                let pk = $pk::zeroized();
                let sig = [0u8; $sig_len];
                let mu = [0x5Au8; 64];
                let ph = [0x33u8; 64];

                assert_eq!(pk.create_verifier(None).err(), Some(ZEROIZED));
                assert_eq!(pk.verify(b"msg", None, &sig).unwrap_err(), ZEROIZED);
                assert_eq!(pk.verify_mu(&mu, &sig).unwrap_err(), ZEROIZED);
                assert_eq!(
                    pk.as_prehash::<SHA512>().verify_ph(&ph, None, &sig).unwrap_err(),
                    ZEROIZED
                );
            }
        }
    };
}

keygen_out_tests!(mldsa44, MLDSA44, MLDSA44PublicKey, MLDSA44PrivateKey, MLDSA44_SIG_LEN);
keygen_out_tests!(mldsa65, MLDSA65, MLDSA65PublicKey, MLDSA65PrivateKey, MLDSA65_SIG_LEN);
keygen_out_tests!(mldsa87, MLDSA87, MLDSA87PublicKey, MLDSA87PrivateKey, MLDSA87_SIG_LEN);
