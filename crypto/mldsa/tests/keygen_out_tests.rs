//! `keygen_out` / `keygen_from_seed_out`, the all-zero keys they write into, and the refusal of
//! a key that was never filled.

use bouncycastle_core::errors::{KeyMaterialError, RNGError, SignatureError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicPreHashSigningKey, DeterministicSigningKey,
    OneShotVerifyingKey, PreHashSigningKey, PreHashVerifyingKey, SigningKey, VerifyingKey,
};
use bouncycastle_core::traits::{PrivateKey, PublicKey};
use bouncycastle_core_test_framework::FailingRNG;
use bouncycastle_mldsa::{
    MLDSA44, MLDSA44_SIG_LEN, MLDSA44PrivateKey, MLDSA44PrivateKeyExpanded, MLDSA44PublicKey,
    MLDSA44PublicKeyExpanded, MLDSA65, MLDSA65_SIG_LEN, MLDSA65PrivateKey,
    MLDSA65PrivateKeyExpanded, MLDSA65PublicKey, MLDSA65PublicKeyExpanded, MLDSA87,
    MLDSA87_SIG_LEN, MLDSA87PrivateKey, MLDSA87PrivateKeyExpanded, MLDSA87PublicKey,
    MLDSA87PublicKeyExpanded, MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait, MLDSATrait,
};
use bouncycastle_sha2::SHA512;

const ZEROIZED: SignatureError =
    SignatureError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);

fn seed(first: u8) -> KeyMaterial256 {
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = first.wrapping_add(i as u8);
    }
    KeyMaterial256::from_bytes_as_type(&bytes, KeyType::Seed).unwrap()
}

/// 64 distinct bytes, so that a second 32-byte draw differs from the first.
fn rng() -> FixedSeedRNG<[u8; 64]> {
    FixedSeedRNG::new(core::array::from_fn(|i| i as u8))
}

macro_rules! keygen_out_tests {
    ($name:ident, $alg:ident, $pk:ident, $sk:ident, $pk_exp:ident, $sk_exp:ident, $sig_len:ident) => {
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
                assert_eq!(pk_out.encode(), pk.encode());
                assert_eq!(sk_out.encode(), sk.encode());
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
                assert_eq!(sk.encode(), sk2.encode());
                assert!(sk.seed() == Some(&seed(2)));
            }

            #[test]
            fn an_error_leaves_both_keys_zeroized() {
                let zero_pk = $pk::zeroized().encode();
                let zero_sk = $sk::zeroized().encode();

                // A seed of the wrong type.
                let (mut pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let bad = KeyMaterial256::from_bytes_as_type(&[7u8; 32], KeyType::MACKey).unwrap();
                assert!(matches!(
                    $alg::keygen_from_seed_out(&bad, &mut pk, &mut sk),
                    Err(SignatureError::KeyGenError(_))
                ));
                assert_eq!(pk.encode(), zero_pk);
                assert_eq!(sk.encode(), zero_sk);
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
                assert_eq!(pk.encode(), zero_pk);
                assert_eq!(sk.encode(), zero_sk);
                assert!(sk.seed().is_none());
            }

            /// The draw itself failing, not the strength check before it.
            #[test]
            fn a_failing_rng_leaves_both_keys_zeroized() {
                let (mut pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                assert!(matches!(
                    $alg::keygen_out(&mut FailingRNG, &mut pk, &mut sk),
                    Err(SignatureError::RNGError(_))
                ));
                assert_eq!(pk.encode(), $pk::zeroized().encode());
                assert_eq!(sk.encode(), $sk::zeroized().encode());
                assert!(sk.seed().is_none());
            }

            /// A decoded key carries no seed; generating into it gives it the new one.
            #[test]
            fn refilling_a_decoded_key_sets_its_seed() {
                let (pk1, sk1) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut pk = $pk::from_bytes(&pk1.encode()).unwrap();
                let mut sk = $sk::from_bytes(&sk1.encode()).unwrap();
                assert!(sk.seed().is_none());
                $alg::keygen_from_seed_out(&seed(2), &mut pk, &mut sk).unwrap();
                let (pk2, sk2) = $alg::keygen_from_seed(&seed(2)).unwrap();
                assert_eq!(pk.encode(), pk2.encode());
                assert_eq!(sk.encode(), sk2.encode());
                assert!(sk.seed() == Some(&seed(2)));
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

            /// The markers are 𝜌 and `tr`: a decoded key with one all zero is refused as an
            /// unfilled key is, which the docs on `zeroized()` say.
            #[test]
            fn a_decoded_key_with_a_zero_marker_is_refused() {
                let (pk, sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let sig = sk.sign_deterministic(b"msg", None).unwrap();

                let mut pk_bytes = pk.encode();
                pk_bytes[..32].fill(0);
                let zero_rho = $pk::from_bytes(&pk_bytes).unwrap();
                assert_eq!(zero_rho.verify(b"msg", None, &sig).unwrap_err(), ZEROIZED);

                let mut sk_bytes = sk.encode();
                sk_bytes[64..128].fill(0);
                let zero_tr = $sk::from_bytes(&sk_bytes).unwrap();
                assert_eq!(zero_tr.sign_deterministic(b"msg", None).unwrap_err(), ZEROIZED);
            }

            #[test]
            fn a_zeroized_private_key_does_not_sign() {
                let sk = $sk::zeroized();
                let exp = $sk_exp::from(&sk);
                let mu = [0x5Au8; 64];
                let ph = [0x33u8; 64];
                let mut out = [0xFFu8; $sig_len];

                assert_eq!(sk.create_signer(&mut rng(), None).err(), Some(ZEROIZED));
                assert_eq!(sk.create_signer_deterministic(None).err(), Some(ZEROIZED));
                assert_eq!(exp.create_signer(&mut rng(), None).err(), Some(ZEROIZED));
                assert_eq!(exp.create_signer_deterministic(None).err(), Some(ZEROIZED));
                assert_eq!(sk.sign_deterministic(b"msg", None).unwrap_err(), ZEROIZED);
                assert_eq!(exp.sign_deterministic(b"msg", None).unwrap_err(), ZEROIZED);

                assert_eq!(sk.sign_mu_deterministic_out(&mu, &mut out).unwrap_err(), ZEROIZED);
                assert_eq!(out, [0u8; $sig_len]);
                out.fill(0xFF);
                assert_eq!(exp.sign_mu_deterministic_out(&mu, &mut out).unwrap_err(), ZEROIZED);
                assert_eq!(out, [0u8; $sig_len]);
                assert_eq!(sk.sign_mu(&mu, &mut rng()).unwrap_err(), ZEROIZED);
                assert_eq!(exp.sign_mu(&mu, &mut rng()).unwrap_err(), ZEROIZED);

                assert_eq!(sk.create_ph_signer::<SHA512>(&mut rng(), None).err(), Some(ZEROIZED));
                assert_eq!(sk.create_ph_signer_deterministic::<SHA512>(None).err(), Some(ZEROIZED));
                assert_eq!(exp.create_ph_signer::<SHA512>(&mut rng(), None).err(), Some(ZEROIZED));
                assert_eq!(
                    exp.create_ph_signer_deterministic::<SHA512>(None).err(),
                    Some(ZEROIZED)
                );
                assert_eq!(sk.sign_ph::<SHA512>(&mut rng(), &ph, None).unwrap_err(), ZEROIZED);
                out.fill(0xFF);
                assert_eq!(
                    sk.sign_ph_deterministic_out::<SHA512>(&ph, None, &mut out).unwrap_err(),
                    ZEROIZED
                );
                assert_eq!(out, [0u8; $sig_len]);
                assert_eq!(exp.sign_ph_deterministic::<SHA512>(&ph, None).unwrap_err(), ZEROIZED);
            }

            #[test]
            fn a_zeroized_public_key_does_not_verify() {
                let pk = $pk::zeroized();
                let exp = $pk_exp::from(&pk);
                let sig = [0u8; $sig_len];
                let mu = [0x5Au8; 64];
                let ph = [0x33u8; 64];

                assert_eq!(pk.create_verifier(None).err(), Some(ZEROIZED));
                assert_eq!(exp.create_verifier(None).err(), Some(ZEROIZED));
                assert_eq!(pk.verify(b"msg", None, &sig).unwrap_err(), ZEROIZED);
                assert_eq!(exp.verify(b"msg", None, &sig).unwrap_err(), ZEROIZED);
                assert_eq!(pk.verify_mu(&mu, &sig).unwrap_err(), ZEROIZED);
                assert_eq!(exp.verify_mu(&mu, &sig).unwrap_err(), ZEROIZED);
                assert_eq!(pk.create_ph_verifier::<SHA512>(None).err(), Some(ZEROIZED));
                assert_eq!(exp.create_ph_verifier::<SHA512>(None).err(), Some(ZEROIZED));
                assert_eq!(pk.verify_ph::<SHA512>(&ph, None, &sig).unwrap_err(), ZEROIZED);
                assert_eq!(exp.verify_ph::<SHA512>(&ph, None, &sig).unwrap_err(), ZEROIZED);
            }
        }
    };
}

keygen_out_tests!(
    mldsa44,
    MLDSA44,
    MLDSA44PublicKey,
    MLDSA44PrivateKey,
    MLDSA44PublicKeyExpanded,
    MLDSA44PrivateKeyExpanded,
    MLDSA44_SIG_LEN
);
keygen_out_tests!(
    mldsa65,
    MLDSA65,
    MLDSA65PublicKey,
    MLDSA65PrivateKey,
    MLDSA65PublicKeyExpanded,
    MLDSA65PrivateKeyExpanded,
    MLDSA65_SIG_LEN
);
keygen_out_tests!(
    mldsa87,
    MLDSA87,
    MLDSA87PublicKey,
    MLDSA87PrivateKey,
    MLDSA87PublicKeyExpanded,
    MLDSA87PrivateKeyExpanded,
    MLDSA87_SIG_LEN
);
