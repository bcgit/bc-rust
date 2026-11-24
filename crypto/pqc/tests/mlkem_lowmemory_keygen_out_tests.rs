//! `keygen_out` / `keygen_from_seed_out` of the low-memory module, the all-zero private key they
//! write into, and the refusal of a key that was never filled.

use bouncycastle_core::errors::{KEMError, KeyMaterialError, RNGError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::PrivateKey;
use bouncycastle_core_test_framework::FailingRNG;
use bouncycastle_pqc::mlkem_lowmemory::mlkem::{
    MLKEM512_FULL_SK_LEN, MLKEM768_FULL_SK_LEN, MLKEM1024_FULL_SK_LEN,
};
use bouncycastle_pqc::mlkem_lowmemory::{
    MLKEM512, MLKEM512_CT_LEN, MLKEM512PrivateKey, MLKEM512PrivateKeyExpanded, MLKEM768,
    MLKEM768_CT_LEN, MLKEM768PrivateKey, MLKEM768PrivateKeyExpanded, MLKEM1024, MLKEM1024_CT_LEN,
    MLKEM1024PrivateKey, MLKEM1024PrivateKeyExpanded, MLKEMPrivateKeyTrait, MLKEMTrait,
};

const ZEROIZED: KEMError = KEMError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);

fn seed(first: u8) -> KeyMaterial<64> {
    let bytes: [u8; 64] = core::array::from_fn(|i| first.wrapping_add(i as u8));
    KeyMaterial::<64>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap()
}

/// 128 distinct bytes, so that a second draw differs from the first.
fn rng() -> FixedSeedRNG<[u8; 128]> {
    FixedSeedRNG::new(core::array::from_fn(|i| i as u8))
}

macro_rules! keygen_out_tests {
    ($name:ident, $alg:ident, $sk:ident, $sk_exp:ident, $ct_len:ident, $full_sk_len:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn from_seed_out_matches_from_seed() {
                let (pk, sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut sk_out = $sk::zeroized();
                $alg::keygen_from_seed_out(&seed(1), &mut sk_out).unwrap();
                assert_eq!(sk_out.pk().unwrap(), pk);
                assert!(sk_out == sk);
                assert_eq!(sk_out.encode(), sk.encode());
                assert!(sk_out.seed() == seed(1));
                $alg::keypair_consistency_check(&pk, &sk_out).unwrap();
            }

            #[test]
            fn keygen_out_matches_keygen_and_decapsulates() {
                let (pk, sk) = $alg::keygen(&mut rng()).unwrap();
                let mut sk_out = $sk::zeroized();
                $alg::keygen_out(&mut rng(), &mut sk_out).unwrap();
                assert_eq!(sk_out.pk().unwrap(), pk);
                assert_eq!(sk_out.encode(), sk.encode());

                let (ss, ct) = sk_out.pk().unwrap().encaps(&mut rng(), ()).unwrap();
                assert!(sk_out.decaps(&ct, ()).unwrap() == ss);
                assert!(sk.decaps(&ct, ()).unwrap() == ss);
            }

            /// A key that already holds one key holds exactly the new one afterwards.
            #[test]
            fn refilling_replaces_every_field() {
                let (pk2, sk2) = $alg::keygen_from_seed(&seed(2)).unwrap();
                let (_pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                $alg::keygen_from_seed_out(&seed(2), &mut sk).unwrap();
                assert_eq!(sk.pk().unwrap(), pk2);
                assert!(sk == sk2);
                assert_eq!(sk.pk_hash(), sk2.pk_hash());
            }

            #[test]
            fn an_error_leaves_the_key_zeroized() {
                // A seed of the wrong type.
                let (_pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let bad =
                    KeyMaterial::<64>::from_bytes_as_type(&[7u8; 64], KeyType::MACKey).unwrap();
                assert!(matches!(
                    $alg::keygen_from_seed_out(&bad, &mut sk),
                    Err(KEMError::KeyGenError(_))
                ));
                assert_eq!(sk.encode(), [0u8; 64]);
                assert_eq!(sk.pk().err(), Some(ZEROIZED));
                assert_eq!(sk.decaps(&[0u8; $ct_len], ()).err(), Some(ZEROIZED));

                // An RNG weaker than the parameter set.
                let (_pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut weak = rng();
                weak.set_security_strength(SecurityStrength::_112bit);
                assert_eq!(
                    $alg::keygen_out(&mut weak, &mut sk).err(),
                    Some(KEMError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
                );
                assert_eq!(sk.pk().err(), Some(ZEROIZED));

                // The draw itself failing.
                let (_pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                assert!(matches!(
                    $alg::keygen_out(&mut FailingRNG, &mut sk),
                    Err(KEMError::RNGError(_))
                ));
                assert_eq!(sk.pk().err(), Some(ZEROIZED));
            }

            /// An unfilled key, plain or expanded, has no public key, does not decapsulate, and
            /// encodes as zeros; the consistency check refuses it.
            #[test]
            fn an_unfilled_key_is_refused() {
                let (pk, _sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let sk = $sk::zeroized();
                let exp = $sk_exp::from(&sk);
                assert_eq!(sk.pk().err(), Some(ZEROIZED));
                assert_eq!(exp.pk().err(), Some(ZEROIZED));
                assert_eq!(sk.decaps(&[0u8; $ct_len], ()).err(), Some(ZEROIZED));
                assert_eq!(exp.decaps(&[0u8; $ct_len], ()).err(), Some(ZEROIZED));
                assert_eq!(sk.encode(), [0u8; 64]);
                assert_eq!(sk.seed().ref_to_bytes(), &[] as &[u8]);
                let full: [u8; $full_sk_len] = sk.encode_full_sk();
                assert_eq!(full, [0u8; $full_sk_len]);
                let full: [u8; $full_sk_len] = exp.encode_full_sk();
                assert_eq!(full, [0u8; $full_sk_len]);
                assert_eq!($alg::keypair_consistency_check(&pk, &sk), Err(ZEROIZED));
            }
        }
    };
}

keygen_out_tests!(
    mlkem512,
    MLKEM512,
    MLKEM512PrivateKey,
    MLKEM512PrivateKeyExpanded,
    MLKEM512_CT_LEN,
    MLKEM512_FULL_SK_LEN
);
keygen_out_tests!(
    mlkem768,
    MLKEM768,
    MLKEM768PrivateKey,
    MLKEM768PrivateKeyExpanded,
    MLKEM768_CT_LEN,
    MLKEM768_FULL_SK_LEN
);
keygen_out_tests!(
    mlkem1024,
    MLKEM1024,
    MLKEM1024PrivateKey,
    MLKEM1024PrivateKeyExpanded,
    MLKEM1024_CT_LEN,
    MLKEM1024_FULL_SK_LEN
);
