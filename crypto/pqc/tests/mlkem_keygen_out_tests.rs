//! `keygen_out` / `keygen_from_seed_out`, the all-zero private key they write into, and the
//! refusal of a key that was never filled.

use bouncycastle_core::errors::{KEMError, KeyMaterialError, RNGError};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KEMDecapsulator, PrivateKey, PublicKey};
use bouncycastle_core_test_framework::FailingRNG;
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_pqc::mlkem::hazmat::EncapsWithRandomness;
use bouncycastle_pqc::mlkem::{
    KdfParams, KeyLen, MLKEM512, MLKEM512_CT_LEN, MLKEM512_HKDF_SHA256_SS_LEN, MLKEM512_PK_LEN,
    MLKEM512PrivateKey, MLKEM512PrivateKeyExpanded, MLKEM768, MLKEM768_CT_LEN,
    MLKEM768_HKDF_SHA512_SS_LEN, MLKEM768_PK_LEN, MLKEM768PrivateKey, MLKEM768PrivateKeyExpanded,
    MLKEM1024, MLKEM1024_CT_LEN, MLKEM1024_PK_LEN, MLKEM1024PrivateKey,
    MLKEM1024PrivateKeyExpanded, MLKEMPrivateKeyTrait, MLKEMTrait,
};
use bouncycastle_sha2::{SHA256, SHA512};

const ZEROIZED: KEMError = KEMError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey);

fn seed(first: u8) -> KeyMaterial<64> {
    let bytes: [u8; 64] = core::array::from_fn(|i| first.wrapping_add(i as u8));
    KeyMaterial::<64>::from_bytes_as_type(&bytes, KeyType::Seed).unwrap()
}

/// 128 distinct bytes, so that a second draw differs from the first.
fn rng() -> FixedSeedRNG<[u8; 128]> {
    FixedSeedRNG::new(core::array::from_fn(|i| i as u8))
}

/// Decodes `bytes` as a key of `like`'s type.
fn decode_like<K: PublicKey<N>, const N: usize>(_like: &K, bytes: &[u8; N]) -> K {
    K::from_bytes(bytes).unwrap()
}

macro_rules! keygen_out_tests {
    ($name:ident, $alg:ident, $sk:ident, $sk_exp:ident, $pk_len:ident, $ct_len:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn from_seed_out_matches_from_seed() {
                let (pk, sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut sk_out = $sk::zeroized();
                $alg::keygen_from_seed_out(&seed(1), &mut sk_out).unwrap();
                assert_eq!(*sk_out.pk(), pk);
                assert!(sk_out == sk);
                assert_eq!(sk_out.pk().encode(), pk.encode());
                assert_eq!(sk_out.encode(), sk.encode());
                assert!(sk_out.seed() == Some(seed(1)));
                $alg::keypair_consistency_check(sk_out.pk(), &sk_out).unwrap();
            }

            #[test]
            fn keygen_out_matches_keygen_and_decapsulates() {
                let (pk, sk) = $alg::keygen(&mut rng()).unwrap();
                let mut sk_out = $sk::zeroized();
                $alg::keygen_out(&mut rng(), &mut sk_out).unwrap();
                assert_eq!(sk_out.pk().encode(), pk.encode());
                assert_eq!(sk_out.encode(), sk.encode());

                let (ss, ct) = sk_out.pk().encaps(&mut rng(), ()).unwrap();
                assert!(sk_out.decaps(&ct, ()).unwrap() == ss);
                assert!(sk.decaps(&ct, ()).unwrap() == ss);
            }

            /// A key that already holds one key pair holds exactly the new one afterwards.
            #[test]
            fn refilling_replaces_every_field() {
                let (pk2, sk2) = $alg::keygen_from_seed(&seed(2)).unwrap();
                let (_pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                $alg::keygen_from_seed_out(&seed(2), &mut sk).unwrap();
                assert_eq!(sk.pk().encode(), pk2.encode());
                assert_eq!(sk.encode(), sk2.encode());
                assert!(sk.seed() == Some(seed(2)));
            }

            #[test]
            fn an_error_leaves_the_key_zeroized() {
                let zero_sk = $sk::zeroized().encode();

                // A seed of the wrong type.
                let (_pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let bad =
                    KeyMaterial::<64>::from_bytes_as_type(&[7u8; 64], KeyType::MACKey).unwrap();
                assert!(matches!(
                    $alg::keygen_from_seed_out(&bad, &mut sk),
                    Err(KEMError::KeyGenError(_))
                ));
                assert_eq!(sk.encode(), zero_sk);
                assert!(sk.seed().is_none());
                assert_eq!(sk.decaps(&[0u8; $ct_len], ()).err(), Some(ZEROIZED));

                // An RNG weaker than the parameter set.
                let (_pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut weak = rng();
                weak.set_security_strength(SecurityStrength::_112bit);
                assert_eq!(
                    $alg::keygen_out(&mut weak, &mut sk).err(),
                    Some(KEMError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
                );
                assert_eq!(sk.encode(), zero_sk);
                assert!(sk.seed().is_none());
            }

            /// The draw itself failing, not the strength check before it.
            #[test]
            fn a_failing_rng_leaves_the_key_zeroized() {
                let (_pk, mut sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                assert!(matches!(
                    $alg::keygen_out(&mut FailingRNG, &mut sk),
                    Err(KEMError::RNGError(_))
                ));
                assert_eq!(sk.encode(), $sk::zeroized().encode());
                assert!(sk.seed().is_none());
            }

            /// A decoded key carries no seed; generating into it gives it the new one.
            #[test]
            fn refilling_a_decoded_key_sets_its_seed() {
                let (_pk1, sk1) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut sk = $sk::from_bytes(&sk1.encode()).unwrap();
                assert!(sk.seed().is_none());
                $alg::keygen_from_seed_out(&seed(2), &mut sk).unwrap();
                let (pk2, sk2) = $alg::keygen_from_seed(&seed(2)).unwrap();
                assert_eq!(sk.pk().encode(), pk2.encode());
                assert_eq!(sk.encode(), sk2.encode());
                assert!(sk.seed() == Some(seed(2)));
            }

            #[test]
            fn the_consistency_check_refuses_an_unfilled_key() {
                let (pk, sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let zero_sk = $sk::zeroized();
                // The unfilled key and the all-zero public key it holds agree, and are refused.
                assert_eq!($alg::keypair_consistency_check(zero_sk.pk(), &zero_sk), Err(ZEROIZED));
                assert_eq!($alg::keypair_consistency_check(&pk, &zero_sk), Err(ZEROIZED));
                assert!(matches!(
                    $alg::keypair_consistency_check(zero_sk.pk(), &sk),
                    Err(KEMError::ConsistencyCheckFailed(_))
                ));
                assert_eq!($alg::keypair_consistency_check(&pk, &sk), Ok(()));
            }

            /// Documented exceptions: `pk()` and the encoders have no error to give. An unfilled
            /// key hands out the all-zero public key, which encapsulates.
            #[test]
            fn what_does_not_refuse_an_unfilled_key() {
                let sk = $sk::zeroized();
                assert_eq!(sk.pk().encode(), [0u8; $pk_len]);
                assert_eq!(sk.encode(), $sk::zeroized().encode());
                let (_ss, ct) = sk.pk().encaps(&mut rng(), ()).unwrap();
                assert_ne!(ct, [0u8; $ct_len]);
                let (_ss, ct): (_, [u8; $ct_len]) = sk.pk().encaps_with_randomness([1u8; 32]);
                assert_ne!(ct, [0u8; $ct_len]);
            }

            /// FIPS 203 Section 7.2 asks of an encapsulation key its type and modulus checks only:
            /// one whose 𝜌 is all zero decodes and is encapsulated to.
            #[test]
            fn a_decoded_public_key_with_a_zero_rho_is_accepted() {
                let (pk, _sk) = $alg::keygen_from_seed(&seed(1)).unwrap();
                let mut pk_bytes = pk.encode();
                pk_bytes[$pk_len - 32..].fill(0);
                let zero_rho = decode_like(&pk, &pk_bytes);
                assert!(zero_rho.encaps(&mut rng(), ()).is_ok());
            }

            #[test]
            fn a_zeroized_private_key_does_not_decapsulate() {
                let sk = $sk::zeroized();
                let exp = $sk_exp::from(&sk);
                let ct = [0u8; $ct_len];

                // The worker is made; it is decapsulation that refuses.
                let filled =
                    || KeyMaterial::<32>::from_bytes_as_type(&[9u8; 32], KeyType::MACKey).unwrap();
                let mut ss = filled();
                let worker = sk.create_decapsulator(()).unwrap();
                assert_eq!(worker.decaps_out(&ct, &mut ss).err(), Some(ZEROIZED));
                assert!(ss == KeyMaterial::<32>::new(), "the secret is cleared on a refusal");
                let mut ss = filled();
                let worker = exp.create_decapsulator(()).unwrap();
                assert_eq!(worker.decaps_out(&ct, &mut ss).err(), Some(ZEROIZED));
                assert!(ss == KeyMaterial::<32>::new());
                assert_eq!(sk.decaps(&ct, ()).err(), Some(ZEROIZED));
                assert_eq!(exp.decaps(&ct, ()).err(), Some(ZEROIZED));
            }
        }
    };
}

keygen_out_tests!(
    mlkem512,
    MLKEM512,
    MLKEM512PrivateKey,
    MLKEM512PrivateKeyExpanded,
    MLKEM512_PK_LEN,
    MLKEM512_CT_LEN
);
keygen_out_tests!(
    mlkem768,
    MLKEM768,
    MLKEM768PrivateKey,
    MLKEM768PrivateKeyExpanded,
    MLKEM768_PK_LEN,
    MLKEM768_CT_LEN
);
keygen_out_tests!(
    mlkem1024,
    MLKEM1024,
    MLKEM1024PrivateKey,
    MLKEM1024PrivateKeyExpanded,
    MLKEM1024_PK_LEN,
    MLKEM1024_CT_LEN
);

/// The KDF pairings refuse an unfilled key as the plain role does, on plain and expanded keys.
macro_rules! kdf_pairing_refuses_a_zeroized_key {
    ($name:ident, $hash:ident, $ss_len:ident, $sk:ident, $sk_exp:ident, $ct_len:ident) => {
        #[test]
        fn $name() {
            let salt =
                KeyMaterial::<32>::from_bytes_as_type(&[0x11u8; 32], KeyType::MACKey).unwrap();
            let hkdf = HkdfDescription::<$hash>::with_salt(&salt).unwrap();
            let params = KdfParams::new(&hkdf, b"info", KeyLen::<$ss_len>);
            let ct = [0u8; $ct_len];

            let sk = $sk::zeroized();
            let sk_exp = $sk_exp::from(&sk);
            assert_eq!(sk.decaps(&ct, params).err(), Some(ZEROIZED));
            assert_eq!(sk_exp.decaps(&ct, params).err(), Some(ZEROIZED));
        }
    };
}

kdf_pairing_refuses_a_zeroized_key!(
    mlkem512_hkdf_sha256_refuses_a_zeroized_key,
    SHA256,
    MLKEM512_HKDF_SHA256_SS_LEN,
    MLKEM512PrivateKey,
    MLKEM512PrivateKeyExpanded,
    MLKEM512_CT_LEN
);
kdf_pairing_refuses_a_zeroized_key!(
    mlkem768_hkdf_sha512_refuses_a_zeroized_key,
    SHA512,
    MLKEM768_HKDF_SHA512_SS_LEN,
    MLKEM768PrivateKey,
    MLKEM768PrivateKeyExpanded,
    MLKEM768_CT_LEN
);
