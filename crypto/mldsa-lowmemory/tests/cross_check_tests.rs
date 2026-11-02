//! Cross-implementation check against `bouncycastle-mldsa`. The two crates carry near-duplicate
//! arithmetic, encodings and parameters with no shared source, so this pins that the same seed
//! gives the same public key and skEncode form in both, that the same mu and rnd give the same
//! signature bytes, and that each crate verifies the other's signatures.

use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey, SignatureVerifier};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_mldsa as full;
use bouncycastle_mldsa_lowmemory as low;
#[allow(unused_imports)]
use full::{MLDSAPublicKeyTrait as _, MLDSATrait as _};
#[allow(unused_imports)]
use low::{MLDSAPrivateKeyTrait as _, MLDSAPublicKeyTrait as _, MLDSATrait as _};

macro_rules! cross_check {
    ($name:ident, $set:ident) => {
        #[test]
        fn $name() {
            let seed =
                KeyMaterial256::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
            let (pk_full, sk_full) = full::$set::keygen_from_seed(&seed).unwrap();
            let (pk_low, sk_low) = low::$set::keygen_from_seed(&seed).unwrap();

            assert_eq!(pk_full.encode().as_slice(), pk_low.encode().as_slice(), "pkEncode");
            assert_eq!(
                SignaturePrivateKey::encode(&sk_full).as_slice(),
                sk_low.encode_full_sk().as_slice(),
                "skEncode"
            );

            let msg = b"the two ML-DSA crates must agree byte for byte";
            let mu_full = full::MuBuilder::compute_mu(&pk_full.compute_tr(), msg, None).unwrap();
            let mu_low = low::MuBuilder::compute_mu(&pk_low.compute_tr(), msg, None).unwrap();
            assert_eq!(mu_full, mu_low, "mu");

            let rnd = [0x5au8; 32];
            let sig_full =
                full::$set::sign_mu_deterministic(&sk_full, None, &mu_full, rnd).unwrap();
            let sig_low = low::$set::sign_mu_deterministic(&sk_low, &mu_low, rnd).unwrap();
            assert_eq!(sig_full.as_slice(), sig_low.as_slice(), "signature bytes");

            full::$set::verify(&pk_full, msg, None, &sig_low).unwrap();
            low::$set::verify(&pk_low, msg, None, &sig_full).unwrap();
        }
    };
}

cross_check!(ml_dsa_44_agrees_with_bouncycastle_mldsa, MLDSA44);
cross_check!(ml_dsa_65_agrees_with_bouncycastle_mldsa, MLDSA65);
cross_check!(ml_dsa_87_agrees_with_bouncycastle_mldsa, MLDSA87);
