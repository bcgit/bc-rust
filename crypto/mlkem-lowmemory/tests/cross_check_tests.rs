//! Cross-implementation check against `bouncycastle-mlkem`. The two crates carry near-duplicate
//! arithmetic, encodings and parameters with no shared source, so this pins that the same seed
//! gives the same encapsulation key and the same FIPS 203 decapsulation key in both, that the
//! same encapsulation randomness gives the same ciphertext and shared secret, and that each
//! crate decapsulates the other's ciphertexts.

use bouncycastle_core::key_material::{KeyMaterial512, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{KEMDecapsulator, KEMPrivateKey, KEMPublicKey};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_mlkem as full;
use bouncycastle_mlkem_lowmemory as low;
#[allow(unused_imports)]
use full::{MLKEMPublicKeyTrait as _, MLKEMTrait as _};
#[allow(unused_imports)]
use low::{MLKEMPrivateKeyTrait as _, MLKEMPublicKeyTrait as _, MLKEMTrait as _};

macro_rules! cross_check {
    ($name:ident, $set:ident) => {
        #[test]
        fn $name() {
            let seed =
                KeyMaterial512::from_bytes_as_type(&DUMMY_SEED[..64], KeyType::Seed).unwrap();
            let (pk_full, sk_full) = full::$set::keygen_from_seed(&seed).unwrap();
            let (pk_low, sk_low) = low::$set::keygen_from_seed(&seed).unwrap();

            assert_eq!(pk_full.encode().as_slice(), pk_low.encode().as_slice(), "ek");
            assert_eq!(
                KEMPrivateKey::encode(&sk_full).as_slice(),
                sk_low.encode_full_sk().as_slice(),
                "dk (Algorithm 16 encoding)"
            );
            assert_eq!(pk_full.compute_hash(), *sk_low.pk_hash(), "H(ek)");

            let m = [0x5au8; 32];
            let (ss_full, ct_full) = {
                use full::hazmat::EncapsWithRandomness;
                full::$set::encaps_with_randomness(&pk_full, None, m)
            };
            let (ss_low, ct_low) = {
                use low::hazmat::EncapsWithRandomness;
                low::$set::encaps_with_randomness(&pk_low, m)
            };
            assert_eq!(ss_full, ss_low, "shared secret");
            assert_eq!(ct_full.as_slice(), ct_low.as_slice(), "ciphertext");

            // each decapsulates the other's ciphertext to the same secret
            let ss = full::$set::decaps(&sk_full, &ct_low).unwrap();
            assert_eq!(ss.ref_to_bytes(), &ss_full);
            let ss = low::$set::decaps(&sk_low, &ct_full).unwrap();
            assert_eq!(ss.ref_to_bytes(), &ss_low);

            // and both implicitly reject a damaged ciphertext to the same value
            let mut bad = ct_full;
            bad[0] ^= 1;
            let rej_full = full::$set::decaps(&sk_full, &bad).unwrap();
            let rej_low = low::$set::decaps(&sk_low, &bad).unwrap();
            assert_eq!(rej_full.ref_to_bytes(), rej_low.ref_to_bytes(), "implicit rejection");
            assert_ne!(rej_full.ref_to_bytes(), &ss_full);
        }
    };
}

cross_check!(mlkem512_agrees_with_bouncycastle_mlkem, MLKEM512);
cross_check!(mlkem768_agrees_with_bouncycastle_mlkem, MLKEM768);
cross_check!(mlkem1024_agrees_with_bouncycastle_mlkem, MLKEM1024);
