//! The behavioural suite every curve's test file runs: the core framework suites, key
//! generation and loading, and `Z` as a KDF's input, written once over `C: Curve`.

#![allow(dead_code)] // each test file calls the functions it needs

use bouncycastle_concatkdf::ConcatKDF;
use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::{KeyAgreementError, RNGError};
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_core_test_framework::key_agreement::{
    TestFrameworkKeyAgreement, TestFrameworkKeyAgreementKeys,
};
use bouncycastle_ec::curve::Curve;
use bouncycastle_eccdh::eccdh::{ECCDH, ECCDH_ConcatKDF, ECCDH_X963KDF, MatchedHash};
use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey, keygen};
use bouncycastle_eccdh::keys_common::DerivePublicKey;
use bouncycastle_rng::{DefaultRNG, FixedSeedRNG};
use bouncycastle_sha2::hkdf::HKDF_SHA256;
use bouncycastle_x963kdf::X963KDF;

/// The framework suites over the raw role and the key codecs, `derive_pk` against `keygen`, and
/// the algorithm's name and strength.
pub fn framework_and_metadata<C, const PK_LEN: usize, const SK_LEN: usize, const SS_LEN: usize>(
    alg_name: &str,
    strength: SecurityStrength,
) where
    C: Curve<PkUncompressed = [u8; PK_LEN], ScalarBytes = [u8; SK_LEN], FeBytes = [u8; SS_LEN]>,
{
    fn keygen_default<C: Curve>()
    -> Result<(ECCDHPublicKey<C>, ECCDHPrivateKey<C>), KeyAgreementError> {
        keygen::<C>(&mut DefaultRNG::default())
    }
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default::<C>, ());
    TestFrameworkKeyAgreementKeys::new()
        .test_keys::<ECCDHPublicKey<C>, ECCDHPrivateKey<C>, PK_LEN, SK_LEN>(keygen_default::<C>);

    let (pk, sk) = keygen_default::<C>().unwrap();
    assert_eq!(sk.derive_pk(), pk);

    assert_eq!(ECCDH::<C>::ALG_NAME, alg_name);
    assert_eq!(ECCDH::<C>::MAX_SECURITY_STRENGTH, strength);
    assert_eq!(SS_LEN, C::FE_LEN);
    assert_eq!(PK_LEN, C::PK_UNCOMPRESSED_LEN);
    assert_eq!(SK_LEN, C::SCALAR_LEN);
    assert!(format!("{pk}").starts_with(&format!("ECCDHPublicKey<{}>", C::NAME)));
}

/// The codecs' edges: a compressed encoding decodes to the same key as the uncompressed one and
/// `encode` always emits the uncompressed form; a private key is refused at `0`, at `n` and
/// above, and `n - 1` is the largest one (SP 800-56A Rev. 3 Section 5.6.2.1.2); a point off the
/// curve is refused when decoded (Section 5.6.2.3.3 step 3), so it never reaches an agreement.
pub fn key_loading<C, const PK_LEN: usize, const SK_LEN: usize>()
where
    C: Curve<PkUncompressed = [u8; PK_LEN], ScalarBytes = [u8; SK_LEN]>,
{
    let (pk, _sk) = keygen::<C>(&mut DefaultRNG::default()).unwrap();
    let uncompressed = pk.encode();
    let compressed = {
        let (x, y) = C::decode(&uncompressed).unwrap();
        C::encode_compressed(&x, &y)
    };
    let from_compressed = ECCDHPublicKey::<C>::from_bytes(compressed.as_ref()).unwrap();
    assert_eq!(from_compressed, pk);
    assert_eq!(from_compressed.encode(), uncompressed);

    match ECCDHPrivateKey::<C>::from_bytes(&[0u8; SK_LEN]) {
        Err(KeyAgreementError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
    let n = C::be_bytes_from_limbs(&C::N);
    let mut n_plus_1 = n;
    n_plus_1[SK_LEN - 1] += 1; // n is odd and n - 1 even, so no carry
    for (what, bytes) in [("n", n), ("n + 1", n_plus_1), ("all ones", [0xffu8; SK_LEN])] {
        match ECCDHPrivateKey::<C>::from_bytes(&bytes) {
            Err(KeyAgreementError::DecodingError(_)) => {}
            other => panic!("d = {what} should have been rejected, got {other:?}"),
        }
    }
    match ECCDHPrivateKey::<C>::from_bytes(&n[..SK_LEN - 1]) {
        Err(KeyAgreementError::DecodingError(_)) => {}
        other => panic!("a short encoding should have been rejected, got {other:?}"),
    }
    let mut n_minus_1 = n;
    n_minus_1[SK_LEN - 1] -= 1;
    let sk = ECCDHPrivateKey::<C>::from_bytes(&n_minus_1).expect("d = n - 1 is in range");
    assert_eq!(sk.encode(), n_minus_1);
    let mut out = [0u8; SK_LEN];
    assert_eq!(sk.encode_out(&mut out), SK_LEN);
    assert_eq!(out, n_minus_1);

    let mut off_curve = pk.encode();
    off_curve[PK_LEN - 1] ^= 1;
    match ECCDHPublicKey::<C>::from_bytes(&off_curve) {
        Err(KeyAgreementError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
    let mut out = [0u8; PK_LEN];
    assert_eq!(pk.encode_out(&mut out), PK_LEN);
    assert_eq!(out, pk.encode());
}

/// Section 5.6.1.2.1 step 4: the RBG must offer the curve's strength, "s bits or more": one
/// step below is refused, exactly the strength is accepted; and key generation is a function of
/// the DRBG output alone.
pub fn rng_rules<C, const PK_LEN: usize>(strength: SecurityStrength, below: SecurityStrength)
where
    C: Curve<PkUncompressed = [u8; PK_LEN]>,
{
    let mut weak = FixedSeedRNG::new([0x5Au8; 96]);
    weak.set_security_strength(below);
    match keygen::<C>(&mut weak) {
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm)) => {}
        other => panic!("expected the RNG to be refused, got {other:?}"),
    }

    let seed = core::array::from_fn::<u8, 128, _>(|i| i as u8);
    let mut rng = FixedSeedRNG::new(seed);
    rng.set_security_strength(strength);
    let (pk, sk) = keygen::<C>(&mut rng).unwrap();
    assert_eq!(sk.derive_pk(), pk);

    let (pk1, sk1) = keygen::<C>(&mut FixedSeedRNG::new(seed)).unwrap();
    let (pk2, sk2) = keygen::<C>(&mut FixedSeedRNG::new(seed)).unwrap();
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
    let (pk3, _) = keygen::<C>(&mut FixedSeedRNG::new([0x42u8; 128])).unwrap();
    assert_ne!(pk1, pk3);
}

/// `Z` is typed for a KDF (HKDF credits it, so the PRK it extracts is full-entropy material),
/// and the X9.63 and concatenation KDF pairings over the curve's matched hash: the key is the
/// KDF over the raw `Z` with the info, both sides agree, and the info selects the key.
pub fn kdf_variants<C, const PK_LEN: usize, const SS_LEN: usize, const KEY_LEN: usize>(
    strength: SecurityStrength,
) where
    C: MatchedHash + Curve<PkUncompressed = [u8; PK_LEN], FeBytes = [u8; SS_LEN]>,
{
    let (pk_a, sk_a) = keygen::<C>(&mut DefaultRNG::default()).unwrap();
    let (pk_b, sk_b) = keygen::<C>(&mut DefaultRNG::default()).unwrap();
    let z = sk_b.agree(&pk_a, ()).unwrap();
    assert_eq!(z.key_type(), KeyType::SharedSecret);
    assert_eq!(z.security_strength(), strength);
    let absent = KeyMaterial0::new();
    let prk = HKDF_SHA256::extract(&absent, &z).unwrap();
    assert_eq!(prk.key_type(), KeyType::CryptographicRandom);
    // min(Z at the curve's strength, HKDF-SHA256's cap of 128 bits) is 128 on every curve here
    assert_eq!(prk.security_strength(), SecurityStrength::_128bit);

    fn keygen_default<C: Curve>()
    -> Result<(ECCDHPublicKey<C>, ECCDHPrivateKey<C>), KeyAgreementError> {
        keygen::<C>(&mut DefaultRNG::default())
    }

    let kdf = X963KDF::<C::Hash>::new();
    let params = KdfParams::new(&kdf, b"eccdh x963 tests", KeyLen::<KEY_LEN>);
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default::<C>, params);
    assert_eq!(
        ECCDH_X963KDF::<C, C::Hash>::ALG_NAME,
        format!("ECC-CDH-{}-{}", C::NAME, X963KDF::<C::Hash>::ALG_NAME)
    );
    assert_eq!(ECCDH_X963KDF::<C, C::Hash>::MAX_SECURITY_STRENGTH, strength);
    let key = sk_a.agree(&pk_b, params).unwrap();
    assert!(key.equals(&sk_b.agree(&pk_a, params).unwrap()));
    assert_eq!(key.key_len(), KEY_LEN);
    assert_eq!(key.key_type(), KeyType::CryptographicRandom);
    assert_eq!(key.security_strength(), strength);
    let z = sk_a.agree(&pk_b, ()).unwrap();
    let mut expected = KeyMaterial::<KEY_LEN>::new();
    X963KDF::<C::Hash>::derive_out(&z, b"eccdh x963 tests", KEY_LEN, &mut expected).unwrap();
    assert!(key.equals(&expected));
    let other = KdfParams::new(&kdf, b"another context", KeyLen::<KEY_LEN>);
    assert!(!sk_a.agree(&pk_b, other).unwrap().equals(&key));
    let none = KdfParams::new(&kdf, b"", KeyLen::<KEY_LEN>);
    assert!(!sk_a.agree(&pk_b, none).unwrap().equals(&key));

    let kdf = ConcatKDF::<C::Hash>::new();
    let params = KdfParams::new(&kdf, b"eccdh concatkdf tests", KeyLen::<KEY_LEN>);
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default::<C>, params);
    assert_eq!(
        ECCDH_ConcatKDF::<C, C::Hash>::ALG_NAME,
        format!("ECC-CDH-{}-{}", C::NAME, ConcatKDF::<C::Hash>::ALG_NAME)
    );
    assert_eq!(ECCDH_ConcatKDF::<C, C::Hash>::MAX_SECURITY_STRENGTH, strength);
    let key = sk_a.agree(&pk_b, params).unwrap();
    assert!(key.equals(&sk_b.agree(&pk_a, params).unwrap()));
    assert_eq!(key.key_len(), KEY_LEN);
    assert_eq!(key.key_type(), KeyType::CryptographicRandom);
    assert_eq!(key.security_strength(), strength);
    let mut expected = KeyMaterial::<KEY_LEN>::new();
    ConcatKDF::<C::Hash>::derive_out(&z, b"eccdh concatkdf tests", KEY_LEN, &mut expected).unwrap();
    assert!(key.equals(&expected));
    let other = KdfParams::new(&kdf, b"another context", KeyLen::<KEY_LEN>);
    assert!(!sk_a.agree(&pk_b, other).unwrap().equals(&key));
    let none = KdfParams::new(&kdf, b"", KeyLen::<KEY_LEN>);
    assert!(!sk_a.agree(&pk_b, none).unwrap().equals(&key));
}
