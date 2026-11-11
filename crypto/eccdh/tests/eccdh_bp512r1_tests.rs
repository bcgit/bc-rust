//! ECC CDH brainpoolP512r1: the core framework suites, key generation and loading, and `Z` as a KDF's
//! input.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::{KeyAgreementError, RNGError};
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::key_material::{KeyMaterial0, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_core_test_framework::key_agreement::{
    TestFrameworkKeyAgreement, TestFrameworkKeyAgreementKeys,
};
use bouncycastle_ec::hazmat::bp512r1_scalar::N_LIMBS;
use bouncycastle_ec::hazmat::bp512r1_sec1::{be_bytes_from_limbs, encode_compressed};
use bouncycastle_eccdh::eccdh_bp512r1::{ECCDHBp512r1, SS_LEN};
use bouncycastle_eccdh::keys_bp512r1::{
    ECCDHBp512r1PrivateKey, ECCDHBp512r1PublicKey, PK_LEN, SK_LEN, keygen,
};
use bouncycastle_eccdh::keys_common::DerivePublicKey;
use bouncycastle_rng::{DefaultRNG, FixedSeedRNG};
use bouncycastle_sha2::hkdf::HKDF_SHA256;

fn keygen_default() -> Result<(ECCDHBp512r1PublicKey, ECCDHBp512r1PrivateKey), KeyAgreementError> {
    keygen(&mut DefaultRNG::default())
}

#[test]
fn core_framework_suites() {
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default, ());
    TestFrameworkKeyAgreementKeys::new()
        .test_keys::<ECCDHBp512r1PublicKey, ECCDHBp512r1PrivateKey, PK_LEN, SK_LEN>(keygen_default);
}

#[test]
fn derive_pk_matches_keygen() {
    let (pk, sk) = keygen_default().unwrap();
    assert_eq!(sk.derive_pk(), pk);
}

#[test]
fn algorithm_metadata() {
    assert_eq!(ECCDHBp512r1::ALG_NAME, "ECC-CDH-brainpoolP512r1");
    assert_eq!(ECCDHBp512r1::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);
    assert_eq!(SS_LEN, 64);
}

/// A compressed encoding decodes to the same key as the uncompressed one; `encode` always emits
/// the uncompressed form.
#[test]
fn compressed_encoding_decodes_to_the_same_key() {
    let (pk, _sk) = keygen_default().unwrap();
    let uncompressed = pk.encode();
    let compressed = {
        let (x, y) = bouncycastle_ec::hazmat::bp512r1_sec1::decode(&uncompressed).unwrap();
        encode_compressed(&x, &y)
    };
    let from_compressed = ECCDHBp512r1PublicKey::from_bytes(&compressed).unwrap();
    assert_eq!(from_compressed, pk);
    assert_eq!(from_compressed.encode(), uncompressed);
}

#[test]
fn private_key_rejects_zero() {
    match ECCDHBp512r1PrivateKey::from_bytes(&[0u8; SK_LEN]) {
        Err(KeyAgreementError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
}

/// SP 800-56A Rev. 3 Section 5.6.2.1.2 puts `d` in `[1, n-1]`: `n` and anything above it is not
/// a key, and `n - 1` is the largest one.
#[test]
fn private_key_rejects_values_at_or_above_the_group_order() {
    let n = be_bytes_from_limbs(&N_LIMBS);
    let mut n_plus_1 = n;
    n_plus_1[SK_LEN - 1] += 1; // N_LIMBS[0] is odd and n - 1 even, so no carry
    for (what, bytes) in [("n", n), ("n + 1", n_plus_1), ("all ones", [0xffu8; SK_LEN])] {
        match ECCDHBp512r1PrivateKey::from_bytes(&bytes) {
            Err(KeyAgreementError::DecodingError(_)) => {}
            other => panic!("d = {what} should have been rejected, got {other:?}"),
        }
    }
    let mut n_minus_1 = n;
    n_minus_1[SK_LEN - 1] -= 1;
    let sk = ECCDHBp512r1PrivateKey::from_bytes(&n_minus_1).expect("d = n - 1 is in range");
    assert_eq!(sk.encode(), n_minus_1);
}

/// A point off the curve is refused when decoded (Section 5.6.2.3.3 step 3), so it never
/// reaches an agreement.
#[test]
fn public_key_off_the_curve_is_refused() {
    let (pk, _sk) = keygen_default().unwrap();
    let mut off_curve = pk.encode();
    off_curve[PK_LEN - 1] ^= 1;
    match ECCDHBp512r1PublicKey::from_bytes(&off_curve) {
        Err(KeyAgreementError::DecodingError(_)) => {}
        other => panic!("expected DecodingError, got {other:?}"),
    }
}

/// Section 5.6.1.2.1 step 4: the RBG must offer the curve's strength; one step below it is
/// refused.
#[test]
fn keygen_refuses_a_weak_rng() {
    let mut weak = FixedSeedRNG::new([0x5Au8; 64]);
    weak.set_security_strength(SecurityStrength::_192bit);
    match keygen(&mut weak) {
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm)) => {}
        other => panic!("expected the RNG to be refused, got {other:?}"),
    }
}

/// Step 4 asks for "s bits or more": an RNG at exactly the curve's strength is accepted.
#[test]
fn keygen_accepts_an_rng_at_exactly_the_curves_strength() {
    let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 128, _>(|i| i as u8));
    rng.set_security_strength(SecurityStrength::_256bit);
    let (pk, sk) = keygen(&mut rng).unwrap();
    assert_eq!(sk.derive_pk(), pk);
}

/// Key generation is a function of the DRBG output alone.
#[test]
fn keygen_is_deterministic_given_a_deterministic_rng() {
    let seed = core::array::from_fn::<u8, 128, _>(|i| i as u8);
    let (pk1, sk1) = keygen(&mut FixedSeedRNG::new(seed)).unwrap();
    let (pk2, sk2) = keygen(&mut FixedSeedRNG::new(seed)).unwrap();
    assert_eq!(pk1, pk2);
    assert_eq!(sk1, sk2);
    let (pk3, _) = keygen(&mut FixedSeedRNG::new([0x42u8; 128])).unwrap();
    assert_ne!(pk1, pk3);
}

/// `Z` is typed for a KDF: HKDF credits it, so the PRK it extracts is full-entropy material.
#[test]
fn z_feeds_hkdf() {
    let (pk_a, _sk_a) = keygen_default().unwrap();
    let (_pk_b, sk_b) = keygen_default().unwrap();
    let z = sk_b.agree(&pk_a, ()).unwrap();
    assert_eq!(z.key_type(), KeyType::SharedSecret);
    let absent = KeyMaterial0::new();
    let prk = HKDF_SHA256::extract(&absent, &z).unwrap();
    assert_eq!(prk.key_type(), KeyType::CryptographicRandom);
    // min(Z at the curve's strength, HKDF-SHA256's cap of 128 bits) is 128 on every curve here
    assert_eq!(prk.security_strength(), SecurityStrength::_128bit);
}

#[test]
fn public_key_display_names_the_type() {
    let (pk, _sk) = keygen_default().unwrap();
    assert!(format!("{pk}").starts_with("ECCDHBp512r1PublicKey"));
}

/// ECC-CDH-brainpoolP512r1-X963KDF-SHA512 on the same keys: the keying data is the X9.63 KDF over the
/// raw Z with the SharedInfo, both sides agree, and the SharedInfo selects the key.
#[test]
fn x963kdf_variant() {
    use bouncycastle_core::key_material::KeyMaterial;
    use bouncycastle_eccdh::eccdh_bp512r1::{ECCDHBp512r1_X963KDF_SHA512, X963KDF_SHA512_SS_LEN};
    use bouncycastle_x963kdf::X963KDF_SHA512;

    let kdf = X963KDF_SHA512::new();
    let params = KdfParams::new(&kdf, b"eccdh x963 tests", KeyLen::<X963KDF_SHA512_SS_LEN>);
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default, params);
    assert_eq!(ECCDHBp512r1_X963KDF_SHA512::ALG_NAME, "ECC-CDH-brainpoolP512r1-X963KDF-SHA512");
    assert_eq!(ECCDHBp512r1_X963KDF_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);

    let (pk_a, sk_a) = keygen_default().unwrap();
    let (pk_b, sk_b) = keygen_default().unwrap();
    let key = sk_a.agree(&pk_b, params).unwrap();
    assert!(key.equals(&sk_b.agree(&pk_a, params).unwrap()));
    assert_eq!(key.key_len(), X963KDF_SHA512_SS_LEN);
    assert_eq!(key.key_type(), KeyType::CryptographicRandom);
    assert_eq!(key.security_strength(), SecurityStrength::_256bit);

    let z = sk_a.agree(&pk_b, ()).unwrap();
    let mut expected = KeyMaterial::<X963KDF_SHA512_SS_LEN>::new();
    X963KDF_SHA512::derive_out(&z, b"eccdh x963 tests", X963KDF_SHA512_SS_LEN, &mut expected)
        .unwrap();
    assert!(key.equals(&expected));

    let other = KdfParams::new(&kdf, b"another context", KeyLen::<X963KDF_SHA512_SS_LEN>);
    assert!(!sk_a.agree(&pk_b, other).unwrap().equals(&key));
    let none = KdfParams::new(&kdf, b"", KeyLen::<X963KDF_SHA512_SS_LEN>);
    assert!(!sk_a.agree(&pk_b, none).unwrap().equals(&key));
}

/// ECC-CDH-brainpoolP512r1-ConcatKDF-SHA512 on the same keys: the keying material is the concatenation
/// KDF over the raw Z with the FixedInfo, both sides agree, and the FixedInfo selects the key.
#[test]
fn concatkdf_variant() {
    use bouncycastle_concatkdf::ConcatKDF_SHA512;
    use bouncycastle_core::key_material::KeyMaterial;
    use bouncycastle_eccdh::eccdh_bp512r1::{
        CONCAT_KDF_SHA512_SS_LEN, ECCDHBp512r1_ConcatKDF_SHA512,
    };

    let kdf = ConcatKDF_SHA512::new();
    let params = KdfParams::new(&kdf, b"eccdh concatkdf tests", KeyLen::<CONCAT_KDF_SHA512_SS_LEN>);
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default, params);
    assert_eq!(ECCDHBp512r1_ConcatKDF_SHA512::ALG_NAME, "ECC-CDH-brainpoolP512r1-ConcatKDF-SHA512");
    assert_eq!(ECCDHBp512r1_ConcatKDF_SHA512::MAX_SECURITY_STRENGTH, SecurityStrength::_256bit);

    let (pk_a, sk_a) = keygen_default().unwrap();
    let (pk_b, sk_b) = keygen_default().unwrap();
    let key = sk_a.agree(&pk_b, params).unwrap();
    assert!(key.equals(&sk_b.agree(&pk_a, params).unwrap()));
    assert_eq!(key.key_len(), CONCAT_KDF_SHA512_SS_LEN);
    assert_eq!(key.key_type(), KeyType::CryptographicRandom);
    assert_eq!(key.security_strength(), SecurityStrength::_256bit);

    let z = sk_a.agree(&pk_b, ()).unwrap();
    let mut expected = KeyMaterial::<CONCAT_KDF_SHA512_SS_LEN>::new();
    ConcatKDF_SHA512::derive_out(
        &z, b"eccdh concatkdf tests", CONCAT_KDF_SHA512_SS_LEN, &mut expected,
    )
    .unwrap();
    assert!(key.equals(&expected));

    let other = KdfParams::new(&kdf, b"another context", KeyLen::<CONCAT_KDF_SHA512_SS_LEN>);
    assert!(!sk_a.agree(&pk_b, other).unwrap().equals(&key));
    let none = KdfParams::new(&kdf, b"", KeyLen::<CONCAT_KDF_SHA512_SS_LEN>);
    assert!(!sk_a.agree(&pk_b, none).unwrap().equals(&key));
}
