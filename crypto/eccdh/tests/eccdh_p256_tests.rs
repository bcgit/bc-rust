//! ECC CDH P-256: the shared behavioural suite in `eccdh_common`, instantiated for the curve.

mod eccdh_common;

use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_ec::P256;

#[test]
fn framework_and_metadata() {
    eccdh_common::framework_and_metadata::<P256, 65, 32, 32>(
        "ECC-CDH-P256",
        SecurityStrength::_128bit,
    );
}

#[test]
fn key_loading() {
    eccdh_common::key_loading::<P256, 65, 32>();
}

#[test]
fn rng_rules() {
    eccdh_common::rng_rules::<P256, 65>(SecurityStrength::_128bit, SecurityStrength::_112bit);
}

/// The pairings' derived key is one output of the matched hash long here; the parameters name any.
#[test]
fn kdf_variants() {
    eccdh_common::kdf_variants::<P256, 65, 32, 32>(SecurityStrength::_128bit);
}

/// ECC-CDH-P256-HKDF-SHA256 on the same keys: the derived key is HKDF-SHA256(salt, Z, info) over
/// the raw Z, both sides agree, the salt and info select the key, and an Unknown salt is refused
/// by HKDF before any parameters exist.
#[test]
fn hkdf_sha256_variant() {
    use bouncycastle_core::agreement_key::AgreementKey;
    use bouncycastle_core::errors::KeyAgreementError;
    use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
    use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
    use bouncycastle_core::traits::Algorithm;
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_core_test_framework::key_agreement::TestFrameworkKeyAgreement;
    use bouncycastle_eccdh::eccdh::ECCDH_HKDF_SHA256;
    use bouncycastle_eccdh::keys::{ECCDHPrivateKey, ECCDHPublicKey, keygen};
    use bouncycastle_hkdf::HkdfDescription;
    use bouncycastle_rng::DefaultRNG;
    use bouncycastle_sha2::SHA256;
    use bouncycastle_sha2::hkdf::HKDF_SHA256;

    const SS_LEN: usize = 32;
    fn keygen_default() -> Result<(ECCDHPublicKey<P256>, ECCDHPrivateKey<P256>), KeyAgreementError>
    {
        keygen::<P256>(&mut DefaultRNG::default())
    }

    let salt =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
            .unwrap();
    let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
    let params = KdfParams::new(&hkdf, b"eccdh hkdf tests", KeyLen::<SS_LEN>);
    TestFrameworkKeyAgreement::new().test_key_agreement(keygen_default, params);
    assert_eq!(ECCDH_HKDF_SHA256::<P256>::ALG_NAME, "ECC-CDH-P256-HKDF-SHA256");
    assert_eq!(ECCDH_HKDF_SHA256::<P256>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);

    let (pk_a, sk_a) = keygen_default().unwrap();
    let (pk_b, sk_b) = keygen_default().unwrap();
    let key = sk_a.agree(&pk_b, params).unwrap();
    assert!(key.equals(&sk_b.agree(&pk_a, params).unwrap()));
    assert_eq!(key.key_len(), SS_LEN);
    assert_eq!(key.key_type(), KeyType::CryptographicRandom);
    assert_eq!(key.security_strength(), SecurityStrength::_128bit);

    let z = sk_a.agree(&pk_b, ()).unwrap();
    let mut expected = KeyMaterial::<SS_LEN>::new();
    HKDF_SHA256::extract_and_expand_out(&salt, &z, b"eccdh hkdf tests", SS_LEN, &mut expected)
        .unwrap();
    assert!(key.equals(&expected));

    let other_info = KdfParams::new(&hkdf, b"another context", KeyLen::<SS_LEN>);
    assert!(!sk_a.agree(&pk_b, other_info).unwrap().equals(&key));
    let absent = KeyMaterial0::new();
    let hkdf_absent = HkdfDescription::<SHA256>::with_salt(&absent).unwrap();
    let no_salt = KdfParams::new(&hkdf_absent, b"eccdh hkdf tests", KeyLen::<SS_LEN>);
    assert!(!sk_a.agree(&pk_b, no_salt).unwrap().equals(&key));

    let unknown =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Unknown).unwrap();
    assert!(HkdfDescription::<SHA256>::with_salt(&unknown).is_err());
}

/// The parameters name the derived key's length: HKDF-SHA256 at 16 bytes (what 16 bytes carry,
/// 128 bits, the curve's strength too) and at its 255-output cap, the X9.63 KDF at 48 bytes,
/// past one hash output so the counter runs; each is what the KDF gives by hand (RFC 5869
/// Section 2.3's OKM is the first L octets of T, SEC 1 v2 Section 3.6.1 step 5 the leftmost
/// keydatalen octets).
#[test]
fn the_parameters_name_the_length() {
    use bouncycastle_core::agreement_key::AgreementKey;
    use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
    use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
    use bouncycastle_core_test_framework::DUMMY_SEED;
    use bouncycastle_eccdh::keys::keygen;
    use bouncycastle_hkdf::HkdfDescription;
    use bouncycastle_rng::DefaultRNG;
    use bouncycastle_sha2::SHA256;
    use bouncycastle_x963kdf::X963KDF_SHA256;

    let salt =
        KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom)
            .unwrap();
    let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
    let (pk_a, sk_a) = keygen::<P256>(&mut DefaultRNG::default()).unwrap();
    let (pk_b, sk_b) = keygen::<P256>(&mut DefaultRNG::default()).unwrap();
    let z = sk_a.agree(&pk_b, ()).unwrap();

    let key = sk_a.agree(&pk_b, KdfParams::new(&hkdf, b"info", KeyLen::<32>)).unwrap();
    let short = sk_b.agree(&pk_a, KdfParams::new(&hkdf, b"info", KeyLen::<16>)).unwrap();
    assert_eq!(short.key_len(), 16);
    assert_eq!(short.ref_to_bytes(), &key.ref_to_bytes()[..16]);
    assert_eq!(short.key_type(), KeyType::CryptographicRandom);
    assert_eq!(short.security_strength(), SecurityStrength::_128bit);
    let long = sk_a.agree(&pk_b, KdfParams::new(&hkdf, b"info", KeyLen::<{ 255 * 32 }>)).unwrap();
    assert_eq!(long.key_len(), 255 * 32);
    assert_eq!(&long.ref_to_bytes()[..32], key.ref_to_bytes());

    let kdf = X963KDF_SHA256::new();
    let key48 = sk_a.agree(&pk_b, KdfParams::new(&kdf, b"info", KeyLen::<48>)).unwrap();
    assert_eq!(key48.key_len(), 48);
    assert_eq!(key48.security_strength(), SecurityStrength::_128bit);
    let mut expected = KeyMaterial::<48>::new();
    X963KDF_SHA256::derive_out(&z, b"info", 48, &mut expected).unwrap();
    assert!(key48.equals(&expected));
}
