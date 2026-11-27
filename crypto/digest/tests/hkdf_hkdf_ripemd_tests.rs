//! HKDF-RIPEMD160 tests. There are no published HKDF-RIPEMD160 vectors: RFC 5869 Appendix A
//! covers SHA-256 and SHA-1, Wycheproof has HKDF files for SHA-1 and SHA-2 only, and
//! bc-test-data has none. The known answers are RFC 5869 Appendix A.1, A.2 and A.3's inputs run
//! through OpenSSL 3.0.13 (`openssl kdf -kdfopt digest:RIPEMD160 ... HKDF`, `mode:EXTRACT_ONLY`
//! for the PRK), which reproduces the RFC's SHA-256 values for the same inputs, and through RFC
//! 5869 Section 2 written out in Python over a pure-Python RIPEMD-160 and HMAC, which share no
//! code with OpenSSL. The two agree on all six values.

use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::hex;
use bouncycastle_core::kdf_params::KdfDescription;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmInfo, HashAlgParams, KDF};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_core_test_framework::kdf::TestFrameworkKDF;
use bouncycastle_digest::hkdf::HkdfDescription;
use bouncycastle_digest::ripemd::RIPEMD160;
use bouncycastle_digest::ripemd::hkdf::HKDF_RIPEMD160;

/// Key material of any length and content, including empty or all-zero, as the RFC 5869
/// inputs need.
fn key(hex_str: &str, key_type: KeyType) -> KeyMaterial<100> {
    let mut k = KeyMaterial::<100>::new();
    do_hazardous_operations(&mut k, |k| {
        k.set_bytes_as_type(&hex::decode(hex_str).unwrap(), key_type)
    })
    .unwrap();
    k
}

#[test]
fn algorithm() {
    assert_eq!(HKDF_RIPEMD160::ALG_NAME, "HKDF-RIPEMD160");
    assert_eq!(HKDF_RIPEMD160::new().alg_name(), "HKDF-RIPEMD160");
    assert_eq!(HkdfDescription::<RIPEMD160>::ALG_NAME, "HKDF-RIPEMD160");
    // The strength is the hash's: none, RIPEMD-160's collision strength being 80 bits.
    assert_eq!(HKDF_RIPEMD160::MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(HKDF_RIPEMD160::new().max_security_strength(), SecurityStrength::None);
    assert_eq!(HkdfDescription::<RIPEMD160>::MAX_SECURITY_STRENGTH, SecurityStrength::None);
    assert_eq!(RIPEMD160::OUTPUT_LEN, 20);
}

/// `(ikm, salt, info, prk, okm)`, from RFC 5869 Appendix A.1, A.2 and A.3's inputs.
const KATS: [(&str, &str, &str, &str, &str); 3] = [
    (
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "000102030405060708090a0b0c",
        "f0f1f2f3f4f5f6f7f8f9",
        "ee783bc4f2019faf334ec85c466822125ec783fd",
        "8e2a6e5c36796c02636a4246873f35edf59684f394da0ec847b3643aa1f0059ce97de9843cf9db968a88",
    ),
    (
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        "9a8de13e63a53ef67af7696e890fb33f84074225",
        "e6c66889907c1a6ec18d7bc8adbe2ec196a02d23a3a0050f3431b2566e32ee835a3cd3f54f478d247a4a57676a73259595d463b81f2792bd78d4a334f31517b78519b57e85607b63851aa2efe51613a457c3",
    ),
    (
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "",
        "",
        "d8369958d78c4decf95c557a6cac61fed954c1e0",
        "8e655255d187ee7f569966330ae6519af9618119fc0ad220b0901f75d39f98617ca4599fae27f4ad3fe8",
    ),
];

#[test]
fn known_answers() {
    for (ikm, salt, info, prk, okm) in KATS {
        let ikm = key(ikm, KeyType::CryptographicRandom);
        let salt = key(salt, KeyType::MACKey);
        let info = hex::decode(info).unwrap();
        let prk = hex::decode(prk).unwrap();
        let okm = hex::decode(okm).unwrap();

        // Extract, then expand.
        let mut prk_key = HKDF_RIPEMD160::extract(&salt, &ikm).unwrap();
        assert_eq!(prk_key.ref_to_bytes(), &prk[..]);
        // A PRK over RIPEMD-160 carries no strength; it is used as a key anyway.
        do_hazardous_operations(&mut prk_key, |p| p.set_key_type(KeyType::MACKey)).unwrap();
        let mut out = KeyMaterial::<100>::new();
        assert_eq!(HKDF_RIPEMD160::expand_out(&prk_key, &info, okm.len(), &mut out), Ok(okm.len()));
        assert_eq!(out.ref_to_bytes(), &okm[..]);

        // Both steps as one derivation.
        let mut out = KeyMaterial::<100>::new();
        let written =
            HKDF_RIPEMD160::extract_and_expand_out(&salt, &ikm, &info, okm.len(), &mut out);
        assert_eq!(written, Ok(okm.len()));
        assert_eq!(out.ref_to_bytes(), &okm[..]);

        // The KDF trait, with the salt in the instance, and through the description's engine.
        let mut out = KeyMaterial::<100>::new();
        let instance = HKDF_RIPEMD160::new_with_salt(&salt).unwrap();
        assert_eq!(instance.derive_key_out(&ikm, &info, okm.len(), &mut out), Ok(okm.len()));
        assert_eq!(out.ref_to_bytes(), &okm[..]);
        let description = HkdfDescription::<RIPEMD160>::with_salt(&salt).unwrap();
        let engine = description.engine().unwrap();
        assert_eq!(engine.derive_key_out(&ikm, &info, okm.len(), &mut out), Ok(okm.len()));
        assert_eq!(out.ref_to_bytes(), &okm[..]);

        // The streaming extract gives the same PRK.
        let mut hkdf = HKDF_RIPEMD160::new();
        hkdf.do_extract_init(&salt).unwrap();
        for chunk in ikm.ref_to_bytes().chunks(5) {
            hkdf.do_extract_update_bytes(chunk).unwrap();
        }
        assert_eq!(hkdf.do_extract_final().unwrap().ref_to_bytes(), &prk[..]);
    }
}

/// The third known answer's absent salt, given as RFC 5869 Section 2.2's "string of HashLen
/// zeros" and through an instance from `new`, is the same derivation.
#[test]
fn the_absent_salt_is_hash_len_zeros() {
    let (ikm, _, _, prk, okm) = KATS[2];
    let ikm = key(ikm, KeyType::CryptographicRandom);
    let zeros = key(&"00".repeat(20), KeyType::MACKey);
    let prk_key = HKDF_RIPEMD160::extract(&zeros, &ikm).unwrap();
    assert_eq!(prk_key.ref_to_bytes(), hex::decode(prk).unwrap());
    let out = HKDF_RIPEMD160::new().derive_key(&ikm, b"", 42).unwrap();
    assert_eq!(out.ref_to_bytes(), hex::decode(okm).unwrap());
    let absent = KeyMaterial0::new();
    let prk_key = HKDF_RIPEMD160::extract(&absent, &ikm).unwrap();
    assert_eq!(prk_key.ref_to_bytes(), hex::decode(prk).unwrap());
}

#[test]
fn as_kdf() {
    // An instance from `new` runs extract-then-expand with the absent salt, which HMAC pads
    // to the same key as 20 zero bytes; the KDF trait's keys are the IKM, so two halves of it
    // through the multi-key form are the same derivation.
    let ikm = key(&hex::encode(&DUMMY_SEED[..64]), KeyType::MACKey);
    let zero_salt = key(&"00".repeat(20), KeyType::MACKey);
    let info = &DUMMY_SEED[64..80];

    let mut expected = KeyMaterial::<64>::new();
    HKDF_RIPEMD160::extract_and_expand_out(&zero_salt, &ikm, info, 64, &mut expected).unwrap();

    let framework = TestFrameworkKDF::new();
    framework.test_kdf_single_key(&HKDF_RIPEMD160::new(), &ikm, info, &expected);
    let ikm_a = key(&hex::encode(&DUMMY_SEED[..32]), KeyType::MACKey);
    let ikm_b = key(&hex::encode(&DUMMY_SEED[32..64]), KeyType::MACKey);
    let keys: [&dyn KeyMaterialTrait; 2] = [&ikm_a, &ikm_b];
    framework.test_kdf_multiple_key(&HKDF_RIPEMD160::new(), &keys, info, &expected);
}

/// RFC 5869 Section 2.3 over a 20-byte hash: L up to 255 * 20 and no further, the PRK at least
/// 20 bytes, and every shorter output a prefix of a longer one.
#[test]
fn lengths() {
    let ikm = key(&hex::encode(&DUMMY_SEED[..32]), KeyType::Seed);
    let absent = KeyMaterial0::new();
    let mut full = KeyMaterial::<5120>::new();
    assert_eq!(
        HKDF_RIPEMD160::extract_and_expand_out(&absent, &ikm, b"i", 5100, &mut full),
        Ok(5100)
    );
    assert!(HKDF_RIPEMD160::extract_and_expand_out(&absent, &ikm, b"i", 5101, &mut full).is_err());
    assert_eq!(full.key_len(), 0);
    HKDF_RIPEMD160::extract_and_expand_out(&absent, &ikm, b"i", 5100, &mut full).unwrap();
    for l in 1..=61 {
        let mut okm = KeyMaterial::<64>::new();
        assert_eq!(HKDF_RIPEMD160::extract_and_expand_out(&absent, &ikm, b"i", l, &mut okm), Ok(l));
        assert_eq!(okm.ref_to_bytes(), &full.ref_to_bytes()[..l], "L = {l}");
    }

    let mut okm = KeyMaterial::<64>::new();
    let prk19 = key(&hex::encode(&DUMMY_SEED[..19]), KeyType::MACKey);
    let prk20 = key(&hex::encode(&DUMMY_SEED[..20]), KeyType::MACKey);
    assert!(HKDF_RIPEMD160::expand_out(&prk19, b"", 20, &mut okm).is_err());
    assert_eq!(HKDF_RIPEMD160::expand_out(&prk20, b"", 20, &mut okm), Ok(20));
}

#[test]
fn struct_size() {
    assert_eq!(size_of::<HKDF_RIPEMD160>(), 344);
}
