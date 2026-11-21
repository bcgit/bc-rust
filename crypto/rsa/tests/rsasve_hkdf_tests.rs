//! RSASVE with the secret value derived through HKDF, `RSASVE_HKDF<K, H>`: the core framework
//! suite over the pairing, what the derivation is (HKDF by hand over the raw `Z`), the names and
//! strengths, and the parameters' length and info.

use bouncycastle_core::errors::KEMError;
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial0, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmInfo, KEMDecapsulator};
use bouncycastle_core_test_framework::DUMMY_SEED;
use bouncycastle_core_test_framework::kem::TestFrameworkKEM;
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_rng::DefaultRNG;
use bouncycastle_rsa::rsasve::{RsaKEMPrivateKey, RsaKEMPublicKey};
use bouncycastle_rsa::rsasve_kdf::RSASVE_HKDF;
use bouncycastle_rsa::{RSA2048, RSA3072, RSA4096};
use bouncycastle_sha2::hkdf::HKDF_SHA256;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};

// A genuine RSA-2048 key pair (the crate docs' example key, Wycheproof's
// rsa_pkcs1_2048_sig_gen_test.json first SHA-256 group): key generation is seconds in a debug
// build, so the tests share this one.
const P: [u64; 16] = [
    0x0ea36cfb3a5b18f1, 0x48a6e65332119129, 0x110ad9e7b48a1c93, 0x569156b90113e2e9,
    0xe79813a575cfad9c, 0x69d659d143ec6f17, 0xe81e6bab5ddaa783, 0xbff1c5b80a69f788,
    0x978f6c35814f50ee, 0xe6a289ad4cfbf78f, 0x34d5681e5809d415, 0xbb028bda42eeb5d2,
    0x41c56e4de086b0d5, 0x58b8d1e24f3b55d0, 0xfb5248247d98cb7d, 0xdc431050f782e894,
];
const Q: [u64; 16] = [
    0x669f140cfbc20f25, 0xb97bb03677207d95, 0xfd4e06f3ed7299d4, 0x160f90536abc9492,
    0xf5b131f39098f7bc, 0xae8d72c57088d7ab, 0x89b94fbde542aba9, 0x3d3f9880ec47d5e0,
    0x1378a6868af3b7a0, 0x5544070beb057c94, 0x16611debc472fac4, 0xe500ffb79f5b8868,
    0x308a5e32196603b2, 0xea5fb19eb4eabc38, 0x122273ae3222b598, 0xbd1a81e7977f9898,
];
const D_P: [u64; 16] = [
    0x209f33f09515d7c1, 0xb4a9b37656917205, 0x276933bb07e4efb9, 0x8c14019808e00414,
    0x289f96da220711e5, 0xfbbd2923d31532fe, 0xc06b414e61c0e1e7, 0x4c23c4588488961d,
    0x4dc48ae34514759c, 0x9c786961ae3e2c35, 0x497e8d9c650688e0, 0x18bf08472612dbe5,
    0x8885fb161870ee12, 0xf21d7c1479d99d47, 0x9121d91952ffd1c7, 0xa94b528b28f29159,
];
const D_Q: [u64; 16] = [
    0xf7597ffb68011d8d, 0x7b3cc538c4bab8c9, 0xa8fa480a81a925af, 0x6d6ede7251a383bf,
    0x8a63f788ce3a0f85, 0x0b920502eb478bc9, 0x7e37e755edfe70d9, 0x9cf9948422a16555,
    0x0d6d9ea1f2ef71fd, 0xf7efa32ea0cb6e00, 0x0629b114ca7f780f, 0xcf51176359654348,
    0x540cdcbd4ad35435, 0x31c02ff1a2bc437c, 0xff2503df78bafed5, 0x3af0e72a933aef09,
];
const Q_INV: [u64; 16] = [
    0x552fe4bfce945f7b, 0x67e50c999c67247b, 0xfb54ef17be3b2853, 0x241f5921b5ad3983,
    0x02de5eccd143cf31, 0x74e45f6fcc60f216, 0xafa5428a74f12708, 0x88d42294b6a2759b,
    0xe923e1097c0c562f, 0xc968b48a91c38b5b, 0x933e85179c0320b0, 0x7993d0445f758d51,
    0x9bfc042ee0924b1b, 0x41f956d90fa8a793, 0xee7a87b6483a66ee, 0x2640fbfbcfefb163,
];

const INFO: &[u8] = b"rsasve hkdf tests";

fn key_pair() -> Result<(RsaKEMPublicKey<RSA2048>, RsaKEMPrivateKey<RSA2048>), KEMError> {
    let sk = RsaKEMPrivateKey::<RSA2048>::from_crt_components(&P, &Q, &D_P, &D_Q, &Q_INV)?;
    let pk = RsaKEMPublicKey::<RSA2048>::new(sk.n(), 65537)?;
    Ok((pk, sk))
}

/// A 32-byte salt of the kind a protocol fixes: typed, not secret.
fn salt() -> KeyMaterial<32> {
    KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::CryptographicRandom).unwrap()
}

#[test]
fn core_framework_suite() {
    let salt = salt();
    let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
    let params = KdfParams::new(&hkdf, INFO, KeyLen::<32>);
    TestFrameworkKEM::new(false, true)
        .test_kem::<KdfParams<'_, HkdfDescription<'_, SHA256>, 32>, _, _, 256, 32>(
            key_pair, params, false,
        );
    let no_salt = HkdfDescription::<SHA512>::new();
    let params = KdfParams::new(&no_salt, b"", KeyLen::<64>);
    TestFrameworkKEM::new(false, true)
        .test_kem::<KdfParams<'_, HkdfDescription<'_, SHA512>, 64>, _, _, 256, 64>(
            key_pair, params, false,
        );
}

/// The key is HKDF-Hash(salt, Z, info) over the raw RSASVE secret value, the length the
/// parameters name, labelled at the lesser of the modulus's and the hash's strength.
#[test]
fn the_derivation_is_hkdf_over_z() {
    let (pk, sk) = key_pair().unwrap();
    let salt = salt();
    let hkdf = HkdfDescription::<SHA256>::with_salt(&salt).unwrap();
    let params = KdfParams::new(&hkdf, INFO, KeyLen::<32>);
    let mut rng = DefaultRNG::default();

    let (key, ct) = pk.encaps(&mut rng, params).unwrap();
    assert_eq!(key.key_len(), 32);
    assert_eq!(key.key_type(), KeyType::CryptographicRandom);
    assert_eq!(key.security_strength(), SecurityStrength::_112bit);
    assert_eq!(sk.decaps(&ct, params).unwrap(), key);

    let z = sk.decaps(&ct, ()).unwrap();
    assert_eq!(z.key_len(), 256);
    let mut expected = KeyMaterial::<32>::new();
    HKDF_SHA256::extract_and_expand_out(&salt, &z, INFO, 32, &mut expected).unwrap();
    assert!(key.equals(&expected));

    // Another info is another key; the absent salt is another key; a shorter length is the
    // prefix (RFC 5869 Section 2.3), which is why two keys take two infos.
    let other = KdfParams::new(&hkdf, b"another context", KeyLen::<32>);
    assert!(!sk.decaps(&ct, other).unwrap().equals(&key));
    let absent = KeyMaterial0::new();
    let no_salt = HkdfDescription::<SHA256>::with_salt(&absent).unwrap();
    assert!(!sk.decaps(&ct, KdfParams::new(&no_salt, INFO, KeyLen::<32>)).unwrap().equals(&key));
    let short = sk.decaps(&ct, KdfParams::new(&hkdf, INFO, KeyLen::<16>)).unwrap();
    assert_eq!(short.ref_to_bytes(), &key.ref_to_bytes()[..16]);
    assert_eq!(short.security_strength(), SecurityStrength::_112bit);
    let long = sk.decaps(&ct, KdfParams::new(&hkdf, INFO, KeyLen::<{ 255 * 32 }>)).unwrap();
    assert_eq!(&long.ref_to_bytes()[..32], key.ref_to_bytes());

    // A ciphertext RSASVE refuses is refused here, with the buffer left zeroized.
    let mut ss = KeyMaterial::<32>::from_bytes_as_type(&DUMMY_SEED[..32], KeyType::Seed).unwrap();
    assert!(matches!(
        sk.create_decapsulator(params).unwrap().decaps_out(&[0u8; 256], &mut ss),
        Err(KEMError::DecapsulationFailed)
    ));
    assert_eq!(ss.key_len(), 0);
    assert_eq!(ss.key_type(), KeyType::Zeroized);
}

#[test]
fn names_and_strengths() {
    assert_eq!(RSASVE_HKDF::<RSA2048, SHA256>::ALG_NAME, "RSASVE-2048-HKDF-SHA256");
    assert_eq!(RSASVE_HKDF::<RSA2048, SHA256>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(RSASVE_HKDF::<RSA3072, SHA256>::ALG_NAME, "RSASVE-3072-HKDF-SHA256");
    assert_eq!(RSASVE_HKDF::<RSA3072, SHA256>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(RSASVE_HKDF::<RSA4096, SHA384>::ALG_NAME, "RSASVE-4096-HKDF-SHA384");
    assert_eq!(RSASVE_HKDF::<RSA4096, SHA256>::MAX_SECURITY_STRENGTH, SecurityStrength::_128bit);
    assert_eq!(RSASVE_HKDF::<RSA2048, SHA512>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
    assert_eq!(RSASVE_HKDF::<RSA2048, SHA256>::MAX_LEN, 255 * 32);

    let (pk, sk) = key_pair().unwrap();
    let hkdf = HkdfDescription::<SHA256>::new();
    let params = KdfParams::new(&hkdf, INFO, KeyLen::<32>);
    assert_eq!(pk.create_encapsulator(params).unwrap().alg_name(), "RSASVE-2048-HKDF-SHA256");
    let worker = sk.create_decapsulator(params).unwrap();
    assert_eq!(worker.alg_name(), "RSASVE-2048-HKDF-SHA256");
    assert_eq!(worker.max_security_strength(), SecurityStrength::_112bit);
    let _: &dyn KEMDecapsulator<256, 32> = &worker;
}
