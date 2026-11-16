use bouncycastle_core::errors::{KeyAgreementError, KeyMaterialError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_core_test_framework::key_agreement::TestFrameworkKeyAgreementKeys;
use bouncycastle_ed::x25519::{
    POINT_LEN, SCALAR_LEN, X25519PrivateKey, X25519PublicKey, keygen, keygen_from_seed,
    keygen_from_seed_out, keygen_out,
};
use bouncycastle_hex as hex;
use bouncycastle_rng::{DefaultRNG, FixedSeedRNG};

/// RFC 7748 Section 6.1: Alice's private key a and public key X25519(a, 9).
const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

fn seed(hex_str: &str, key_type: KeyType) -> KeyMaterial256 {
    KeyMaterial256::from_bytes_as_type(&hex::decode(hex_str).unwrap(), key_type).unwrap()
}

fn keygen_default() -> Result<(X25519PublicKey, X25519PrivateKey), KeyAgreementError> {
    keygen(&mut DefaultRNG::default())
}

#[test]
fn core_framework_tests() {
    TestFrameworkKeyAgreementKeys::new()
        .test_keys::<X25519PublicKey, X25519PrivateKey, POINT_LEN, SCALAR_LEN>(keygen_default);
}

#[test]
fn keygen_from_seed_takes_a_seed_or_random_material() {
    for key_type in [KeyType::Seed, KeyType::CryptographicRandom] {
        let (pk, sk) = keygen_from_seed(&seed(ALICE_SK, key_type)).unwrap();
        assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
        assert_eq!(sk.pk(), pk);
    }
}

#[test]
fn keygen_from_seed_rejects_bad_seeds() {
    // Wrong key type.
    match keygen_from_seed(&seed(ALICE_SK, KeyType::MACKey)) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        other => panic!("expected InvalidKeyType, got {:?}", other.err()),
    }

    // All zeros: KeyMaterial marks it KeyType::Zeroized, and the refusal says so.
    match keygen_from_seed(&seed(&"00".repeat(32), KeyType::Seed)) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey)) => {}
        other => panic!("expected ActingOnZeroizedKey, got {:?}", other.err()),
    }

    // Undersized.
    let short = seed(&ALICE_SK[..62], KeyType::Seed);
    assert_eq!(short.key_len(), 31);
    match keygen_from_seed(&short) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_))) => {}
        other => panic!("expected InvalidKeyType, got {:?}", other.err()),
    }

    // Security strength below the algorithm's, and exactly at it.
    let mut weak = seed(ALICE_SK, KeyType::Seed);
    weak.set_security_strength(SecurityStrength::_112bit).unwrap();
    match keygen_from_seed(&weak) {
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::SecurityStrength(_))) => {}
        other => panic!("expected SecurityStrength, got {:?}", other.err()),
    }
    let mut just_right = seed(ALICE_SK, KeyType::Seed);
    just_right.set_security_strength(SecurityStrength::_128bit).unwrap();
    keygen_from_seed(&just_right).unwrap();
}

#[test]
fn keygen_uses_the_rng_output_as_the_key() {
    // The RNG output is used as the seed, so this must match keygen_from_seed.
    let seed_bytes: [u8; 32] = hex::decode(ALICE_SK).unwrap().try_into().unwrap();
    let mut rng = FixedSeedRNG::new(seed_bytes);
    let (pk, sk) = keygen(&mut rng).unwrap();
    assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk(), pk);

    // RNG too weak.
    let mut rng = FixedSeedRNG::new(seed_bytes);
    rng.set_security_strength(SecurityStrength::_112bit);
    match keygen(&mut rng) {
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm)) => {}
        other => {
            panic!(
                "expected RNGError::SecurityStrengthInsufficientForAlgorithm, got {:?}",
                other.err()
            )
        }
    }

    // RNG just right.
    let mut rng = FixedSeedRNG::new(seed_bytes);
    rng.set_security_strength(SecurityStrength::_128bit);
    keygen(&mut rng).unwrap();
}

/// The out forms write into a key the caller holds: a stale key is overwritten with what the
/// by-value forms give for the same RNG output or seed, the returned public key is the key's
/// own, and a refused RNG or seed leaves the key all zero.
#[test]
fn the_out_forms_fill_the_callers_key_and_zeroize_it_on_refusal() {
    let seed_bytes: [u8; 32] = hex::decode(ALICE_SK).unwrap().try_into().unwrap();
    let zero = X25519PrivateKey::zeroized();
    assert_eq!(zero.pk().as_bytes(), &[0u8; POINT_LEN]);

    let (_, mut sk) = keygen_default().unwrap();
    let pk = keygen_out(&mut FixedSeedRNG::new(seed_bytes), &mut sk).unwrap();
    assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk(), pk);
    assert!(sk == keygen(&mut FixedSeedRNG::new(seed_bytes)).unwrap().1);

    let mut weak = FixedSeedRNG::new(seed_bytes);
    weak.set_security_strength(SecurityStrength::_112bit);
    assert!(matches!(
        keygen_out(&mut weak, &mut sk),
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));
    assert!(sk == zero);
    assert_eq!(sk.pk(), zero.pk());

    let (_, mut sk) = keygen_default().unwrap();
    let pk = keygen_from_seed_out(&seed(ALICE_SK, KeyType::Seed), &mut sk).unwrap();
    assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    assert_eq!(sk.pk(), pk);
    assert!(sk == keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap().1);

    assert!(matches!(
        keygen_from_seed_out(&seed(ALICE_SK, KeyType::Unknown), &mut sk),
        Err(KeyAgreementError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(sk == zero);
    assert_eq!(sk.pk(), zero.pk());
}

#[test]
fn keygen_gives_fresh_pairs_whose_public_keys_belong_to_them() {
    let (pk1, sk1) = keygen_default().unwrap();
    let (pk2, sk2) = keygen_default().unwrap();
    assert_ne!(pk1, pk2);
    assert_eq!(sk1.pk(), pk1);
    assert_eq!(sk2.pk(), pk2);
    assert_ne!(sk1.pk(), pk2);
    assert_ne!(sk2.pk(), pk1);
}

#[test]
fn private_key_pk() {
    let (_, sk) = keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    assert_eq!(sk.pk().as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());

    let (pk, sk) = keygen_default().unwrap();
    assert_eq!(sk.pk(), pk);
}

#[test]
fn public_key_to_bytes() {
    let (pk, _) = keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    let expected = hex::decode(ALICE_PK).unwrap();

    let as_ref: &[u8] = pk.as_ref();
    assert_eq!(as_ref, expected);
}

fn decode_32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

/// Clamps as `decodeScalar25519` does (RFC 7748 Section 5).
fn clamp(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

#[test]
fn public_key_encoding() {
    let bytes = decode_32(ALICE_PK);
    let pk = X25519PublicKey::from_bytes(&bytes).unwrap();
    assert_eq!(KeyAgreementPublicKey::encode(&pk), bytes);

    let mut out = [0xFF_u8; 32];
    assert_eq!(KeyAgreementPublicKey::encode_out(&pk, &mut out), 32);
    assert_eq!(out, bytes);

    // Decoding round-trips, and accepts any 32 bytes, including bit 255 set (RFC 7748 Section 5).
    let decoded = <X25519PublicKey as KeyAgreementPublicKey<32>>::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, pk);
    let top_bit = [0xFF_u8; 32];
    let decoded = <X25519PublicKey as KeyAgreementPublicKey<32>>::from_bytes(&top_bit).unwrap();
    assert_eq!(KeyAgreementPublicKey::encode(&decoded), top_bit);

    for len in [0, 31, 33] {
        match <X25519PublicKey as KeyAgreementPublicKey<32>>::from_bytes(&vec![1_u8; len]) {
            Err(KeyAgreementError::DecodingError(_)) => { /* good */ }
            _ => panic!("expected DecodingError for {len} bytes"),
        }
    }
}

#[test]
fn private_key_encoding() {
    // The RFC 7748 Section 6.1 key is unclamped, so this exercises the clamping.
    let raw = decode_32(ALICE_SK);
    assert_ne!(raw, clamp(raw));

    let sk = <X25519PrivateKey as KeyAgreementPrivateKey<32>>::from_bytes(&raw).unwrap();
    assert_eq!(KeyAgreementPrivateKey::encode(&sk), clamp(raw));
    assert_eq!(sk.pk().as_bytes(), &decode_32(ALICE_PK));

    let mut out = [0xFF_u8; 32];
    assert_eq!(KeyAgreementPrivateKey::encode_out(&sk, &mut out), 32);
    assert_eq!(out, clamp(raw));

    // A key built from the unclamped seed is the same key, with the same encoding, and it
    // round-trips through its encoding.
    let (_, from_seed) = keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    assert!(from_seed == sk);
    assert_eq!(KeyAgreementPrivateKey::encode(&from_seed), clamp(raw));
    let encoded = KeyAgreementPrivateKey::encode(&from_seed);
    let decoded = <X25519PrivateKey as KeyAgreementPrivateKey<32>>::from_bytes(&encoded).unwrap();
    assert!(decoded == from_seed);

    for len in [0, 31, 33] {
        match <X25519PrivateKey as KeyAgreementPrivateKey<32>>::from_bytes(&vec![1_u8; len]) {
            Err(KeyAgreementError::DecodingError(_)) => { /* good */ }
            _ => panic!("expected DecodingError for {len} bytes"),
        }
    }
}
