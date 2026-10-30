use bouncycastle_core::errors::{KeyAgreementError, RNGError};
use bouncycastle_core::key_material::{KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_ed::x25519::X25519;
use bouncycastle_hex as hex;

/// RFC 7748 Section 6.1: Alice's private key a and public key X25519(a, 9).
const ALICE_SK: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
const ALICE_PK: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

fn seed(hex_str: &str, key_type: KeyType) -> KeyMaterial256 {
    KeyMaterial256::from_bytes_as_type(&hex::decode(hex_str).unwrap(), key_type).unwrap()
}

#[test]
fn keygen_from_seed() {
    for key_type in [KeyType::Seed, KeyType::CryptographicRandom] {
        let (pk, sk) = X25519::keygen_from_seed(&seed(ALICE_SK, key_type)).unwrap();
        assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
        X25519::keypair_consistency_check(&pk, &sk).unwrap();
    }
}

#[test]
fn keygen_from_seed_rejects_bad_seeds() {
    // Wrong key type.
    match X25519::keygen_from_seed(&seed(ALICE_SK, KeyType::MACKey)) {
        Err(KeyAgreementError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError"),
    }

    // All zeros: KeyMaterial marks it KeyType::Zeroized.
    match X25519::keygen_from_seed(&seed(&"00".repeat(32), KeyType::Seed)) {
        Err(KeyAgreementError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError"),
    }

    // Undersized.
    let short = seed(&ALICE_SK[..62], KeyType::Seed);
    assert_eq!(short.key_len(), 31);
    match X25519::keygen_from_seed(&short) {
        Err(KeyAgreementError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError"),
    }

    // Security strength below the algorithm's, and exactly at it.
    let mut weak = seed(ALICE_SK, KeyType::Seed);
    weak.set_security_strength(SecurityStrength::_112bit).unwrap();
    match X25519::keygen_from_seed(&weak) {
        Err(KeyAgreementError::KeyGenError(_)) => { /* good */ }
        _ => panic!("expected KeyGenError"),
    }
    let mut just_right = seed(ALICE_SK, KeyType::Seed);
    just_right.set_security_strength(SecurityStrength::_128bit).unwrap();
    X25519::keygen_from_seed(&just_right).unwrap();
}

#[test]
fn keygen_from_rng() {
    // The RNG output is used as the seed, so this must match keygen_from_seed.
    let seed_bytes: [u8; 32] = hex::decode(ALICE_SK).unwrap().try_into().unwrap();
    let mut rng = FixedSeedRNG::new(seed_bytes);
    let (pk, sk) = X25519::keygen_from_rng(&mut rng).unwrap();
    assert_eq!(pk.as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());
    X25519::keypair_consistency_check(&pk, &sk).unwrap();

    // RNG too weak.
    let mut rng = FixedSeedRNG::new(seed_bytes);
    rng.set_security_strength(SecurityStrength::_112bit);
    match X25519::keygen_from_rng(&mut rng) {
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm)) => {
            /* good */
        }
        _ => panic!("expected RNGError::SecurityStrengthInsufficientForAlgorithm"),
    }

    // RNG just right.
    let mut rng = FixedSeedRNG::new(seed_bytes);
    rng.set_security_strength(SecurityStrength::_128bit);
    X25519::keygen_from_rng(&mut rng).unwrap();
}

#[test]
fn keygen() {
    let (pk1, sk1) = X25519::keygen().unwrap();
    let (pk2, sk2) = X25519::keygen().unwrap();
    assert_ne!(pk1, pk2);
    X25519::keypair_consistency_check(&pk1, &sk1).unwrap();
    X25519::keypair_consistency_check(&pk2, &sk2).unwrap();
}

#[test]
fn keypair_consistency_check() {
    let (pk1, sk1) = X25519::keygen().unwrap();
    let (pk2, sk2) = X25519::keygen().unwrap();
    X25519::keypair_consistency_check(&pk1, &sk1).unwrap();

    match X25519::keypair_consistency_check(&pk1, &sk2) {
        Err(KeyAgreementError::ConsistencyCheckFailed(_)) => { /* good */ }
        _ => panic!("expected ConsistencyCheckFailed"),
    }
    match X25519::keypair_consistency_check(&pk2, &sk1) {
        Err(KeyAgreementError::ConsistencyCheckFailed(_)) => { /* good */ }
        _ => panic!("expected ConsistencyCheckFailed"),
    }
}

#[test]
fn private_key_pk() {
    let (_, sk) = X25519::keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    assert_eq!(sk.pk().as_bytes().as_slice(), hex::decode(ALICE_PK).unwrap());

    let (pk, sk) = X25519::keygen().unwrap();
    assert_eq!(sk.pk(), pk);
}

#[test]
fn private_key_consistency_check() {
    let (pk1, sk1) = X25519::keygen().unwrap();
    let (pk2, sk2) = X25519::keygen().unwrap();
    sk1.consistency_check(&pk1).unwrap();
    sk2.consistency_check(&pk2).unwrap();

    match sk1.consistency_check(&pk2) {
        Err(KeyAgreementError::ConsistencyCheckFailed(_)) => { /* good */ }
        _ => panic!("expected ConsistencyCheckFailed"),
    }
    match sk2.consistency_check(&pk1) {
        Err(KeyAgreementError::ConsistencyCheckFailed(_)) => { /* good */ }
        _ => panic!("expected ConsistencyCheckFailed"),
    }
}

#[test]
fn public_key_to_bytes() {
    let (pk, _) = X25519::keygen_from_seed(&seed(ALICE_SK, KeyType::Seed)).unwrap();
    let expected = hex::decode(ALICE_PK).unwrap();

    let as_ref: &[u8] = pk.as_ref();
    assert_eq!(as_ref, expected);
}
