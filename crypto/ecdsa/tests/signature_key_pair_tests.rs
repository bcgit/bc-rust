//! [`SignatureKeyPair`] on the seven [`bouncycastle_ec`] curve markers: each marker's
//! `generate_signature_key_pair::<H>` is that curve's `keygen::<C, H>` (the same pair from the
//! same RNG output, the same strength gate), under the conventional hash and another, and the
//! pair it gives signs and verifies.

use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{SigningKey, VerifyingKey};
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_ecdsa::ecdsa::EcdsaHash;
use bouncycastle_ecdsa::keys::keygen;
use bouncycastle_ecdsa::keys_common::SignatureKeyPair;
use bouncycastle_rng::{DefaultRNG, FixedSeedRNG};
use bouncycastle_sha2::{SHA256, SHA384, SHA512};
use bouncycastle_sha3::SHA3_256;

/// A counting seed longer than any curve's draw, so consecutive bytes differ.
fn seed() -> [u8; 96] {
    core::array::from_fn(|i| i as u8)
}

/// The marker's pair under `H` is `keygen::<C, H>`'s pair for the same RNG output, and the
/// marker applies the same strength gate: an RNG at 112 bits is below every curve here.
fn is_keygen<C: SignatureKeyPair, H: EcdsaHash>() {
    let from_marker = C::generate_signature_key_pair::<H>(&mut FixedSeedRNG::new(seed())).unwrap();
    let from_keygen = keygen::<C, H>(&mut FixedSeedRNG::new(seed())).unwrap();
    assert_eq!(from_marker, from_keygen);

    let mut weak = FixedSeedRNG::new(seed());
    weak.set_security_strength(SecurityStrength::_112bit);
    assert!(matches!(
        C::generate_signature_key_pair::<H>(&mut weak),
        Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));
}

#[test]
fn p256_marker_pair_is_keygen_and_signs() {
    is_keygen::<P256, SHA256>();
    is_keygen::<P256, SHA3_256>();

    let mut rng = DefaultRNG::default();
    let (pk, sk) = P256::generate_signature_key_pair::<SHA256>(&mut rng).unwrap();
    let signature = sk.sign(&mut rng, b"from the curve marker", None).unwrap();
    pk.verify(b"from the curve marker", None, &signature).unwrap();
    assert!(pk.verify(b"another message", None, &signature).is_err());
}

#[test]
fn p384_marker_pair_is_keygen_and_signs() {
    is_keygen::<P384, SHA384>();
    is_keygen::<P384, SHA3_256>();

    let mut rng = DefaultRNG::default();
    let (pk, sk) = P384::generate_signature_key_pair::<SHA384>(&mut rng).unwrap();
    let signature = sk.sign(&mut rng, b"from the curve marker", None).unwrap();
    pk.verify(b"from the curve marker", None, &signature).unwrap();
    assert!(pk.verify(b"another message", None, &signature).is_err());
}

#[test]
fn p521_marker_pair_is_keygen_and_signs() {
    is_keygen::<P521, SHA512>();
    is_keygen::<P521, SHA3_256>();

    let mut rng = DefaultRNG::default();
    let (pk, sk) = P521::generate_signature_key_pair::<SHA512>(&mut rng).unwrap();
    let signature = sk.sign(&mut rng, b"from the curve marker", None).unwrap();
    pk.verify(b"from the curve marker", None, &signature).unwrap();
    assert!(pk.verify(b"another message", None, &signature).is_err());
}

#[test]
fn p256k1_marker_pair_is_keygen_and_signs() {
    is_keygen::<Secp256K1, SHA256>();
    is_keygen::<Secp256K1, SHA3_256>();

    let mut rng = DefaultRNG::default();
    let (pk, sk) = Secp256K1::generate_signature_key_pair::<SHA256>(&mut rng).unwrap();
    let signature = sk.sign(&mut rng, b"from the curve marker", None).unwrap();
    pk.verify(b"from the curve marker", None, &signature).unwrap();
    assert!(pk.verify(b"another message", None, &signature).is_err());
}

#[test]
fn bp256r1_marker_pair_is_keygen_and_signs() {
    is_keygen::<Bp256r1, SHA256>();
    is_keygen::<Bp256r1, SHA3_256>();

    let mut rng = DefaultRNG::default();
    let (pk, sk) = Bp256r1::generate_signature_key_pair::<SHA256>(&mut rng).unwrap();
    let signature = sk.sign(&mut rng, b"from the curve marker", None).unwrap();
    pk.verify(b"from the curve marker", None, &signature).unwrap();
    assert!(pk.verify(b"another message", None, &signature).is_err());
}

#[test]
fn bp384r1_marker_pair_is_keygen_and_signs() {
    is_keygen::<Bp384r1, SHA384>();
    is_keygen::<Bp384r1, SHA3_256>();

    let mut rng = DefaultRNG::default();
    let (pk, sk) = Bp384r1::generate_signature_key_pair::<SHA384>(&mut rng).unwrap();
    let signature = sk.sign(&mut rng, b"from the curve marker", None).unwrap();
    pk.verify(b"from the curve marker", None, &signature).unwrap();
    assert!(pk.verify(b"another message", None, &signature).is_err());
}

#[test]
fn bp512r1_marker_pair_is_keygen_and_signs() {
    is_keygen::<Bp512r1, SHA512>();
    is_keygen::<Bp512r1, SHA3_256>();

    let mut rng = DefaultRNG::default();
    let (pk, sk) = Bp512r1::generate_signature_key_pair::<SHA512>(&mut rng).unwrap();
    let signature = sk.sign(&mut rng, b"from the curve marker", None).unwrap();
    pk.verify(b"from the curve marker", None, &signature).unwrap();
    assert!(pk.verify(b"another message", None, &signature).is_err());
}
