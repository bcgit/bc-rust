//! [`AgreementKeyPair`] on the seven [`bouncycastle_ec`] curve markers: each marker's
//! `generate_agreement_key_pair` is that curve's `keygen` (the same pair from the same RNG
//! output, the same strength gate), and two pairs it gives agree on one `Z`.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::errors::{KeyAgreementError, RNGError};
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_eccdh::keys::keygen;
use bouncycastle_eccdh::keys_common::AgreementKeyPair;
use bouncycastle_rng::{DefaultRNG, FixedSeedRNG};
use core::fmt::Debug;

/// A counting seed longer than any curve's draw, so consecutive bytes differ.
fn seed() -> [u8; 96] {
    core::array::from_fn(|i| i as u8)
}

/// A curve's own `keygen`.
type Keygen<C> = fn(
    &mut dyn RNG,
) -> Result<
    (<C as AgreementKeyPair>::PublicKey, <C as AgreementKeyPair>::PrivateKey),
    KeyAgreementError,
>;

/// The marker's pair is the curve's `keygen` pair for the same RNG output, and the marker
/// applies the same strength gate: an RNG at 112 bits is below every curve here.
fn is_keygen<C: AgreementKeyPair>(keygen: Keygen<C>)
where
    C::PublicKey: PartialEq + Debug,
    C::PrivateKey: PartialEq + Debug,
{
    let from_marker = C::generate_agreement_key_pair(&mut FixedSeedRNG::new(seed())).unwrap();
    let from_keygen = keygen(&mut FixedSeedRNG::new(seed())).unwrap();
    assert_eq!(from_marker, from_keygen);

    let mut weak = FixedSeedRNG::new(seed());
    weak.set_security_strength(SecurityStrength::_112bit);
    assert!(matches!(
        C::generate_agreement_key_pair(&mut weak),
        Err(KeyAgreementError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    ));
}

#[test]
fn p256_marker_pair_is_keygen_and_agrees() {
    is_keygen::<P256>(keygen::<P256>);

    let mut rng = DefaultRNG::default();
    let (pk_a, sk_a) = P256::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_b, sk_b) = P256::generate_agreement_key_pair(&mut rng).unwrap();
    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.agree(&pk_a, ()).unwrap();
    assert!(z_a.equals(&z_b));
}

#[test]
fn p384_marker_pair_is_keygen_and_agrees() {
    is_keygen::<P384>(keygen::<P384>);

    let mut rng = DefaultRNG::default();
    let (pk_a, sk_a) = P384::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_b, sk_b) = P384::generate_agreement_key_pair(&mut rng).unwrap();
    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.agree(&pk_a, ()).unwrap();
    assert!(z_a.equals(&z_b));
}

#[test]
fn p521_marker_pair_is_keygen_and_agrees() {
    is_keygen::<P521>(keygen::<P521>);

    let mut rng = DefaultRNG::default();
    let (pk_a, sk_a) = P521::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_b, sk_b) = P521::generate_agreement_key_pair(&mut rng).unwrap();
    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.agree(&pk_a, ()).unwrap();
    assert!(z_a.equals(&z_b));
}

#[test]
fn p256k1_marker_pair_is_keygen_and_agrees() {
    is_keygen::<Secp256K1>(keygen::<Secp256K1>);

    let mut rng = DefaultRNG::default();
    let (pk_a, sk_a) = Secp256K1::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_b, sk_b) = Secp256K1::generate_agreement_key_pair(&mut rng).unwrap();
    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.agree(&pk_a, ()).unwrap();
    assert!(z_a.equals(&z_b));
}

#[test]
fn bp256r1_marker_pair_is_keygen_and_agrees() {
    is_keygen::<Bp256r1>(keygen::<Bp256r1>);

    let mut rng = DefaultRNG::default();
    let (pk_a, sk_a) = Bp256r1::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_b, sk_b) = Bp256r1::generate_agreement_key_pair(&mut rng).unwrap();
    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.agree(&pk_a, ()).unwrap();
    assert!(z_a.equals(&z_b));
}

#[test]
fn bp384r1_marker_pair_is_keygen_and_agrees() {
    is_keygen::<Bp384r1>(keygen::<Bp384r1>);

    let mut rng = DefaultRNG::default();
    let (pk_a, sk_a) = Bp384r1::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_b, sk_b) = Bp384r1::generate_agreement_key_pair(&mut rng).unwrap();
    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.agree(&pk_a, ()).unwrap();
    assert!(z_a.equals(&z_b));
}

#[test]
fn bp512r1_marker_pair_is_keygen_and_agrees() {
    is_keygen::<Bp512r1>(keygen::<Bp512r1>);

    let mut rng = DefaultRNG::default();
    let (pk_a, sk_a) = Bp512r1::generate_agreement_key_pair(&mut rng).unwrap();
    let (pk_b, sk_b) = Bp512r1::generate_agreement_key_pair(&mut rng).unwrap();
    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.agree(&pk_a, ()).unwrap();
    assert!(z_a.equals(&z_b));
}
