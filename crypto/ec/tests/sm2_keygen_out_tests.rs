//! `keygen_out` for SM2 signing (`sm2::keys`) and SM2 encryption (`sm2::encryption`): the key it
//! fills signs or decrypts; it is the key the by-value `keygen` gives from the same RNG output;
//! it clears a key it is handed and leaves it cleared on every error; and a key it never filled
//! has no public key and signs or decrypts nothing.

use bouncycastle_core::errors::{
    KeyMaterialError, PublicKeyEncryptionError, RNGError, SignatureError,
};
use bouncycastle_core::hazmat::FixedSeedRNG;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{OneShotSigningKey, OneShotVerifyingKey, SigningKey};
use bouncycastle_core::traits::PrivateKey;
use bouncycastle_core_test_framework::{FailingRNG, ShortRNG};
use bouncycastle_ec::sm2::encryption::{self, OVERHEAD_LEN, SM2EncryptionPrivateKey};
use bouncycastle_ec::sm2::keys::{self, SM2PrivateKey};
use bouncycastle_rng::DefaultRNG;

const ID: &[u8] = b"test-identity@example.com";

fn seed() -> [u8; 128] {
    core::array::from_fn(|i| i as u8)
}

#[test]
fn signing_keygen_out_is_keygen_and_signs() {
    let (pk, expected) = keys::keygen(&mut FixedSeedRNG::new(seed())).unwrap();
    let mut sk = SM2PrivateKey::zeroized();
    keys::keygen_out(&mut FixedSeedRNG::new(seed()), &mut sk).unwrap();
    assert_eq!(sk, expected, "keygen_out is keygen's key for the same RNG output");
    assert_eq!(sk.pub_key().unwrap(), pk);

    let mut rng = DefaultRNG::default();
    let mut fresh = SM2PrivateKey::zeroized();
    keys::keygen_out(&mut rng, &mut fresh).unwrap();
    let signature = fresh.sign(&mut rng, b"from keygen_out", Some(ID)).unwrap();
    let fresh_pk = fresh.pub_key().unwrap();
    fresh_pk.verify(b"from keygen_out", Some(ID), &signature).unwrap();
    assert!(fresh_pk.verify(b"another message", Some(ID), &signature).is_err());

    // A filled key is overwritten.
    keys::keygen_out(&mut rng, &mut sk).unwrap();
    assert_ne!(sk, expected);
}

#[test]
fn signing_keygen_out_clears_on_every_error() {
    let zero = SM2PrivateKey::zeroized();
    let (_, filled) = keys::keygen(&mut DefaultRNG::default()).unwrap();

    let mut sk = filled.clone();
    let mut weak = FixedSeedRNG::new(seed());
    weak.set_security_strength(SecurityStrength::_112bit);
    assert_eq!(
        keys::keygen_out(&mut weak, &mut sk),
        Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    );
    assert_eq!(sk, zero);

    let mut sk = filled.clone();
    assert!(matches!(
        keys::keygen_out(&mut ShortRNG, &mut sk),
        Err(SignatureError::RNGError(RNGError::GenericError(_)))
    ));
    assert_eq!(sk, zero);

    let mut sk = filled.clone();
    assert!(keys::keygen_out(&mut FailingRNG, &mut sk).is_err());
    assert_eq!(sk, zero);
}

#[test]
fn an_unfilled_signing_key_is_refused() {
    let refused = |r: Result<(), SignatureError>| {
        r == Err(SignatureError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
    };
    let zero = SM2PrivateKey::zeroized();
    let (_, filled) = keys::keygen(&mut DefaultRNG::default()).unwrap();
    assert_eq!(zero, SM2PrivateKey::zeroized());
    assert_ne!(zero, filled);
    assert_eq!(zero.encode(), [0u8; keys::SK_LEN]);
    assert!(refused(zero.pub_key().map(|_| ())));
    let mut rng = DefaultRNG::default();
    assert!(refused(zero.create_signer(&mut rng, Some(ID)).map(|_| ())));
    assert!(refused(zero.sign(&mut rng, b"never filled", Some(ID)).map(|_| ())));
    let mut out = [0xA5u8; 64];
    assert!(refused(zero.sign_out(&mut rng, b"never filled", Some(ID), &mut out).map(|_| ())));
    assert_eq!(out, [0u8; 64]);
}

#[test]
fn encryption_keygen_out_is_keygen_and_decrypts() {
    let (pk, expected) = encryption::keygen(&mut FixedSeedRNG::new(seed())).unwrap();
    let mut sk = SM2EncryptionPrivateKey::zeroized();
    encryption::keygen_out(&mut FixedSeedRNG::new(seed()), &mut sk).unwrap();
    assert_eq!(sk, expected, "keygen_out is keygen's key for the same RNG output");
    assert_eq!(sk.pub_key().unwrap(), pk);

    let mut rng = DefaultRNG::default();
    let mut fresh = SM2EncryptionPrivateKey::zeroized();
    encryption::keygen_out(&mut rng, &mut fresh).unwrap();
    let fresh_pk = fresh.pub_key().unwrap();
    let msg = b"encrypted to a key from keygen_out";
    let mut ct = [0u8; 34 + OVERHEAD_LEN];
    assert_eq!(fresh_pk.encrypt_out(&mut rng, msg, &mut ct).unwrap(), ct.len());
    let mut pt = [0u8; 34];
    assert_eq!(fresh.decrypt_out(&ct, &mut pt).unwrap(), msg.len());
    assert_eq!(&pt, msg);
    // The key it replaced does not decrypt it.
    assert!(expected.decrypt_out(&ct, &mut pt).is_err());

    encryption::keygen_out(&mut rng, &mut sk).unwrap();
    assert_ne!(sk, expected, "a filled key is overwritten");
}

#[test]
fn encryption_keygen_out_clears_on_every_error() {
    let zero = SM2EncryptionPrivateKey::zeroized();
    let (_, filled) = encryption::keygen(&mut DefaultRNG::default()).unwrap();

    let mut sk = filled.clone();
    let mut weak = FixedSeedRNG::new(seed());
    weak.set_security_strength(SecurityStrength::_112bit);
    assert_eq!(
        encryption::keygen_out(&mut weak, &mut sk),
        Err(PublicKeyEncryptionError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    );
    assert_eq!(sk, zero);

    let mut sk = filled.clone();
    assert!(matches!(
        encryption::keygen_out(&mut ShortRNG, &mut sk),
        Err(PublicKeyEncryptionError::RNGError(RNGError::GenericError(_)))
    ));
    assert_eq!(sk, zero);

    let mut sk = filled.clone();
    assert!(encryption::keygen_out(&mut FailingRNG, &mut sk).is_err());
    assert_eq!(sk, zero);
}

#[test]
fn an_unfilled_decryption_key_is_refused() {
    let refused = |r: Result<(), PublicKeyEncryptionError>| {
        r == Err(PublicKeyEncryptionError::KeyMaterialError(KeyMaterialError::ActingOnZeroizedKey))
    };
    let zero = SM2EncryptionPrivateKey::zeroized();
    let (pk, filled) = encryption::keygen(&mut DefaultRNG::default()).unwrap();
    assert_eq!(zero, SM2EncryptionPrivateKey::zeroized());
    assert_ne!(zero, filled);
    assert_eq!(zero.encode(), [0u8; keys::SK_LEN]);
    assert!(refused(zero.pub_key().map(|_| ())));

    let mut rng = DefaultRNG::default();
    let msg = b"sent to a key that was filled";
    let mut ct = [0u8; 29 + OVERHEAD_LEN];
    pk.encrypt_out(&mut rng, msg, &mut ct).unwrap();
    let mut pt = [0xA5u8; 29];
    assert!(refused(zero.decrypt_out(&ct, &mut pt).map(|_| ())));
    assert_eq!(pt, [0u8; 29]);
    assert!(refused(zero.decrypt_c1c2c3_out(&ct, &mut pt).map(|_| ())));
    let (mut buf, c1, c3) = {
        let mut buf = *msg;
        let (c1, c3) = pk.encrypt_detached_inplace(&mut rng, &mut buf).unwrap();
        (buf, c1, c3)
    };
    assert!(refused(zero.decrypt_detached_inplace(&c1, &c3, &mut buf)));
    assert_eq!(buf, [0u8; 29], "the buffer is zeroized");
}
