//! Key generation into a key the caller holds (`generate_signature_key_out`,
//! `generate_kem_key_out`, `RSASVE::keygen_out`), and the refusal of a key that was never filled.

use bouncycastle_core::errors::{
    KEMError, KeyMaterialError, KeyTransportError, RNGError, SignatureError,
};
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::key_transport_key::KeyTransportDecryptingKey;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{
    DeterministicOneShotSigningKey, DeterministicSigningKey, OneShotSigningKey,
    OneShotVerifyingKey, SigningKey,
};
use bouncycastle_core::traits::RNG;
use bouncycastle_digest::hkdf::HkdfDescription;
use bouncycastle_digest::sha2::SHA256;
use bouncycastle_modexp::rsa::RSA2048;
use bouncycastle_modexp::rsa::keys::RsaPrivateKey;
use bouncycastle_modexp::rsa::rsa_2048::{
    RSA2048KEMPrivateKey, RSASSA_PKCS1_v1_5_SHA256, RSASSA_PSS_SHA256, RSASVE,
};
use bouncycastle_modexp::rsa::rsaes_oaep::OaepParams;
use bouncycastle_modexp::rsa::rsassa::sign_from_hash;
use bouncycastle_modexp::rsa::size::{KemKeyPair, SignatureKeyPair};
use bouncycastle_rng::DefaultRNG;

/// An RNG that fills the first half of what it is asked for and returns the count it wrote.
struct WritesHalf;

impl RNG for WritesHalf {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Err(RNGError::GenericError("not seedable"))
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("not used"))
    }
    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        out.fill(0);
        let half = out.len() / 2;
        out[..half].fill(0xA5);
        Ok(half)
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("not used"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

const ZEROIZED: KeyMaterialError = KeyMaterialError::ActingOnZeroizedKey;

#[test]
fn signature_key_out_signs_under_both_schemes() {
    let msg = b"signed with a key generated in place";

    let mut sk = RsaPrivateKey::<RSASSA_PKCS1_v1_5_SHA256>::zeroized();
    RSA2048::generate_signature_key_out(&mut DefaultRNG::default(), &mut sk).unwrap();
    let pk = sk.pub_key().unwrap();
    let sig = sk.sign_deterministic(msg, None).unwrap();
    pk.verify(msg, None, &sig).unwrap();
    assert!(pk.verify(b"other", None, &sig).is_err());

    let mut sk = RsaPrivateKey::<RSASSA_PSS_SHA256>::zeroized();
    RSA2048::generate_signature_key_out(&mut DefaultRNG::default(), &mut sk).unwrap();
    let pk = sk.pub_key().unwrap();
    let sig = sk.sign(&mut DefaultRNG::default(), msg, None).unwrap();
    pk.verify(msg, None, &sig).unwrap();
}

#[test]
fn kem_key_out_round_trips_under_rsasve_rsasve_kdf_and_oaep() {
    let mut sk = RSA2048KEMPrivateKey::zeroized();
    RSASVE::keygen_out(&mut DefaultRNG::default(), &mut sk).unwrap();
    let pk = sk.pub_key().unwrap();
    let (ss, ct) = pk.encaps(&mut DefaultRNG::default(), ()).unwrap();
    assert_eq!(sk.decaps(&ct, ()).unwrap().ref_to_bytes(), ss.ref_to_bytes());

    let mut sk = RSA2048KEMPrivateKey::zeroized();
    RSA2048::generate_kem_key_out(&mut DefaultRNG::default(), &mut sk).unwrap();
    let pk = sk.pub_key().unwrap();
    let hkdf = HkdfDescription::<SHA256>::new();
    let params = KdfParams::new(&hkdf, b"info", KeyLen::<32>);
    let (ss, ct) = pk.encaps(&mut DefaultRNG::default(), params).unwrap();
    assert_eq!(sk.decaps(&ct, params).unwrap().ref_to_bytes(), ss.ref_to_bytes());

    let params = OaepParams::<SHA256>::new(b"label");
    let (ss, ct) = pk.encaps(&mut DefaultRNG::default(), params).unwrap();
    let ss: KeyMaterial<32> = ss;
    assert_eq!(sk.decaps(&ct, params).unwrap().ref_to_bytes(), ss.ref_to_bytes());
}

#[test]
fn an_unfilled_signature_key_is_refused() {
    let sk = RsaPrivateKey::<RSASSA_PKCS1_v1_5_SHA256>::zeroized();
    assert_eq!(sk.pub_key().unwrap_err(), SignatureError::KeyMaterialError(ZEROIZED));
    assert_eq!(
        sk.sign_deterministic(b"message", None).unwrap_err(),
        SignatureError::KeyMaterialError(ZEROIZED)
    );
    assert!(matches!(
        sk.create_signer_deterministic(None),
        Err(SignatureError::KeyMaterialError(ZEROIZED))
    ));
    assert_eq!(
        sk.components().validate(&mut DefaultRNG::default()),
        Err(SignatureError::KeyMaterialError(ZEROIZED))
    );

    // Refused when the signer is made, before the salt is drawn: an RNG that writes short
    // would otherwise be the error.
    let sk = RsaPrivateKey::<RSASSA_PSS_SHA256>::zeroized();
    assert_eq!(
        sk.sign(&mut WritesHalf, b"message", None).unwrap_err(),
        SignatureError::KeyMaterialError(ZEROIZED)
    );
    assert!(matches!(
        sk.create_signer(&mut WritesHalf, None),
        Err(SignatureError::KeyMaterialError(ZEROIZED))
    ));
    assert_eq!(
        sign_from_hash(&sk, &[0x11; 32], &mut WritesHalf),
        Err(SignatureError::KeyMaterialError(ZEROIZED))
    );
}

#[test]
fn an_unfilled_kem_key_is_refused() {
    let sk = RSA2048KEMPrivateKey::zeroized();
    let ct = [0x01u8; 256];
    assert!(matches!(sk.pub_key(), Err(KEMError::KeyMaterialError(ZEROIZED))));
    assert!(matches!(sk.decaps(&ct, ()), Err(KEMError::KeyMaterialError(ZEROIZED))));

    let hkdf = HkdfDescription::<SHA256>::new();
    let params = KdfParams::new(&hkdf, b"info", KeyLen::<32>);
    assert!(matches!(sk.decaps(&ct, params), Err(KEMError::KeyMaterialError(ZEROIZED))));

    let params = OaepParams::<SHA256>::new(b"label");
    let r: Result<KeyMaterial<32>, KEMError> = sk.decaps(&ct, params);
    assert!(matches!(r, Err(KEMError::KeyMaterialError(ZEROIZED))));
    let mut key = KeyMaterial::<32>::new();
    assert!(matches!(
        sk.recover_out(&ct, params, &mut key),
        Err(KeyTransportError::KeyMaterialError(ZEROIZED))
    ));
}

/// A failed generation leaves the key zeroized, even one that held a key before.
#[test]
fn a_failed_generation_leaves_the_key_unfilled() {
    let mut sk = RsaPrivateKey::<RSASSA_PSS_SHA256>::zeroized();
    RSA2048::generate_signature_key_out(&mut DefaultRNG::default(), &mut sk).unwrap();
    assert!(matches!(
        RSA2048::generate_signature_key_out(&mut WritesHalf, &mut sk),
        Err(SignatureError::RNGError(_))
    ));
    assert_eq!(sk.pub_key().unwrap_err(), SignatureError::KeyMaterialError(ZEROIZED));

    let mut sk = RSA2048KEMPrivateKey::zeroized();
    RSASVE::keygen_out(&mut DefaultRNG::default(), &mut sk).unwrap();
    assert!(matches!(RSASVE::keygen_out(&mut WritesHalf, &mut sk), Err(KEMError::RNGError(_))));
    assert!(matches!(sk.pub_key(), Err(KEMError::KeyMaterialError(ZEROIZED))));
}
