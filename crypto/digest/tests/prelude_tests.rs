//! `bouncycastle_digest::prelude` alone brings the methods of the calls below into scope: a hash, a XOF,
//! HMAC and HKDF are called below with no other trait imported.

use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
use bouncycastle_digest::hkdf::HKDF_SHA256;
use bouncycastle_digest::hmac::HmacKey;
use bouncycastle_digest::prelude::*;
use bouncycastle_digest::sha2::SHA256;
use bouncycastle_digest::sha3::SHAKE128;
use bouncycastle_rng::HashDRBG_SHA512;

#[test]
fn hash() {
    let mut one_shot = [0u8; 32];
    SHA256::hash_out(b"abc", &mut one_shot);

    let mut h = SHA256::new();
    assert_eq!(h.alg_name(), SHA256::ALG_NAME);
    h.do_update(b"a");
    h.do_update(b"bc");
    let mut streamed = [0u8; 32];
    assert_eq!(h.do_final_out(&mut streamed), SHA256::OUTPUT_LEN);
    assert_eq!(streamed, one_shot);
}

#[test]
fn xof() {
    let mut one_shot = [0u8; 64];
    SHAKE128::new().xof_out(b"abc", &mut one_shot);

    let mut shake = SHAKE128::new();
    shake.do_update(b"abc");
    let mut squeezer = shake.into_squeezer();
    let mut out = [0u8; 64];
    squeezer.do_output_out(&mut out[..10]);
    squeezer.do_output_final_out(&mut out[10..]);
    assert_eq!(out, one_shot);
}

#[test]
fn hmac() {
    let key = HmacKey::<SHA256>::generate(&mut HashDRBG_SHA512::new_from_os()).unwrap();
    let mut generator = key.create_generator();
    generator.do_update(b"message");
    let mut tag = [0u8; 32];
    generator.do_final_out(&mut tag);
    assert_eq!(key.mac(b"message"), tag);

    let mut verifier = key.create_verifier();
    verifier.do_update(b"message");
    assert!(verifier.do_verify_final(&tag).is_ok());
    assert!(key.verify(b"message", &tag).is_ok());
}

#[test]
fn hkdf() {
    let ikm = KeyMaterial256::from_bytes_as_type(&[0x0b; 32], KeyType::Seed).unwrap();
    let mut okm = KeyMaterial256::new();
    assert_eq!(HKDF_SHA256::new().derive_key_out(&ikm, b"info", 32, &mut okm).unwrap(), 32);
    assert_eq!(okm.key_len(), 32);
}
