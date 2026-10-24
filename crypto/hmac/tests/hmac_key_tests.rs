//! `HmacKey`: the key object holding RFC 2104 Section 4's two pad states, and the workers it hands
//! out producing exactly what RFC 2104's formula gives from the same material.

use bouncycastle_core::errors::{KeyMaterialError, MACError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{Hash, MAC, SuspendableKeyed};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_hmac::{HMAC, HmacKey};
use bouncycastle_sha2::{SHA256, SHA512, SUSPENDED_SHA256_STATE_LEN};
use bouncycastle_sha3::SHA3_256;

fn mac_key<const N: usize>(fill: u8) -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[fill; N], KeyType::MACKey).expect("a MAC key")
}

const MSG: &[u8] = b"The quick brown fox jumps over the lazy dog";

#[test]
fn the_key_follows_rfc_2104_for_every_key_shape() {
    // Shorter than the block, exactly the block, and longer than the block (pre-hashed, RFC 2104
    // Section 3), for a 64-byte-block hash and a 136-byte-block one, against RFC 2104 Section 2
    // written out over the bare hash.
    fn reference<H: Hash + Default>(key_bytes: &[u8], msg: &[u8]) -> Vec<u8> {
        let block_len = H::default().block_bitlen() / 8;
        let mut k = vec![0u8; block_len];
        if key_bytes.len() > block_len {
            let hashed = H::default().hash(key_bytes);
            k[..hashed.len()].copy_from_slice(&hashed);
        } else {
            k[..key_bytes.len()].copy_from_slice(key_bytes);
        }
        let mut inner = H::default();
        inner.do_update(&k.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
        inner.do_update(msg);
        let mut outer = H::default();
        outer.do_update(&k.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
        outer.do_update(&inner.do_final());
        outer.do_final()
    }
    fn check<H: Hash + Default>(key_bytes: &[u8]) {
        let km = KeyMaterial::<200>::from_bytes_as_type(key_bytes, KeyType::MACKey).unwrap();
        let expected = reference::<H>(key_bytes, MSG);
        let key = HmacKey::<H>::from_key_material_allow_weak(&km).unwrap();
        assert_eq!(key.mac(MSG), expected);
        let mut generator = key.create_generator();
        generator.do_update(&MSG[..10]);
        generator.do_update(&MSG[10..]);
        assert_eq!(generator.do_final(), expected);
    }
    for len in [1usize, 20, 64, 65, 136, 137, 200] {
        let bytes: Vec<u8> = (0..len).map(|i| i as u8).collect();
        check::<SHA256>(&bytes);
        check::<SHA512>(&bytes);
        check::<SHA3_256>(&bytes);
    }
}

#[test]
fn several_workers_from_one_key_are_independent_and_the_key_is_unchanged() {
    let key = HmacKey::<SHA256>::from_key_material(&mac_key::<32>(0x0b)).unwrap();
    let before = key.mac(MSG);

    let mut a = key.create_generator();
    let mut b = key.create_generator();
    a.do_update(b"message one");
    b.do_update(b"message two");
    let mut tag_b = [0u8; 32];
    let nb = b.do_final_out(&mut tag_b).unwrap(); // finished in the other order
    let mut tag_a = [0u8; 32];
    let na = a.do_final_out(&mut tag_a).unwrap();
    assert_eq!((na, nb), (32, 32));
    assert_ne!(tag_a, tag_b);
    assert_eq!(tag_a.to_vec(), key.mac(b"message one"));

    let mut v = key.create_verifier();
    v.do_update(b"message one");
    assert!(v.do_verify_final(&tag_a));
    assert!(key.verify(b"message two", &tag_b));
    assert!(!key.verify(b"message two", &tag_a));
    assert_eq!(key.mac(MSG), before);
}

#[test]
fn one_shots_match_the_streaming_path_and_zeroize_the_output_first() {
    let key = HmacKey::<SHA512>::from_key_material(&mac_key::<64>(0x42)).unwrap();
    let full = key.mac(MSG);
    assert_eq!(full.len(), 64);

    let mut out = [0xEEu8; 80];
    let n = key.mac_out(MSG, &mut out).unwrap();
    assert_eq!(n, 64);
    assert_eq!(&out[..64], &full[..]);
    assert!(out[64..].iter().all(|&b| b == 0), "the whole output buffer is zeroized first");

    // Truncation below the FIPS floor is refused, as on the worker.
    assert!(matches!(key.mac_out(MSG, &mut [0u8; 3]), Err(MACError::InvalidLength(_))));
    // A 16-byte truncation is accepted and is a prefix of the full MAC.
    let mut short = [0u8; 16];
    assert_eq!(key.mac_out(MSG, &mut short).unwrap(), 16);
    assert_eq!(short, full[..16]);
}

#[test]
fn construction_applies_the_key_type_and_strength_policy() {
    // Wrong key type.
    let seed = KeyMaterial256::from_bytes_as_type(&[7; 32], KeyType::Seed).unwrap();
    assert!(matches!(
        HmacKey::<SHA256>::from_key_material(&seed),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
    assert!(matches!(
        HmacKey::<SHA256>::from_key_material_allow_weak(&seed),
        Err(MACError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));

    // Too weak for the construction: refused by the checked form, admitted by the weak form.
    let mut weak = mac_key::<32>(0x0b);
    weak.set_security_strength(SecurityStrength::_112bit).unwrap();
    assert!(matches!(
        HmacKey::<SHA256>::from_key_material(&weak),
        Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));
    assert!(HmacKey::<SHA256>::from_key_material_allow_weak(&weak).is_ok());

    // An empty (zeroized) key, HKDF's absent salt, is admitted by the weak form and is the
    // all-zero key of RFC 2104 step (1): the zero-length-key vector from `hmac_tests.rs`.
    let no_salt = KeyMaterial256::new();
    let salt_key = HmacKey::<SHA256>::from_key_material_allow_weak(&no_salt).unwrap();
    assert_eq!(
        salt_key.mac(b"Hi There"),
        b"\xe4\x84\x11\x26\x27\x15\xc8\x37\x0c\xd5\xe7\xbf\x8e\x82\xbe\xf5\x3b\xd5\x37\x12\xd0\x07\xf3\x42\x93\x51\x84\x3b\x77\xc7\xbb\x9b"
    );
}

#[test]
fn generate_draws_a_key_of_the_hash_output_length_at_the_rng_strength() {
    let mut rng = FixedSeedRNG::<32>::new([0x5Au8; 32]);
    let key =
        HmacKey::<SHA256>::generate(&mut rng).expect("a 256-bit RNG suffices for HMAC-SHA256");
    let tag = key.mac(MSG);
    assert!(key.verify(MSG, &tag));
    // A draw from another RNG stream is a different key.
    let other = HmacKey::<SHA256>::generate(&mut FixedSeedRNG::<32>::new([0xA5u8; 32])).unwrap();
    assert!(!other.verify(MSG, &tag));

    // The drawn material is the hash's output length, tagged MACKey: the same bytes through
    // `from_key_material` give the same key.
    let mut rng2 = FixedSeedRNG::<32>::new([0x5Au8; 32]);
    let mut km = KeyMaterial::<32>::from_rng(&mut rng2).unwrap();
    km.set_key_type(KeyType::MACKey).unwrap();
    assert_eq!(HmacKey::<SHA256>::from_key_material(&km).unwrap().mac(MSG), tag);

    // An RNG below the HMAC's strength is refused, through the material's strength tag.
    let mut weak_rng = FixedSeedRNG::<32>::new([0x5Au8; 32]);
    weak_rng.set_security_strength(SecurityStrength::_128bit);
    assert!(HmacKey::<SHA256>::generate(&mut weak_rng).is_ok());
    assert!(matches!(
        HmacKey::<SHA512>::generate(&mut weak_rng),
        Err(MACError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));
}

#[test]
fn a_worker_from_the_key_suspends_and_resumes() {
    let km = mac_key::<32>(0x0b);
    let key = HmacKey::<SHA256>::from_key_material(&km).unwrap();
    let mut w = key.create_generator();
    w.do_update(&MSG[..7]);
    let state: [u8; SUSPENDED_SHA256_STATE_LEN] = w.suspend();
    let mut resumed = HMAC::<SHA256>::from_suspended(state, &key).unwrap();
    resumed.do_update(&MSG[7..]);
    assert_eq!(resumed.do_final(), key.mac(MSG));
}

#[test]
fn a_cloned_key_is_the_same_key() {
    let key = HmacKey::<SHA3_256>::from_key_material(&mac_key::<32>(0x33)).unwrap();
    assert_eq!(key.clone().mac(MSG), key.mac(MSG));
}
