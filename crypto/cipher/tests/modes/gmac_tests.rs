//! Structural tests for GMAC, driven by a toy permutation: both routes onto it give the tag `Gcm`
//! gives over AAD alone, streaming splits, tag, nonce and message sensitivity, and key validation.
//! The known-answer tests (ACVP, Wycheproof) are in the `aes` crate, `crypto/aes/tests/gmac_*.rs`.

mod common;
#[path = "../common/toy_key.rs"]
mod toy_key;

use bouncycastle_cipher::modes::{GCM_NONCE_LEN, GcmKeyState, Gmac, ModeNames};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core_test_framework::FixedSeedRNG;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use common::{TOY_LEN, Toy, toy_key};
use toy_key::{ToyGCM, ToyGMAC, ToyKey};

type ToyGmac<Dir, const TAG_LEN: usize = 16> = Gmac<Toy, Dir, TOY_LEN, TAG_LEN>;
type ToyGmacKey<const TAG_LEN: usize = 16> = ToyKey<Toy, ToyGMAC<TAG_LEN>>;

fn gmac_key<const TAG_LEN: usize>() -> ToyGmacKey<TAG_LEN> {
    ToyGmacKey::from_key_material(&mac_key()).expect("the toy MAC key")
}

const NONCE: [u8; GCM_NONCE_LEN] = [0x5A; GCM_NONCE_LEN];

fn mac_key() -> KeyMaterial<TOY_LEN> {
    KeyMaterial::<TOY_LEN>::from_bytes_as_type(toy_key().ref_to_bytes(), KeyType::MACKey).unwrap()
}

fn key_state() -> GcmKeyState<Toy> {
    GcmKeyState::new::<TOY_LEN>(Toy::new(&toy_key()).unwrap())
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(3)).collect()
}

fn rng() -> FixedSeedRNG<GCM_NONCE_LEN> {
    FixedSeedRNG::new(NONCE)
}

/// GMAC is GCM's tag over AAD alone: every constructor gives that tag, and the 12-byte tag is the
/// 16-byte one's prefix (Algorithm 4 step 6, `MSB_t`).
#[test]
fn every_route_gives_gcm_s_aad_only_tag() {
    let state = key_state();
    for len in [0, 1, 15, 16, 17, 32, 33, 100] {
        let msg = message(len);
        let (_, gcm_nonce, expected) = ToyKey::<Toy, ToyGCM>::from_key_material(&toy_key())
            .unwrap()
            .encrypt_detached_out(&mut rng(), &msg, &[], &mut [])
            .unwrap();
        assert_eq!(gcm_nonce, NONCE);

        let key = gmac_key::<16>();
        let (gen_, nonce) = key.create_generator(&mut rng()).unwrap();
        assert_eq!(nonce, NONCE, "len {len}");
        assert_eq!(gen_.mac(&msg), expected, "key.create_generator, len {len}");
        assert_eq!(
            key.create_generator_nonce(&NONCE).mac(&msg),
            expected,
            "key.create_generator_nonce, len {len}"
        );
        assert!(key.create_verifier(&NONCE).verify(&msg, &expected));

        let (gen_, nonce) = ToyGmac::<Encrypting>::from_key_state(&state, &mut rng()).unwrap();
        assert_eq!(nonce, NONCE, "len {len}");
        assert_eq!(gen_.mac(&msg), expected, "from_key_state, len {len}");
        assert_eq!(
            ToyGmac::<Encrypting>::from_key_state_nonce(&state, &NONCE).mac(&msg),
            expected,
            "from_key_state_nonce, len {len}"
        );
        let (gen_, nonce) = ToyGmac::<Encrypting>::new(&mac_key(), &mut rng()).unwrap();
        assert_eq!(nonce, NONCE);
        assert_eq!(gen_.mac(&msg), expected, "new, len {len}");
        assert_eq!(
            ToyGmac::<Encrypting>::new_nonce(&mac_key(), &NONCE).unwrap().mac(&msg),
            expected,
            "new_nonce, len {len}"
        );

        assert!(ToyGmac::<Decrypting>::from_key_state(&state, &NONCE).verify(&msg, &expected));
        assert!(ToyGmac::<Decrypting>::new(&mac_key(), &NONCE).unwrap().verify(&msg, &expected));

        let short = ToyGmac::<Encrypting, 12>::from_key_state_nonce(&state, &NONCE).mac(&msg);
        assert_eq!(short[..], expected[..12], "len {len}");
        assert!(ToyGmac::<Decrypting, 12>::from_key_state(&state, &NONCE).verify(&msg, &short));
    }
}

#[test]
fn streaming_split_points() {
    let state = key_state();
    for mlen in [16, 20, 32, 33, 64] {
        let msg = message(mlen);
        let expected = ToyGmac::<Encrypting>::from_key_state_nonce(&state, &NONCE).mac(&msg);
        for split in 0..=mlen {
            let mut gen_ = ToyGmac::<Encrypting>::from_key_state_nonce(&state, &NONCE);
            gen_.do_update(&msg[..split]);
            gen_.do_update(&msg[split..]);
            assert_eq!(gen_.do_final(), expected, "generate, mlen {mlen}, split at {split}");

            let mut ver = ToyGmac::<Decrypting>::from_key_state(&state, &NONCE);
            ver.do_update(&msg[..split]);
            ver.do_update(&msg[split..]);
            assert!(ver.do_verify_final(&expected), "verify, mlen {mlen}, split at {split}");
        }
    }
}

#[test]
fn rejects_changed_tag_nonce_or_message() {
    let state = key_state();
    let msg = message(100);
    let tag = ToyGmac::<Encrypting>::from_key_state_nonce(&state, &NONCE).mac(&msg);
    let verify = |nonce: &[u8; GCM_NONCE_LEN], msg: &[u8], tag: &[u8; 16]| {
        ToyGmac::<Decrypting>::from_key_state(&state, nonce).verify(msg, tag)
    };
    assert!(verify(&NONCE, &msg, &tag));

    for i in 0..tag.len() {
        let mut bad = tag;
        bad[i] ^= 0x01;
        assert!(!verify(&NONCE, &msg, &bad), "tag byte {i}");
    }
    let mut other_nonce = NONCE;
    other_nonce[0] ^= 0x80;
    assert!(!verify(&other_nonce, &msg, &tag));
    assert!(!verify(&NONCE, &msg[..99], &tag));

    // The empty message has a tag of its own, which is not the tag of anything else.
    let empty_tag = ToyGmac::<Encrypting>::from_key_state_nonce(&state, &NONCE).mac(&[]);
    assert!(verify(&NONCE, &[], &empty_tag));
    assert!(!verify(&NONCE, &[0], &empty_tag));
}

/// A nonce drawn per generator: two draws from one RNG are two nonces, and so two tags.
#[test]
fn a_fresh_nonce_per_generator() {
    let state = key_state();
    let mut rng = FixedSeedRNG::<64>::new(core::array::from_fn(|i| i as u8));
    let (g1, n1) = ToyGmac::<Encrypting>::from_key_state(&state, &mut rng).unwrap();
    let (g2, n2) = ToyGmac::<Encrypting>::from_key_state(&state, &mut rng).unwrap();
    assert_ne!(n1, n2);
    assert_ne!(g1.mac(b"m"), g2.mac(b"m"));
}

/// The material route takes a `MACKey` at the permutation's strength and nothing else.
#[test]
fn key_validation() {
    let cipher_key = toy_key();
    let is_type_error = |r: Result<(), SymmetricCipherError>| {
        matches!(
            r,
            Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
        )
    };
    assert!(is_type_error(ToyGmac::<Encrypting>::new(&cipher_key, &mut rng()).map(drop)));
    assert!(is_type_error(ToyGmac::<Encrypting>::new_nonce(&cipher_key, &NONCE).map(drop)));
    assert!(is_type_error(ToyGmac::<Decrypting>::new(&cipher_key, &NONCE).map(drop)));

    let mut weak = mac_key();
    weak.set_security_strength(SecurityStrength::_112bit).unwrap();
    assert!(matches!(
        ToyGmac::<Encrypting>::new_nonce(&weak, &NONCE),
        Err(SymmetricCipherError::KeyMaterialError(KeyMaterialError::SecurityStrength(_)))
    ));

    let zero = KeyMaterial::<TOY_LEN>::from_bytes_as_type(&[0; TOY_LEN], KeyType::MACKey).unwrap();
    assert!(ToyGmac::<Decrypting>::new(&zero, &NONCE).is_err());
}

/// The key's construction suite: a `MACKey` of the permutation's length and strength, bound to
/// the GMAC name or to nothing.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<TOY_LEN, ToyGmacKey>(Toy::GMAC_ALG_NAME, SecurityStrength::_128bit);
}
