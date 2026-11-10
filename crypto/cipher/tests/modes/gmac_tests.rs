//! Structural tests for GMAC, driven by a toy permutation: the key and the mode's own route give
//! the tag `Gcm` gives over AAD alone, streaming splits, tag, nonce and message sensitivity, and key
//! validation.
//! The known-answer tests (ACVP, Wycheproof) are in the `aes` crate, `crypto/aes/tests/gmac_*.rs`.

mod common;

use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::{GCM, GCM_NONCE_LEN, GMAC, ModeNames};
use bouncycastle_core::errors::MACError;
use bouncycastle_core::hazmat::{KeyExpansion, Mode, NonceMacMode};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    AeadEncryptionKey, FromKeyMaterial, NonceMacGenerationKey, NonceMacVerificationKey,
};
use bouncycastle_core::traits::{MACGenerator, MACVerifier};
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromKeyMaterial;
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_rng::FixedSeedRNG;
use common::{TOY_LEN, Toy, toy_key};

type ToyGmacKey<const TAG_LEN: usize = 16> = BlockCipherKey<Toy, GMAC<TAG_LEN>>;

fn gmac_key<const TAG_LEN: usize>() -> ToyGmacKey<TAG_LEN> {
    ToyGmacKey::from_key_material(&mac_key()).expect("the toy MAC key")
}

const NONCE: [u8; GCM_NONCE_LEN] = [0x5A; GCM_NONCE_LEN];

fn mac_key() -> KeyMaterial<TOY_LEN> {
    KeyMaterial::<TOY_LEN>::from_bytes_as_type(toy_key().ref_to_bytes(), KeyType::MACKey).unwrap()
}

/// The mode's own route onto the workers, through the hazmat mode trait the key forwards to.
fn key_state() -> <GMAC as Mode<Toy>>::KeyState {
    <GMAC as Mode<Toy>>::key_state(Toy::new(&toy_key()).unwrap())
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(29).wrapping_add(3)).collect()
}

fn rng() -> FixedSeedRNG<[u8; GCM_NONCE_LEN]> {
    FixedSeedRNG::new(NONCE)
}

/// The tag a generator gives over `msg`.
fn tag_of<const N: usize>(mut generator: impl MACGenerator<N>, msg: &[u8]) -> [u8; N] {
    generator.do_update(msg);
    generator.do_final()
}

/// Whether a verifier accepts `tag` over `msg`.
fn accepts<const N: usize>(mut verifier: impl MACVerifier<N>, msg: &[u8], tag: &[u8; N]) -> bool {
    verifier.do_update(msg);
    verifier.do_verify_final(tag).is_ok()
}

/// GMAC is GCM's tag over AAD alone: every constructor gives that tag, and the 12-byte tag is the
/// 16-byte one's prefix (Algorithm 4 step 6, `MSB_t`). The key passes the shared nonce-bound MAC
/// key suite against it.
#[test]
fn every_route_gives_gcm_s_aad_only_tag() {
    let state = key_state();
    for len in [0, 1, 15, 16, 17, 32, 33, 100] {
        let msg = message(len);
        let (_, gcm_nonce, expected) = BlockCipherKey::<Toy, GCM>::from_key_material(&toy_key())
            .unwrap()
            .encrypt_detached_out(&mut rng(), &msg, &[], &mut [])
            .unwrap();
        assert_eq!(gcm_nonce, NONCE);

        let key = gmac_key::<16>();
        let (gen_, nonce) = key.create_generator(&mut rng()).unwrap();
        assert_eq!(nonce, NONCE, "len {len}");
        assert_eq!(tag_of(gen_, &msg), expected, "key.create_generator, len {len}");
        assert_eq!(key.mac_nonce(&NONCE, &msg), expected, "key.mac_nonce, len {len}");
        assert_eq!(key.verify(&NONCE, &msg, &expected), Ok(()));
        TestFrameworkMAC::new().test_nonce_mac_key(&key, &NONCE, &msg, &expected);

        type Full = GMAC<16>;
        type Short = GMAC<12>;
        let (gen_, nonce) =
            <Full as NonceMacMode<Toy, GCM_NONCE_LEN, 16>>::generate_init(&state, &mut rng())
                .unwrap();
        assert_eq!(nonce, NONCE, "len {len}");
        assert_eq!(tag_of(gen_, &msg), expected, "generate_init, len {len}");
        assert_eq!(
            tag_of(
                <Full as NonceMacMode<Toy, GCM_NONCE_LEN, 16>>::generate_init_nonce(&state, &NONCE),
                &msg
            ),
            expected,
            "generate_init_nonce, len {len}"
        );
        assert!(accepts(
            <Full as NonceMacMode<Toy, GCM_NONCE_LEN, 16>>::verify_init(&state, &NONCE),
            &msg,
            &expected
        ));

        let short = tag_of(
            <Short as NonceMacMode<Toy, GCM_NONCE_LEN, 12>>::generate_init_nonce(&state, &NONCE),
            &msg,
        );
        assert_eq!(short[..], expected[..12], "len {len}");
        assert!(accepts(
            <Short as NonceMacMode<Toy, GCM_NONCE_LEN, 12>>::verify_init(&state, &NONCE),
            &msg,
            &short
        ));
    }
}

#[test]
fn streaming_split_points() {
    let key = gmac_key::<16>();
    for mlen in [16, 20, 32, 33, 64] {
        let msg = message(mlen);
        let expected = key.mac_nonce(&NONCE, &msg);
        for split in 0..=mlen {
            let mut gen_ = key.create_generator_nonce(&NONCE);
            gen_.do_update(&msg[..split]);
            gen_.do_update(&msg[split..]);
            assert_eq!(gen_.do_final(), expected, "generate, mlen {mlen}, split at {split}");

            let mut ver = key.create_verifier(&NONCE);
            ver.do_update(&msg[..split]);
            ver.do_update(&msg[split..]);
            assert_eq!(
                ver.do_verify_final(&expected),
                Ok(()),
                "verify, mlen {mlen}, split {split}"
            );
        }
    }
}

#[test]
fn rejects_changed_tag_nonce_or_message() {
    let key = gmac_key::<16>();
    let msg = message(100);
    let tag = key.mac_nonce(&NONCE, &msg);
    let verify =
        |nonce: &[u8; GCM_NONCE_LEN], msg: &[u8], tag: &[u8; 16]| key.verify(nonce, msg, tag);
    assert_eq!(verify(&NONCE, &msg, &tag), Ok(()));

    for i in 0..tag.len() {
        let mut bad = tag;
        bad[i] ^= 0x01;
        assert_eq!(verify(&NONCE, &msg, &bad), Err(MACError::VerificationFailed), "tag byte {i}");
    }
    let mut other_nonce = NONCE;
    other_nonce[0] ^= 0x80;
    assert_eq!(verify(&other_nonce, &msg, &tag), Err(MACError::VerificationFailed));
    assert_eq!(verify(&NONCE, &msg[..99], &tag), Err(MACError::VerificationFailed));

    // The empty message has a tag of its own, which is not the tag of anything else.
    let empty_tag = key.mac_nonce(&NONCE, &[]);
    assert_eq!(verify(&NONCE, &[], &empty_tag), Ok(()));
    assert_eq!(verify(&NONCE, &[0], &empty_tag), Err(MACError::VerificationFailed));
}

/// A nonce drawn per generator: two draws from one RNG are two nonces, and so two tags; the
/// drawing one-shots return the nonce they drew.
#[test]
fn a_fresh_nonce_per_generator() {
    let key = gmac_key::<16>();
    let mut rng = FixedSeedRNG::new(core::array::from_fn::<u8, 64, _>(|i| i as u8));
    let (g1, n1) = key.create_generator(&mut rng).unwrap();
    let (g2, n2) = key.create_generator(&mut rng).unwrap();
    assert_ne!(n1, n2);
    assert_ne!(tag_of(g1, b"m"), tag_of(g2, b"m"));

    let (n3, t3) = key.mac(&mut rng, b"m").unwrap();
    assert_eq!(t3, key.mac_nonce(&n3, b"m"));
    let mut out = [0u8; 16];
    let (written, n4) = key.mac_out(&mut rng, b"m", &mut out).unwrap();
    assert_eq!(written, 16);
    assert_ne!(n4, n3);
    assert_eq!(out, key.mac_nonce(&n4, b"m"));
}

/// The key's construction suite: a `MACKey` of the permutation's length and strength, bound to
/// the GMAC name or to nothing.
#[test]
fn the_key_enforces_the_material_policy() {
    TestFrameworkFromKeyMaterial::new()
        .test::<TOY_LEN, ToyGmacKey>(Toy::GMAC_ALG_NAME, SecurityStrength::_128bit);
}
