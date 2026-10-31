//! AES-GCM through the shared conformance suites.
//!
//! What is checked here is that all three key lengths reach the shared `AeadEncryptionKey` /
//! `AeadDecryptionKey` conformance suite (`TestFrameworkAEADCipher`), that the inline
//! `ciphertext || tag` layout holds at every byte-boundary edge (`TestFrameworkAEADTaggedLayout`),
//! and that a fresh nonce is generated per encryption. Algorithm correctness itself is pinned by
//! the ACVP and bc-java known-answer suites beside this file.

use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
use bouncycastle_cipher::modes::GCM;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core_test_framework::aead::TestFrameworkAEADCipher;
use bouncycastle_core_test_framework::aead::TestFrameworkAEADTaggedLayout;
use bouncycastle_rng::HashDRBG_SHA512;

fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

fn key<const N: usize, K: FromKeyMaterial<N>>() -> K {
    K::from_key_material(&material::<N>()).expect("a valid key")
}

fn os_rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// All three key lengths satisfy the shared AEAD conformance suite, which reaches the no-AAD
/// symmetric contract as the AEAD one with an empty AAD.
#[test]
fn all_three_key_lengths_conform_to_the_aead_suite() {
    let framework = TestFrameworkAEADCipher::new();
    let mut rng = os_rng();
    framework.test_key::<16, 12, 16, 16, _>(&key::<16, AES128Key<GCM>>(), &mut rng);
    framework.test_key::<24, 12, 16, 16, _>(&key::<24, AES192Key<GCM>>(), &mut rng);
    framework.test_key::<32, 12, 16, 16, _>(&key::<32, AES256Key<GCM>>(), &mut rng);
}

/// The inline `ciphertext || tag` layout -- where the tag lands, what the decryptor holds back,
/// and how an input shorter than the tag is refused -- at every length across a few multiples of
/// the tag and under every chunking, through the shared runner, at both ends of the key-length
/// range.
#[test]
fn the_inline_tag_layout_conforms_at_every_edge() {
    let framework = TestFrameworkAEADTaggedLayout::new();
    framework.test_key::<16, 12, 16, 16, _>(&key::<16, AES128Key<GCM>>());
    framework.test_key::<32, 12, 16, 16, _>(&key::<32, AES256Key<GCM>>());
}

/// The nonce is generated per encryption, so the same plaintext gives different ciphertext, and
/// each still round-trips.
#[test]
fn each_encryption_gets_a_fresh_nonce() {
    let data = *b"the quick brown fox jumps over the lazy dog!!!";
    let key = key::<16, AES128Key<GCM>>();
    let mut rng = os_rng();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let mut ct = [0u8; 46];
        let (_, nonce, tag) = key.encrypt_detached_out(&mut rng, b"aad", &data, &mut ct).unwrap();
        assert!(seen.insert(nonce), "nonce repeated across encryptions");
        let mut pt = [0u8; 46];
        key.decrypt_detached_out(&nonce, b"aad", &ct, &tag, &mut pt).unwrap();
        assert_eq!(pt, data);
    }
}
