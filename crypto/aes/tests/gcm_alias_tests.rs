//! Tests for the AES-GCM aliases.
//!
//! The aliases are only type aliases, so what is worth testing is that they name the *right* type
//! at both directions, that all three key lengths reach the shared `AEADCipherEncryptor` /
//! `AEADCipherDecryptor` conformance suite (`TestFrameworkAEADCipher`, which runs the
//! `SymmetricCipherEncryptor` / `SymmetricCipherDecryptor` suite first), and that a fresh nonce is
//! generated per encryption. Algorithm correctness itself is pinned by `bouncycastle-modes`'
//! ACVP and bc-java known-answer suites.

use bouncycastle_aes::{AES_128, AES_GCM_128, AES_GCM_192, AES_GCM_256};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor};
use bouncycastle_core_test_framework::symmetric_ciphers::TestFrameworkAEADCipher;
use bouncycastle_modes::{Decrypting, Encrypting, Gcm};

fn key<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// The alias must resolve to exactly the type it claims to, at both directions.
#[test]
fn the_alias_names_the_expected_type() {
    use core::mem::size_of;

    assert_eq!(size_of::<AES_GCM_128<Encrypting>>(), size_of::<Gcm<AES_128, Encrypting, 16, 16>>());
    assert_eq!(size_of::<AES_GCM_128<Decrypting>>(), size_of::<Gcm<AES_128, Decrypting, 16, 16>>());
}

/// All three key lengths satisfy the shared AEAD conformance suite, which includes the
/// symmetric-cipher suite the padding adapters and the stream modes run.
#[test]
fn all_three_key_lengths_conform_to_the_aead_suite() {
    let framework = TestFrameworkAEADCipher::new();
    framework.test_encryptor_decryptor::<
        16,
        12,
        16,
        16,
        AES_GCM_128<Encrypting>,
        AES_GCM_128<Decrypting>,
    >();
    framework.test_encryptor_decryptor::<
        24,
        12,
        16,
        16,
        AES_GCM_192<Encrypting>,
        AES_GCM_192<Decrypting>,
    >();
    framework.test_encryptor_decryptor::<
        32,
        12,
        16,
        16,
        AES_GCM_256<Encrypting>,
        AES_GCM_256<Decrypting>,
    >();
}

/// The nonce is generated per encryption, so the same plaintext gives different ciphertext, and
/// each still round-trips.
#[test]
fn each_encryption_gets_a_fresh_nonce() {
    let data = *b"the quick brown fox jumps over the lazy dog!!!";
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..16 {
        let mut ct = [0u8; 46];
        let (nonce, _, tag) =
            AES_GCM_128::<Encrypting>::encrypt_out_detached(&key::<16>(), b"aad", &data, &mut ct)
                .unwrap();
        assert!(seen.insert(nonce), "nonce repeated across encryptions");
        let mut pt = [0u8; 46];
        AES_GCM_128::<Decrypting>::decrypt_out_detached(
            &key::<16>(),
            &nonce,
            b"aad",
            &ct,
            &tag,
            &mut pt,
        )
        .unwrap();
        assert_eq!(pt, data);
    }
}
