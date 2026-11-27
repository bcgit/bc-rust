//! AES-GCM-SIV (RFC 8452) through the key objects: what the in-place one-shots of
//! `AES128Key<GCM_SIV>` and `AES256Key<GCM_SIV>` promise beyond the known answers, which are in
//! `aes_gcm_siv_rfc8452_tests.rs`, and beyond the shared in-place AEAD suite, which
//! `aes_gcm_siv_key_tests.rs` runs: longer messages and more AAD lengths, every byte of the tag,
//! the ciphertext and the nonce tampered with, and the mode's own property under a repeated nonce.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadInPlaceDecryptionKey, AeadInPlaceEncryptionKey, FromKeyMaterial,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_symmetric::aes::{AES128Key, AES256Key};
use bouncycastle_symmetric::modes::{GCM_SIV, GCM_SIV_NONCE_LEN, GCM_SIV_TAG_LEN};

fn key<K: FromKeyMaterial<N>, const N: usize>(seed: u8) -> K {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(seed));
    let material = KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
        .expect("a valid key");
    K::from_key_material(&material).expect("a valid key")
}

fn message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(5)).collect()
}

const NONCE: [u8; GCM_SIV_NONCE_LEN] = [0x24; GCM_SIV_NONCE_LEN];

/// Round trips at every length across four blocks and a few longer ones, under several AAD
/// lengths, with the nonce drawn and with it supplied; the two forms agree under one nonce.
fn round_trips<K, const N: usize>(key: &K)
where
    K: AeadInPlaceEncryptionKey<N, 12, 16> + AeadInPlaceDecryptionKey<N, 12, 16>,
{
    let mut rng = HashDRBG_SHA512::new_from_os();
    for len in (0..=64).chain([65, 127, 128, 129, 1000, 4097]) {
        for aad_len in [0usize, 1, 15, 16, 17, 100] {
            let plaintext = message(len);
            let aad = message(aad_len);

            let mut buf = plaintext.clone();
            let (nonce, tag) = key.encrypt_detached_inplace(&mut rng, &aad, &mut buf).unwrap();
            if len >= 8 {
                assert_ne!(buf, plaintext, "length {len}, AAD {aad_len}");
            }

            let mut again = plaintext.clone();
            let tag_again = key.encrypt_detached_inplace_nonce(&nonce, &aad, &mut again).unwrap();
            assert_eq!((&again, tag_again), (&buf, tag), "length {len}, AAD {aad_len}");

            key.decrypt_detached_inplace(&nonce, &aad, &mut buf, &tag).unwrap();
            assert_eq!(buf, plaintext, "length {len}, AAD {aad_len}");
        }
    }
}

#[test]
fn both_key_lengths_round_trip_in_place() {
    round_trips::<_, 16>(&key::<AES128Key<GCM_SIV>, 16>(1));
    round_trips::<_, 32>(&key::<AES256Key<GCM_SIV>, 32>(1));
}

/// Asserts that the decryption fails its tag check and leaves `buf` all zeros.
fn refused<K, const N: usize>(
    key: &K,
    nonce: &[u8; 12],
    aad: &[u8],
    mut buf: Vec<u8>,
    tag: &[u8; 16],
    what: &str,
) where
    K: AeadInPlaceDecryptionKey<N, 12, 16>,
{
    assert_eq!(
        key.decrypt_detached_inplace(nonce, aad, &mut buf, tag),
        Err(SymmetricCipherError::AEADTagCheckFailed),
        "{what}"
    );
    assert!(buf.iter().all(|&b| b == 0), "{what}: the buffer is zeroized");
}

/// A change to any byte of the tag, any byte of the ciphertext, the AAD, the nonce or the key
/// fails the tag check and leaves no plaintext, and no ciphertext, in the buffer.
fn tampering<K, const N: usize>(key: &K, other_key: &K)
where
    K: AeadInPlaceEncryptionKey<N, 12, 16> + AeadInPlaceDecryptionKey<N, 12, 16>,
{
    let aad = b"additional data".to_vec();
    for len in [0usize, 1, 16, 17, 40] {
        let plaintext = message(len);
        let mut ciphertext = plaintext.clone();
        let tag = key.encrypt_detached_inplace_nonce(&NONCE, &aad, &mut ciphertext).unwrap();

        for i in 0..GCM_SIV_TAG_LEN {
            for bit in [0x01u8, 0x80] {
                let mut bad = tag;
                bad[i] ^= bit;
                refused(key, &NONCE, &aad, ciphertext.clone(), &bad, &format!("tag byte {i}"));
            }
        }
        for i in 0..len {
            let mut bad = ciphertext.clone();
            bad[i] ^= 0x01;
            refused(key, &NONCE, &aad, bad, &tag, &format!("length {len}, ciphertext byte {i}"));
        }

        let mut bad_aad = aad.clone();
        bad_aad[3] ^= 0x01;
        refused(key, &NONCE, &bad_aad, ciphertext.clone(), &tag, "AAD changed");
        refused(key, &NONCE, &aad[..aad.len() - 1], ciphertext.clone(), &tag, "AAD shortened");
        refused(key, &NONCE, b"", ciphertext.clone(), &tag, "AAD dropped");

        for i in 0..GCM_SIV_NONCE_LEN {
            let mut bad = NONCE;
            bad[i] ^= 0x01;
            refused(key, &bad, &aad, ciphertext.clone(), &tag, &format!("nonce byte {i}"));
        }

        refused(other_key, &NONCE, &aad, ciphertext.clone(), &tag, "another key");

        // The untampered message still opens.
        let mut buf = ciphertext.clone();
        key.decrypt_detached_inplace(&NONCE, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);
    }
}

#[test]
fn tampering_fails_the_tag_check_and_zeroizes_the_buffer() {
    tampering::<_, 16>(&key::<AES128Key<GCM_SIV>, 16>(1), &key::<AES128Key<GCM_SIV>, 16>(2));
    tampering::<_, 32>(&key::<AES256Key<GCM_SIV>, 32>(1), &key::<AES256Key<GCM_SIV>, 32>(2));
}

/// The misuse-resistance property, RFC 8452 Section 9: under a repeated nonce "the only security
/// loss is that identical plaintexts will produce identical ciphertexts". The same message gives
/// the same output, and a message that differs anywhere, or in its AAD alone, gives a different
/// tag and with it a different keystream: two messages with a common first block do not have a
/// common first ciphertext block, as they would under GCM with a repeated nonce.
#[test]
fn a_repeated_nonce_reveals_only_equality() {
    let key = key::<AES256Key<GCM_SIV>, 32>(1);
    let seal = |aad: &[u8], plaintext: &[u8]| {
        let mut buf = plaintext.to_vec();
        let tag = key.encrypt_detached_inplace_nonce(&NONCE, aad, &mut buf).unwrap();
        (buf, tag)
    };

    let plaintext = message(48);
    let (ciphertext, tag) = seal(b"aad", &plaintext);
    assert_eq!(seal(b"aad", &plaintext), (ciphertext.clone(), tag));

    // A difference in the last byte only.
    let mut other = plaintext.clone();
    other[47] ^= 0x01;
    let (other_ciphertext, other_tag) = seal(b"aad", &other);
    assert_ne!(other_tag, tag);
    assert_ne!(other_ciphertext[..16], ciphertext[..16]);

    // The same plaintext under other AAD.
    let (aad_ciphertext, aad_tag) = seal(b"aae", &plaintext);
    assert_ne!(aad_tag, tag);
    assert_ne!(aad_ciphertext[..16], ciphertext[..16]);

    // Under another nonce.
    let mut buf = plaintext.clone();
    let nonce_tag = key.encrypt_detached_inplace_nonce(&[0x25; 12], b"aad", &mut buf).unwrap();
    assert_ne!(nonce_tag, tag);
    assert_ne!(buf[..16], ciphertext[..16]);
}
