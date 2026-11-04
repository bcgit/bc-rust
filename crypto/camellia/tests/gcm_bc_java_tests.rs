//! Camellia-GCM known answers produced with Bouncy Castle Java, run against the keys.
//!
//! No standard publishes a Camellia-GCM vector: RFC 6367 defines the TLS cipher suites without
//! one, and neither Wycheproof nor bc-test-data has a file; the Camellia authors' own cases are
//! in `gcm_authors_tests.rs`, and cover 128 and 256 bits only. These answers come from bc-java
//! 1.87's `GCMBlockCipher.newInstance(new CamelliaEngine())` under `AEADParameters` with a
//! 128-bit tag, over inputs anyone can regenerate: the three RFC 3713 Appendix A keys, the
//! 12-byte nonce `10 11 .. 1b`, the 20 AAD bytes `20 21 .. 33` and the 45-byte message
//! `40 41 .. 6c` (not a block multiple, so the last counter block is used in part); and, at each
//! key, the tag of an empty message with no AAD, which is GHASH over the lengths block alone.
//! `tests/mode_key_tests.rs` has the AEAD suite over the same keys; this file pins the answers
//! both ways.

mod common;

use bouncycastle_camellia::{Camellia128Key, Camellia192Key, Camellia256Key};
use bouncycastle_cipher::modes::GCM;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use common::bytes;

fn nonce() -> [u8; 12] {
    bytes("101112131415161718191a1b")
}

fn aad() -> [u8; 20] {
    bytes("202122232425262728292a2b2c2d2e2f30313233")
}

fn msg() -> [u8; 45] {
    bytes(
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c",
    )
}

/// (key, ciphertext, tag, tag of the empty message with no AAD), from bc-java 1.87.
const VECTORS: [(&str, &str, &str, &str); 3] = [
    (
        "0123456789abcdeffedcba9876543210",
        "7a49673f1fc95a61bdbd4fd9991e69ce66e11221900db3fe0477c8db0fde7c3f86f9fb95ddcfd29d32fba91dc8",
        "254bc51b6e3af975424eab7b4cf3bd25",
        "23b111413e7a7d163b09f86dc5a9c8fc",
    ),
    (
        "0123456789abcdeffedcba98765432100011223344556677",
        "ed112533b2cfe17a9db68a9c230c10a83cc3abef4991ee76baf0faf8d14bd0c87091ad693bd85a062f022c3fc2",
        "157cb0bc12aed1c6a327cc7d0d7d93ca",
        "cd362853de88b6f8d8a6b4a4b4a818fa",
    ),
    (
        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
        "a8f62afcade453f94e2773f6d2318693ea4d48319cd2ee0268ba9bd4c5c88f57b78226b445b5440e3006df2118",
        "e66a02576a8bad35da49a0c073cae837",
        "4ddd90b5409d15cf1a7b0469bdf6e7b7",
    ),
];

fn key<const KEY_LEN: usize, K: FromKeyMaterial<KEY_LEN>>(hex: &str) -> K {
    let material = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
        &bytes::<KEY_LEN>(hex),
        KeyType::SymmetricCipherKey,
    )
    .expect("a valid key");
    K::from_key_material(&material).expect("a valid key")
}

/// The vector's ciphertext and tag both ways, the empty-message tag both ways, and a flipped
/// ciphertext bit refused.
fn check<const KEY_LEN: usize, K>(key: &K, (_, ct, tag, empty_tag): (&str, &str, &str, &str))
where
    K: AeadEncryptionKey<KEY_LEN, 12, 16, 16> + AeadDecryptionKey<KEY_LEN, 12, 16, 16>,
{
    let mut expected = bytes::<45>(ct).to_vec();
    expected.extend_from_slice(&bytes::<16>(tag));
    assert_eq!(key.encrypt_with_aad_nonce(&nonce(), &aad(), &msg()).unwrap(), expected);
    assert_eq!(key.decrypt_with_aad(&nonce(), &aad(), &expected).unwrap(), msg());
    let empty_tag = bytes::<16>(empty_tag);
    assert_eq!(key.encrypt_with_aad_nonce(&nonce(), &[], &[]).unwrap(), empty_tag);
    assert_eq!(key.decrypt_with_aad(&nonce(), &[], &empty_tag).unwrap(), []);
    let mut wrong = expected.clone();
    wrong[0] ^= 1;
    assert!(key.decrypt_with_aad(&nonce(), &aad(), &wrong).is_err());
}

#[test]
fn camellia_gcm_matches_bc_java() {
    check::<16, _>(&key::<16, Camellia128Key<GCM>>(VECTORS[0].0), VECTORS[0]);
    check::<24, _>(&key::<24, Camellia192Key<GCM>>(VECTORS[1].0), VECTORS[1]);
    check::<32, _>(&key::<32, Camellia256Key<GCM>>(VECTORS[2].0), VECTORS[2]);
}
