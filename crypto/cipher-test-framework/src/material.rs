//! Key material and RNGs for the suites.

use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_rng::HashDRBG_SHA512;

/// A fixed cipher key: bytes `7i + 1`.
pub fn material<const N: usize>() -> KeyMaterial<N> {
    let bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// [`material`] with one bit of its last byte flipped.
pub fn material_flipped<const N: usize>() -> KeyMaterial<N> {
    let mut bytes: [u8; N] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
    bytes[N - 1] ^= 1;
    KeyMaterial::<N>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).expect("a valid key")
}

/// A fixed MAC key: `0x42` throughout.
pub fn mac_material<const N: usize>() -> KeyMaterial<N> {
    KeyMaterial::<N>::from_bytes_as_type(&[0x42; N], KeyType::MACKey).unwrap()
}

/// The OS-backed DRBG the suites draw IVs and nonces from.
pub fn rng() -> HashDRBG_SHA512 {
    HashDRBG_SHA512::new_from_os()
}

/// Deterministic pseudo-random bytes (xorshift), so a check needs no RNG.
pub fn filler(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            (state >> 24) as u8
        })
        .collect()
}

/// A vector file's raw key bytes as cipher-key material, promoted when `KeyMaterial`'s entropy
/// heuristic declined to call them one (the sets include all-zero and other low-entropy keys).
pub fn cipher_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
        .expect("key bytes fit the buffer");
    if key.key_type() != KeyType::SymmetricCipherKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::SymmetricCipherKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting a test key");
    }
    key
}

/// A vector file's raw key bytes as MAC-key material, promoted as [`cipher_key`] promotes.
pub fn mac_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::MACKey)
        .expect("key bytes fit the buffer");
    if key.key_type() != KeyType::MACKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::MACKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting a test key");
    }
    key
}
