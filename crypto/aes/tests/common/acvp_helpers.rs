//! Shared plumbing for every known-answer suite in this crate that reads `bc-test-data`'s ACVP
//! JSON: building a `KeyMaterial` from the raw key bytes. The per-mode suites differ only in how
//! they run a case, so that part stays with each of them.

#![allow(dead_code)]

use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::SymmetricCipherKey;

/// Builds a `KeyMaterial` from raw ACVP key bytes, including the all-zero keys.
///
/// The ACVP sets deliberately include an all-zero key. `KeyMaterial` tags an all-zero buffer as
/// `KeyType::Zeroized` and will not promote it outside a `do_hazardous_operations` closure, which
/// is the right default -- so this opts in explicitly rather than the engine weakening its guard.
pub fn cipher_key<K: SymmetricCipherKey<N>, const N: usize>(bytes: &[u8]) -> K {
    K::from_keymaterial({
        assert_eq!(bytes.len(), N, "key length should match the parameter set");
        let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)
            .expect("ACVP key bytes fit the buffer");
        if key.key_type() != KeyType::SymmetricCipherKey {
            do_hazardous_operations(&mut key, |k| {
                k.set_key_type(KeyType::SymmetricCipherKey)?;
                k.set_security_strength(SecurityStrength::from_bytes(N))
            })
            .expect("promoting a NIST all-zero test key");
        }
        key
    })
    .expect("a valid key")
}
