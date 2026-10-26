//! Shared plumbing for the CMAC vector suites: building `KeyType::MACKey` material from raw key
//! bytes, including the all-zero keys the sets include, which `KeyMaterial` tags `Zeroized` and
//! will not promote outside a `do_hazardous_operations` closure.

#![allow(dead_code)]

use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;

pub fn mac_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
    assert_eq!(bytes.len(), N, "key length should match the parameter set");
    let mut key = KeyMaterial::<N>::from_bytes_as_type(bytes, KeyType::MACKey)
        .expect("key bytes fit the buffer");
    if key.key_type() != KeyType::MACKey {
        do_hazardous_operations(&mut key, |k| {
            k.set_key_type(KeyType::MACKey)?;
            k.set_security_strength(SecurityStrength::from_bytes(N))
        })
        .expect("promoting an all-zero test key");
    }
    key
}
