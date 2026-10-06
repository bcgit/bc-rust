//! Shared plumbing for every known-answer suite in this crate that reads `bc-test-data`'s ACVP
//! JSON: decoding a hex field, and building a `KeyMaterial` from the raw key bytes. The per-mode
//! suites differ only in how they run a case, so that part stays with each of them.
//!
//! Included via `#[path = "common/acvp_helpers.rs"]` rather than through `mod common;`, for the
//! reason `gcm_bc-test-data.rs` gives: the `serde_json::Value` import here makes `u8: PartialEq<_>`
//! ambiguous at every bare `assert_eq!(byte_array, [])` in the files that share `common/mod.rs`.

#![allow(dead_code)]

use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_hex as hex;
use serde_json::Value;

/// Builds a `KeyMaterial` from raw ACVP key bytes, including the all-zero keys.
///
/// The ACVP sets deliberately include an all-zero key. `KeyMaterial` tags an all-zero buffer as
/// `KeyType::Zeroized` and will not promote it outside a `do_hazardous_operations` closure, which
/// is the right default -- so this opts in explicitly rather than the engine weakening its guard.
pub fn cipher_key<const N: usize>(bytes: &[u8]) -> KeyMaterial<N> {
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
}

/// The hex-encoded `field` of one test case, decoded; a missing field or bad hex names the case.
pub fn decode(value: &Value, field: &str, tc_id: u64) -> Vec<u8> {
    let s = value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("tcId {tc_id}: missing field {field}"));
    hex::decode(s).unwrap_or_else(|_| panic!("tcId {tc_id}: bad hex in {field}"))
}
