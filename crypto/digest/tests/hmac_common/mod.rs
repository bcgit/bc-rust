//! Helpers shared by the hmac module's known-answer test files.

use bouncycastle_core::hex;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::symmetric_key::FromAnyKeyMaterial;
use bouncycastle_core_test_framework::from_key_material::TestFrameworkFromAnyKeyMaterial;
use bouncycastle_core_test_framework::mac::TestFrameworkMAC;
use bouncycastle_digest::hmac::{HMACParams, HmacKey};

/// What `TestFrameworkMAC::test_mac` ran per vector: the key built with the weak form (the RFC
/// vectors' short keys are below the HMAC's strength), its workers against the vector, and the
/// key policy.
pub fn test_hmac<const N: usize, H: HMACParams<MACKey = KeyMaterial<N>>>(
    key: &impl KeyMaterialTrait,
    input: &[u8],
    expected: &[u8],
) {
    let expected: &[u8; N] = expected.try_into().expect("the hash's output length");
    let hmac_key = HmacKey::<H>::from_key_material_allow_weak(key).unwrap();
    TestFrameworkMAC::new().test_mac_key(&hmac_key, input, expected);
    TestFrameworkFromAnyKeyMaterial::new().test::<N, HmacKey<H>>(key);
}

/// A tag from hex, as the array the roles take.
pub fn arr<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().expect("the expected length")
}
