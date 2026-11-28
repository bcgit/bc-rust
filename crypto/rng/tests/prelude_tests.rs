//! `bouncycastle_rng::prelude` brings the DRBG's methods into scope: a caller-seeded DRBG is
//! instantiated, drawn from and reseeded below with no other library trait imported but the
//! hazmat constructor, which the prelude leaves out. Nothing draws from the operating system, so
//! this runs without the `std` feature.

use bouncycastle_core::key_material::{KeyMaterial0, KeyMaterial256, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_rng::HashDRBG_SHA256;
use bouncycastle_rng::hazmat::NewUninitialized;
use bouncycastle_rng::prelude::*;

#[test]
fn drbg() {
    let seed = KeyMaterial256::from_bytes_as_type(&[0x5a; 32], KeyType::Seed).unwrap();
    let mut drbg = HashDRBG_SHA256::new_uninitialized();
    drbg.instantiate(
        false,
        seed,
        &KeyMaterial0::new(),
        b"personalization",
        SecurityStrength::_128bit,
    )
    .unwrap();

    // `Sp80090ADrbg`, then `RNG` and `RNGExt`.
    let mut a = [0u8; 32];
    assert_eq!(drbg.generate_out(&[], &mut a).unwrap(), 32);
    let b: [u8; 32] = drbg.next_array().unwrap();
    assert_ne!(a, b);
    assert_eq!(drbg.security_strength(), SecurityStrength::_128bit);

    let fresh = KeyMaterial256::from_bytes_as_type(&[0xa5; 32], KeyType::Seed).unwrap();
    drbg.reseed(&fresh, &[]).unwrap();
}
