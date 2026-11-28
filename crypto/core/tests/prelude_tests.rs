//! `bouncycastle_core::prelude` alone brings the RNG and key material methods into scope. The
//! family crates' `prelude_tests` cover the key and worker roles, which need an algorithm.

use bouncycastle_core::key_material::KeyMaterial256;
use bouncycastle_core::prelude::*;
use bouncycastle_rng::HashDRBG_SHA512;

#[test]
fn rng_and_key_material_methods_resolve() {
    let mut rng = HashDRBG_SHA512::new_from_os();

    // `RNG` and `RNGExt`.
    let mut out = [0u8; 32];
    assert_eq!(rng.next_bytes_out(&mut out).unwrap(), 32);
    let drawn: [u8; 32] = rng.next_array().unwrap();
    assert_ne!(drawn, out);

    // `KeyMaterialTrait`.
    let key = KeyMaterial256::from_rng(&mut rng).unwrap();
    assert_eq!(key.key_len(), 32);
    assert!(key.is_full_entropy());
}
