//! ML-KEM-768 with its shared secret derived through HKDF-SHA512: `MLKEM768_HKDF_SHA512` on
//! plain ML-KEM-768 keys, with the HKDF configuration as the parameters the KEM roles are made
//! from. See `bouncycastle_mlkem_common::hkdf` for what is derived.
//!
//! Run with `cargo run -p bouncycastle-mlkem --example mlkem_with_hkdf`.

// `K` is FIPS 203's name for the shared secret key.
#![allow(non_snake_case)]

use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::traits::KEMDecapsulator;
use bouncycastle_mlkem::{HkdfParams, MLKEM768, MLKEMTrait};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::SHA512;

fn main() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();

    // The HKDF configuration both parties agree on out of band: RFC 5869's salt and info. The
    // hash on the parameter type is what selects ML-KEM-768-HKDF-SHA512 on these keys; a
    // zero-length salt would be RFC 5869's absent one.
    let salt = KeyMaterial::<32>::from_rng(&mut rng).unwrap();
    let params = HkdfParams::<SHA512>::new(&salt, b"example protocol v1");

    // One-shots: a 64-byte key, one SHA-512 output, at ML-KEM-768's 192 bits.
    let (key, ct) = pk.encaps(&mut rng, params).unwrap();
    let key1 = sk.decaps(&ct, params).unwrap();
    assert_eq!(key, key1);
    println!("derived key: {} bytes at {:?}: {key}", key.key_len(), key.security_strength());

    // A static key holds its worker; the parameters are fixed in it once.
    let decapsulator = sk.create_decapsulator(params).unwrap();
    assert_eq!(decapsulator.decaps(&ct).unwrap(), key);

    // A different context derives a different key from the same ciphertext.
    let other = HkdfParams::<SHA512>::new(&salt, b"example protocol v2");
    assert_ne!(sk.decaps(&ct, other).unwrap(), key);

    // The same key pair still runs plain ML-KEM-768, with `()` selecting it.
    let (K, ct) = pk.encaps(&mut rng, ()).unwrap();
    assert_eq!(sk.decaps(&ct, ()).unwrap(), K);
    println!("plain ML-KEM secret: {K}");
}
