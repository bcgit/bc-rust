//! ECC CDH over P-256 through the key-agreement roles: two parties make keys and agree on `Z`,
//! a static key keeps its worker, and the same keys derive a key through HKDF-SHA256 as
//! `ECCDHP256_HKDF_SHA256` and through the X9.63 KDF as `ECCDHP256_X963KDF_SHA256`.
//!
//! Run with `cargo run -p bouncycastle-eccdh --example p256_key_agreement`.

use bouncycastle_core::agreement_key::AgreementKey;
use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::traits::KeyAgreement;
use bouncycastle_eccdh::keys_p256::keygen;
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::hkdf::HKDF_SHA256;
use bouncycastle_x963kdf::X963KDF_SHA256;

fn main() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk_a, sk_a) = keygen(&mut rng).unwrap();
    let (pk_b, sk_b) = keygen(&mut rng).unwrap();

    // ECC CDH: each side's private key with the other's public key gives the same Z, typed
    // SharedSecret at the curve's strength. It is keying material for a KDF, not a key.
    let z_a = sk_a.agree(&pk_b, ()).unwrap();
    let z_b = sk_b.agree(&pk_a, ()).unwrap();
    assert!(z_a.equals(&z_b));
    println!("Z: {z_a}");

    // A static key keeps its worker and uses it against every peer.
    let agreement_a = sk_a.create_agreement(()).unwrap();
    assert!(agreement_a.agree(&pk_b).unwrap().equals(&z_a));

    // The same keys under HKDF-SHA256: the KDF type on the parameters selects the algorithm
    // and the KeyLen the key's length, and the result is a key, HKDF-SHA256(salt, Z, info)
    // with the salt the instance's.
    let salt = KeyMaterial::<32>::from_rng(&mut rng).unwrap();
    let hkdf = HKDF_SHA256::new_with_salt(&salt).unwrap();
    let params = KdfParams::new(&hkdf, b"example protocol v1", KeyLen::<32>);
    let key_a = sk_a.agree(&pk_b, params).unwrap();
    let key_b = sk_b.agree(&pk_a, params).unwrap();
    assert!(key_a.equals(&key_b));
    println!("HKDF-SHA256 over Z: {key_a}");

    // Or SEC 1 Section 6.1's ECDH scheme, the X9.63 KDF with its SharedInfo, on the same keys.
    let x963kdf = X963KDF_SHA256::new();
    let params = KdfParams::new(&x963kdf, b"example protocol v1", KeyLen::<32>);
    let key_a = sk_a.agree(&pk_b, params).unwrap();
    assert!(key_a.equals(&sk_b.agree(&pk_a, params).unwrap()));
    println!("X9.63 KDF over Z: {key_a}");
}
