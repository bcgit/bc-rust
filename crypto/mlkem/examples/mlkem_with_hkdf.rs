//! ML-KEM-768 with its shared secret derived through HKDF-SHA512: `MLKEM768_HKDF_SHA512` on
//! plain ML-KEM-768 keys, with the HKDF description and info as the parameters the KEM roles are
//! made from. See `bouncycastle_mlkem_common::kdf` for what is derived.
//!
//! Run with `cargo run -p bouncycastle-mlkem --example mlkem_with_hkdf`.

// `K` is FIPS 203's name for the shared secret key.
#![allow(non_snake_case)]

use bouncycastle_core::kdf_params::{KdfParams, KeyLen};
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::traits::KEMDecapsulator;
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_mlkem::{MLKEM768, MLKEM768_CT_LEN, MLKEMTrait};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::SHA512;

fn main() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();

    // The KDF both parties agree on out of band: HKDF-SHA512 with RFC 5869's salt, described
    // rather than instantiated so a key held in a token could read it, and the info. The KDF type on the parameters is what selects ML-KEM-768-HKDF-SHA512 on these
    // keys. Both parties must hold the same salt: it is not secret (RFC 5869 Section 3.1), so
    // a protocol fixes it or sends it beside the ciphertext; this example draws one and uses it
    // on both sides. A zero-length salt would be RFC 5869's absent one.
    let salt = KeyMaterial::<32>::from_rng(&mut rng).unwrap();
    let hkdf = HkdfDescription::<SHA512>::with_salt(&salt).unwrap();
    let params = KdfParams::new(&hkdf, b"example protocol v1", KeyLen::<64>);

    // One-shots: the parameters name the key's length, 64 bytes here, one SHA-512 output, at
    // ML-KEM-768's 192 bits.
    let (key, ct) = pk.encaps(&mut rng, params).unwrap();
    let key1 = sk.decaps(&ct, params).unwrap();
    assert_eq!(key, key1);
    println!("derived key: {} bytes at {:?}: {key}", key.key_len(), key.security_strength());

    // A worker borrows the key and holds the parameters, fixed in it once.
    let decapsulator = sk.create_decapsulator(params).unwrap();
    assert_eq!(decapsulator.decaps(&ct).unwrap(), key);

    // A different context derives a different key from the same ciphertext.
    let other = KdfParams::new(&hkdf, b"example protocol v2", KeyLen::<64>);
    assert_ne!(sk.decaps(&ct, other).unwrap(), key);

    // A 32-byte key from the same exchange: by RFC 5869 Section 2.3 the OKM is the first L
    // octets of the expand stream, so it is the first half of the 64-byte one. That is why the
    // length is the protocol's to fix along with the info, and why two keys from one exchange
    // take two infos (as `other` above does), never two lengths of one.
    let short = KdfParams::new(&hkdf, b"example protocol v1", KeyLen::<32>);
    let key32 = sk.decaps(&ct, short).unwrap();
    assert_eq!(key32.ref_to_bytes(), &key.ref_to_bytes()[..32]);
    println!("derived key: {} bytes at {:?}", key32.key_len(), key32.security_strength());

    // The `_out` forms write into buffers the caller owns, zeroized first: the ciphertext and
    // the derived key on encapsulation, the key on decapsulation. Where the key lives is then
    // the caller's choice, which is what a long `KeyLen` or a small stack wants.
    let mut ct_out = [0u8; MLKEM768_CT_LEN];
    let mut key_a = KeyMaterial::<64>::new();
    let written = pk.encaps_out(&mut rng, params, &mut ct_out, &mut key_a).unwrap();
    assert_eq!(written, MLKEM768_CT_LEN);
    let mut key_b = KeyMaterial::<64>::new();
    let decapsulator = sk.create_decapsulator(params).unwrap();
    assert_eq!(decapsulator.decaps_out(&ct_out, &mut key_b).unwrap(), 64);
    assert_eq!(key_a, key_b);
    println!("derived key, _out: {key_b}");

    // The same key pair still runs plain ML-KEM-768, with `()` selecting it.
    let (K, ct) = pk.encaps(&mut rng, ()).unwrap();
    assert_eq!(sk.decaps(&ct, ()).unwrap(), K);
    println!("plain ML-KEM secret: {K}");
}
