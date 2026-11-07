//! ML-KEM-768 with its shared secret derived through HKDF-SHA256: the parameter mechanism of
//! `bouncycastle_core::kem_key` over a real KDF.
//!
//! ML-KEM's own output is uniform, so its role impls take `()`. A protocol that wants the KEM's
//! output run through a KDF with its own salt and context implements the roles a second time on
//! the same keys, over the HKDF configuration the caller holds as the parameter type and naming
//! `MLKEM768_HKDF_SHA256` as the algorithm. One key pair then serves both algorithms, the
//! parameter type picks between them at the call, and the two sides of the exchange are made to
//! pass the same kind of parameters.
//!
//! The derived key reports 128 bits, not ML-KEM-768's 192: HKDF caps its output at half the
//! hash's output length, and HKDF-SHA384 would credit a 32-byte IKM as less than fully seeded
//! (its rule is at least `OUTPUT_LEN` typed bytes) and return `Unknown`. A KDF-bearing KEM in
//! the library will have to settle that accounting; this example only shows the plumbing.
//!
//! Run with `cargo run -p bouncycastle-mlkem --example mlkem_with_hkdf`.

// `K` is FIPS 203's name for the shared secret key.
#![allow(non_snake_case)]

use bouncycastle_core::errors::KEMError;
use bouncycastle_core::kem_key::{DecapsulatingKey, EncapsulatingKey, KEMAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, KEMDecapsulator, KEMEncapsulator, RNG};
use bouncycastle_mlkem::{
    MLKEM_SS_LEN, MLKEM768, MLKEM768_CT_LEN, MLKEM768PrivateKey, MLKEM768PublicKey, MLKEMTrait,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::hkdf::HKDF_SHA256;

/// The length of the derived key this marker produces. A marker fixes it; a protocol wanting
/// another length is another marker instantiation.
const DERIVED_LEN: usize = 32;

/// The HKDF configuration a worker is made from: RFC 5869's salt and info, borrowed from the
/// caller for `'p`. `Copy` so that the one value serves every construction.
#[derive(Clone, Copy)]
struct HkdfParams<'p> {
    salt: &'p KeyMaterial<32>,
    info: &'p [u8],
}

/// The marker: ML-KEM-768 whose shared secret is HKDF-SHA256(salt, K, info || ct).
#[allow(non_camel_case_types)]
struct MLKEM768_HKDF_SHA256;

impl Algorithm for MLKEM768_HKDF_SHA256 {
    const ALG_NAME: &'static str = "ML-KEM-768-HKDF-SHA256";
    const MAX_SECURITY_STRENGTH: SecurityStrength = MLKEM768::MAX_SECURITY_STRENGTH;
}

impl KEMAlgorithm for MLKEM768_HKDF_SHA256 {}

/// Both workers: the ML-KEM key, borrowed for `'k`, and the HKDF configuration, for `'p`.
struct HkdfWorker<'k, 'p, K> {
    key: &'k K,
    params: HkdfParams<'p>,
}

impl<K> Algorithm for HkdfWorker<'_, '_, K> {
    const ALG_NAME: &'static str = MLKEM768_HKDF_SHA256::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = MLKEM768_HKDF_SHA256::MAX_SECURITY_STRENGTH;
}

/// HKDF-SHA256 over the ML-KEM secret `K`, with the ciphertext bound into the info so that the
/// derived key is tied to this encapsulation (the KEM context of RFC 9180 Section 4.1).
fn derive(
    params: HkdfParams<'_>,
    K: &KeyMaterial<MLKEM_SS_LEN>,
    ct: &[u8; MLKEM768_CT_LEN],
) -> Result<KeyMaterial<DERIVED_LEN>, KEMError> {
    let mut info = Vec::with_capacity(params.info.len() + ct.len());
    info.extend_from_slice(params.info);
    info.extend_from_slice(ct);

    let mut okm = KeyMaterial::<DERIVED_LEN>::new();
    HKDF_SHA256::extract_and_expand_out(params.salt, K, &info, DERIVED_LEN, &mut okm)
        .map_err(|_| KEMError::GenericError("HKDF failed"))?;
    Ok(okm)
}

impl KEMEncapsulator<MLKEM768_CT_LEN, DERIVED_LEN> for HkdfWorker<'_, '_, MLKEM768PublicKey> {
    fn encaps_out(
        &self,
        rng: &mut dyn RNG,
        ct: &mut [u8; MLKEM768_CT_LEN],
    ) -> Result<(KeyMaterial<DERIVED_LEN>, usize), KEMError> {
        // The plain ML-KEM path on the same key: `()` selects it.
        let (K, written) = self.key.encaps_out(rng, (), ct)?;
        Ok((derive(self.params, &K, ct)?, written))
    }
}

impl KEMDecapsulator<MLKEM768_CT_LEN, DERIVED_LEN> for HkdfWorker<'_, '_, MLKEM768PrivateKey> {
    fn decaps(&self, ct: &[u8; MLKEM768_CT_LEN]) -> Result<KeyMaterial<DERIVED_LEN>, KEMError> {
        let K = self.key.decaps((), ct)?;
        derive(self.params, &K, ct)
    }
}

impl<'p> EncapsulatingKey<HkdfParams<'p>, MLKEM768_CT_LEN, DERIVED_LEN> for MLKEM768PublicKey {
    type Algorithm = MLKEM768_HKDF_SHA256;
    type Encapsulator<'k> = HkdfWorker<'k, 'p, MLKEM768PublicKey>;

    fn create_encapsulator<'k>(
        &'k self,
        params: HkdfParams<'p>,
    ) -> Result<Self::Encapsulator<'k>, KEMError> {
        // Where a KDF-bearing KEM validates its parameters: HKDF refuses a salt of unknown
        // provenance, and this is the one place to say so before any encapsulation.
        if params.salt.key_type() == KeyType::Unknown {
            return Err(KEMError::GenericError("the HKDF salt must be typed key material"));
        }
        Ok(HkdfWorker { key: self, params })
    }
}

impl<'p> DecapsulatingKey<HkdfParams<'p>, MLKEM768_CT_LEN, DERIVED_LEN> for MLKEM768PrivateKey {
    type Algorithm = MLKEM768_HKDF_SHA256;
    type Decapsulator<'k> = HkdfWorker<'k, 'p, MLKEM768PrivateKey>;

    fn create_decapsulator<'k>(
        &'k self,
        params: HkdfParams<'p>,
    ) -> Result<Self::Decapsulator<'k>, KEMError> {
        if params.salt.key_type() == KeyType::Unknown {
            return Err(KEMError::GenericError("the HKDF salt must be typed key material"));
        }
        Ok(HkdfWorker { key: self, params })
    }
}

fn main() {
    let mut rng = HashDRBG_SHA512::new_from_os();
    let (pk, sk) = MLKEM768::keygen(&mut rng).unwrap();

    // The HKDF configuration both parties agree on out of band.
    let salt = KeyMaterial::<32>::from_rng(&mut rng).unwrap();
    let params = HkdfParams { salt: &salt, info: b"example protocol v1" };

    // One-shots: the parameter type says which algorithm, so nothing else needs naming.
    let (key, ct) = pk.encaps(&mut rng, params).unwrap();
    let key1 = sk.decaps(params, &ct).unwrap();
    assert_eq!(key, key1);
    println!("derived key: {key}");

    // A static key holds its worker; the parameters are fixed in it once.
    let decapsulator = sk.create_decapsulator(params).unwrap();
    assert_eq!(decapsulator.decaps(&ct).unwrap(), key);

    // A different context derives a different key from the same ciphertext.
    let other = HkdfParams { salt: &salt, info: b"example protocol v2" };
    assert_ne!(sk.decaps(other, &ct).unwrap(), key);

    // The same key pair still runs plain ML-KEM-768, with `()` selecting it.
    let (K, ct) = pk.encaps(&mut rng, ()).unwrap();
    assert_eq!(sk.decaps((), &ct).unwrap(), K);
    println!("plain ML-KEM secret: {K}");
}
