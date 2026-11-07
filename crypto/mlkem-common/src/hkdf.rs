//! ML-KEM with its shared secret derived through HKDF: the algorithm markers, and the pairing of
//! a parameter set with the hash of its HKDF that the two ML-KEM crates implement the KEM roles
//! over, with [`HkdfParams`] as the parameters.
//!
//! The derived key is HKDF-Hash(salt, 𝐾, info): 𝐾 is the shared secret key of FIPS 203 Algorithm
//! 17 (ML-KEM.Encaps_internal), the salt and info are the caller's [`HkdfParams`], and the length
//! is one hash output. The ciphertext is not fed into the info: Algorithm 17 line 1 derives 𝐾 as
//! part of G(𝑚‖H(ek)) and line 2 derives 𝑐 from the same 𝑚 and ek, so 𝐾 is already bound to the
//! encapsulation key and the ciphertext.
//!
//! The pairings are [`MLKEM512_HKDF_SHA256`], [`MLKEM768_HKDF_SHA512`] and
//! [`MLKEM1024_HKDF_SHA512`]: the key types of either crate implement the roles over
//! `HkdfParams<'p, SHA256>` for ML-KEM-512 and over `HkdfParams<'p, SHA512>` for the other two, so
//! the parameter type selects the algorithm at the call. A marker's strength is the lesser of the
//! parameter set's and the HKDF's, and the derived key carries it: HKDF credits the 32-byte 𝐾 as
//! seeding it fully, and caps the output at 𝐾's strength.

use crate::MLKEM_SS_LEN;
use crate::params::{MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParamsBase};
use bouncycastle_core::errors::{KEMError, KeyMaterialError};
use bouncycastle_core::kem_key::KEMAlgorithm;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
use bouncycastle_hkdf::HkdfParams;
use bouncycastle_hmac::HMACParams;
use bouncycastle_sha2::hkdf::{HKDF_SHA256, HKDF_SHA512};
use bouncycastle_sha2::{SHA256, SHA512};

/// Algorithm name of ML-KEM-512-HKDF-SHA256, as reported by `Algorithm::ALG_NAME`.
pub const ML_KEM_512_HKDF_SHA256_NAME: &str = "ML-KEM-512-HKDF-SHA256";
/// Algorithm name of ML-KEM-768-HKDF-SHA512.
pub const ML_KEM_768_HKDF_SHA512_NAME: &str = "ML-KEM-768-HKDF-SHA512";
/// Algorithm name of ML-KEM-1024-HKDF-SHA512.
pub const ML_KEM_1024_HKDF_SHA512_NAME: &str = "ML-KEM-1024-HKDF-SHA512";

/// Length of the key ML-KEM-512-HKDF-SHA256 derives: one SHA-256 output.
pub const MLKEM512_HKDF_SHA256_SS_LEN: usize = 32;
/// Length of the key ML-KEM-768-HKDF-SHA512 derives: one SHA-512 output.
pub const MLKEM768_HKDF_SHA512_SS_LEN: usize = 64;
/// Length of the key ML-KEM-1024-HKDF-SHA512 derives: one SHA-512 output.
pub const MLKEM1024_HKDF_SHA512_SS_LEN: usize = 64;

/// The lesser of the KEM's and the KDF's strengths, which is what the pairing can claim.
const fn min_strength(a: SecurityStrength, b: SecurityStrength) -> SecurityStrength {
    if (a as u8) <= (b as u8) { a } else { b }
}

/// ML-KEM-512 with the shared secret derived through HKDF-SHA256: the algorithm a plain
/// ML-KEM-512 key runs when made into a worker from `HkdfParams<'p, SHA256>`.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM512_HKDF_SHA256;

impl Algorithm for MLKEM512_HKDF_SHA256 {
    const ALG_NAME: &'static str = ML_KEM_512_HKDF_SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(MLKEM512Params::MAX_SECURITY_STRENGTH, HKDF_SHA256::MAX_SECURITY_STRENGTH);
}

impl KEMAlgorithm for MLKEM512_HKDF_SHA256 {}

/// ML-KEM-768 with the shared secret derived through HKDF-SHA512: the algorithm a plain
/// ML-KEM-768 key runs when made into a worker from `HkdfParams<'p, SHA512>`.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM768_HKDF_SHA512;

impl Algorithm for MLKEM768_HKDF_SHA512 {
    const ALG_NAME: &'static str = ML_KEM_768_HKDF_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(MLKEM768Params::MAX_SECURITY_STRENGTH, HKDF_SHA512::MAX_SECURITY_STRENGTH);
}

impl KEMAlgorithm for MLKEM768_HKDF_SHA512 {}

/// ML-KEM-1024 with the shared secret derived through HKDF-SHA512: the algorithm a plain
/// ML-KEM-1024 key runs when made into a worker from `HkdfParams<'p, SHA512>`.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM1024_HKDF_SHA512;

impl Algorithm for MLKEM1024_HKDF_SHA512 {
    const ALG_NAME: &'static str = ML_KEM_1024_HKDF_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(MLKEM1024Params::MAX_SECURITY_STRENGTH, HKDF_SHA512::MAX_SECURITY_STRENGTH);
}

impl KEMAlgorithm for MLKEM1024_HKDF_SHA512 {}

/// A parameter set paired with the hash of its HKDF: `P: MLKEMHkdfPairing<H, SS_LEN>` has one
/// solution per parameter set, so a role impl generic over `H` and `SS_LEN` and bound on it
/// infers both from `P` and the parameter type, as `CiphertextLen` does for the ciphertext.
/// Sealed through [`MLKEMParamsBase`]; the three impls are the pairings the library supports,
/// so a key under a hash it is not paired with has no role, and `pk.encaps(&mut rng, params)`
/// with the wrong `HkdfParams` is a compile error.
pub trait MLKEMHkdfPairing<H: HMACParams, const SS_LEN: usize>: MLKEMParamsBase {
    /// The algorithm the pairing is.
    type Algorithm: KEMAlgorithm;

    /// HKDF-Hash(salt, 𝐾, info) into a key of `SS_LEN` bytes, one hash output.
    ///
    /// # Errors
    /// [`KEMError::KeyMaterialError`] for a salt HKDF refuses, which [`check_salt`] catches at
    /// construction.
    fn derive(
        params: HkdfParams<'_, H>,
        K: &KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<KeyMaterial<SS_LEN>, KEMError>;
}

impl MLKEMHkdfPairing<SHA256, MLKEM512_HKDF_SHA256_SS_LEN> for MLKEM512Params {
    type Algorithm = MLKEM512_HKDF_SHA256;

    fn derive(
        params: HkdfParams<'_, SHA256>,
        K: &KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<KeyMaterial<MLKEM512_HKDF_SHA256_SS_LEN>, KEMError> {
        let mut okm = KeyMaterial::new();
        HKDF_SHA256::extract_and_expand_out(
            params.salt(),
            K,
            params.info(),
            MLKEM512_HKDF_SHA256_SS_LEN,
            &mut okm,
        )
        .map_err(|_| KEMError::GenericError("HKDF-SHA256 over the ML-KEM secret failed"))?;
        Ok(okm)
    }
}

impl MLKEMHkdfPairing<SHA512, MLKEM768_HKDF_SHA512_SS_LEN> for MLKEM768Params {
    type Algorithm = MLKEM768_HKDF_SHA512;

    fn derive(
        params: HkdfParams<'_, SHA512>,
        K: &KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<KeyMaterial<MLKEM768_HKDF_SHA512_SS_LEN>, KEMError> {
        let mut okm = KeyMaterial::new();
        HKDF_SHA512::extract_and_expand_out(
            params.salt(),
            K,
            params.info(),
            MLKEM768_HKDF_SHA512_SS_LEN,
            &mut okm,
        )
        .map_err(|_| KEMError::GenericError("HKDF-SHA512 over the ML-KEM secret failed"))?;
        Ok(okm)
    }
}

impl MLKEMHkdfPairing<SHA512, MLKEM1024_HKDF_SHA512_SS_LEN> for MLKEM1024Params {
    type Algorithm = MLKEM1024_HKDF_SHA512;

    fn derive(
        params: HkdfParams<'_, SHA512>,
        K: &KeyMaterial<MLKEM_SS_LEN>,
    ) -> Result<KeyMaterial<MLKEM1024_HKDF_SHA512_SS_LEN>, KEMError> {
        let mut okm = KeyMaterial::new();
        HKDF_SHA512::extract_and_expand_out(
            params.salt(),
            K,
            params.info(),
            MLKEM1024_HKDF_SHA512_SS_LEN,
            &mut okm,
        )
        .map_err(|_| KEMError::GenericError("HKDF-SHA512 over the ML-KEM secret failed"))?;
        Ok(okm)
    }
}

/// Where a KDF-bearing KEM validates its parameters, at construction: HKDF refuses a salt of
/// [`KeyType::Unknown`] (bytes of unknown provenance are not promoted to a key outside hazmat),
/// and a worker says so once, when it is made, rather than at every encapsulation.
///
/// # Errors
/// [`KEMError::KeyMaterialError`] with [`KeyMaterialError::InvalidKeyType`] for such a salt.
pub fn check_salt<H: HMACParams>(params: &HkdfParams<'_, H>) -> Result<(), KEMError> {
    if params.salt().key_type() == KeyType::Unknown {
        return Err(KEMError::KeyMaterialError(KeyMaterialError::InvalidKeyType(
            "the HKDF salt must not be KeyType::Unknown",
        )));
    }
    Ok(())
}
