//! ML-KEM with its shared secret derived through a KDF: the algorithm markers, and the pairing
//! of a parameter set with its KDF that the two ML-KEM crates implement the KEM roles over, with
//! [`KdfParams`] as the parameters.
//!
//! The derived key is KDF(𝐾, info), of the length the parameters name: 𝐾 is the shared secret
//! key of FIPS 203 Algorithm 17 (ML-KEM.Encaps_internal), the KDF's input key material, and the
//! KDF's description, the info and the length are the caller's [`KdfParams`], the length anything
//! from one byte to 255 hash outputs (RFC 5869 Section 2.3), checked when a worker is made or a
//! derivation compiled. For the HKDF pairings that is HKDF-Hash(salt, 𝐾, info), the salt the
//! description names ([`HkdfDescription`]), readable there by a key that cannot run the
//! derivation itself. The length is part of the protocol's
//! agreement as the info is, and it is not folded into the info: the key at one length is a
//! prefix of the key at a longer one under the same info (RFC 5869 Section 2.3), so a protocol
//! that wants two keys from one encapsulation gives them two infos, not two lengths (SP 800-56C
//! Rev. 2 Section 4.1 puts `L` in `FixedInfo` for that reason). The ciphertext is not fed into the
//! info: Algorithm 17 line 1 derives 𝐾 as part of G(𝑚‖H(ek)) and line 2 derives 𝑐 from the same
//! 𝑚 and ek, so 𝐾 is already bound to the encapsulation key and the ciphertext.
//!
//! The pairings are [`MLKEM512_HKDF_SHA256`], [`MLKEM768_HKDF_SHA512`] and
//! [`MLKEM1024_HKDF_SHA512`]: the key types of either crate implement the roles over
//! `KdfParams<'p, HkdfDescription<'s, SHA256>, LEN>` for ML-KEM-512 and over
//! `KdfParams<'p, HkdfDescription<'s, SHA512>, LEN>` for the other two, so the parameter type selects the algorithm and the length at the call. A marker's strength is the
//! lesser of the parameter set's and the KDF's, and the derived key carries no more than it, and
//! no more than its length holds (a key under 14 bytes carries none): HKDF credits the
//! 32-byte 𝐾 as seeding it fully, and caps the output at 𝐾's strength; the pairing then caps the
//! label at its own, so a secret salt (SP 800-56C Rev. 2 Section 5.1, a `MACKey`), which HKDF
//! also credits, does not lift the key above what the algorithm claims.

use crate::MLKEM_SS_LEN;
use crate::params::{MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParamsBase};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::kdf_params::{KdfDescription, KdfParams};
use bouncycastle_core::kem_key::KEMAlgorithm;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, KDF};
use bouncycastle_hkdf::HkdfDescription;
use bouncycastle_sha2::hkdf::{HKDF_SHA256, HKDF_SHA512};
use bouncycastle_sha2::{SHA256, SHA512};

/// Algorithm name of ML-KEM-512-HKDF-SHA256, as reported by `Algorithm::ALG_NAME`.
pub const ML_KEM_512_HKDF_SHA256_NAME: &str = "ML-KEM-512-HKDF-SHA256";
/// Algorithm name of ML-KEM-768-HKDF-SHA512.
pub const ML_KEM_768_HKDF_SHA512_NAME: &str = "ML-KEM-768-HKDF-SHA512";
/// Algorithm name of ML-KEM-1024-HKDF-SHA512.
pub const ML_KEM_1024_HKDF_SHA512_NAME: &str = "ML-KEM-1024-HKDF-SHA512";

/// The length the CLI derives for ML-KEM-512-HKDF-SHA256: one SHA-256 output.
pub const MLKEM512_HKDF_SHA256_SS_LEN: usize = 32;
/// The length the CLI derives for ML-KEM-768-HKDF-SHA512: one SHA-512 output.
pub const MLKEM768_HKDF_SHA512_SS_LEN: usize = 64;
/// The length the CLI derives for ML-KEM-1024-HKDF-SHA512: one SHA-512 output.
pub const MLKEM1024_HKDF_SHA512_SS_LEN: usize = 64;

/// The lesser of the KEM's and the KDF's strengths, which is what the pairing can claim.
const fn min_strength(a: SecurityStrength, b: SecurityStrength) -> SecurityStrength {
    if (a as u8) <= (b as u8) { a } else { b }
}

/// ML-KEM-512 with the shared secret derived through HKDF-SHA256: the algorithm a plain
/// ML-KEM-512 key runs when made into a worker from `KdfParams<'p, HkdfDescription<'s, SHA256>, LEN>`.
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
/// ML-KEM-768 key runs when made into a worker from `KdfParams<'p, HkdfDescription<'s, SHA512>, LEN>`.
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
/// ML-KEM-1024 key runs when made into a worker from `KdfParams<'p, HkdfDescription<'s, SHA512>, LEN>`.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM1024_HKDF_SHA512;

impl Algorithm for MLKEM1024_HKDF_SHA512 {
    const ALG_NAME: &'static str = ML_KEM_1024_HKDF_SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength =
        min_strength(MLKEM1024Params::MAX_SECURITY_STRENGTH, HKDF_SHA512::MAX_SECURITY_STRENGTH);
}

impl KEMAlgorithm for MLKEM1024_HKDF_SHA512 {}

/// A KDF the library pairs ML-KEM with, by its description: HKDF-SHA256 and HKDF-SHA512. Sealed, so that the pairing trait,
/// which is generic over the KDF, cannot be implemented outside this crate: the orphan rule
/// would otherwise let a downstream crate pair a parameter set with a KDF of its own, under any
/// name and strength, and the blanket role impls of both ML-KEM crates would take it.
pub trait PairedKdf: sealed::Sealed {
    /// The most bytes one derivation produces: 255 hash outputs for HKDF (RFC 5869 Section 2.3).
    const MAX_LEN: usize;
}

impl PairedKdf for HkdfDescription<'_, SHA256> {
    const MAX_LEN: usize = 255 * SHA256::OUTPUT_LEN;
}
impl PairedKdf for HkdfDescription<'_, SHA512> {
    const MAX_LEN: usize = 255 * SHA512::OUTPUT_LEN;
}

mod sealed {
    use bouncycastle_hkdf::HkdfDescription;
    use bouncycastle_sha2::{SHA256, SHA512};
    pub trait Sealed {}
    impl Sealed for HkdfDescription<'_, SHA256> {}
    impl Sealed for HkdfDescription<'_, SHA512> {}
}

/// A parameter set paired with its KDF: `P: MLKEMKdfPairing<D, SS_LEN>` has one solution per
/// parameter set and length, so a role impl generic over `D` and `SS_LEN` and bound on it takes
/// both from the parameter type, `KdfParams<'p, D, SS_LEN>`. The length is the caller's, from one
/// byte to the KDF's [`PairedKdf::MAX_LEN`], checked by [`MLKEMKdfPairing::LEN_CHECK`] when a
/// worker is made or a derivation compiled. Sealed on both sides,
/// through [`MLKEMParamsBase`] and [`PairedKdf`]; the three impls are the pairings the library
/// supports, so a key under a KDF it is not paired with has no role, and
/// `pk.encaps(&mut rng, params)` with the wrong `KdfParams` is a compile error. The derivation
/// is the same for every pairing, so it is provided here.
pub trait MLKEMKdfPairing<D: KdfDescription + PairedKdf + ?Sized, const SS_LEN: usize>:
    MLKEMParamsBase
{
    /// The algorithm the pairing is.
    type Algorithm: KEMAlgorithm;

    /// The length check, a compile-time error where it is evaluated: `SS_LEN` is from one byte
    /// to the KDF's [`PairedKdf::MAX_LEN`]. The role impls evaluate it when a worker is made,
    /// and [`derive`](Self::derive) does, so no worker exists at a length no derivation accepts.
    const LEN_CHECK: () = assert!(
        SS_LEN > 0 && SS_LEN <= D::MAX_LEN,
        "the derived key is from one byte to the KDF's MAX_LEN long"
    );

    /// KDF(𝐾, info) into `out`, zeroized first: a key of `SS_LEN` bytes, labelled at no more
    /// than the algorithm's strength. The caller's buffer is where the key lives, so its length
    /// costs the caller's frame.
    ///
    /// # Errors
    /// [`KEMError::KDFError`] with what the KDF refused, building the engine from the
    /// description or deriving; [`KEMError::GenericError`] if it writes anything but `SS_LEN`
    /// bytes. `out` is left zeroized.
    fn derive(
        params: KdfParams<'_, D, SS_LEN>,
        K: &KeyMaterial<MLKEM_SS_LEN>,
        out: &mut KeyMaterial<SS_LEN>,
    ) -> Result<(), KEMError> {
        const { Self::LEN_CHECK };
        out.zeroize();
        // The engine is built from the description for this derivation: for HKDF, an instance
        // keyed with the salt. `derive_key_out` zeroizes `out` first and leaves it so on its
        // errors.
        let kdf = params.kdf().engine().map_err(KEMError::KDFError)?;
        let written =
            kdf.derive_key_out(K, params.info(), SS_LEN, out).map_err(KEMError::KDFError)?;
        // The trait says `len` bytes come back; the key the worker hands out is SS_LEN bytes.
        if written != SS_LEN || out.key_len() != SS_LEN {
            out.zeroize();
            return Err(KEMError::GenericError("the KDF derived a key of the wrong length"));
        }
        // The label is the pairing's: HKDF credits a secret salt and would label the key above
        // the KEM's strength, which this algorithm does not claim. Lowering needs no window.
        let strength =
            min_strength(out.security_strength(), Self::Algorithm::MAX_SECURITY_STRENGTH);
        if out.set_security_strength(strength).is_err() {
            out.zeroize();
            return Err(KEMError::GenericError("the derived key's strength could not be set"));
        }
        Ok(())
    }
}

impl<const SS_LEN: usize> MLKEMKdfPairing<HkdfDescription<'_, SHA256>, SS_LEN> for MLKEM512Params {
    type Algorithm = MLKEM512_HKDF_SHA256;
}

impl<const SS_LEN: usize> MLKEMKdfPairing<HkdfDescription<'_, SHA512>, SS_LEN> for MLKEM768Params {
    type Algorithm = MLKEM768_HKDF_SHA512;
}

impl<const SS_LEN: usize> MLKEMKdfPairing<HkdfDescription<'_, SHA512>, SS_LEN> for MLKEM1024Params {
    type Algorithm = MLKEM1024_HKDF_SHA512;
}
