//! This crate's view of the three ML-DSA parameter sets of FIPS 204, Section 4, and the four
//! HashML-DSA pairings built on them, each as a sealed trait with one type per set.
//!
//! The values of Table 1 and Table 2, the algorithm metadata and the derived constants live on
//! [`MLDSAParamsBase`] in `bouncycastle-mldsa-common`, shared with `bouncycastle-mldsa`;
//! [`MLDSAParams`] extends it with the packed-vector buffers this implementation works from. This
//! crate never materializes 𝐀̂ or a whole polynomial vector, so the only parameter-sized types it
//! needs are byte buffers.

use crate::hash_mldsa::{
    HASH_ML_DSA_44_with_SHA256_NAME, HASH_ML_DSA_44_with_SHA512_NAME,
    HASH_ML_DSA_65_with_SHA512_NAME, HASH_ML_DSA_87_with_SHA512_NAME,
};
use crate::mldsa::{MLDSA_SEED_LEN, POLY_T1PACKED_LEN};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, HashOneShot};
use bouncycastle_mldsa_common::params::{ByteBuffer, weaker_of};
use bouncycastle_sha2::{SHA256, SHA512};

pub use bouncycastle_mldsa_common::params::{
    MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParamsBase,
};

/// One ML-DSA parameter set as this crate uses it: everything on [`MLDSAParamsBase`], plus the
/// packed forms of the vectors a key is stored as.
///
/// Sealed through its supertrait, so [`MLDSA44Params`], [`MLDSA65Params`] and [`MLDSA87Params`]
/// are the only implementations.
pub trait MLDSAParams: MLDSAParamsBase {
    /// The length of a private key as this crate stores it: the 32-byte seed 𝜉, for every
    /// parameter set. FIPS 204, Section 4 notes that 𝜉 "is sufficient to generate the other parts
    /// of the private key". The FIPS 204 encoding is [`MLDSAParamsBase::FULL_SK_LEN`] long.
    const SK_LEN: usize = MLDSA_SEED_LEN;

    /// The packed length of the whole of 𝐬1, i.e. all ℓ coordinates.
    const S1_PACKED_LEN: usize = Self::POLY_ETA_PACKED_LEN * Self::l;

    /// The packed length of the whole of 𝐬2, i.e. all 𝑘 coordinates.
    const S2_PACKED_LEN: usize = Self::POLY_ETA_PACKED_LEN * Self::k;

    /// The packed length of the whole of 𝐭1, i.e. 𝑘 coordinates of SimpleBitPack output.
    const T1_PACKED_LEN: usize = POLY_T1PACKED_LEN * Self::k;

    /// The whole of 𝐬1 packed, of [`MLDSAParams::S1_PACKED_LEN`] bytes.
    type S1Packed: ByteBuffer;
    /// The whole of 𝐬2 packed, of [`MLDSAParams::S2_PACKED_LEN`] bytes.
    type S2Packed: ByteBuffer;
    /// The whole of 𝐭1 packed, of [`MLDSAParams::T1_PACKED_LEN`] bytes.
    type T1Packed: ByteBuffer;
}

impl MLDSAParams for MLDSA44Params {
    type S1Packed = [u8; 384]; // 96 * 4
    type S2Packed = [u8; 384]; // 96 * 4
    type T1Packed = [u8; 1280]; // 320 * 4
}

impl MLDSAParams for MLDSA65Params {
    type S1Packed = [u8; 640]; // 128 * 5
    type S2Packed = [u8; 768]; // 128 * 6
    type T1Packed = [u8; 1920]; // 320 * 6
}

impl MLDSAParams for MLDSA87Params {
    type S1Packed = [u8; 672]; // 96 * 7
    type S2Packed = [u8; 768]; // 96 * 8
    type T1Packed = [u8; 2560]; // 320 * 8
}

/// A crate-private (aka "sealed") trait that prevents a new HashML-DSA pairing from being defined
/// outside this crate.
trait HashMLDSAParamsInternalTrait {}

/// One HashML-DSA algorithm: an ML-DSA parameter set paired with a pre-hash function.
///
/// FIPS 204, Algorithm 4 (HashML-DSA.Sign) leaves the choice of PH open, so an instantiation is a
/// pairing rather than a single parameter set. Everything that varies across the pairings lives
/// here, so [`crate::hash_mldsa::HashMLDSA`] takes one type rather than a parameter set plus a
/// hash function plus a digest length.
///
/// Sealed via a private supertrait, so the four types below are the only implementations.
pub trait HashMLDSAParams: HashMLDSAParamsInternalTrait {
    /// The ML-DSA parameter set underneath.
    type MLDSA: MLDSAParams;
    /// PH, the pre-hash function.
    type PreHash: HashOneShot + HashAlgParams + AlgorithmOID;

    /// The algorithm name, as reported by `Algorithm::ALG_NAME`.
    ///
    /// Written out per pairing rather than derived: it is the two component names spliced
    /// together, and `&'static str` cannot be concatenated in a const context.
    const ALG_NAME: &'static str;

    /* Derived. Never written out per pairing. */

    /// The length of the pre-hash `ph`, which is just PH's output length.
    const PH_LEN: usize = <Self::PreHash as HashAlgParams>::OUTPUT_LEN;

    /// The strength claimed for the pairing, as reported by `Algorithm::MAX_SECURITY_STRENGTH`.
    ///
    /// A HashML-DSA signature is no stronger than either of its two components, so this is the
    /// weaker of the two; in every pairing here the ML-DSA parameter set is the binding one.
    const MAX_SECURITY_STRENGTH: SecurityStrength = weaker_of(
        <Self::MLDSA as MLDSAParamsBase>::MAX_SECURITY_STRENGTH,
        <Self::PreHash as Algorithm>::MAX_SECURITY_STRENGTH,
    );
}

/// The HashML-DSA-44_with_SHA256 pairing.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashMLDSA44_with_SHA256Params;
/// The HashML-DSA-44_with_SHA512 pairing.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashMLDSA44_with_SHA512Params;
/// The HashML-DSA-65_with_SHA512 pairing.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashMLDSA65_with_SHA512Params;
/// The HashML-DSA-87_with_SHA512 pairing.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashMLDSA87_with_SHA512Params;

impl HashMLDSAParamsInternalTrait for HashMLDSA44_with_SHA256Params {}
impl HashMLDSAParamsInternalTrait for HashMLDSA44_with_SHA512Params {}
impl HashMLDSAParamsInternalTrait for HashMLDSA65_with_SHA512Params {}
impl HashMLDSAParamsInternalTrait for HashMLDSA87_with_SHA512Params {}

impl HashMLDSAParams for HashMLDSA44_with_SHA256Params {
    type MLDSA = MLDSA44Params;
    type PreHash = SHA256;
    const ALG_NAME: &'static str = HASH_ML_DSA_44_with_SHA256_NAME;
}
impl HashMLDSAParams for HashMLDSA44_with_SHA512Params {
    type MLDSA = MLDSA44Params;
    type PreHash = SHA512;
    const ALG_NAME: &'static str = HASH_ML_DSA_44_with_SHA512_NAME;
}
impl HashMLDSAParams for HashMLDSA65_with_SHA512Params {
    type MLDSA = MLDSA65Params;
    type PreHash = SHA512;
    const ALG_NAME: &'static str = HASH_ML_DSA_65_with_SHA512_NAME;
}
impl HashMLDSAParams for HashMLDSA87_with_SHA512Params {
    type MLDSA = MLDSA87Params;
    type PreHash = SHA512;
    const ALG_NAME: &'static str = HASH_ML_DSA_87_with_SHA512_NAME;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The packed-vector types are written out by hand per parameter set, so this guards against
    /// a typo in one of them. The per-coordinate buffers are checked the same way in
    /// `bouncycastle-mldsa-common`.
    fn check_packed_vector_sizes<P: MLDSAParams>() {
        for (got, want, what) in [
            (size_of::<P::S1Packed>(), P::S1_PACKED_LEN, "S1Packed"),
            (size_of::<P::S2Packed>(), P::S2_PACKED_LEN, "S2Packed"),
            (size_of::<P::T1Packed>(), P::T1_PACKED_LEN, "T1Packed"),
        ] {
            assert_eq!(got, want, "{}: {} vs its length const", P::ALG_NAME, what);
        }
        // This crate stores the seed, not the expanded key, for every parameter set.
        assert_eq!(P::SK_LEN, 32, "{}: stored private key size", P::ALG_NAME);
    }

    #[test]
    fn test_packed_vector_types_are_the_length_their_consts_claim() {
        check_packed_vector_sizes::<MLDSA44Params>();
        check_packed_vector_sizes::<MLDSA65Params>();
        check_packed_vector_sizes::<MLDSA87Params>();
    }
}
