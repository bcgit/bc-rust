//! This crate's view of the three ML-DSA parameter sets of FIPS 204, Section 4, and the four
//! HashML-DSA pairings built on them, each as a sealed trait with one type per set.
//!
//! The values of Table 1 and Table 2, the algorithm metadata and the derived constants live on
//! [`MLDSAParamsBase`] in `bouncycastle-mldsa-common`, shared with `bouncycastle-mldsa-lowmemory`;
//! [`MLDSAParams`] extends it with the vector and matrix types this implementation materializes.

use crate::hash_mldsa::{
    HASH_ML_DSA_44_with_SHA256_NAME, HASH_ML_DSA_44_with_SHA512_NAME,
    HASH_ML_DSA_65_with_SHA512_NAME, HASH_ML_DSA_87_with_SHA512_NAME,
};
use crate::matrix::{Matrix, MatrixTrait, Vector, VectorTrait};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, HashOneShot};
use bouncycastle_mldsa_common::params::weaker_of;
use bouncycastle_sha2::{SHA256, SHA512};

pub use bouncycastle_mldsa_common::params::{
    ByteBuffer, MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParamsBase,
};

/// One ML-DSA parameter set as this crate uses it: everything on [`MLDSAParamsBase`], plus the
/// vector and matrix types whose dimensions the set fixes.
///
/// Sealed through its supertrait, so [`MLDSA44Params`], [`MLDSA65Params`] and [`MLDSA87Params`]
/// are the only implementations.
pub trait MLDSAParams: MLDSAParamsBase {
    /// The length of an encoded private key, which this crate stores in its FIPS 204 form.
    const SK_LEN: usize = Self::FULL_SK_LEN;

    /// A vector of 𝑘 polynomials, i.e. an element of 𝑅^𝑘.
    type VecK: VectorTrait;
    /// A vector of ℓ polynomials, i.e. an element of 𝑅^ℓ.
    type VecL: VectorTrait;
    /// The 𝑘 × ℓ public matrix 𝐀̂.
    type MatrixA: MatrixTrait<VecL = Self::VecL, VecK = Self::VecK>;
    /// `[u8; PK_LEN]`, for an encoding made where no const generic names the length.
    type PkEncoded: ByteBuffer;
    /// `[u8; SK_LEN]`, likewise.
    type SkEncoded: ByteBuffer;
}

impl MLDSAParams for MLDSA44Params {
    type PkEncoded = [u8; 1312];
    type SkEncoded = [u8; 2560];
    type VecK = Vector<4>;
    type VecL = Vector<4>;
    type MatrixA = Matrix<4, 4>;
}

impl MLDSAParams for MLDSA65Params {
    type PkEncoded = [u8; 1952];
    type SkEncoded = [u8; 4032];
    type VecK = Vector<6>;
    type VecL = Vector<5>;
    type MatrixA = Matrix<6, 5>;
}

impl MLDSAParams for MLDSA87Params {
    type PkEncoded = [u8; 2592];
    type SkEncoded = [u8; 4896];
    type VecK = Vector<8>;
    type VecL = Vector<7>;
    type MatrixA = Matrix<8, 7>;
}

/// A parameter set's public key length as a const generic: `P: PublicKeyLen<N>` has exactly one
/// solution per parameter set, so an impl or method generic over `N` and bound on it infers `N`
/// from `P`. That is what lets the key types carry only `P` while the `core` traits keep their
/// `[u8; N]` arrays. [`PrivateKeyLen`] and [`SignatureLen`] are the same for the other two.
pub trait PublicKeyLen<const N: usize>: MLDSAParams {}
/// See [`PublicKeyLen`].
pub trait PrivateKeyLen<const N: usize>: MLDSAParams {}
/// See [`PublicKeyLen`].
pub trait SignatureLen<const N: usize>: MLDSAParams {}

impl PublicKeyLen<{ MLDSA44Params::PK_LEN }> for MLDSA44Params {}
impl PrivateKeyLen<{ MLDSA44Params::SK_LEN }> for MLDSA44Params {}
impl SignatureLen<{ MLDSA44Params::SIG_LEN }> for MLDSA44Params {}
impl PublicKeyLen<{ MLDSA65Params::PK_LEN }> for MLDSA65Params {}
impl PrivateKeyLen<{ MLDSA65Params::SK_LEN }> for MLDSA65Params {}
impl SignatureLen<{ MLDSA65Params::SIG_LEN }> for MLDSA65Params {}
impl PublicKeyLen<{ MLDSA87Params::PK_LEN }> for MLDSA87Params {}
impl PrivateKeyLen<{ MLDSA87Params::SK_LEN }> for MLDSA87Params {}
impl SignatureLen<{ MLDSA87Params::SIG_LEN }> for MLDSA87Params {}

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

    /// The vector types are written out by hand per parameter set, so this guards against a typo
    /// in one of them. The byte-buffer types are checked the same way in `bouncycastle-mldsa-common`.
    fn check_vector_lengths<P: MLDSAParams>() {
        assert_eq!(<P::VecK as VectorTrait>::LEN, P::k, "{}: VecK vs 𝑘", P::ALG_NAME);
        assert_eq!(<P::VecL as VectorTrait>::LEN, P::l, "{}: VecL vs ℓ", P::ALG_NAME);
    }

    #[test]
    fn test_vector_types_are_the_length_their_consts_claim() {
        check_vector_lengths::<MLDSA44Params>();
        check_vector_lengths::<MLDSA65Params>();
        check_vector_lengths::<MLDSA87Params>();
    }

    #[test]
    fn test_sk_len_is_the_fips_encoding() {
        assert_eq!(MLDSA44Params::SK_LEN, MLDSA44Params::FULL_SK_LEN);
        assert_eq!(MLDSA65Params::SK_LEN, MLDSA65Params::FULL_SK_LEN);
        assert_eq!(MLDSA87Params::SK_LEN, MLDSA87Params::FULL_SK_LEN);
    }
}
