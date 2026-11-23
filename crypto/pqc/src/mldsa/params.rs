//! This module's view of the three ML-DSA parameter sets of FIPS 204, Section 4, as a sealed
//! trait with one type per set.
//!
//! The values of Table 1 and Table 2, the algorithm metadata and the derived constants live on
//! [`MLDSAParamsBase`] in `pqc::mldsa_common`, shared with `pqc::mldsa_lowmemory`;
//! [`MLDSAParams`] extends it with the vector and matrix types this implementation materializes.

use crate::mldsa::matrix::{Matrix, MatrixTrait, Vector, VectorTrait};

pub use crate::mldsa_common::params::{
    ByteBuffer, MLDSA44Params, MLDSA65Params, MLDSA87Params, MLDSAParamsBase,
};

/// One ML-DSA parameter set as this module uses it: everything on [`MLDSAParamsBase`], plus the
/// vector and matrix types whose dimensions the set fixes.
///
/// Sealed through its supertrait, so [`MLDSA44Params`], [`MLDSA65Params`] and [`MLDSA87Params`]
/// are the only implementations.
pub trait MLDSAParams: MLDSAParamsBase {
    /// The length of an encoded private key, which this module stores in its FIPS 204 form.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The vector types are written out by hand per parameter set, so this guards against a typo
    /// in one of them. The byte-buffer types are checked the same way in `pqc::mldsa_common`.
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
