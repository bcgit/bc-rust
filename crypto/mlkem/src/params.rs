//! This crate's view of the three ML-KEM parameter sets of FIPS 203, Section 8.
//!
//! The values of Table 2, the algorithm metadata and the sizes of Table 3 live on
//! [`MLKEMParamsBase`] in `bouncycastle-mlkem-common`, shared with `bouncycastle-mlkem-lowmemory`;
//! [`MLKEMParams`] extends it with the vector and matrix types this implementation materializes.

use crate::matrix::{Matrix, MatrixTrait, Vector, VectorTrait};

pub use bouncycastle_mlkem_common::params::{
    MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParamsBase,
};

/// One ML-KEM parameter set as this crate uses it: everything on [`MLKEMParamsBase`], plus the
/// vector and matrix types whose dimensions the set fixes.
///
/// Sealed through its supertrait, so [`MLKEM512Params`], [`MLKEM768Params`] and
/// [`MLKEM1024Params`] are the only implementations.
pub trait MLKEMParams: MLKEMParamsBase {
    /// The length of an encoded private key, which this crate stores in its FIPS 203 form.
    const SK_LEN: usize = Self::FULL_SK_LEN;

    /// A vector of 𝑘 polynomials, i.e. an element of 𝑅^𝑘.
    type VecK: VectorTrait;
    /// The 𝑘 × 𝑘 public matrix 𝐀̂.
    type MatrixA: MatrixTrait<Vec = Self::VecK>;
}

impl MLKEMParams for MLKEM512Params {
    type VecK = Vector<2>;
    type MatrixA = Matrix<2, 2>;
}

impl MLKEMParams for MLKEM768Params {
    type VecK = Vector<3>;
    type MatrixA = Matrix<3, 3>;
}

impl MLKEMParams for MLKEM1024Params {
    type VecK = Vector<4>;
    type MatrixA = Matrix<4, 4>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The associated types must be as long as `k` says; they are written out by hand per
    /// parameter set, so this guards against a typo in one of them. The Table 2 and Table 3
    /// values are checked in `bouncycastle-mlkem-common`.
    fn check_associated_type_sizes<P: MLKEMParams>() {
        // Measured rather than read off a const: `MatrixTrait<Vec = Self::VecK>` already ties the
        // matrix to the vector at the type level, so the only thing left to check is that both
        // are 𝑘 polynomials long.
        let poly = size_of::<bouncycastle_mlkem_common::polynomial::Polynomial>();
        assert_eq!(size_of::<P::VecK>(), P::k * poly, "{}: VecK vs 𝑘", P::ALG_NAME);
        assert_eq!(
            size_of::<P::MatrixA>(),
            P::k * P::k * poly,
            "{}: MatrixA vs 𝑘 × 𝑘",
            P::ALG_NAME
        );
    }

    #[test]
    fn test_associated_types_are_the_length_their_consts_claim() {
        check_associated_type_sizes::<MLKEM512Params>();
        check_associated_type_sizes::<MLKEM768Params>();
        check_associated_type_sizes::<MLKEM1024Params>();
    }

    #[test]
    fn test_sk_len_is_the_fips_encoding() {
        assert_eq!(MLKEM512Params::SK_LEN, MLKEM512Params::FULL_SK_LEN);
        assert_eq!(MLKEM768Params::SK_LEN, MLKEM768Params::FULL_SK_LEN);
        assert_eq!(MLKEM1024Params::SK_LEN, MLKEM1024Params::FULL_SK_LEN);
    }
}
