//! This crate's view of the three ML-KEM parameter sets of FIPS 203, Section 8.
//!
//! The values of Table 2, the algorithm metadata and the sizes of Table 3 live on
//! [`MLKEMParamsBase`] in `bouncycastle-mlkem-common`, shared with `bouncycastle-mlkem`;
//! [`MLKEMParams`] extends it with the one parameter-sized type this crate needs, the packed 𝐭̂.
//! This crate never materializes 𝐀̂ or a whole polynomial vector.

use crate::mlkem::MLKEM_SEED_LEN;
use bouncycastle_mlkem_common::params::ByteBuffer;

pub use bouncycastle_mlkem_common::params::{
    MLKEM512Params, MLKEM768Params, MLKEM1024Params, MLKEMParamsBase,
};

/// One ML-KEM parameter set as this crate uses it: everything on [`MLKEMParamsBase`], plus the
/// packed form of 𝐭̂.
///
/// Sealed through its supertrait, so [`MLKEM512Params`], [`MLKEM768Params`] and
/// [`MLKEM1024Params`] are the only implementations.
pub trait MLKEMParams: MLKEMParamsBase {
    /// The length of a private key as this crate stores it: the 64-byte seed (𝑑, 𝑧), for every
    /// parameter set. The FIPS 203 encoding is [`MLKEMParamsBase::FULL_SK_LEN`] long.
    const SK_LEN: usize = MLKEM_SEED_LEN;

    /// The packed length of 𝐭̂: 𝑘 polynomials of 12-bit coefficients, i.e. 384𝑘 bytes. This is the
    /// encapsulation key without its trailing 32-byte 𝜌.
    const T_PACKED_LEN: usize = 12 * Self::k * 32;

    /// The packed 𝐭̂, of [`MLKEMParams::T_PACKED_LEN`] bytes.
    type TPacked: ByteBuffer;
}

impl MLKEMParams for MLKEM512Params {
    type TPacked = [u8; 768]; // 384 * 2
}

impl MLKEMParams for MLKEM768Params {
    type TPacked = [u8; 1152]; // 384 * 3
}

impl MLKEMParams for MLKEM1024Params {
    type TPacked = [u8; 1536]; // 384 * 4
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `TPacked` is written out by hand per parameter set, so this guards against a typo in one
    /// of them. The Table 2 and Table 3 values are checked in `bouncycastle-mlkem-common`.
    fn check_associated_type_sizes<P: MLKEMParams>() {
        assert_eq!(
            size_of::<P::TPacked>(),
            P::T_PACKED_LEN,
            "{}: TPacked vs T_PACKED_LEN",
            P::ALG_NAME
        );
        assert_eq!(P::T_PACKED_LEN + 32, P::PK_LEN, "{}: 384𝑘 + 32 = PK_LEN", P::ALG_NAME);
        // This crate stores the seed, not the expanded key, for every parameter set.
        assert_eq!(P::SK_LEN, 64, "{}: stored private key size", P::ALG_NAME);
    }

    #[test]
    fn test_associated_types_are_the_length_their_consts_claim() {
        check_associated_type_sizes::<MLKEM512Params>();
        check_associated_type_sizes::<MLKEM768Params>();
        check_associated_type_sizes::<MLKEM1024Params>();
    }
}
