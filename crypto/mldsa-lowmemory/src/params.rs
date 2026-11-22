//! This crate's view of the three ML-DSA parameter sets of FIPS 204, Section 4, as a sealed
//! trait with one type per set.
//!
//! The values of Table 1 and Table 2, the algorithm metadata and the derived constants live on
//! [`MLDSAParamsBase`] in `bouncycastle-mldsa-common`, shared with `bouncycastle-mldsa`;
//! [`MLDSAParams`] extends it with the packed-vector buffers this implementation works from. This
//! crate never materializes 𝐀̂ or a whole polynomial vector, so the only parameter-sized types it
//! needs are byte buffers.

use crate::mldsa::{MLDSA_SEED_LEN, POLY_T1PACKED_LEN};
use bouncycastle_mldsa_common::params::ByteBuffer;

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

/// A parameter set's public key length as a const generic: `P: PublicKeyLen<N>` has exactly one
/// solution per parameter set, so an impl or method generic over `N` and bound on it infers `N`
/// from `P`. That is what lets the key types carry only `P` while the `core` traits keep their
/// `[u8; N]` arrays. The other three traits are the same for the other lengths.
pub trait PublicKeyLen<const N: usize>: MLDSAParams {}
/// See [`PublicKeyLen`]; the stored (seed) form of the private key.
pub trait PrivateKeyLen<const N: usize>: MLDSAParams {}
/// See [`PublicKeyLen`]; the FIPS 204 Algorithm 24 form of the private key.
pub trait FullPrivateKeyLen<const N: usize>: MLDSAParams {}
/// See [`PublicKeyLen`].
pub trait SignatureLen<const N: usize>: MLDSAParams {}

impl PublicKeyLen<{ MLDSA44Params::PK_LEN }> for MLDSA44Params {}
impl PrivateKeyLen<{ MLDSA44Params::SK_LEN }> for MLDSA44Params {}
impl FullPrivateKeyLen<{ MLDSA44Params::FULL_SK_LEN }> for MLDSA44Params {}
impl SignatureLen<{ MLDSA44Params::SIG_LEN }> for MLDSA44Params {}
impl PublicKeyLen<{ MLDSA65Params::PK_LEN }> for MLDSA65Params {}
impl PrivateKeyLen<{ MLDSA65Params::SK_LEN }> for MLDSA65Params {}
impl FullPrivateKeyLen<{ MLDSA65Params::FULL_SK_LEN }> for MLDSA65Params {}
impl SignatureLen<{ MLDSA65Params::SIG_LEN }> for MLDSA65Params {}
impl PublicKeyLen<{ MLDSA87Params::PK_LEN }> for MLDSA87Params {}
impl PrivateKeyLen<{ MLDSA87Params::SK_LEN }> for MLDSA87Params {}
impl FullPrivateKeyLen<{ MLDSA87Params::FULL_SK_LEN }> for MLDSA87Params {}
impl SignatureLen<{ MLDSA87Params::SIG_LEN }> for MLDSA87Params {}

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
