//! The three ML-KEM parameter sets of FIPS 203, Section 8, as a sealed trait with one type per set.
//!
//! [`MLKEMParamsBase`] holds what both ML-KEM crates read from a parameter set: the values of
//! Table 2, the algorithm metadata and the sizes of Table 3. Each crate extends it with a trait of
//! its own for the types only it needs (the vector and matrix types in `bouncycastle-mlkem`, the
//! packed 𝐭̂ buffer in `bouncycastle-mlkem-lowmemory`), and implements that extension for the three
//! marker types defined here.
//!
//! # Derived parameters
//!
//! FIPS 203, Table 2 assigns five values per set (𝑘, 𝜂1, 𝜂2, 𝑑𝑢, 𝑑𝑣); its last column, the
//! required RBG strength, is carried by `MAX_SECURITY_STRENGTH`.
//! The sizes of Table 3 are each a function of those, so they are written once as defaulted
//! associated consts rather than three times as a hand-computed number. `params::tests` checks every
//! derivation against the values tabulated in FIPS 203.

use crate::{ML_KEM_512_NAME, ML_KEM_768_NAME, ML_KEM_1024_NAME, MLKEM_SS_LEN};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// A fixed-size byte buffer whose length depends on the parameter set.
///
/// [`ZeroizablePrimitive`] rather than [`Default`] supplies the all-zero value, because `Default`
/// for arrays stops at 32 elements and every buffer here is longer than that.
pub trait ByteBuffer: ZeroizablePrimitive + AsRef<[u8]> + AsMut<[u8]> {}
impl<const N: usize> ByteBuffer for [u8; N] {}

mod sealed {
    /// Prevents a new ML-KEM parameter set from being defined outside this crate: the three
    /// marker types below are the only implementations, here and in the crates that extend
    /// [`super::MLKEMParamsBase`].
    pub trait Sealed {}
}

/// One ML-KEM parameter set: the values of FIPS 203, Table 2 and the sizes of Table 3.
///
/// Sealed, so [`MLKEM512Params`], [`MLKEM768Params`] and [`MLKEM1024Params`] are the only
/// implementations.
pub trait MLKEMParamsBase: sealed::Sealed {
    /* FIPS 203, Table 2: the values assigned by each parameter set. */

    /// 𝑘, the rank of the module.
    const k: usize;
    /// 𝜂1, the CBD parameter used for the secret vector 𝐬 and the keygen error vector 𝐞.
    const eta1: i16;
    /// 𝜂2, the CBD parameter used for the encaps error terms 𝐞1 and 𝑒2.
    /// FIPS 203, Table 2 lists this per parameter set even though all three assign it 2.
    const eta2: i16;
    /// 𝑑𝑢, the compression parameter for 𝐮.
    const du: i16;
    /// 𝑑𝑣, the compression parameter for 𝑣.
    const dv: i16;

    /* Algorithm meta-data */

    /// The algorithm name, as reported by `Algorithm::ALG_NAME`.
    const ALG_NAME: &'static str;
    /// The strength claimed for this parameter set, as reported by `Algorithm::MAX_SECURITY_STRENGTH`.
    const MAX_SECURITY_STRENGTH: SecurityStrength;
    /// The OID in component form, as reported by `AlgorithmOID::OID`.
    const OID: &'static [u32];
    /// The DER encoding of [`MLKEMParamsBase::OID`], as reported by `AlgorithmOID::OID_DER`.
    const OID_DER: &'static [u8];

    /* Derived. Never written out per parameter set -- see the module docs. */

    /// The length of an encapsulation key: FIPS 203, Algorithm 16 (ML-KEM.KeyGen_internal) gives
    /// ek ∈ 𝔹^(384𝑘+32).
    const PK_LEN: usize = 384 * Self::k + 32;

    /// The length of the FIPS 203 encoding of a decapsulation key: Algorithm 16
    /// (ML-KEM.KeyGen_internal) gives dk ∈ 𝔹^(768𝑘+96).
    ///
    /// Named `FULL_SK_LEN` because a crate may store a private key in another form (the 64-byte
    /// seed, in `bouncycastle-mlkem-lowmemory`) and reserve `SK_LEN` for what it stores.
    const FULL_SK_LEN: usize = 768 * Self::k + 96;

    /// The length of a ciphertext: FIPS 203, Algorithm 17 (ML-KEM.Encaps_internal) gives
    /// 𝑐 ∈ 𝔹^(32(𝑑𝑢𝑘+𝑑𝑣)).
    const CT_LEN: usize = 32 * (Self::du as usize * Self::k + Self::dv as usize);

    /// The length of a shared secret. 32 bytes for every parameter set (FIPS 203, Table 3).
    const SS_LEN: usize = MLKEM_SS_LEN;
}

/// A parameter set's encapsulation-key length as a const generic: `P: PublicKeyLen<N>` has
/// exactly one solution per parameter set, so an impl or method generic over `N` and bound on it
/// infers `N` from `P`. That is what lets the key types carry only `P` while the `core` traits
/// keep their `[u8; N]` arrays. [`PrivateKeyLen`] (the FIPS 203 encoding of `dk`, Algorithm 16)
/// and [`CiphertextLen`] are the same for the other two lengths.
pub trait PublicKeyLen<const N: usize>: MLKEMParamsBase {}
/// See [`PublicKeyLen`].
pub trait PrivateKeyLen<const N: usize>: MLKEMParamsBase {}
/// See [`PublicKeyLen`].
pub trait CiphertextLen<const N: usize>: MLKEMParamsBase {}

impl PublicKeyLen<{ MLKEM512Params::PK_LEN }> for MLKEM512Params {}
impl PrivateKeyLen<{ MLKEM512Params::FULL_SK_LEN }> for MLKEM512Params {}
impl CiphertextLen<{ MLKEM512Params::CT_LEN }> for MLKEM512Params {}
impl PublicKeyLen<{ MLKEM768Params::PK_LEN }> for MLKEM768Params {}
impl PrivateKeyLen<{ MLKEM768Params::FULL_SK_LEN }> for MLKEM768Params {}
impl CiphertextLen<{ MLKEM768Params::CT_LEN }> for MLKEM768Params {}
impl PublicKeyLen<{ MLKEM1024Params::PK_LEN }> for MLKEM1024Params {}
impl PrivateKeyLen<{ MLKEM1024Params::FULL_SK_LEN }> for MLKEM1024Params {}
impl CiphertextLen<{ MLKEM1024Params::CT_LEN }> for MLKEM1024Params {}

/// The ML-KEM-512 parameter set (FIPS 203, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM512Params;
/// The ML-KEM-768 parameter set (FIPS 203, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM768Params;
/// The ML-KEM-1024 parameter set (FIPS 203, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM1024Params;

impl sealed::Sealed for MLKEM512Params {}
impl sealed::Sealed for MLKEM768Params {}
impl sealed::Sealed for MLKEM1024Params {}

impl MLKEMParamsBase for MLKEM512Params {
    const k: usize = 2;
    const eta1: i16 = 3;
    const eta2: i16 = 2;
    const du: i16 = 10;
    const dv: i16 = 4;

    const ALG_NAME: &'static str = ML_KEM_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-alg-ml-kem-512 { kems 1 }
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 1];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01];
}

impl MLKEMParamsBase for MLKEM768Params {
    const k: usize = 3;
    const eta1: i16 = 2;
    const eta2: i16 = 2;
    const du: i16 = 10;
    const dv: i16 = 4;

    const ALG_NAME: &'static str = ML_KEM_768_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-alg-ml-kem-768 { kems 2 }
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 2];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02];
}

impl MLKEMParamsBase for MLKEM1024Params {
    const k: usize = 4;
    const eta1: i16 = 2;
    const eta2: i16 = 2;
    const du: i16 = 11;
    const dv: i16 = 5;

    const ALG_NAME: &'static str = ML_KEM_1024_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-alg-ml-kem-1024 { kems 3 }
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 4, 3];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 203, Table 2, transcribed row by row: the five values each parameter set
    /// assigns, plus its last column. `(k, eta1, eta2, du, dv, rbg_strength)`.
    const TABLE_2: [(usize, i16, i16, i16, i16, i16); 3] =
        [(2, 3, 2, 10, 4, 128), (3, 2, 2, 10, 4, 192), (4, 2, 2, 11, 5, 256)];

    /// FIPS 203, Table 3, transcribed row by row, in bytes:
    /// `(encapsulation key, decapsulation key, ciphertext, shared secret key)`.
    const TABLE_3: [(usize, usize, usize, usize); 3] =
        [(800, 1632, 768, 32), (1184, 2400, 1088, 32), (1568, 3168, 1568, 32)];

    fn check_table_2<P: MLKEMParamsBase>(i: usize) {
        let (k, eta1, eta2, du, dv, rbg_strength) = TABLE_2[i];
        assert_eq!(P::k, k, "{}: 𝑘", P::ALG_NAME);
        assert_eq!(P::eta1, eta1, "{}: 𝜂1", P::ALG_NAME);
        assert_eq!(P::eta2, eta2, "{}: 𝜂2", P::ALG_NAME);
        assert_eq!(P::du, du, "{}: 𝑑𝑢", P::ALG_NAME);
        assert_eq!(P::dv, dv, "{}: 𝑑𝑣", P::ALG_NAME);
        assert_eq!(
            P::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bits(rbg_strength as usize),
            "{}: required RBG strength",
            P::ALG_NAME
        );
    }

    fn check_table_3<P: MLKEMParamsBase>(i: usize) {
        let (pk_len, full_sk_len, ct_len, ss_len) = TABLE_3[i];
        assert_eq!(P::PK_LEN, pk_len, "{}: encapsulation key size", P::ALG_NAME);
        assert_eq!(P::FULL_SK_LEN, full_sk_len, "{}: decapsulation key size", P::ALG_NAME);
        assert_eq!(P::CT_LEN, ct_len, "{}: ciphertext size", P::ALG_NAME);
        assert_eq!(P::SS_LEN, ss_len, "{}: shared secret size", P::ALG_NAME);
    }

    #[test]
    fn test_parameter_sets_match_fips203_table_2() {
        check_table_2::<MLKEM512Params>(0);
        check_table_2::<MLKEM768Params>(1);
        check_table_2::<MLKEM1024Params>(2);
    }

    #[test]
    fn test_sizes_match_fips203_table_3() {
        check_table_3::<MLKEM512Params>(0);
        check_table_3::<MLKEM768Params>(1);
        check_table_3::<MLKEM1024Params>(2);
    }
}
