//! The three ML-KEM parameter sets of FIPS 203, Section 8, as a sealed trait with one type per set.
//!
//! This mirrors `bouncycastle_mlkem::params`, minus the vector and matrix types: this crate never
//! materializes 𝐀̂ or a whole polynomial vector, so the only parameter-sized type it needs is a
//! byte buffer for the packed 𝐭̂.
//!
//! # Derived parameters
//!
//! FIPS 203, Table 2 assigns five values per set (𝑘, 𝜂1, 𝜂2, 𝑑𝑢, 𝑑𝑣); its last column, the
//! required RBG strength, is carried by `MAX_SECURITY_STRENGTH`.
//! The sizes of Table 3 are each a function of those, so they are written once as defaulted
//! associated consts rather than three times as a hand-computed number. `params::tests` checks every
//! derivation against the values tabulated in FIPS 203.

use crate::mlkem::{
    ML_KEM_512_NAME, ML_KEM_768_NAME, ML_KEM_1024_NAME, MLKEM_SEED_LEN, MLKEM_SS_LEN,
};
use bouncycastle_core::traits::SecurityStrength;
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// A fixed-size byte buffer whose length depends on the parameter set.
///
/// [`ZeroizablePrimitive`] rather than [`Default`] supplies the all-zero value, because `Default`
/// for arrays stops at 32 elements and every buffer here is longer than that.
trait ByteBuffer: ZeroizablePrimitive + AsRef<[u8]> + AsMut<[u8]> {}
impl<const N: usize> ByteBuffer for [u8; N] {}

/// A crate-private (aka "sealed") trait that prevents a new ML-KEM parameter set from being defined
/// outside this crate.
trait MLKEMParamsInternalTrait {}

/// One ML-KEM parameter set: the values of FIPS 203, Table 2 and Table 3, and the types whose size
/// they determine.
///
/// Sealed via a private supertrait, so [`MLKEM512Params`], [`MLKEM768Params`] and
/// [`MLKEM1024Params`] are the only implementations.
pub trait MLKEMParams: MLKEMParamsInternalTrait {
    /* FIPS 203, Table 2: the values assigned by each parameter set. */

    /// 𝑘, the rank of the module.
    const k: usize;
    /// 𝜂1, the CBD parameter used for the secret vector 𝐬 and the keygen error vector 𝐞.
    const eta1: i16;
    /// 𝜂2, the CBD parameter used for the encaps error terms 𝐞1 and 𝑒2.
    ///
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
    /// The DER encoding of [`MLKEMParams::OID`], as reported by `AlgorithmOID::OID_DER`.
    const OID_DER: &'static [u8];

    /* Derived. Never written out per parameter set -- see the module docs. */

    /// The length of an encapsulation key: FIPS 203, Algorithm 16 (ML-KEM.KeyGen_internal) gives
    /// ek ∈ 𝔹^(384𝑘+32).
    const PK_LEN: usize = 384 * Self::k + 32;

    /// The length of the FIPS 203 encoding of a decapsulation key: Algorithm 16 gives
    /// dk ∈ 𝔹^(768𝑘+96).
    ///
    /// Named `FULL_SK_LEN` rather than `SK_LEN` because this crate's private keys are held as the
    /// 64-byte seed and expanded on demand; see [`MLKEMParams::SK_LEN`].
    const FULL_SK_LEN: usize = 768 * Self::k + 96;

    /// The length of a ciphertext: FIPS 203, Algorithm 17 (ML-KEM.Encaps_internal) gives
    /// 𝑐 ∈ 𝔹^(32(𝑑𝑢𝑘+𝑑𝑣)).
    const CT_LEN: usize = 32 * (Self::du as usize * Self::k + Self::dv as usize);

    /// The length of a private key as this crate stores it: the 64-byte seed (𝑑, 𝑧), for every
    /// parameter set.
    const SK_LEN: usize = MLKEM_SEED_LEN;

    /// The length of a shared secret. 32 bytes for every parameter set (FIPS 203, Table 3).
    const SS_LEN: usize = MLKEM_SS_LEN;

    /// The packed length of 𝐭̂: 𝑘 polynomials of 12-bit coefficients, i.e. 384𝑘 bytes. This is the
    /// encapsulation key without its trailing 32-byte 𝜌.
    const T_PACKED_LEN: usize = 12 * Self::k * 32;

    /* Types whose size depends on the parameter set. */

    /// The packed 𝐭̂, of [`MLKEMParams::T_PACKED_LEN`] bytes.
    type TPacked: ByteBuffer;
}

/// The ML-KEM-512 parameter set (FIPS 203, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM512Params;
/// The ML-KEM-768 parameter set (FIPS 203, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM768Params;
/// The ML-KEM-1024 parameter set (FIPS 203, Table 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLKEM1024Params;

impl MLKEMParamsInternalTrait for MLKEM512Params {}
impl MLKEMParamsInternalTrait for MLKEM768Params {}
impl MLKEMParamsInternalTrait for MLKEM1024Params {}

impl MLKEMParams for MLKEM512Params {
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

    type TPacked = [u8; 768]; // 384 * 2
}

impl MLKEMParams for MLKEM768Params {
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

    type TPacked = [u8; 1152]; // 384 * 3
}

impl MLKEMParams for MLKEM1024Params {
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

    type TPacked = [u8; 1536]; // 384 * 4
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 203, Table 2, transcribed row by row: the five values each parameter set
    /// assigns, plus its last column. `(k, eta1, eta2, du, dv, rbg_strength)`.
    const TABLE_2: [(usize, i16, i16, i16, i16, i16); 3] =
        [(2, 3, 2, 10, 4, 128), (3, 2, 2, 10, 4, 192), (4, 2, 2, 11, 5, 256)];

    /// FIPS 203, Table 3, transcribed row by row, in bytes:
    /// `(encapsulation key, decapsulation key, ciphertext, shared secret key)`. The decapsulation
    /// key column is the full FIPS encoding, which this crate calls `FULL_SK_LEN`.
    const TABLE_3: [(usize, usize, usize, usize); 3] =
        [(800, 1632, 768, 32), (1184, 2400, 1088, 32), (1568, 3168, 1568, 32)];

    fn check_table_2<P: MLKEMParams>(i: usize) {
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

    fn check_table_3<P: MLKEMParams>(i: usize) {
        let (pk_len, full_sk_len, ct_len, ss_len) = TABLE_3[i];
        assert_eq!(P::PK_LEN, pk_len, "{}: encapsulation key size", P::ALG_NAME);
        assert_eq!(P::FULL_SK_LEN, full_sk_len, "{}: decapsulation key size", P::ALG_NAME);
        assert_eq!(P::CT_LEN, ct_len, "{}: ciphertext size", P::ALG_NAME);
        assert_eq!(P::SS_LEN, ss_len, "{}: shared secret size", P::ALG_NAME);
        // This crate stores the seed, not the expanded key, for every parameter set.
        assert_eq!(P::SK_LEN, 64, "{}: stored private key size", P::ALG_NAME);
    }

    fn check_associated_type_sizes<P: MLKEMParams>() {
        assert_eq!(
            size_of::<P::TPacked>(),
            P::T_PACKED_LEN,
            "{}: TPacked vs T_PACKED_LEN",
            P::ALG_NAME
        );
        // The encapsulation key is the packed 𝐭̂ followed by the 32-byte 𝜌.
        assert_eq!(P::T_PACKED_LEN + 32, P::PK_LEN, "{}: 384𝑘 + 32 = PK_LEN", P::ALG_NAME);
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

    #[test]
    fn test_associated_types_are_the_length_their_consts_claim() {
        check_associated_type_sizes::<MLKEM512Params>();
        check_associated_type_sizes::<MLKEM768Params>();
        check_associated_type_sizes::<MLKEM1024Params>();
    }
}
