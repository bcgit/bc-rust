//! The three ML-DSA parameter sets of FIPS 204, Section 4, and the six HashML-DSA pairings built on
//! them, each as a sealed trait with one type per set.
//!
//! # Derived parameters
//!
//! FIPS 204, Table 1 assigns eight independent values per set (𝜏, 𝜆, 𝛾1, 𝛾2, (𝑘, ℓ), 𝜂, 𝜔) plus the
//! three sizes of Table 2. Everything else this implementation needs is a function of those, so it
//! is written once as a defaulted associated const rather than three times as a hand-computed
//! number. `params::tests` checks every derivation against the values tabulated in FIPS 204.

use crate::hash_mldsa::{
    HASH_ML_DSA_44_with_SHA256_NAME, HASH_ML_DSA_44_with_SHA512_NAME,
    HASH_ML_DSA_65_WITH_SHA256_NAME, HASH_ML_DSA_65_WITH_SHA512_NAME,
    HASH_ML_DSA_87_WITH_SHA512_NAME, HASH_ML_DSA_87_with_SHA256_NAME,
};
use crate::matrix::{Matrix, MatrixTrait, Vector, VectorTrait};
use crate::mldsa::{ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME, q};
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, Hash, HashAlgParams, SecurityStrength};
use bouncycastle_sha2::{SHA256, SHA512};
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// `bitlen 𝑥`, the length of the binary expansion of 𝑥 (FIPS 204, Section 2.3).
///
/// `bitlen 0` is 0; every use below has a positive argument.
pub(crate) const fn bitlen(x: u32) -> usize {
    if x == 0 { 0 } else { x.ilog2() as usize + 1 }
}

/// A fixed-size byte buffer whose length depends on the parameter set.
///
/// [`ZeroizablePrimitive`] rather than [`Default`] supplies the all-zero value, because `Default`
/// for arrays stops at 32 elements and every buffer here is longer than that.
trait ByteBuffer: ZeroizablePrimitive + AsRef<[u8]> + AsMut<[u8]> {}
impl<const N: usize> ByteBuffer for [u8; N] {}

/// A crate-private (aka "sealed") trait that prevents a new ML-DSA parameter set from being defined
/// outside this crate.
trait MLDSAParamsInternalTrait {}

/// One ML-DSA parameter set: the values of FIPS 204, Table 1 and Table 2, and the types whose size
/// they determine.
///
/// Sealed via a private supertrait, so [`MLDSA44Params`], [`MLDSA65Params`] and [`MLDSA87Params`]
/// are the only implementations.
pub trait MLDSAParams: MLDSAParamsInternalTrait {
    /* FIPS 204, Table 1: the values assigned by each parameter set. */

    /// 𝜏, the number of ±1's in the polynomial 𝑐.
    const tau: i32;
    /// 𝜆, the collision strength of 𝑐̃, in bits.
    const lambda: i32;
    /// 𝛾1, the coefficient range of 𝐲. Always a power of two.
    const gamma1: i32;
    /// 𝛾2, the low-order rounding range.
    const gamma2: i32;
    /// 𝑘, the number of rows of 𝐀.
    const k: usize;
    /// ℓ, the number of columns of 𝐀.
    const l: usize;
    /// 𝜂, the private key range.
    const eta: usize;
    /// 𝜔, the maximum number of 1's in the hint 𝐡.
    const omega: i32;

    /* FIPS 204, Table 2: sizes in bytes of keys and signatures. */

    /// The length of an encoded public key.
    const PK_LEN: usize;
    /// The length of an encoded private key.
    const SK_LEN: usize;
    /// The length of a signature.
    const SIG_LEN: usize;

    /* Algorithm meta-data */

    /// The algorithm name, as reported by `Algorithm::ALG_NAME`.
    const ALG_NAME: &'static str;
    /// The strength claimed for this parameter set, as reported by `Algorithm::MAX_SECURITY_STRENGTH`.
    const MAX_SECURITY_STRENGTH: SecurityStrength;
    /// The OID in component form, as reported by `AlgorithmOID::OID`.
    const OID: &'static [u32];
    /// The DER encoding of [`MLDSAParams::OID`], as reported by `AlgorithmOID::OID_DER`.
    const OID_DER: &'static [u8];

    /* Derived. Never written out per parameter set -- see the module docs. */

    /// 𝛽, which FIPS 204, Table 1 defines as "𝛽 = 𝜏 ⋅ 𝜂".
    const beta: i32 = Self::tau * Self::eta as i32;

    /// The length of the commitment hash 𝑐̃, which FIPS 204, Algorithm 26 (sigEncode) gives as
    /// 𝑐̃ ∈ 𝔹^(𝜆/4).
    const C_TILDE_LEN: usize = Self::lambda as usize / 4;

    /// The packed length of one coordinate of 𝐳: FIPS 204, Algorithm 26 (sigEncode) writes each of
    /// the ℓ coordinates as 𝔹^(32⋅(1+bitlen (𝛾1−1))).
    ///
    /// This is also the number of bytes ExpandMask squeezes per coordinate: FIPS 204,
    /// Algorithm 34, line 1 sets 𝑐 ← 1 + bitlen (𝛾1 − 1) and line 4 squeezes 32𝑐 bytes.
    const POLY_Z_PACKED_LEN: usize = 32 * (1 + bitlen(Self::gamma1 as u32 - 1));

    /// The packed length of one coordinate of 𝐬1 or 𝐬2: FIPS 204, Algorithm 24 (skEncode), line 3
    /// packs each with BitPack(𝐬1[𝑖], 𝜂, 𝜂), and Algorithm 17 (BitPack) outputs
    /// 𝔹^(32⋅bitlen (𝑎+𝑏)), so 32⋅bitlen (2𝜂).
    const POLY_ETA_PACKED_LEN: usize = 32 * bitlen(2 * Self::eta as u32);

    /// The packed length of one coordinate of 𝐰1: FIPS 204, Algorithm 28 (w1Encode) outputs
    /// 𝔹^(32𝑘⋅bitlen ((𝑞−1)/(2𝛾2)−1)) for all 𝑘 coordinates together.
    const POLY_W1_PACKED_LEN: usize = 32 * bitlen(((q - 1) / (2 * Self::gamma2)) as u32 - 1);

    /// 𝛾1 − 𝛽, the rejection bound on ‖𝐳‖∞ (FIPS 204, Algorithm 7, line 23).
    const gamma1_minus_beta: i32 = Self::gamma1 - Self::beta;

    /// 𝛾2 − 𝛽, the rejection bound on ‖𝐫0‖∞ (FIPS 204, Algorithm 7, line 23).
    const gamma2_minus_beta: i32 = Self::gamma2 - Self::beta;

    /* Types whose size depends on the parameter set. */

    /// A vector of 𝑘 polynomials, i.e. an element of 𝑅^𝑘.
    type VecK: VectorTrait;
    /// A vector of ℓ polynomials, i.e. an element of 𝑅^ℓ.
    type VecL: VectorTrait;
    /// The 𝑘 × ℓ public matrix 𝐀̂.
    type MatrixA: MatrixTrait<VecL = Self::VecL, VecK = Self::VecK>;

    /// The commitment hash 𝑐̃, of [`MLDSAParams::C_TILDE_LEN`] bytes.
    type SigCTilde: ByteBuffer;
    /// One packed coordinate of 𝐳, of [`MLDSAParams::POLY_Z_PACKED_LEN`] bytes.
    ///
    /// ExpandMask squeezes into a buffer of this same length; see
    /// [`MLDSAParams::POLY_Z_PACKED_LEN`].
    type PolyZPacked: ByteBuffer;
    /// One packed coordinate of 𝐰1, of [`MLDSAParams::POLY_W1_PACKED_LEN`] bytes.
    type PolyW1Packed: ByteBuffer;
}

/// The ML-DSA-44 parameter set (FIPS 204, Table 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLDSA44Params;
/// The ML-DSA-65 parameter set (FIPS 204, Table 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLDSA65Params;
/// The ML-DSA-87 parameter set (FIPS 204, Table 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MLDSA87Params;

impl MLDSAParamsInternalTrait for MLDSA44Params {}
impl MLDSAParamsInternalTrait for MLDSA65Params {}
impl MLDSAParamsInternalTrait for MLDSA87Params {}

impl MLDSAParams for MLDSA44Params {
    const tau: i32 = 39;
    const lambda: i32 = 128;
    const gamma1: i32 = 1 << 17;
    // mutants note: because 𝛾1 is applied by bit-shifting, the "- 1" ends up not mattering.
    const gamma2: i32 = (q - 1) / 88;
    const k: usize = 4;
    const l: usize = 4;
    const eta: usize = 2;
    const omega: i32 = 80;

    const PK_LEN: usize = 1312;
    const SK_LEN: usize = 2560;
    const SIG_LEN: usize = 2420;

    const ALG_NAME: &'static str = ML_DSA_44_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-ml-dsa-44 { sigAlgs 17 }
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11];

    type VecK = Vector<4>;
    type VecL = Vector<4>;
    type MatrixA = Matrix<4, 4>;

    type SigCTilde = [u8; 32]; // 𝜆/4 = 128/4
    type PolyZPacked = [u8; 576]; // 32 * (1 + bitlen(2^17 - 1)) = 32 * 18
    type PolyW1Packed = [u8; 192]; // 32 * bitlen(44 - 1) = 32 * 6
}

impl MLDSAParams for MLDSA65Params {
    const tau: i32 = 49;
    const lambda: i32 = 192;
    const gamma1: i32 = 1 << 19;
    // mutants note: because 𝛾1 is applied by bit-shifting, the "- 1" ends up not mattering.
    const gamma2: i32 = (q - 1) / 32;
    const k: usize = 6;
    const l: usize = 5;
    const eta: usize = 4;
    const omega: i32 = 55;

    const PK_LEN: usize = 1952;
    const SK_LEN: usize = 4032;
    const SIG_LEN: usize = 3309;

    const ALG_NAME: &'static str = ML_DSA_65_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-ml-dsa-65 { sigAlgs 18 }
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12];

    type VecK = Vector<6>;
    type VecL = Vector<5>;
    type MatrixA = Matrix<6, 5>;

    type SigCTilde = [u8; 48]; // 𝜆/4 = 192/4
    type PolyZPacked = [u8; 640]; // 32 * (1 + bitlen(2^19 - 1)) = 32 * 20
    type PolyW1Packed = [u8; 128]; // 32 * bitlen(16 - 1) = 32 * 4
}

impl MLDSAParams for MLDSA87Params {
    const tau: i32 = 60;
    const lambda: i32 = 256;
    const gamma1: i32 = 1 << 19;
    // mutants note: because 𝛾1 is applied by bit-shifting, the "- 1" ends up not mattering.
    const gamma2: i32 = (q - 1) / 32;
    const k: usize = 8;
    const l: usize = 7;
    const eta: usize = 2;
    const omega: i32 = 75;

    const PK_LEN: usize = 2592;
    const SK_LEN: usize = 4896;
    const SIG_LEN: usize = 4627;

    const ALG_NAME: &'static str = ML_DSA_87_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
    /// Assigned by NIST in the Computer Security Objects Register: id-ml-dsa-87 { sigAlgs 19 }
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13];

    type VecK = Vector<8>;
    type VecL = Vector<7>;
    type MatrixA = Matrix<8, 7>;

    type SigCTilde = [u8; 64]; // 𝜆/4 = 256/4
    type PolyZPacked = [u8; 640]; // 32 * (1 + bitlen(2^19 - 1)) = 32 * 20
    type PolyW1Packed = [u8; 128]; // 32 * bitlen(16 - 1) = 32 * 4
}

/// The two distinct values 𝛾1 takes across the three parameter sets (FIPS 204, Table 1).
///
/// The bit-packing routines have one layout per distinct 𝛾1, so they dispatch on these rather than
/// on the parameter set. ML-DSA-65 and ML-DSA-87 share the second value.
pub(crate) const GAMMA1_2_POW_17: i32 = MLDSA44Params::gamma1;
/// See [`GAMMA1_2_POW_17`].
pub(crate) const GAMMA1_2_POW_19: i32 = MLDSA65Params::gamma1;

/// The two distinct values 𝛾2 takes across the three parameter sets (FIPS 204, Table 1).
///
/// As with 𝛾1, the routines that depend on 𝛾2 have one form per distinct value rather than one per
/// parameter set. ML-DSA-65 and ML-DSA-87 share the second value.
pub(crate) const GAMMA2_Q_MINUS_1_OVER_88: i32 = MLDSA44Params::gamma2;
/// See [`GAMMA2_Q_MINUS_1_OVER_88`].
pub(crate) const GAMMA2_Q_MINUS_1_OVER_32: i32 = MLDSA65Params::gamma2;

/// The weaker of two security strengths.
///
/// [`SecurityStrength`]'s discriminants are assigned in increasing order of strength, so comparing
/// them as integers orders them. A `const fn` because the strength of a HashML-DSA pairing is a
/// defaulted associated const.
const fn weaker_of(a: SecurityStrength, b: SecurityStrength) -> SecurityStrength {
    if (a as u8) <= (b as u8) { a } else { b }
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
/// Sealed via a private supertrait, so the six types below are the only implementations.
pub trait HashMLDSAParams: HashMLDSAParamsInternalTrait {
    /// The ML-DSA parameter set underneath.
    type MLDSA: MLDSAParams;
    /// PH, the pre-hash function.
    type PreHash: Hash + HashAlgParams + AlgorithmOID + Default;

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
    /// weaker of the two. That is what caps, for example, HashML-DSA-87_with_SHA256 at 128 bits.
    const MAX_SECURITY_STRENGTH: SecurityStrength = weaker_of(
        <Self::MLDSA as MLDSAParams>::MAX_SECURITY_STRENGTH,
        <Self::PreHash as Algorithm>::MAX_SECURITY_STRENGTH,
    );
}

/// The HashML-DSA-44_with_SHA256 pairing.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashMLDSA44_with_SHA256Params;
/// The HashML-DSA-65_with_SHA256 pairing.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashMLDSA65_with_SHA256Params;
/// The HashML-DSA-87_with_SHA256 pairing.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashMLDSA87_with_SHA256Params;
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
impl HashMLDSAParamsInternalTrait for HashMLDSA65_with_SHA256Params {}
impl HashMLDSAParamsInternalTrait for HashMLDSA87_with_SHA256Params {}
impl HashMLDSAParamsInternalTrait for HashMLDSA44_with_SHA512Params {}
impl HashMLDSAParamsInternalTrait for HashMLDSA65_with_SHA512Params {}
impl HashMLDSAParamsInternalTrait for HashMLDSA87_with_SHA512Params {}

impl HashMLDSAParams for HashMLDSA44_with_SHA256Params {
    type MLDSA = MLDSA44Params;
    type PreHash = SHA256;
    const ALG_NAME: &'static str = HASH_ML_DSA_44_with_SHA256_NAME;
}
impl HashMLDSAParams for HashMLDSA65_with_SHA256Params {
    type MLDSA = MLDSA65Params;
    type PreHash = SHA256;
    const ALG_NAME: &'static str = HASH_ML_DSA_65_WITH_SHA256_NAME;
}
impl HashMLDSAParams for HashMLDSA87_with_SHA256Params {
    type MLDSA = MLDSA87Params;
    type PreHash = SHA256;
    const ALG_NAME: &'static str = HASH_ML_DSA_87_with_SHA256_NAME;
}
impl HashMLDSAParams for HashMLDSA44_with_SHA512Params {
    type MLDSA = MLDSA44Params;
    type PreHash = SHA512;
    const ALG_NAME: &'static str = HASH_ML_DSA_44_with_SHA512_NAME;
}
impl HashMLDSAParams for HashMLDSA65_with_SHA512Params {
    type MLDSA = MLDSA65Params;
    type PreHash = SHA512;
    const ALG_NAME: &'static str = HASH_ML_DSA_65_WITH_SHA512_NAME;
}
impl HashMLDSAParams for HashMLDSA87_with_SHA512Params {
    type MLDSA = MLDSA87Params;
    type PreHash = SHA512;
    const ALG_NAME: &'static str = HASH_ML_DSA_87_WITH_SHA512_NAME;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mldsa::d;

    /// FIPS 204, Table 1, transcribed column by column: the eight values each parameter set
    /// assigns. `(tau, lambda, gamma1, gamma2, k, l, eta, omega)`.
    const TABLE_1: [(i32, i32, i32, i32, usize, usize, usize, i32); 3] = [
        (39, 128, 131072, (q - 1) / 88, 4, 4, 2, 80),
        (49, 192, 524288, (q - 1) / 32, 6, 5, 4, 55),
        (60, 256, 524288, (q - 1) / 32, 8, 7, 2, 75),
    ];

    /// FIPS 204, Table 2, transcribed row by row: `(private key, public key, signature)` in bytes.
    const TABLE_2: [(usize, usize, usize); 3] =
        [(2560, 1312, 2420), (4032, 1952, 3309), (4896, 2592, 4627)];

    /// FIPS 204, Table 1 also tabulates 𝛽, which it labels "𝛽 = 𝜏 ⋅ 𝜂".
    const TABLE_1_BETA: [i32; 3] = [78, 196, 120];

    fn check_table_1<P: MLDSAParams>(i: usize) {
        let (tau, lambda, gamma1, gamma2, k, l, eta, omega) = TABLE_1[i];
        assert_eq!(P::tau, tau, "{}: 𝜏", P::ALG_NAME);
        assert_eq!(P::lambda, lambda, "{}: 𝜆", P::ALG_NAME);
        assert_eq!(P::gamma1, gamma1, "{}: 𝛾1", P::ALG_NAME);
        assert_eq!(P::gamma2, gamma2, "{}: 𝛾2", P::ALG_NAME);
        assert_eq!(P::k, k, "{}: 𝑘", P::ALG_NAME);
        assert_eq!(P::l, l, "{}: ℓ", P::ALG_NAME);
        assert_eq!(P::eta, eta, "{}: 𝜂", P::ALG_NAME);
        assert_eq!(P::omega, omega, "{}: 𝜔", P::ALG_NAME);
        assert_eq!(P::beta, TABLE_1_BETA[i], "{}: 𝛽 = 𝜏 ⋅ 𝜂", P::ALG_NAME);
    }

    fn check_table_2<P: MLDSAParams>(i: usize) {
        let (sk_len, pk_len, sig_len) = TABLE_2[i];
        assert_eq!(P::SK_LEN, sk_len, "{}: private key size", P::ALG_NAME);
        assert_eq!(P::PK_LEN, pk_len, "{}: public key size", P::ALG_NAME);
        assert_eq!(P::SIG_LEN, sig_len, "{}: signature size", P::ALG_NAME);
    }

    /// Each of the three sizes of Table 2 also has a formula in FIPS 204, and the two must agree.
    /// Table 2 is what is written down above; this is what re-derives it.
    fn check_table_2_formulas<P: MLDSAParams>() {
        // Algorithm 22 (pkEncode): 𝑝𝑘 ∈ 𝔹^(32+32𝑘(bitlen (𝑞−1)−𝑑)).
        let pk_len = 32 + 32 * P::k * (bitlen((q - 1) as u32) - d as usize);
        assert_eq!(P::PK_LEN, pk_len, "{}: Algorithm 22 output size", P::ALG_NAME);

        // Algorithm 24 (skEncode): 𝑠𝑘 ∈ 𝔹^(32+32+64+32⋅((𝑘+ℓ)⋅bitlen (2𝜂)+𝑑𝑘)).
        let sk_len =
            32 + 32 + 64 + 32 * ((P::k + P::l) * bitlen(2 * P::eta as u32) + d as usize * P::k);
        assert_eq!(P::SK_LEN, sk_len, "{}: Algorithm 24 output size", P::ALG_NAME);

        // Algorithm 26 (sigEncode): 𝜎 ∈ 𝔹^(𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘).
        let sig_len = P::lambda as usize / 4
            + P::l * 32 * (1 + bitlen(P::gamma1 as u32 - 1))
            + P::omega as usize
            + P::k;
        assert_eq!(P::SIG_LEN, sig_len, "{}: Algorithm 26 output size", P::ALG_NAME);
    }

    /// The associated types must be exactly as long as the consts that describe them; they are
    /// written out by hand per parameter set, so this guards against a typo in one of them.
    fn check_associated_type_sizes<P: MLDSAParams>() {
        assert_eq!(
            size_of::<P::SigCTilde>(),
            P::C_TILDE_LEN,
            "{}: SigCTilde vs C_TILDE_LEN",
            P::ALG_NAME
        );
        assert_eq!(
            size_of::<P::PolyZPacked>(),
            P::POLY_Z_PACKED_LEN,
            "{}: PolyZPacked vs POLY_Z_PACKED_LEN",
            P::ALG_NAME
        );
        assert_eq!(
            size_of::<P::PolyW1Packed>(),
            P::POLY_W1_PACKED_LEN,
            "{}: PolyW1Packed vs POLY_W1_PACKED_LEN",
            P::ALG_NAME
        );
        assert_eq!(<P::VecK as VectorTrait>::LEN, P::k, "{}: VecK vs 𝑘", P::ALG_NAME);
        assert_eq!(<P::VecL as VectorTrait>::LEN, P::l, "{}: VecL vs ℓ", P::ALG_NAME);
    }

    #[test]
    fn test_parameter_sets_match_fips204_table_1() {
        check_table_1::<MLDSA44Params>(0);
        check_table_1::<MLDSA65Params>(1);
        check_table_1::<MLDSA87Params>(2);
    }

    #[test]
    fn test_sizes_match_fips204_table_2() {
        check_table_2::<MLDSA44Params>(0);
        check_table_2::<MLDSA65Params>(1);
        check_table_2::<MLDSA87Params>(2);
    }

    #[test]
    fn test_table_2_sizes_agree_with_the_encoding_formulas() {
        check_table_2_formulas::<MLDSA44Params>();
        check_table_2_formulas::<MLDSA65Params>();
        check_table_2_formulas::<MLDSA87Params>();
    }

    #[test]
    fn test_associated_types_are_the_length_their_consts_claim() {
        check_associated_type_sizes::<MLDSA44Params>();
        check_associated_type_sizes::<MLDSA65Params>();
        check_associated_type_sizes::<MLDSA87Params>();
    }

    #[test]
    fn test_bitlen_matches_its_definition() {
        // FIPS 204 Section 2.3 defines bitlen 𝑥 as the length of the binary expansion of 𝑥.
        assert_eq!(bitlen(0), 0);
        assert_eq!(bitlen(1), 1);
        assert_eq!(bitlen(2), 2);
        assert_eq!(bitlen(3), 2);
        assert_eq!(bitlen(4), 3);
        // The two arguments the derivations above actually use, plus bitlen(𝑞 − 1) = 23.
        assert_eq!(bitlen((1 << 17) - 1), 17);
        assert_eq!(bitlen((1 << 19) - 1), 19);
        assert_eq!(bitlen((q - 1) as u32), 23);
    }

    #[test]
    fn test_gamma_dispatch_constants_cover_every_parameter_set() {
        // The packing routines dispatch on these; a parameter set whose 𝛾 is neither value would
        // fall through to a panic at runtime rather than fail to compile, so pin them here.
        for gamma1 in [MLDSA44Params::gamma1, MLDSA65Params::gamma1, MLDSA87Params::gamma1] {
            assert!(gamma1 == GAMMA1_2_POW_17 || gamma1 == GAMMA1_2_POW_19);
        }
        for gamma2 in [MLDSA44Params::gamma2, MLDSA65Params::gamma2, MLDSA87Params::gamma2] {
            assert!(gamma2 == GAMMA2_Q_MINUS_1_OVER_88 || gamma2 == GAMMA2_Q_MINUS_1_OVER_32);
        }
        assert_ne!(GAMMA1_2_POW_17, GAMMA1_2_POW_19);
        assert_ne!(GAMMA2_Q_MINUS_1_OVER_88, GAMMA2_Q_MINUS_1_OVER_32);
    }
}
