//! todo -- docs

#![allow(dead_code)] // todo - remove
#![forbid(unsafe_code)]
#![feature(generic_const_exprs)]

mod mldsa;
mod ntt;
mod encodings;
mod polynomial;
mod poly_vec_k;
mod poly_vec_l;
mod poly_vec_matrix;
mod reduce;
mod rounding;
mod symmetric;
mod mldsa_keys;


/*** String constants ***/
pub const ML_DSA_44_NAME: &str = "ML-DSA-44";
pub const ML_DSA_65_NAME: &str = "ML-DSA-65";
pub const ML_DSA_87_NAME: &str = "ML-DSA-87";

/*** pub types ***/

pub use mldsa_keys::MLDSAPublickey;

pub type MLDSA44PublicKey = MLDSAPublickey<MLDSA44Params>;
pub type MLDSA65PublicKey = MLDSAPublickey<MLDSA65Params>;
pub type MLDSA87PublicKey = MLDSAPublickey<MLDSA87Params>;

pub use mldsa_keys::MLDSAPrivatekey;
use crate::MldsaSize::MlDsa87;

pub type MLDSA44PrivateKey = MLDSAPrivatekey<MLDSA44Params>;
pub type MLDSA65PrivateKey = MLDSAPrivatekey<MLDSA65Params>;
pub type MLDSA87PrivateKey = MLDSAPrivatekey<MLDSA87Params>;


/*** Param traits ***/

enum MldsaSize {
    MlDsa44 = 44,
    MlDsa65 = 65,
    MlDsa87 = 87,
}

/// Private trait on purpose so that only the NIST-approved params can be used.
/// Values taken directly from FIPS 204 Table 1 and Table 2
trait MLDSAParams {
    // from FIPS 204 Table 1
    // q, zeta, d defined as global constants since they do not vary by parameter set
    const TAU: i32;
    const GAMMA1: i32;
    const GAMMA2: i32;
    const K: usize;
    const L: usize;
    const ETA: i32;
    const BETA: i32; // tau * eta
    const OMEGA: i32;

    // from FIPS 204 Table 2
    const SK_LEN: usize;
    const PK_LEN: usize;
    const SIG_LEN: usize;

    // useful derived values
    const ALG: MldsaSize;
    const C_TILDE: usize;
    const POLY_VEC_H_PACKED_LEN: usize;
    const POLY_Z_PACKED_LEN: usize;
    const POLY_W1_PACKED_LEN: usize;
    const POLY_ETA_PACKED_LEN: usize;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize;
}

pub struct MLDSA44Params;
impl MLDSAParams for MLDSA44Params {
    const TAU: i32 = 39;
    const GAMMA1: i32 = 1 << 17;
    const GAMMA2: i32 = (Q - 1) / 88;
    const K: usize = 4;
    const L: usize = 4;
    const ETA: i32 = 2;
    const BETA: i32 = 78;
    const OMEGA: i32 = 80;
    const SK_LEN: usize = 2560;
    const PK_LEN: usize = 1312;
    const SIG_LEN: usize = 2420;
    const ALG: MldsaSize = MldsaSize::MlDsa44;
    const C_TILDE: usize = 32;
    const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
    const POLY_Z_PACKED_LEN: usize = 576;
    const POLY_W1_PACKED_LEN: usize = 192;
    const POLY_ETA_PACKED_LEN: usize = 96;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize = 0; // todo -- compute: 576usize.div_ceil(symmetric.stream_256_block_bytes)
}

pub struct MLDSA65Params;
impl MLDSAParams for MLDSA65Params {
    const TAU: i32 = 49;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (Q - 1) / 32;
    const K: usize = 6;
    const L: usize = 5;
    const ETA: i32 = 4;
    const BETA: i32 = 196;
    const OMEGA: i32 = 55;
    const SK_LEN: usize = 4032;
    const PK_LEN: usize = 1952;
    const SIG_LEN: usize = 3309;
    const ALG: MldsaSize = MldsaSize::MlDsa65;
    const C_TILDE: usize = 48;
    const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
    const POLY_Z_PACKED_LEN: usize = 640;
    const POLY_W1_PACKED_LEN: usize = 128;
    const POLY_ETA_PACKED_LEN: usize = 128;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize = 0; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
}

pub struct MLDSA87Params;
impl MLDSAParams for MLDSA87Params {
    const TAU: i32 = 60;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (Q - 1) / 32;
    const K: usize = 8;
    const L: usize = 7;
    const ETA: i32 = 2;
    const BETA: i32 = 120;
    const OMEGA: i32 = 75;
    const SK_LEN: usize = 4896;
    const PK_LEN: usize = 2592;
    const SIG_LEN: usize = 4627;
    const ALG: MldsaSize = MldsaSize::MlDsa87;
    const C_TILDE: usize = 64;
    const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
    const POLY_Z_PACKED_LEN: usize = 640;
    const POLY_W1_PACKED_LEN: usize = 128;
    const POLY_ETA_PACKED_LEN: usize = 96;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize = 0; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
}

// todo -- impl bouncycastle_core_interface::traits::Algorithm with the security strengths from Table 1

/*** Internal fixed ML-DSA constants ***/
pub(crate) const N: usize = 256;
pub(crate) const Q: i32 = 8380417;
pub(crate) const Q_INV: i32 = 58728449; // Q ^ (-1) mod 2 ^32
pub(crate) const D: i32 = 13;
pub(crate) const ROOT_OF_UNITY: i32 = 1753;
pub(crate) const SEED_LEN: usize = 32;
pub(crate) const CRH_LEN: usize = 64;
pub(crate) const RND_LEN: usize = 32;
pub(crate) const TR_LEN: usize = 64;
pub(crate) const POLY_T1PACKED_LEN: usize = 320;
pub(crate) const POLY_T0PACKED_LEN: usize = 416;

