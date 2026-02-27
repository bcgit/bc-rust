//! todo -- docs -- turn this back on:
// #![forbid(missing_docs)]

#![allow(unused_variables)] // todo - remove
#![allow(dead_code)] // todo - remove
#![allow(private_interfaces)] // todo debugging -- remove

#![forbid(unsafe_code)]
#![allow(incomplete_features)] // needed because currently generic_const_exprs is experimental
#![feature(generic_const_exprs)]
#![feature(int_roundings)]

// These are because I'm matching variable names exactly against FIPS 204, for example both 'K' and 'k',
// or 'A' and 'a' are used and have specific meanings.
// But need to tell the rust linter to not care.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

mod mldsa;
mod hashmldsa;
mod mldsa_keys;
mod polynomial;
mod aux_functions;
mod matrix;

/*** Exported types ***/
pub use mldsa::{MLDSA, MuBuilder};
pub use mldsa_keys::{MLDSAPublicKey, MLDSAPrivateKey};

pub use hashmldsa::HashMLDSA;

/*** String constants ***/
pub const ML_DSA_44_NAME: &str = "ML-DSA-44";
pub const ML_DSA_65_NAME: &str = "ML-DSA-65";
pub const ML_DSA_87_NAME: &str = "ML-DSA-87";

/*** pub types ***/
pub type MLDSA44 = MLDSA<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_SIG_LEN, MLDSA44Params>;
pub type MLDSA44PublicKey = MLDSAPublicKey<MLDSA44_k, MLDSA44_PK_LEN>;
pub type MLDSA44PrivateKey = MLDSAPrivateKey<MLDSA44_k, MLDSA44_l, MLDSA44_ETA, MLDSA44_SK_LEN, MLDSA44_PK_LEN>;


pub type MLDSA65 = MLDSA<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_SIG_LEN, MLDSA65Params>;
pub type MLDSA65PublicKey = MLDSAPublicKey<MLDSA65_k, MLDSA65_PK_LEN>;
pub type MLDSA65PrivateKey = MLDSAPrivateKey<MLDSA65_k, MLDSA65_l, MLDSA65_ETA, MLDSA65_SK_LEN, MLDSA65_PK_LEN>;

pub type MLDSA87 = MLDSA<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_SIG_LEN, MLDSA87Params>;
pub type MLDSA87PublicKey = MLDSAPublicKey<MLDSA87_k, MLDSA87_PK_LEN>;
pub type MLDSA87PrivateKey = MLDSAPrivateKey<MLDSA87_k, MLDSA87_l, MLDSA87_ETA, MLDSA87_SK_LEN, MLDSA87_PK_LEN>;


// TODO: I'm gonna need to duplicate all these types for HashML-DSA.
// TODO: probably with an extra param <HASH: Hash> to the HashML_DSA struct definition.
// TODO: Need to decide whether to also add this to public and private keys for no other reason than to
// TODO:   make it hard to cross-use keys between ML-DSA and HashML-DSA.

/*** Constants ***/
// The way the constants are defined is a bit weird, so let me explain:
// We have three sets of constants:
//   * Constants for sizing arrays, which are used in type definitions, these include the sizes of
//     the vectors and matrices k and l, and the byte sizes of the public key, private key, and signature.
//     These are defined as global constants because the rust compiler seems to need them that way to be
//     usable in a typedef.
//   * Computational values that are fixed across parameter sets. These are defined as global constants.
//   * Computational values that vary by parameter set. These are defined in an instance of the MLDSAParams trait.

/*** Size values ***/
const MLDSA44_k: usize = 4;
const MLDSA44_l: usize = 4;
const MLDSA44_ETA: usize = 2;
const MLDSA44_ETA_PACK_LEN: usize = 32*3;
const MLDSA44_PK_LEN: usize = 1312;
const MLDSA44_SK_LEN: usize = 2560;
const MLDSA44_SIG_LEN: usize = 2420;

const MLDSA65_k: usize = 6;
const MLDSA65_l: usize = 5;
const MLDSA65_ETA: usize = 4;
const MLDSA65_ETA_PACK_LEN: usize = 32*4;
const MLDSA65_PK_LEN: usize = 1952;
const MLDSA65_SK_LEN: usize = 4032;
const MLDSA65_SIG_LEN: usize = 3309;

const MLDSA87_k: usize = 8;
const MLDSA87_l: usize = 7;
const MLDSA87_ETA: usize = 2;
const MLDSA87_ETA_PACK_LEN: usize = 32*3;
const MLDSA87_PK_LEN: usize = 2592;
const MLDSA87_SK_LEN: usize = 4896;
const MLDSA87_SIG_LEN: usize = 4627;


/*** Internal fixed ML-DSA constants ***/
pub(crate) const N: usize = 256;
pub(crate) const q: i32 = 8380417;
pub(crate) const q_inv: i32 = 58728449; // q ^ (-1) mod 2 ^32
pub(crate) const d: i32 = 13;
pub(crate) const ROOT_OF_UNITY: i32 = 1753;
pub(crate) const SEED_LEN: usize = 32;
pub(crate) const CRH_LEN: usize = 64;
pub(crate) const RND_LEN: usize = 32;
pub(crate) const TR_LEN: usize = 64;
pub(crate) const POLY_T1PACKED_LEN: usize = 320;
pub(crate) const POLY_T0PACKED_LEN: usize = 416;


/*** Param traits ***/

// TODO: remove the constants from the trait that are also defined above

/// Private trait on purpose so that only the NIST-approved params can be used.
/// Values taken directly from FIPS 204 Table 1 and Table 2
#[allow(private_bounds)]
trait MLDSAParams {
    // from FIPS 204 Table 1
    // q, zeta, d defined as global constants since they do not vary by parameter set
    const TAU: i32;
    const GAMMA1: i32;
    const GAMMA2: i32;
    const k: usize;
    const l: usize;
    const ETA: i32;
    const BETA: i32; // tau * eta
    const OMEGA: i32;

    // from FIPS 204 Table 2
    const SK_LEN: usize;
    const PK_LEN: usize;
    const SIG_LEN: usize;

    // useful derived values
    // const ALG: MldsaAlg;
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
    const GAMMA2: i32 = (q - 1) / 88;
    const k: usize = 4;
    const l: usize = 4;
    const ETA: i32 = 2;
    const BETA: i32 = 78;
    const OMEGA: i32 = 80;
    const SK_LEN: usize = 2560;
    const PK_LEN: usize = 1312;
    const SIG_LEN: usize = 2420;
    // const ALG: MldsaAlg = MldsaAlg::MlDsa44;
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
    const GAMMA2: i32 = (q - 1) / 32;
    const k: usize = 6;
    const l: usize = 5;
    const ETA: i32 = 4;
    const BETA: i32 = 196;
    const OMEGA: i32 = 55;
    const SK_LEN: usize = 4032;
    const PK_LEN: usize = 1952;
    const SIG_LEN: usize = 3309;
    // const ALG: MldsaAlg = MldsaAlg::MlDsa65;
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
    const GAMMA2: i32 = (q - 1) / 32;
    const k: usize = 8;
    const l: usize = 7;
    const ETA: i32 = 2;
    const BETA: i32 = 120;
    const OMEGA: i32 = 75;
    const SK_LEN: usize = 4896;
    const PK_LEN: usize = 2592;
    const SIG_LEN: usize = 4627;
    // const ALG: MldsaAlg = MldsaAlg::MlDsa87;
    const C_TILDE: usize = 64;
    const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
    const POLY_Z_PACKED_LEN: usize = 640;
    const POLY_W1_PACKED_LEN: usize = 128;
    const POLY_ETA_PACKED_LEN: usize = 96;
    const POLY_UNIFORM_GAMMA1_N_LEN: usize = 0; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
}

// todo -- impl bouncycastle_core_interface::traits::Algorithm with the security strengths from Table 1
