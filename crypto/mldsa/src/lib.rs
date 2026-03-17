//! todo -- docs -- turn this back on:
// #![forbid(missing_docs)]

#![allow(unused_variables)] // todo - remove
#![allow(dead_code)] // todo - remove
// #![allow(private_interfaces)] // todo debugging -- remove

#![forbid(unsafe_code)]
#![allow(incomplete_features)] // needed because currently generic_const_exprs is experimental
#![feature(generic_const_exprs)]
#![feature(int_roundings)]
#![feature(inherent_associated_types)]
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
pub use mldsa::{MLDSA, MLDSA44, MLDSA65, MLDSA87};
pub use mldsa_keys::{MLDSAPrivateKeyTrait, MLDSAPublicKeyTrait};
pub use mldsa_keys::{MLDSAPublicKey, MLDSA44PublicKey, MLDSA65PublicKey, MLDSA87PublicKey};
pub use mldsa_keys::{MLDSAPrivateKey, MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey};
pub use mldsa::{MuBuilder};

// todo
// pub use hashmldsa::HashMLDSA;

/*** Exported constants ***/
pub const ML_DSA_44_NAME: &str = "ML-DSA-44";
pub const ML_DSA_65_NAME: &str = "ML-DSA-65";
pub const ML_DSA_87_NAME: &str = "ML-DSA-87";

pub use mldsa::{MLDSA44_PK_LEN, MLDSA44_SK_LEN, MLDSA44_SIG_LEN};
pub use mldsa::{MLDSA65_PK_LEN, MLDSA65_SK_LEN, MLDSA65_SIG_LEN};
pub use mldsa::{MLDSA87_PK_LEN, MLDSA87_SK_LEN, MLDSA87_SIG_LEN};

/*** pub types ***/


// TODO: I'm gonna need to duplicate all these types for HashML-DSA.
// TODO: probably with an extra param <HASH: Hash> to the HashML_DSA struct definition.
// TODO: Need to decide whether to also add this to public and private keys for no other reason than to
// TODO:   make it hard to cross-use keys between ML-DSA and HashML-DSA.



/*** Param traits ***/

// todo -- delete
// /// Private trait on purpose so that only the NIST-approved params can be used.
// /// Values taken directly from FIPS 204 Table 1 and Table 2
// #[allow(private_bounds)]
// trait MLDSAParams {
//     // from FIPS 204 Table 1
//     // q, zeta, d defined as global constants since they do not vary by parameter set
//     const TAU: i32;
//     const GAMMA1: i32;
//     const GAMMA2: i32;
//     const k: usize;
//     const l: usize;
//     const ETA: i32;
//     const BETA: i32; // tau * eta
//     const OMEGA: i32;
//
//     // useful derived values
//     const C_TILDE: usize;
//     const POLY_VEC_H_PACKED_LEN: usize;
//     const POLY_Z_PACKED_LEN: usize;
//     const POLY_W1_PACKED_LEN: usize;
//     const POLY_ETA_PACKED_LEN: usize;
//     const GAMMA1_MASK_LEN: usize;
//     const LAMBDA_over_4: usize;
// }

// pub struct MLDSA44Params;
//
// impl MLDSAParams for MLDSA44Params {
//     const TAU: i32 = 39;
//     const GAMMA1: i32 = 1 << 17;
//     const GAMMA2: i32 = (q - 1) / 88;
//     const k: usize = 4;
//     const l: usize = 4;
//     const ETA: i32 = 2;
//     const BETA: i32 = 78;
//     const OMEGA: i32 = 80;
//
//     // const ALG: MldsaAlg = MldsaAlg::MlDsa44;
//     const C_TILDE: usize = 32;
//     const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
//     const POLY_Z_PACKED_LEN: usize = 576;
//     const POLY_W1_PACKED_LEN: usize = 192;
//     const POLY_ETA_PACKED_LEN: usize = 96;
//
//     // Alg 32
//     // 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
//     const GAMMA1_MASK_LEN: usize = 576;  // 32*(1 + bitlen (𝛾1 − 1) )
//     const LAMBDA_over_4: usize = 128/4;
//     // todo -- bc-java does it as compute: 576usize.div_ceil(symmetric.stream_256_block_bytes) -- which should be 5
//     // todo -- might need to debug this against bc-java
//     // todo -- debug this against bc-java; or look in other implementations. I feel like this should be 32*17=544 or 32*19=608
//     // todo -- I'm not sure why they're adding an extra 32
//     // todo -- corresponds to aux_functions::expand_mask()
// }

// pub struct MLDSA65Params;
//
// impl MLDSAParams for MLDSA65Params {
//     const TAU: i32 = 49;
//     const GAMMA1: i32 = 1 << 19;
//     const GAMMA2: i32 = (q - 1) / 32;
//     const k: usize = 6;
//     const l: usize = 5;
//     const ETA: i32 = 4;
//     const BETA: i32 = 196;
//     const OMEGA: i32 = 55;
//
//     const C_TILDE: usize = 48;
//     const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
//     const POLY_Z_PACKED_LEN: usize = 640;
//     const POLY_W1_PACKED_LEN: usize = 128;
//     const POLY_ETA_PACKED_LEN: usize = 128;
//     const GAMMA1_MASK_LEN: usize = 640; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
//     const LAMBDA_over_4: usize = 192/4;
// }

// pub struct MLDSA87Params;
//
// impl MLDSAParams for MLDSA87Params {
//     const TAU: i32 = 60;
//     const GAMMA1: i32 = 1 << 19;
//     const GAMMA2: i32 = (q - 1) / 32;
//     const k: usize = 8;
//     const l: usize = 7;
//     const ETA: i32 = 2;
//     const BETA: i32 = 120;
//     const OMEGA: i32 = 75;
//
//     const C_TILDE: usize = 64;
//     const POLY_VEC_H_PACKED_LEN: usize = 0; // todo -- compute
//     const POLY_Z_PACKED_LEN: usize = 640;
//     const POLY_W1_PACKED_LEN: usize = 128;
//     const POLY_ETA_PACKED_LEN: usize = 96;
//     const GAMMA1_MASK_LEN: usize = 640; // todo -- compute: 640usize.div_ceil(symmetric.stream_256_block_bytes)
//     const LAMBDA_over_4: usize = 256/4;
// }

// todo -- impl bouncycastle_core_interface::traits::Algorithm with the security strengths from Table 1
