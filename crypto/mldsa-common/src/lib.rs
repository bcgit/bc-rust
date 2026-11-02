//! The arithmetic, encodings and parameters that `bouncycastle-mldsa` and
//! `bouncycastle-mldsa-lowmemory` share.
//!
//! This is not an API for callers, and every item in it is `#[doc(hidden)]`. The two ML-DSA crates
//! differ in how they hold a private key and in how they schedule FIPS 204's algorithms, but they
//! agree on the ring arithmetic, the samplers, the bit packing, the rounding and the parameter
//! tables; this crate holds that one copy. Use one of those two crates.
//!
//! # 🚨 Security Considerations 🚨
//!
//! Nothing here checks the lengths it is handed beyond debug assertions, and nothing here is a
//! complete signature operation. The security considerations of ML-DSA are documented on the two
//! crates that build on this one.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
// Names follow FIPS 204, where for example 'K' and 'k', or 'A' and 'a', are different things.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[doc(hidden)]
pub mod aux_functions;
#[doc(hidden)]
pub mod mu_builder;
#[doc(hidden)]
pub mod params;
#[doc(hidden)]
pub mod polynomial;

use bouncycastle_sha3::{SHAKE128, SHAKE256};

/* FIPS 204, Table 1: the values that are the same for all parameter sets. */

/// The degree of the ring polynomial, 256.
#[doc(hidden)]
pub const N: usize = 256;
/// The modulus 𝑞 = 2^23 − 2^13 + 1.
#[doc(hidden)]
pub const q: i32 = 8380417;
/// 𝑞^(−1) mod 2^32, for Montgomery reduction.
#[doc(hidden)]
pub const q_inv: i32 = 58728449;
/// 𝑑, the number of dropped bits from 𝐭.
#[doc(hidden)]
pub const d: i32 = 13;

/// Length of the \[u8] holding an ML-DSA seed value.
#[doc(hidden)]
pub const MLDSA_SEED_LEN: usize = 32;
/// Length of the \[u8] holding an ML-DSA signing random value.
#[doc(hidden)]
pub const MLDSA_RND_LEN: usize = 32;
/// Length of the \[u8] holding an ML-DSA tr value (which is the SHAKE256 hash of the public key).
#[doc(hidden)]
pub const MLDSA_TR_LEN: usize = 64;
/// Length of the \[u8] holding an ML-DSA mu value.
#[doc(hidden)]
pub const MLDSA_MU_LEN: usize = 64;

/// The packed length of one coordinate of 𝐭0: 32 ⋅ 𝑑 bytes (FIPS 204, Algorithm 24, line 7).
#[doc(hidden)]
pub const POLY_T0PACKED_LEN: usize = 416;
/// The packed length of one coordinate of 𝐭1: 32 ⋅ (bitlen (𝑞 − 1) − 𝑑) bytes (FIPS 204, Algorithm 22).
#[doc(hidden)]
pub const POLY_T1PACKED_LEN: usize = 320;

// Typedefs just to make the algorithms look more like the FIPS 204 sample code.
/// H, the SHAKE256 XOF of FIPS 204, Section 3.7.
#[doc(hidden)]
pub type H = SHAKE256;
/// G, the SHAKE128 XOF of FIPS 204, Section 3.7.
#[doc(hidden)]
pub type G = SHAKE128;

/// Algorithm name of ML-DSA-44, as used by the CLI and `Algorithm::ALG_NAME`.
#[doc(hidden)]
pub const ML_DSA_44_NAME: &str = "ML-DSA-44";
/// Algorithm name of ML-DSA-65.
#[doc(hidden)]
pub const ML_DSA_65_NAME: &str = "ML-DSA-65";
/// Algorithm name of ML-DSA-87.
#[doc(hidden)]
pub const ML_DSA_87_NAME: &str = "ML-DSA-87";

/// Algorithm name of HashML-DSA-44 with SHA-256, as used by the CLI and `Algorithm::ALG_NAME`.
#[doc(hidden)]
pub const HASH_ML_DSA_44_with_SHA256_NAME: &str = "HashML-DSA-44_with_SHA256";
/// Algorithm name of HashML-DSA-44 with SHA-512.
#[doc(hidden)]
pub const HASH_ML_DSA_44_with_SHA512_NAME: &str = "HashML-DSA-44_with_SHA512";
/// Algorithm name of HashML-DSA-65 with SHA-512.
#[doc(hidden)]
pub const HASH_ML_DSA_65_with_SHA512_NAME: &str = "HashML-DSA-65_with_SHA512";
/// Algorithm name of HashML-DSA-87 with SHA-512.
#[doc(hidden)]
pub const HASH_ML_DSA_87_with_SHA512_NAME: &str = "HashML-DSA-87_with_SHA512";
