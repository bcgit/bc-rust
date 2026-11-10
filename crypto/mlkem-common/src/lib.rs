//! The arithmetic, encodings and parameters that `bouncycastle-mlkem` and
//! `bouncycastle-mlkem-lowmemory` share.
//!
//! This is not an API for callers, and every item in it is `#[doc(hidden)]`. The two ML-KEM crates
//! differ in how they hold a private key and in how they schedule FIPS 203's algorithms, but they
//! agree on the ring arithmetic, the samplers, the byte encodings, the compression and the
//! parameter tables; this crate holds that one copy, and the markers of ML-KEM with its secret
//! derived through HKDF ([`kdf`]), which both crates implement. Use one of those two crates.
//!
//! # 🚨 Security Considerations 🚨
//!
//! Nothing here checks the lengths it is handed beyond debug assertions, and nothing here is a
//! complete KEM operation. The security considerations of ML-KEM are documented on the two crates
//! that build on this one.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
// Names follow FIPS 203, where for example 'K' and 'k', or 'A' and 'a', are different things.
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

#[doc(hidden)]
pub mod aux_functions;
#[doc(hidden)]
pub mod kdf;
#[doc(hidden)]
pub mod params;
#[doc(hidden)]
pub mod polynomial;

use bouncycastle_sha3::{SHA3_256, SHA3_512, SHAKE256};

/* FIPS 203, Section 8: the constants that are the same for all parameter sets. */

/// The degree of the ring polynomial, 𝑛 = 256.
#[doc(hidden)]
pub const N: usize = 256;
/// The modulus 𝑞 = 3329.
#[doc(hidden)]
pub const q: i16 = 3329;
/// 𝑞^(−1) mod 2^16, for Montgomery reduction.
#[doc(hidden)]
pub const q_inv: i32 = 62209;
/// The length of one polynomial under ByteEncode12: 32 ⋅ 12 bytes.
#[doc(hidden)]
pub const POLY_BYTES: usize = 384;

/// Length of the \[u8] holding an ML-KEM seed value, (𝑑 ‖ 𝑧).
#[doc(hidden)]
pub const MLKEM_SEED_LEN: usize = 64;
/// Length of the \[u8] holding an ML-KEM encaps random value, also sometimes called the message `m`
#[doc(hidden)]
pub const MLKEM_RND_LEN: usize = 32;
/// Size of in bytes of an ML-KEM shared secret key.
#[doc(hidden)]
pub const MLKEM_SS_LEN: usize = 32;

// Typedefs just to make the algorithms look more like the FIPS 203 pseudocode.
/// G, the SHA3-512 hash of FIPS 203, Section 4.1.
#[doc(hidden)]
pub type G = SHA3_512;
/// H, the SHA3-256 hash of FIPS 203, Section 4.1.
#[doc(hidden)]
pub type H = SHA3_256;
/// J, the SHAKE256 XOF of FIPS 203, Section 4.1.
#[doc(hidden)]
pub type J = SHAKE256;

/// Algorithm name of ML-KEM-512, as used by the CLI and `Algorithm::ALG_NAME`.
#[doc(hidden)]
pub const ML_KEM_512_NAME: &str = "ML-KEM-512";
/// Algorithm name of ML-KEM-768.
#[doc(hidden)]
pub const ML_KEM_768_NAME: &str = "ML-KEM-768";
/// Algorithm name of ML-KEM-1024.
#[doc(hidden)]
pub const ML_KEM_1024_NAME: &str = "ML-KEM-1024";
