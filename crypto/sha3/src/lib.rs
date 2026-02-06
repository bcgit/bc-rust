//! Implements SHA3 as per NIST FIPS 202.
//!
//! # Examples
//! ## Hash
//! Hash functionality is accessed via the [Hash] trait,
//! which is implemented by [SHA3_224], [SHA3_256], [SHA3_384] and [SHA3_512].
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use bouncycastle_core_interface::traits::Hash;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"Hello, world!";
//! let output: Vec<u8> = sha3::SHA3_256::new().hash(data);
//! ```
//!
//! More advanced usage will require creating a SHA3 or SHAKE object to hold state between successive calls,
//! for example if input is received in chunks and not all available at the same time:
//!
//! ```
//! use bouncycastle_core_interface::traits::Hash;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F
//!                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F
//!                     \x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F
//!                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
//! let mut sha3 = sha3::SHA3_256::new();
//!
//! for chunk in data.chunks(16) {
//!     sha3.do_update(chunk);
//! }
//!
//! let output: Vec<u8> = sha3.do_final();
//! ```
//!
//! It is also possible to provide input where the final byte contains less than 8 bits of data (ie is a partial byte);
//! for example, the following code uses only 3 bits of the final byte:
//! ```
//! use bouncycastle_core_interface::traits::Hash;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
//! let mut sha3 = sha3::SHA3_256::new();
//! sha3.do_update(&data[..data.len()-1]);
//! let final_byte = data[data.len()-1];
//! let output: Vec<u8> = sha3.do_final_partial_bits(final_byte, 3).expect("Failed to finalize hash state.");
//! ```
//!
//! ## XOF
//! SHA3 offers Extendable-Output Functions in the form of SHAKE, which is accessed through the [XOF] trait,
//! which is implemented by [SHAKE128] and [SHAKE256].
//! The difference from [Hash] is that SHAKE can produce output of any length.
//!
//! The simplest usage is via the static functions. The following example produces a 16 byte (128-bit) and 16KiB output:
//!```
//! use bouncycastle_core_interface::traits::XOF;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"Hello, world!";
//! let output_16byte: Vec<u8> = sha3::SHAKE128::new().hash_xof(data, 16);
//! let output_16KiB: Vec<u8> = sha3::SHAKE128::new().hash_xof(data, 16 * 1024);
//! ```
//!
//! As with [Hash] above, the [XOF] trait has streaming APIs in the form of [XOF::absorb] and [XOF::squeeze].
//! Unlike [Hash::do_final], [XOF::squeeze] can be called multiple times.
//! The following code produces the same output as the previous example:
//!```
//! use bouncycastle_core_interface::traits::XOF;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"Hello, world!";
//! let mut shake = sha3::SHAKE128::new();
//! shake.absorb(data).expect("Failed to absorb data.");
//! let output_16byte: Vec<u8> = shake.squeeze(16).expect("Is infallible");
//!
//! let mut shake = sha3::SHAKE128::new();
//! let mut output_16KiB: Vec<u8> = vec![];
//! for i in 0..16 { output_16KiB.extend_from_slice(&shake.squeeze(1024).expect("Is infallible")) }
//! ```
//!
//! ## KDF
//! SHA3 offers Key Derivation Functions in the form of KDF, which is accessed through the [KDF] trait,
//! which is implemented by all SHA3 and SHAKE variants.
//! [KDF] acts on [KeyMaterialInternal] objects as both the input and output values.
//! In the case of SHA3, the [KDF] interfaces are simple wrapper functions around the underlying SHA3 or SHAKE
//! primitive that correctly maintains the length and entropy metadata of the key material that it is acting on.
//! This is intended to act as a developer ait to prevent  some classes of developer mistakes, such as
//! deriving a cryptographic key from uninitialized (aka zeroized) input key material, or using low-entropy
//! input key material to derive a MAC, symmetric, or asymmetric key.
//!
//! ```
//! use bouncycastle_core_interface::traits::KDF;
//! use bouncycastle_core_interface::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_sha3 as sha3;
//!
//! let input_key = KeyMaterial256::from_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F").unwrap();
//! let output_key = sha3::SHA3_256::new().derive_key(&input_key, b"Additional input").unwrap();
//!```
//! In the previous example, since [KeyMaterialInternal::from_bytes] cannot know the amount of entropy in the input data,
//! it automatically tags it as [KeyType::BytesLowEntropy], and thus [SHA3::derive_key] produces an output key
//! which also has type [KeyType::BytesLowEntropy].
//! This would also be the case even if the input had type
//! [KeyType::BytesFullEntropy] since the input [KeyMaterialInternal] is 16 bytes but [SHA3_256] needs at least 32 bytes of
//! full-entropy input key material in order to be able to produce full entropy output key material.

#![forbid(unsafe_code)]
#![allow(private_bounds)]

use crate::keccak::{KeccakSize};
use bouncycastle_core_interface::traits::{Algorithm, HashAlgParams, SecurityStrength};

// imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core_interface::traits::{Hash, KDF, XOF};
#[allow(unused_imports)]
use bouncycastle_core_interface::key_material::{KeyMaterialInternal, KeyType};
// end of doc-only imports

mod keccak;
mod sha3;
mod shake;
/*** String constants ***/
pub const SHA3_224_NAME: &str = "SHA3-224";
pub const SHA3_256_NAME: &str = "SHA3-256";
pub const SHA3_384_NAME: &str = "SHA3-384";
pub const SHA3_512_NAME: &str = "SHA3-512";
pub const SHAKE128_NAME: &str = "SHAKE128";
pub const SHAKE256_NAME: &str = "SHAKE256";

/*** pub types ***/
pub use sha3::SHA3;
pub use shake::SHAKE;
pub type SHA3_224 = SHA3<SHA3_224Params>;
pub type SHA3_256 = SHA3<SHA3_256Params>;
pub type SHA3_384 = SHA3<SHA3_384Params>;
pub type SHA3_512 = SHA3<SHA3_512Params>;
pub type SHAKE128 = SHAKE<SHAKE128Params>;
pub type SHAKE256 = SHAKE<SHAKE256Params>;

/*** Param traits ***/
trait SHA3Params: HashAlgParams {
    const SIZE: KeccakSize;
}

// TODO: more elegant to macro this?
impl Algorithm for SHA3_224 {
    const ALG_NAME: &'static str = SHA3_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}
impl HashAlgParams for SHA3_224 {
    const OUTPUT_LEN: usize = 28;
    // const BLOCK_LEN: usize = 64;
    const BLOCK_LEN: usize = 144; // FIPS 202 Table 3
}
pub struct SHA3_224Params;
impl Algorithm for SHA3_224Params {
    const ALG_NAME: &'static str = SHA3_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}
impl HashAlgParams for SHA3_224Params {
    const OUTPUT_LEN: usize = 28;
    // const BLOCK_LEN: usize = 64;
    const BLOCK_LEN: usize = 144; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_224Params {
    const SIZE: KeccakSize = KeccakSize::_224;}

impl Algorithm for SHA3_256 {
    const ALG_NAME: &'static str = SHA3_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl HashAlgParams for SHA3_256 {
    const OUTPUT_LEN: usize = 32;
    // const BLOCK_LEN: usize = 64;
    const BLOCK_LEN: usize = 136; // FIPS 202 Table 3
}
pub struct SHA3_256Params;
impl Algorithm for SHA3_256Params {
    const ALG_NAME: &'static str = SHA3_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl HashAlgParams for SHA3_256Params {
    const OUTPUT_LEN: usize = 32;
    // const BLOCK_LEN: usize = 64;
    const BLOCK_LEN: usize = 136; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_256Params {
    const SIZE: KeccakSize = KeccakSize::_256;
}

pub struct SHA3_384Params;
impl Algorithm for SHA3_384 {
    const ALG_NAME: &'static str = SHA3_384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}
impl HashAlgParams for SHA3_384 {
    const OUTPUT_LEN: usize = 48;
    // const BLOCK_LEN: usize = 128;
    const BLOCK_LEN: usize = 104; // FIPS 202 Table 3
}
impl Algorithm for SHA3_384Params {
    const ALG_NAME: &'static str = SHA3_384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}
impl HashAlgParams for SHA3_384Params {
    const OUTPUT_LEN: usize = 48;
    // const BLOCK_LEN: usize = 128;
    const BLOCK_LEN: usize = 104; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_384Params {
    const SIZE: KeccakSize = KeccakSize::_384;
}

pub struct SHA3_512Params;
impl Algorithm for SHA3_512 {
    const ALG_NAME: &'static str = SHA3_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl HashAlgParams for SHA3_512 {
    const OUTPUT_LEN: usize = 64;
    // const BLOCK_LEN: usize = 128;
    const BLOCK_LEN: usize = 72; // FIPS 202 Table 3
}
impl Algorithm for SHA3_512Params {
    const ALG_NAME: &'static str = SHA3_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl HashAlgParams for SHA3_512Params {
    const OUTPUT_LEN: usize = 64;
    // const BLOCK_LEN: usize = 128;
    const BLOCK_LEN: usize = 72; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_512Params {
    const SIZE: KeccakSize = KeccakSize::_512;
}

trait SHAKEParams: Algorithm {
    const SIZE: KeccakSize;
}
pub struct SHAKE128Params;
impl Algorithm for SHAKE128Params {
    const ALG_NAME: &'static str = SHAKE128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl SHAKEParams for SHAKE128Params {
    const SIZE: KeccakSize = KeccakSize::_128;
}

pub struct SHAKE256Params;
impl Algorithm for SHAKE256Params {
    const ALG_NAME: &'static str = SHAKE256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl SHAKEParams for SHAKE256Params {
    const SIZE: KeccakSize = KeccakSize::_256;
}

