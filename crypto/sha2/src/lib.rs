//! Implements SHA2 as per NIST FIPS 180-4.
//!
//! # Examples
//! ## Hash
//! Hash functionality is accessed via the [bouncycastle_core_interface::traits::Hash] trait,
//! which is implemented by [SHA224], [SHA256], [SHA384] and [SHA512].
//!
//! The simplest usage is via the static functions.
//! ```
//! use bouncycastle_core_interface::traits::Hash;
//!
//! let data: &[u8] = b"Hello, world!";
//! let output: Vec<u8> = sha2::SHA256::new().hash(data);
//! ```
//!
//! More advanced usage will require creating a SHA3 or SHAKE object to hold state between successive calls,
//! for example if input is received in chunks and not all available at the same time:
//!
//! ```
//! use bouncycastle_core_interface::traits::Hash;
//! use bouncycastle_sha2 as sha2;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F
//!                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F
//!                     \x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F
//!                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
//! let mut sha2 = sha2::SHA256::new();
//!
//! for chunk in data.chunks(16) {
//!     sha2.do_update(chunk);
//! }
//!
//! let output: Vec<u8> = sha2.do_final();
//! ```

#![forbid(unsafe_code)]
#![allow(private_bounds)]

mod sha256;
mod sha512;

pub use self::sha256::SHA256Internal;
pub use self::sha512::Sha512Internal;
use bouncycastle_core_interface::traits::{Algorithm, HashAlgParams, SecurityStrength};

/*** String constants ***/
pub const SHA224_NAME: &str = "SHA224";
pub const SHA256_NAME: &str = "SHA256";
pub const SHA384_NAME: &str = "SHA384";
pub const SHA512_NAME: &str = "SHA512";

/*** pub types ***/
pub type SHA224 = SHA256Internal<SHA224Params>;
pub type SHA256 = SHA256Internal<SHA256Params>;
pub type SHA384 = Sha512Internal<SHA384Params>;
pub type SHA512 = Sha512Internal<SHA512Params>;

/*** Param traits ***/

trait SHA2Params: HashAlgParams {}

impl Algorithm for SHA224 {
    const ALG_NAME: &'static str = SHA224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}
impl HashAlgParams for SHA224 {
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 64;
}
pub struct SHA224Params;
impl Algorithm for SHA224Params {
    const ALG_NAME: &'static str = SHA224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}
impl HashAlgParams for SHA224Params {
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 64;
}
impl SHA2Params for SHA224Params {}

impl Algorithm for SHA256 {
    const ALG_NAME: &'static str = SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl HashAlgParams for SHA256 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}
pub struct SHA256Params;
impl Algorithm for SHA256Params {
    const ALG_NAME: &'static str = SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl HashAlgParams for SHA256Params {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}
impl SHA2Params for SHA256Params {}

impl Algorithm for SHA384 {
    const ALG_NAME: &'static str = SHA384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}
impl HashAlgParams for SHA384 {
    const OUTPUT_LEN: usize = 48;
    const BLOCK_LEN: usize = 128;
}
pub struct SHA384Params;
impl Algorithm for SHA384Params {
    const ALG_NAME: &'static str = SHA384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}
impl HashAlgParams for SHA384Params {
    const OUTPUT_LEN: usize = 48;
    const BLOCK_LEN: usize = 128;
}
impl SHA2Params for SHA384Params {}

pub struct SHA512Params;
impl Algorithm for SHA512 {
    const ALG_NAME: &'static str = SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl HashAlgParams for SHA512 {
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;
}
impl Algorithm for SHA512Params {
    const ALG_NAME: &'static str = SHA512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl HashAlgParams for SHA512Params {
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;
}
impl SHA2Params for SHA512Params {}
