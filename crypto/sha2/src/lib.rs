//! Implements SHA2 as per NIST FIPS 180-4.
//!
//! # Examples
//! ## Hash
//! Hash functionality is accessed via the [bouncycastle_core::traits::Hash] trait,
//! which is implemented by [SHA224], [SHA256], [SHA384] and [SHA512].
//!
//! The simplest usage is via the static functions.
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_sha2 as sha2;
//!
//! let data: &[u8] = b"Hello, world!";
//! let output: Vec<u8> = sha2::SHA256::new().hash(data);
//! ```
//!
//! More advanced usage will require creating a SHA3 or SHAKE object to hold state between successive calls,
//! for example if input is received in chunks and not all available at the same time:
//!
//! ```
//! use bouncycastle_sha2 as sha2;
//! use bouncycastle_core::traits::Hash;
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
//!
//! # Suspending and resuming execution
//!
//! When hashing a large message, it can be advantageous to be able to suspend the operation
//! to a cache and resume it later; for example if waiting for the message to stream over a slow network
//! connection.
//!
//! For this reason, all SHA2 algorithms impl [Suspendable].
//!
//! ```rust
//! use bouncycastle_sha2 as sha2;
//! use bouncycastle_core::traits::{Hash, Suspendable};
//!
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let mut sha2 = sha2::SHA256::new();
//! sha2.do_update(msg_part1);
//!
//! // suspend the in-progress extract while "waiting" for the second part of the message.
//! let serialized_state = sha2.suspend();
//!
//! // ...
//! // do other things in the meantime
//! // ...
//!
//! // ... later, possibly on another host: resume from the serialized state.
//! let mut sha2_resumed = sha2::SHA256::from_suspended(serialized_state).unwrap();
//! sha2_resumed.do_update(msg_part2);
//! let h: Vec<u8> = sha2_resumed.do_final();
//! ```

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![allow(private_bounds)]

// The `Vec`-returning convenience APIs (`hash`, `do_final`, ...) live behind the default-on `alloc`
// feature. `no_std` users without an allocator should use the `*_out(&mut [u8])` / `*_array::<N>()`
// APIs from the [bouncycastle_core::traits::Hash] trait instead.
#[cfg(feature = "alloc")]
extern crate alloc;

mod sha256;
mod sha512;

pub use self::sha256::SHA256Internal;
pub use self::sha512::SHA512Internal;
use bouncycastle_core::traits::{Algorithm, HashAlgParams, SecurityStrength};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::traits::Suspendable;

/*** String constants ***/
pub const SHA224_NAME: &str = "SHA224";
pub const SHA256_NAME: &str = "SHA256";
pub const SHA384_NAME: &str = "SHA384";
pub const SHA512_NAME: &str = "SHA512";

/*** pub types ***/
pub type SHA224 = SHA256Internal<SHA224Params>;
pub type SHA256 = SHA256Internal<SHA256Params>;
pub type SHA384 = SHA512Internal<SHA384Params>;
pub type SHA512 = SHA512Internal<SHA512Params>;

/*** Param traits ***/

trait SHA2Params: HashAlgParams {}

impl HashAlgParams for SHA224 {
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 64;
}
#[derive(Clone)]
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

impl HashAlgParams for SHA256 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}
#[derive(Clone)]
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

impl HashAlgParams for SHA384 {
    const OUTPUT_LEN: usize = 48;
    const BLOCK_LEN: usize = 128;
}
#[derive(Clone)]
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

#[derive(Clone)]
pub struct SHA512Params;
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

pub use sha256::SUSPENDED_SHA256_STATE_LEN;
pub use sha512::SUSPENDED_SHA512_STATE_LEN;
