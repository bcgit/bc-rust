//! Implements SHA2 as per NIST FIPS 180-4.
//!
//! This crate provides the following primitives:
//!
//! * SHA2 [`Hash`] functions.
//! * HMAC_SHA2* [`MAC`] functions.
//! * HKDF-SHA2* [`KDF`] functions.
//!
//! # Examples
//! ## Hash
//! Hash functionality is accessed via the [`bouncycastle_core::traits::Hash`] trait,
//! which is implemented by [`SHA224`], [`SHA256`], [`SHA384`] and [`SHA512`].
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
//! More advanced usage will require creating a SHA2 object to hold state between successive calls,
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
//! ## HMAC
//! See [hmac].
//!
//! ## HKDF
//!
//! See [hkdf]
//!
//! # Memory Usage
//!
//! No heap memory is used by the algorithms themselves; the `Vec<u8>`-returning convenience methods
//! allocate only the output buffer, and the `*_out` variants allocate nothing.
//!
//! | Object                                                   | Size (bytes) |
//! |----------------------------------------------------------|--------------|
//! | `SHA224`, `SHA256`                                       | 112          |
//! | `SHA384`, `SHA512`                                       | 208          |
//! | Suspended `SHA224`/`SHA256` state                        | 108          |
//! | Suspended `SHA384`/`SHA512` state                        | 204          |
//!
//! The object holds the 8-word chaining value plus one block of buffered input. The compression
//! function additionally uses a 64-word (SHA-256 family, 256 bytes) or 80-word (SHA-512 family,
//! 640 bytes) message schedule on the stack for the duration of a call.
//!
//! # Security Considerations
//!
//! * SHA-224/256/384/512 offer 112/128/192/256 bits of collision resistance respectively.
//! * SHA-2 is a Merkle–Damgård construction and is therefore subject to length-extension:
//!   `H(k || m)` is not a secure MAC. Use HMAC ([`crate::hmac`]) for keyed hashing.
//! * SHA-224 and SHA-384 are truncations of SHA-256 and SHA-512 with distinct initial values, and
//!   are not vulnerable to length extension in the same direct way, but should still not be used as
//!   `H(k || m)` MACs.
//! * The chaining value and input buffer are held in [`bouncycastle_utils::secret::Secret`] and
//!   zeroized on drop. Transient copies (working variables and message schedule) in registers/stack
//!   locals during compression are not zeroized.
//! * The implementation contains no data-dependent branches or table lookups.
//! * Messages up to 2^64 bytes are supported (FIPS 180-4 permits 2^64 bits for SHA-224/256 and
//!   2^128 bits for SHA-384/512; the SHA-512 family limit here is 2^67 bits).
//!
//! # Suspending and resuming execution
//!
//! When hashing a large message, it can be advantageous to be able to suspend the operation
//! to a cache and resume it later; for example if waiting for the message to stream over a slow network
//! connection.
//!
//! For this reason, all SHA2 algorithms impl [`Suspendable`].
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

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![allow(private_bounds)]

mod sha256;
mod sha512;

pub mod hkdf;
pub mod hmac;

pub use self::sha256::SHA256Internal;
pub use self::sha512::SHA512Internal;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, SecurityStrength};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::traits::{Hash, KDF, MAC, Suspendable};

/*** String constants ***/
///
pub const SHA224_NAME: &str = "SHA224";
///
pub const SHA256_NAME: &str = "SHA256";
///
pub const SHA384_NAME: &str = "SHA384";
///
pub const SHA512_NAME: &str = "SHA512";

/*** pub types ***/
/// Public type for SHA224.
pub type SHA224 = SHA256Internal<SHA224Params>;
/// Public type for SHA256.
pub type SHA256 = SHA256Internal<SHA256Params>;
/// Public type for SHA384.
pub type SHA384 = SHA512Internal<SHA384Params>;
/// Public type for SHA512.
pub type SHA512 = SHA512Internal<SHA512Params>;

/*** Param traits ***/
/// Private trait on purpose so that only the NIST-approved params can be used.
trait SHA2Params: HashAlgParams {}

/*** SHA224 ***/
impl HashAlgParams for SHA224 {
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 64;
}
/// The parameters for SHA224.
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
/// Assigned by NIST in the Computer Security Objects Register: id-sha224 { hashAlgs 4 }
impl AlgorithmOID for SHA224 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 4];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];
}
impl SHA2Params for SHA224Params {}

/*** SHA256 ***/
impl HashAlgParams for SHA256 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}
/// The parameters for SHA256.
#[derive(Clone)]
pub struct SHA256Params;
impl Algorithm for SHA256Params {
    const ALG_NAME: &'static str = SHA256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
/// Assigned by NIST in the Computer Security Objects Register: id-sha256 { hashAlgs 1 }
impl AlgorithmOID for SHA256 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
}
impl HashAlgParams for SHA256Params {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}
impl SHA2Params for SHA256Params {}

/*** SHA384 ***/
impl HashAlgParams for SHA384 {
    const OUTPUT_LEN: usize = 48;
    const BLOCK_LEN: usize = 128;
}
/// The parameters for SHA384.
#[derive(Clone)]
pub struct SHA384Params;
impl Algorithm for SHA384Params {
    const ALG_NAME: &'static str = SHA384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}
/// Assigned by NIST in the Computer Security Objects Register: id-sha384 { hashAlgs 2 }
impl AlgorithmOID for SHA384 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 2];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
}
impl HashAlgParams for SHA384Params {
    const OUTPUT_LEN: usize = 48;
    const BLOCK_LEN: usize = 128;
}
impl SHA2Params for SHA384Params {}

/*** SHA512 ***/
/// The parameters for SHA512.
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
/// Assigned by NIST in the Computer Security Objects Register: id-sha512 { hashAlgs 3 }
impl AlgorithmOID for SHA512 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 3];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
}
impl SHA2Params for SHA512Params {}

pub use sha256::SUSPENDED_SHA256_STATE_LEN;
pub use sha512::SUSPENDED_SHA512_STATE_LEN;
