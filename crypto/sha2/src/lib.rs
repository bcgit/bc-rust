//! Implements SHA2 as per NIST FIPS 180-4.
//!
//! This crate provides the following primitives:
//!
//! * SHA2 [`Hash`] functions.
//!
//! # Examples
//! ## Hash
//! Hash functionality is accessed via the [`bouncycastle_core::traits::Hash`] trait,
//! which is implemented by all the SHA2 primitives.
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
//! for example, if input is received in chunks and not all available at the same time:
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
//! ## Partial byte
//! It is also possible to provide input where the final byte contains fewer than 8 bits of data
//! (a bit-oriented message, FIPS 180-4 s. 5.1). The partial byte is taken as the most significant bits,
//! leading bit first, and the low "unused" bits are ignored. The following hashes 16 bytes plus the
//! 3 padding bits `101`:
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_sha2 as sha2;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\xA0";
//! let mut sha2 = sha2::SHA256::new();
//! sha2.do_update(&data[..16]);
//! let output: Vec<u8> = sha2.do_final_partial_bits(data[16], 3).expect("num_partial_bits is in 0..=7");
//! ```
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
//!
//! # Memory Usage
//!
//! | Object                                                   | Size (bytes) |
//! |----------------------------------------------------------|--------------|
//! | `SHA224`, `SHA256`                                       | 112          |
//! | `SHA384`, `SHA512`, `SHA512_224`, `SHA512_256`           | 208          |
//! | Suspended `SHA224`/`SHA256` state                        | 108          |
//! | Suspended `SHA384`/`SHA512`/`SHA512_224`/`SHA512_256` state | 204       |
//!
//! # Security Considerations
//!
//! * SHA-224/256/384/512 offer 112/128/192/256 bits of collision resistance respectively;
//!   SHA-512/224 and SHA-512/256 offer 112 and 128 bits (SP 800-107r1, Table 1 (§4.2)).
//! * SHA-2 is a Merkle–Damgård construction and is therefore subject to length-extension:
//!   `H(k || m)` is not a secure MAC. Use HMAC (`bouncycastle-hmac`) for keyed hashing.
//! * SHA-224, SHA-384, SHA-512/224 and SHA-512/256 are truncations of SHA-256 or SHA-512 with
//!   distinct initial values, and are not vulnerable to length extension in the same direct way, but
//!   should still not be used as `H(k || m)` MACs.
//! * The chaining value and input buffer are held in [`bouncycastle_utils::secret::Secret`] and
//!   zeroized on drop. Transient copies (working variables and message schedule) in registers/stack
//!   locals during compression are not zeroized.
//! * The implementation contains no data-dependent branches or table lookups.
//! * Messages up to 2^64 bytes are supported (FIPS 180-4 permits 2^64 bits for SHA-224/256 and
//!   2^128 bits for SHA-384/512 and SHA-512/t; the SHA-512 family limit here is 2^67 bits).

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![allow(private_bounds)]

mod sha256;
mod sha512;

pub use self::sha256::SHA256Internal;
use self::sha256::{SHA224_H0, SHA256_H0};
pub use self::sha512::SHA512Internal;
use self::sha512::{SHA384_H0, SHA512_H0, sha512t_h0};
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, SecurityStrength};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::traits::{Hash, Suspendable};
/*** end of doc-only imports ***/

/*** String constants ***/
/// Algorithm name string for SHA224, as used by the factories and CLI.
pub const SHA224_NAME: &str = "SHA224";
/// Algorithm name string for SHA256, as used by the factories and CLI.
pub const SHA256_NAME: &str = "SHA256";
/// Algorithm name string for SHA384, as used by the factories and CLI.
pub const SHA384_NAME: &str = "SHA384";
/// Algorithm name string for SHA512, as used by the factories and CLI.
pub const SHA512_NAME: &str = "SHA512";
/// Algorithm name string for SHA512/224, as used by the factories and CLI.
pub const SHA512_224_NAME: &str = "SHA512/224";
/// Algorithm name string for SHA512/256, as used by the factories and CLI.
pub const SHA512_256_NAME: &str = "SHA512/256";

/*** pub types ***/
/// Public type for SHA224.
pub type SHA224 = SHA256Internal<SHA224Params>;
/// Public type for SHA256.
pub type SHA256 = SHA256Internal<SHA256Params>;
/// Public type for SHA384.
pub type SHA384 = SHA512Internal<SHA384Params>;
/// Public type for SHA512.
pub type SHA512 = SHA512Internal<SHA512Params>;
/// Public type for the SHA-512/t family (FIPS 180-4 s. 5.3.6): SHA-512 with a t-specific initial
/// hash value, truncated to `T` bits. Only the NIST-approved truncations `T = 224` and `T = 256`
/// can be instantiated; see [`SHA512_224`] and [`SHA512_256`].
pub type SHA512t<const T: usize> = SHA512Internal<SHA512tParams<T>>;
/// Public type for SHA512/224 (FIPS 180-4 s. 6.6).
pub type SHA512_224 = SHA512t<224>;
/// Public type for SHA512/256 (FIPS 180-4 s. 6.7).
pub type SHA512_256 = SHA512t<256>;

/*** Param traits ***/
/// Private trait on purpose so that only the NIST-approved params can be used.
trait SHA2Params: HashAlgParams {}

/// The SHA-256 family (SHA-224, SHA-256) shares one compression function and differs only in the
/// initial hash value and the output truncation, so each member supplies its H(0) here.
/// Private for the same reason as [`SHA2Params`].
trait Sha256Family: SHA2Params {
    /// The initial hash value H(0), FIPS 180-4 s. 5.3.2 / 5.3.3.
    const H0: [u32; 8];
}

/// The SHA-512 family (SHA-384, SHA-512, SHA-512/t) shares one compression function and differs
/// only in the initial hash value and the output truncation, so each member supplies its H(0) here.
/// Private for the same reason as [`SHA2Params`].
trait Sha512Family: SHA2Params {
    /// The initial hash value H(0), FIPS 180-4 s. 5.3.4 / 5.3.5 / 5.3.6.
    const H0: [u64; 8];
}

/// The public hash types expose the same parameters as their `*Params` marker, so the constants
/// are defined exactly once (on the params struct) and forwarded here.
impl<PARAMS: Sha256Family> HashAlgParams for SHA256Internal<PARAMS> {
    const OUTPUT_LEN: usize = PARAMS::OUTPUT_LEN;
    const BLOCK_LEN: usize = PARAMS::BLOCK_LEN;
}
impl<PARAMS: Sha512Family> HashAlgParams for SHA512Internal<PARAMS> {
    const OUTPUT_LEN: usize = PARAMS::OUTPUT_LEN;
    const BLOCK_LEN: usize = PARAMS::BLOCK_LEN;
}

/*** SHA224 ***/
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
impl Sha256Family for SHA224Params {
    // FIPS 180-4 s. 6.3 exception 1: H(0) as specified in s. 5.3.2.
    const H0: [u32; 8] = SHA224_H0;
}

/*** SHA256 ***/
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
impl Sha256Family for SHA256Params {
    // FIPS 180-4 s. 6.2.1 step 1: H(0) as specified in s. 5.3.3.
    const H0: [u32; 8] = SHA256_H0;
}

/*** SHA384 ***/
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
impl Sha512Family for SHA384Params {
    // FIPS 180-4 s. 6.5 exception 1: H(0) as specified in s. 5.3.4.
    const H0: [u64; 8] = SHA384_H0;
}

/*** SHA512 ***/
/// The parameters for SHA512.
#[derive(Clone)]
pub struct SHA512Params;
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
impl Sha512Family for SHA512Params {
    // FIPS 180-4 s. 6.4.1 step 1: H(0) as specified in s. 5.3.5.
    const H0: [u64; 8] = SHA512_H0;
}

/*** SHA-512/t ***/
/// The parameters for SHA-512/t (FIPS 180-4 s. 5.3.6), for a truncation of `T` bits.
///
/// The parameter traits are implemented only for the NIST-approved truncations `T = 224` and
/// `T = 256` ("Other SHA-512/t hash algorithms with different t values may be specified in
/// [SP 800-107] in the future as the need arises"), so any other `T` is a compile-time error.
#[derive(Clone)]
pub struct SHA512tParams<const T: usize>;

/*** SHA512/224 ***/
impl Algorithm for SHA512tParams<224> {
    const ALG_NAME: &'static str = SHA512_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}
impl HashAlgParams for SHA512tParams<224> {
    const OUTPUT_LEN: usize = 28; // FIPS 180-4 s. 6.6 exception 2: truncated to the left-most 224 bits
    const BLOCK_LEN: usize = 128; // FIPS 180-4 Figure 1: block size 1024 bits
}
/// Assigned by NIST in the Computer Security Objects Register: id-sha512-224 { hashAlgs 5 }
impl AlgorithmOID for SHA512_224 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 5];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05];
}
impl SHA2Params for SHA512tParams<224> {}
impl Sha512Family for SHA512tParams<224> {
    // FIPS 180-4 s. 6.6 exception 1: H(0) as specified in s. 5.3.6.1 (pinned against the words
    // listed there by tests/sha512t_h0_tests.rs).
    const H0: [u64; 8] = sha512t_h0(224);
}

/*** SHA512/256 ***/
impl Algorithm for SHA512tParams<256> {
    const ALG_NAME: &'static str = SHA512_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl HashAlgParams for SHA512tParams<256> {
    const OUTPUT_LEN: usize = 32; // FIPS 180-4 s. 6.7 exception 2: truncated to the left-most 256 bits
    const BLOCK_LEN: usize = 128; // FIPS 180-4 Figure 1: block size 1024 bits
}
/// Assigned by NIST in the Computer Security Objects Register: id-sha512-256 { hashAlgs 6 }
impl AlgorithmOID for SHA512_256 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 6];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06];
}
impl SHA2Params for SHA512tParams<256> {}
impl Sha512Family for SHA512tParams<256> {
    // FIPS 180-4 s. 6.7 exception 1: H(0) as specified in s. 5.3.6.2 (pinned against the words
    // listed there by tests/sha512t_h0_tests.rs).
    const H0: [u64; 8] = sha512t_h0(256);
}

pub use sha256::SUSPENDED_SHA256_STATE_LEN;
pub use sha512::SUSPENDED_SHA512_STATE_LEN;
