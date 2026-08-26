//! Implements SHA3 as per NIST FIPS 202.
//!
//! # Examples
//! ## Hash
//! Hash functionality is accessed via the [`Hash`] trait,
//! which is implemented by [`SHA3_224`], [`SHA3_256`], [`SHA3_384`] and [`SHA3_512`].
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use bouncycastle_core::traits::Hash;
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
//! use bouncycastle_core::traits::Hash;
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
//! use bouncycastle_core::traits::Hash;
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
//! SHA3 offers Extendable-Output Functions in the form of SHAKE, which is accessed through the [`XOF`] trait,
//! which is implemented by [`SHAKE128`] and [`SHAKE256`].
//! The difference from [`Hash`] is that SHAKE can produce output of any length.
//!
//! The simplest usage is via the static functions. The following example produces a 16 byte (128-bit) and 16KiB output:
//!```
//! use bouncycastle_core::traits::XOF;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"Hello, world!";
//! let output_16byte: Vec<u8> = sha3::SHAKE128::new().hash_xof(data, 16);
//! let output_16KiB: Vec<u8> = sha3::SHAKE128::new().hash_xof(data, 16 * 1024);
//! ```
//!
//! As with [`Hash`] above, the [`XOF`] trait has streaming APIs in the form of [`XOF::absorb`] and [`XOF::squeeze`].
//! Unlike [`Hash::do_final`], [`XOF::squeeze`] can be called multiple times.
//! Note, however, that once you start squeezing, you can no longer absorb more input -- [`XOF::absorb`]
//! will throw a [`HashError::InvalidState`], but the SHAKE object will still be usable for squeezing
//! as if the erroneous `absorb` call never happened.
//!
//! The following code produces the same output as the previous example:
//!```
//! use bouncycastle_core::traits::XOF;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"Hello, world!";
//! let mut shake = sha3::SHAKE128::new();
//! shake.absorb(data).expect("infallible before squeeze");
//! let output_16byte: Vec<u8> = shake.squeeze(16);
//!
//! let mut shake = sha3::SHAKE128::new();
//! let mut output_16KiB: Vec<u8> = vec![];
//! for i in 0..16 { output_16KiB.extend_from_slice(&shake.squeeze(1024)) }
//! ```
//!
//! ## KDF
//! SHA3 offers Key Derivation Functions in the form of KDF, which is accessed through the [`KDF`] trait,
//! which is implemented by all SHA3 and SHAKE variants.
//! [`KDF`] acts on [`KeyMaterial`] objects as both the input and output values.
//! In the case of SHA3, the [`KDF`] interfaces are simple wrapper functions around the underlying SHA3 or SHAKE
//! primitive that correctly maintains the length and entropy metadata of the key material that it is acting on.
//! This is intended to act as a developer aid to prevent some classes of developer mistakes, such as
//! deriving a cryptographic key from uninitialized (aka zeroized) input key material, or using low-entropy
//! input key material to derive a MAC, symmetric, or asymmetric key.
//!
//! ```
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_sha3 as sha3;
//!
//! let input_key = KeyMaterial256::from_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F").unwrap();
//! let output_key = sha3::SHA3_256::new().derive_key(&input_key, b"Additional input").unwrap();
//!```
//! In the previous example, since [`KeyMaterial::from_bytes`] cannot know the amount of entropy in the input data,
//! it automatically tags it as [`KeyType::Unknown`], and thus [`SHA3Internal::derive_key`] produces an output key
//! which also has type [`KeyType::Unknown`].
//! This would also be the case even if the input had type
//! [`KeyType::CryptographicRandom`] since the input [`KeyMaterial`] is 16 bytes but [`SHA3_256`] needs at least 32 bytes of
//! full-entropy input key material in order to be able to produce full entropy output key material.
//!
//! # Memory Usage
//!
//! All SHA3 and SHAKE variants share the same Keccak-f\[1600\] sponge and so have identical memory
//! footprints. No heap memory is used by the algorithms themselves; the `Vec<u8>`-returning
//! convenience methods allocate only the output buffer, and the `*_out` variants allocate nothing.
//!
//! | Object                                  | Size (bytes) |
//! |-----------------------------------------|--------------|
//! | `SHA3_224` .. `SHA3_512`, `SHAKE128/256` | 440          |
//! | Suspended state ([`Suspendable`])       | 415          |
//!
//! The object size is dominated by the 200-byte sponge state and a 192-byte input/output queue.
//! The Keccak permutation itself runs on 25 `u64` locals plus a handful of temporaries, so transient
//! stack usage per call is on the order of a few hundred bytes beyond the object.
//!
//! # Security Considerations
//!
//! * SHA3-224/256/384/512 offer 112/128/192/256 bits of collision resistance respectively; SHAKE128
//!   and SHAKE256 offer 128 and 256 bits of security for output lengths at least twice that size
//!   (FIPS 202 Appendix A.1).
//! * SHAKE is an XOF, not a hash: `SHAKE128(m, 32)` is a prefix of `SHAKE128(m, 64)`. If the output
//!   length must be bound to the digest, include it in the message (FIPS 202 Appendix A.2). For this
//!   reason SHAKE does not implement [`Hash`].
//! * Once squeezing begins, no further input can be absorbed; [`XOF::absorb`] returns
//!   [`HashError::InvalidState`] rather than silently producing an unapproved construction.
//! * The sponge state and queue are held in [`bouncycastle_utils::secret::Secret`] and zeroized on
//!   drop. Transient copies in registers/stack locals during the permutation are not zeroized.
//! * The implementation contains no data-dependent branches or table lookups.
//! * The [`KDF`] entropy tracking is a developer aid, not a security proof: it can only reason about
//!   the metadata attached to [`KeyMaterial`] inputs.
//!
//! # Suspending and resuming execution
//!
//! When hashing a large message, it can be advantageous to be able to suspend the operation
//! to a cache and resume it later; for example if waiting for the message to stream over a slow network
//! connection.
//!
//! For this reason, all SHA3 algorithms impl [`Suspendable`].
//!
//!```rust
//! use bouncycastle_sha3 as sha3;
//! use bouncycastle_core::traits::{Hash, Suspendable};
//!
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let mut sha3 = sha3::SHA3_256::new();
//! sha3.do_update(msg_part1);
//!
//! // suspend the in-progress extract while "waiting" for the second part of the message.
//! let serialized_state = sha3.suspend();
//!
//! // ...
//! // do other things in the meantime
//! // ...
//!
//! // ... later, possibly on another host: resume from the serialized state.
//! let mut sha3_resumed = sha3::SHA3_256::from_suspended(serialized_state).unwrap();
//! sha3_resumed.do_update(msg_part2);
//! let h: Vec<u8> = sha3_resumed.do_final();
//! ```

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![allow(private_bounds)]

use crate::keccak::KeccakSize;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, SecurityStrength};

// imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::errors::HashError;
#[allow(unused_imports)]
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
#[allow(unused_imports)]
use bouncycastle_core::traits::{Hash, KDF, Suspendable, XOF};
// end of doc-only imports

mod keccak;
mod sha3;
mod shake;

/*** String constants ***/
/// Algorithm name string for SHA3-224, as used by the factories and CLI.
pub const SHA3_224_NAME: &str = "SHA3-224";
/// Algorithm name string for SHA3-256, as used by the factories and CLI.
pub const SHA3_256_NAME: &str = "SHA3-256";
/// Algorithm name string for SHA3-384, as used by the factories and CLI.
pub const SHA3_384_NAME: &str = "SHA3-384";
/// Algorithm name string for SHA3-512, as used by the factories and CLI.
pub const SHA3_512_NAME: &str = "SHA3-512";
/// Algorithm name string for SHAKE128, as used by the factories and CLI.
pub const SHAKE128_NAME: &str = "SHAKE128";
/// Algorithm name string for SHAKE256, as used by the factories and CLI.
pub const SHAKE256_NAME: &str = "SHAKE256";

/*** pub types ***/
pub use sha3::SHA3Internal;
pub use shake::SHAKEInternal;

pub use keccak::SUSPENDED_SHA3_STATE_LEN;

/// Public type for SHA3_224.
pub type SHA3_224 = SHA3Internal<SHA3_224Params>;
/// Public type for SHA3_256.
pub type SHA3_256 = SHA3Internal<SHA3_256Params>;
/// Public type for SHA3_384.
pub type SHA3_384 = SHA3Internal<SHA3_384Params>;
/// Public type for SHA3_512.
pub type SHA3_512 = SHA3Internal<SHA3_512Params>;
/// Public type for SHAKE128.
pub type SHAKE128 = SHAKEInternal<SHAKE128Params>;
/// Public type for SHAKE256.
pub type SHAKE256 = SHAKEInternal<SHAKE256Params>;

/*** Param traits ***/

/// Private trait on purpose so that only the NIST-approved params can be used.
trait SHA3Params: HashAlgParams {
    const SIZE: KeccakSize;
    /// A tag, unique across all SHA3 *and* SHAKE variants, identifying which variant produced a
    /// serialized state. Distinguishing same-rate variants (e.g. SHA3-256 vs SHAKE256) requires
    /// this to be distinct from every value used by [`SHAKEParams::STATE_TAG`]. Never reuse a value.
    const STATE_TAG: u8;
}

// TODO: it would probably be more elegant to macro these.

/// The public hash types expose the same parameters as their `*Params` marker, so the constants
/// are defined exactly once (on the params struct) and forwarded here.
impl<PARAMS: SHA3Params> HashAlgParams for SHA3Internal<PARAMS> {
    const OUTPUT_LEN: usize = PARAMS::OUTPUT_LEN;
    const BLOCK_LEN: usize = PARAMS::BLOCK_LEN;
}

/// The parameters for SHA3_224.
#[derive(Clone)]
pub struct SHA3_224Params;
impl Algorithm for SHA3_224Params {
    const ALG_NAME: &'static str = SHA3_224_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}
impl HashAlgParams for SHA3_224Params {
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 144; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_224Params {
    const SIZE: KeccakSize = KeccakSize::_224;
    const STATE_TAG: u8 = 1;
}
/// Assigned by NIST in the Computer Security Objects Register: id-sha3-224 { hashAlgs 7 }
impl AlgorithmOID for SHA3_224 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 7];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07];
}

/// The parameters for SHA3_256.
#[derive(Clone)]
pub struct SHA3_256Params;
impl Algorithm for SHA3_256Params {
    const ALG_NAME: &'static str = SHA3_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl HashAlgParams for SHA3_256Params {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 136; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_256Params {
    const SIZE: KeccakSize = KeccakSize::_256;
    const STATE_TAG: u8 = 2;
}
/// Assigned by NIST in the Computer Security Objects Register: id-sha3-256 { hashAlgs 8 }
impl AlgorithmOID for SHA3_256 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 8];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08];
}
/// The parameters for SHA3_384.
#[derive(Clone)]
pub struct SHA3_384Params;
impl Algorithm for SHA3_384Params {
    const ALG_NAME: &'static str = SHA3_384_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}
impl HashAlgParams for SHA3_384Params {
    const OUTPUT_LEN: usize = 48;
    const BLOCK_LEN: usize = 104; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_384Params {
    const SIZE: KeccakSize = KeccakSize::_384;
    const STATE_TAG: u8 = 3;
}
/// Assigned by NIST in the Computer Security Objects Register: id-sha3-384 { hashAlgs 9 }
impl AlgorithmOID for SHA3_384 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 9];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09];
}
/// The parameters for SHA3_512.
#[derive(Clone)]
pub struct SHA3_512Params;
impl Algorithm for SHA3_512Params {
    const ALG_NAME: &'static str = SHA3_512_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl HashAlgParams for SHA3_512Params {
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 72; // FIPS 202 Table 3
}
impl SHA3Params for SHA3_512Params {
    const SIZE: KeccakSize = KeccakSize::_512;
    const STATE_TAG: u8 = 4;
}
/// Assigned by NIST in the Computer Security Objects Register: id-sha3-512 { hashAlgs 10 }
impl AlgorithmOID for SHA3_512 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 10];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a];
}

trait SHAKEParams: Algorithm {
    const SIZE: KeccakSize;
    /// See [`SHA3Params::STATE_TAG`]. Must be distinct from every SHA3 *and* SHAKE variant's tag.
    const STATE_TAG: u8;
}
/// The parameters for SHAKE128.
#[derive(Clone)]
pub struct SHAKE128Params;
impl Algorithm for SHAKE128Params {
    const ALG_NAME: &'static str = SHAKE128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}
impl SHAKEParams for SHAKE128Params {
    const SIZE: KeccakSize = KeccakSize::_128;
    const STATE_TAG: u8 = 5;
}
/// Assigned by NIST in the Computer Security Objects Register: id-shake128 { hashAlgs 11 }
impl AlgorithmOID for SHAKE128 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 11];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b];
}
/// The parameters for SHAKE256.
#[derive(Clone)]
pub struct SHAKE256Params;
impl Algorithm for SHAKE256Params {
    const ALG_NAME: &'static str = SHAKE256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}
impl SHAKEParams for SHAKE256Params {
    const SIZE: KeccakSize = KeccakSize::_256;
    const STATE_TAG: u8 = 6;
}
/// Assigned by NIST in the Computer Security Objects Register: id-shake256 { hashAlgs 12 }
impl AlgorithmOID for SHAKE256 {
    const OID: &'static [u32] = &[2, 16, 840, 1, 101, 3, 4, 2, 12];
    const OID_DER: &'static [u8] =
        &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c];
}
