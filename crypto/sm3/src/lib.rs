//! Implements the SM3 cryptographic hash function as per GB/T 32905-2016 (also ISO/IEC 10118-3:2018
//! and IETF draft-shen-sm3-hash-01).
//!
//! SM3 is a 256-bit Merkle–Damgård hash with a 512-bit block, structurally similar to SHA-256 but
//! with its own message expansion, round functions and constants.
//!
//! # Examples
//! ## Hash
//! Hash functionality is accessed via the [`Hash`] trait, which is implemented by [`SM3`].
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_sm3::SM3;
//!
//! let data: &[u8] = b"abc";
//! let output: Vec<u8> = SM3::new().hash(data);
//! assert_eq!(output[..4], [0x66, 0xc7, 0xf0, 0xf4]);
//! ```
//!
//! More advanced usage will require creating an SM3 object to hold state between successive calls,
//! for example if input is received in chunks and not all available at the same time:
//!
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_sm3::SM3;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F
//!                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
//! let mut sm3 = SM3::new();
//!
//! for chunk in data.chunks(16) {
//!     sm3.do_update(chunk);
//! }
//!
//! let output: Vec<u8> = sm3.do_final();
//! ```
//!
//! It is also possible to provide input where the final byte contains fewer than 8 bits of data
//! (a bit-oriented message, GB/T 32905-2016 s. 5.2); the partial bits are taken from the least
//! significant bits of the supplied byte. The following hashes 16 bytes plus 3 bits:
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_sm3::SM3;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x05";
//! let mut sm3 = SM3::new();
//! sm3.do_update(&data[..16]);
//! let output: Vec<u8> = sm3.do_final_partial_bits(data[16], 3).expect("num_partial_bits is in 0..=7");
//! ```
//!
//! # Memory Usage
//!
//! No heap memory is used by the algorithm itself; the `Vec<u8>`-returning convenience methods
//! allocate only the output buffer, and the `*_out` variants allocate nothing.
//!
//! | Object                     | Size (bytes) |
//! |----------------------------|--------------|
//! | `SM3`                      | 112          |
//! | Suspended state            | 108          |
//!
//! The object holds the 8-word chaining value plus one 64-byte block of buffered input. The
//! compression function additionally uses a 68-word message schedule (272 bytes) on the stack for
//! the duration of a call.
//!
//! # Security Considerations
//!
//! * SM3 offers 128 bits of collision resistance and 256 bits of preimage resistance.
//! * SM3 is a Merkle–Damgård construction and is therefore subject to length-extension:
//!   `H(k || m)` is not a secure MAC. Use HMAC for keyed hashing.
//! * The chaining value and input buffer are held in [`bouncycastle_utils::secret::Secret`] and
//!   zeroized on drop. Transient copies (working variables and message schedule) in registers/stack
//!   locals during compression are not zeroized.
//! * The implementation contains no data-dependent branches or table lookups.
//! * Messages up to 2^64 bytes are supported (the specification allows 2^64 bits).
//!
//! # Suspending and resuming execution
//!
//! When hashing a large message, it can be advantageous to be able to suspend the operation
//! to a cache and resume it later; for example if waiting for the message to stream over a slow network
//! connection. For this reason, [`SM3`] impls [`Suspendable`].
//!
//! ```rust
//! use bouncycastle_sm3::SM3;
//! use bouncycastle_core::traits::{Hash, Suspendable};
//!
//! let msg_part1 = b"The quick brown fox";
//! let msg_part2 = b" jumped over the lazy dog";
//!
//! let mut sm3 = SM3::new();
//! sm3.do_update(msg_part1);
//!
//! // suspend the in-progress hash while "waiting" for the second part of the message.
//! let serialized_state = sm3.suspend();
//!
//! // ... later, possibly on another host: resume from the serialized state.
//! let mut sm3_resumed = SM3::from_suspended(serialized_state).unwrap();
//! sm3_resumed.do_update(msg_part2);
//! let h: Vec<u8> = sm3_resumed.do_final();
//! ```

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

mod sm3;

pub use self::sm3::{SM3, SUSPENDED_SM3_STATE_LEN};
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams, SecurityStrength};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::traits::{Hash, Suspendable};

/// Algorithm name string for SM3, as used by the factories and CLI.
pub const SM3_NAME: &str = "SM3";

impl Algorithm for SM3 {
    const ALG_NAME: &'static str = SM3_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// GB/T 32905-2016: 256-bit digest, 512-bit block.
impl HashAlgParams for SM3 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
}

/// Assigned by the Chinese OSCCA: sm3 { 1 2 156 10197 1 401 }
impl AlgorithmOID for SM3 {
    const OID: &'static [u32] = &[1, 2, 156, 10197, 1, 401];
    const OID_DER: &'static [u8] = &[0x06, 0x08, 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x83, 0x11];
}
