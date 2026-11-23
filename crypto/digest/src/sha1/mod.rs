//! Implements SHA-1 as per FIPS 180-4, for the protocols that still name it.
//!
//! SHA-1 is here so that existing data and peers can be interoperated with: a mask generation
//! function or a label hash an older RSA-OAEP peer chose, a fingerprint, a legacy key
//! identifier. It is not for new designs; see [Security Considerations](#-security-considerations-).
//!
//! # Usage Examples
//!
//! Hash functionality is accessed via the [`Hash`] trait, which is implemented by [`SHA1`].
//!
//! The simplest usage is via the one-shot functions.
//! ```
//! use bouncycastle_core::traits::HashOneShot;
//! use bouncycastle_digest::sha1::SHA1;
//!
//! let output: Vec<u8> = SHA1::hash(b"abc");
//! ```
//!
//! It also has a streaming API that can accept input in chunks of any size.
//!
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_digest::sha1::SHA1;
//!
//! let data: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F
//!                     \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
//! let mut sha1 = SHA1::new();
//!
//! for chunk in data.chunks(16) {
//!     sha1.do_update(chunk);
//! }
//!
//! let output: Vec<u8> = sha1.do_final();
//! ```
//!
//! A bit-oriented message (FIPS 180-4 s. 5.1) is finished with
//! [`do_final_partial_bits`](Hash::do_final_partial_bits), the trailing bits being the most
//! significant bits of the last byte, as in the SHA-2 crate. A computation in progress can be
//! suspended and resumed through [`Suspendable`], also as there.
//!
//! # Memory Usage
//!
//! No heap memory is used by the algorithm itself; the `Vec<u8>`-returning convenience methods
//! allocate only the output buffer, and the `*_out` variants allocate nothing.
//!
//! | Object          | Size (bytes) |
//! |-----------------|--------------|
//! | `SHA1`          | 104          |
//! | Suspended state | 96           |
//!
//! The object holds the 5-word hash value plus one 64-byte block of buffered input.
//!
//! Per-call stack usage does not depend on the data length. The figures are the frames the
//! compiler reports for the release build (x86-64 Linux, rustc 1.97.0-nightly), summed down
//! each entry point's deepest call path with a return address per call; the compression
//! function, with its 80-word message schedule, is 264 bytes of every one (see
//! `mem_usage_benches/src/bench_sha1_mem_usage.rs`):
//!
//! | Entry point                              | Stack   |
//! |------------------------------------------|---------|
//! | `SHA1::do_update`                        | 328 B   |
//! | `SHA1::do_final_out`                     | 352 B   |
//! | `SHA1::do_final_partial_bits_out`        | 376 B   |
//! | `SHA1::hash_out` (one-shot)              | 584 B   |
//! | `SHA1::suspend` / `SHA1::from_suspended` | 8 / 8 B |
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **SHA-1 is not collision resistant.** Collisions have been published, and chosen-prefix
//!   collisions are practical, so it must not be used where an attacker gains from two messages
//!   with one digest: signatures, certificates, commitments, content addressing of untrusted
//!   data. Its [`MAX_SECURITY_STRENGTH`](Algorithm::MAX_SECURITY_STRENGTH) is
//!   [`SecurityStrength::None`] for that reason, and it does not carry
//!   [`CollisionResistantHash`](bouncycastle_core::traits::CollisionResistantHash), which the
//!   library's signing roles require: a signature over SHA-1 verifies and is not generated,
//!   unless the caller names the hash as
//!   [`WithoutCollisionResistance<SHA1>`](bouncycastle_core::hazmat::WithoutCollisionResistance).
//! * Uses that do not rest on collision resistance, such as MGF1 and the label hash of RSA-OAEP,
//!   are not broken by the collision attacks, but offer no reason to choose SHA-1 over SHA-2
//!   where the choice is open.
//! * SHA-1 is a Merkle-Damgard construction and is subject to length extension: `H(k || m)` is
//!   not a MAC.
//! * The hash value and input buffer are held in [`bouncycastle_utils::secret::Secret`] and
//!   zeroized on drop. The message schedule and working variables on the stack during
//!   compression are not zeroized.
//! * The implementation contains no data-dependent branches or table lookups.
//! * Message length: FIPS 180-4 permits messages shorter than 2^64 bits, so this implementation
//!   supports 2^61 - 1 bytes.

mod sha1;

pub use self::sha1::{SHA1, SUSPENDED_SHA1_STATE_LEN};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, AlgorithmOID, HashAlgParams};

/*** Imports needed for docs ***/
#[allow(unused_imports)]
use bouncycastle_core::traits::{Hash, Suspendable};

/// Algorithm name string for SHA-1, as used by the CLI.
pub const SHA1_NAME: &str = "SHA1";

/// SHA-1 is credited with no security strength: see the module's Security Considerations.
impl Algorithm for SHA1 {
    const ALG_NAME: &'static str = SHA1_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}

/// FIPS 180-4 Figure 1: 160-bit digest, 512-bit block.
impl HashAlgParams for SHA1 {
    const OUTPUT_LEN: usize = 20;
    const BLOCK_LEN: usize = 64;
}

/// RFC 8017 Appendix B.1: id-sha1 { iso(1) identified-organization(3) oiw(14) secsig(3)
/// algorithms(2) 26 }
impl AlgorithmOID for SHA1 {
    const OID: &'static [u32] = &[1, 3, 14, 3, 2, 26];
    const OID_DER: &'static [u8] = &[0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A];
}
