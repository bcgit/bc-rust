#![forbid(unsafe_code)]
#![forbid(missing_docs)]

//! Ascon-based lightweight cryptography (NIST SP 800-232).
//!
//! This crate implements the four Ascon functions standardized in NIST SP 800-232 (August 2025):
//!
//! - [`ascon_aead128::AsconAead128`] — Ascon-AEAD128 authenticated encryption (128-bit
//!   key/nonce/tag, 128-bit single-key security).
//! - [`ascon_hash256::AsconHash256`] — Ascon-Hash256 hash function (256-bit digest, 128-bit
//!   security).
//! - [`ascon_xof128::AsconXof128`] — Ascon-XOF128 extendable-output function.
//! - [`ascon_cxof128::AsconCXof128`] — Ascon-CXOF128 customized extendable-output function.
//!
//! All four share the same `Ascon-p` permutation. The implementation follows the little-endian
//! convention of the standard and uses the precomputed initialization states from SP 800-232
//! Table 12.
//!
//! # Usage Examples
//!
//! Hashing (one-shot and streaming):
//! ```
//! use bouncycastle_ascon::ascon_hash256::AsconHash256;
//!
//! // One-shot:
//! let digest = AsconHash256::digest(b"hello world");
//! assert_eq!(digest.len(), 32);
//!
//! // Streaming:
//! let mut h = AsconHash256::new();
//! h.update_bytes(b"hello ");
//! h.update_bytes(b"world");
//! let mut out = [0u8; 32];
//! h.do_final_into(&mut out);
//! assert_eq!(out, digest);
//! ```
//!
//! Authenticated encryption (one-shot):
//! ```
//! use bouncycastle_ascon::ascon_aead128::AsconAead128;
//!
//! let key = [0u8; 16];
//! let nonce = [1u8; 16];           // MUST be unique per encryption under a given key
//! let ad = b"associated data";
//! let plaintext = b"secret message";
//!
//! let mut ct = vec![0u8; plaintext.len() + 16]; // ciphertext || 16-byte tag
//! let n = AsconAead128::encrypt(&key, &nonce, Some(ad), plaintext, &mut ct);
//! ct.truncate(n);
//!
//! let mut pt = vec![0u8; ct.len() - 16];
//! let m = AsconAead128::decrypt(&key, &nonce, Some(ad), &ct, &mut pt).unwrap();
//! pt.truncate(m);
//! assert_eq!(&pt, plaintext);
//! ```
//!
//! Extendable output:
//! ```
//! use bouncycastle_ascon::ascon_xof128::AsconXof128;
//! use bouncycastle_core::traits::XOF;
//!
//! let out = AsconXof128::new().hash_xof(b"input", 64);
//! assert_eq!(out.len(), 64);
//! ```
//!
//! # Memory Usage
//!
//! Ascon is a lightweight, permutation-based design intended for constrained devices. The internal
//! permutation state is 320 bits (40 bytes), held as five `u64` words. Each function additionally
//! keeps a small fixed input buffer (8 bytes for the hash/XOFs, 32 bytes for AEAD decryption). There
//! are no heap allocations in the streaming/`*_out` APIs, and stack usage is small and constant;
//! consequently this crate has no dedicated `mem_usage_benches` harness.
//!
//! # Security Considerations
//!
//! - **Nonce uniqueness (SP 800-232 R3):** a (key, nonce) pair must never be reused for two
//!   different Ascon-AEAD128 encryptions. Nonce reuse breaks confidentiality.
//! - **Tag length:** this crate always produces and verifies the full 128-bit tag. Truncated tags
//!   (SP 800-232 §4.2.1) are not exposed.
//! - **Key handling:** [`ascon_aead128::AsconAead128`] zeroizes its key, nonce, and working state on
//!   drop and implements [`bouncycastle_core::traits::Secret`]; the hash/XOF states are likewise
//!   zeroized on drop.
//! - **Decryption release:** never release decrypted plaintext until finalization returns `Ok`; an
//!   `Err(AuthenticationFailed)` means the ciphertext or tag was tampered with.

mod util;

pub mod ascon_aead128;
pub mod ascon_cxof128;
pub mod ascon_hash256;
pub mod ascon_xof128;

/// Algorithm name for Ascon-AEAD128.
pub const ASCON_AEAD128_NAME: &str = "Ascon-AEAD128";
/// Algorithm name for Ascon-Hash256.
pub const ASCON_HASH256_NAME: &str = "Ascon-Hash256";
/// Algorithm name for Ascon-XOF128.
pub const ASCON_XOF128_NAME: &str = "Ascon-XOF128";
/// Algorithm name for Ascon-CXOF128.
pub const ASCON_CXOF128_NAME: &str = "Ascon-CXOF128";
