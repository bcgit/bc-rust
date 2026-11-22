//! Hash functions, and the key derivation functions built on a hash.
//!
//! | Module        | Contents                                                              |
//! |---------------|-----------------------------------------------------------------------|
//! | [`blake2`]    | BLAKE2b-512 and BLAKE2s-256 (RFC 7693), unkeyed and keyed             |
//! | [`blake3`]    | BLAKE3: hash, keyed hash, key derivation and XOF                      |
//! | [`ripemd`]    | RIPEMD-128, -160, -256 and -320, and HMAC over RIPEMD-160             |
//! | [`sm3`]       | SM3 (GB/T 32905-2016), with HMAC and HKDF over it                     |
//! | [`pbkdf2`]    | PBKDF2 (RFC 8018 Section 5.2) over HMAC                               |
//! | [`scrypt`]    | scrypt (RFC 7914)                                                     |
//! | [`concatkdf`] | The NIST concatenation KDF (SP 800-56C Rev. 2 Section 4.1)            |
//! | [`x963kdf`]   | The ANSI X9.63 KDF (SEC 1 v2 Section 3.6.1)                           |
//!
//! SHA-2, SHA-3, HMAC and HKDF are crates of their own for now (`bouncycastle-sha2`, `-sha3`,
//! `-hmac`, `-hkdf`).
//!
//! # Usage Examples
//!
//! Each module above has its own.
//!
//! # Memory Usage
//!
//! Each module's docs give the size of its state and, for a KDF, of its working memory.
//!
//! # 🚨 Security Considerations 🚨
//!
//! Each module's docs carry the considerations for its algorithm.
//!
//! # Features
//!
//! `std`, on by default, gates [`scrypt`]'s `KDF` implementation, which allocates its working
//! memory, and [`blake3`]'s one-shots that return a `Vec`; without it `scrypt` is the
//! caller-supplied-memory function alone.

#![no_std]
// Docs link to the `Vec` one-shots, which a build without `std` does not have.
#![cfg_attr(not(feature = "std"), allow(rustdoc::broken_intra_doc_links))]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

pub mod blake2;
pub mod blake3;
pub mod concatkdf;
pub mod pbkdf2;
pub mod ripemd;
pub mod scrypt;
pub mod sm3;
pub mod x963kdf;
