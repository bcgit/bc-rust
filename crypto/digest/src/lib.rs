//! Hash functions, and the key derivation functions built on a hash.
//!
//! | Module        | Contents                                                              |
//! |---------------|-----------------------------------------------------------------------|
//! | [`blake2`]    | BLAKE2b-512 and BLAKE2s-256 (RFC 7693), unkeyed and keyed             |
//! | [`blake3`]    | BLAKE3: hash, keyed hash, key derivation and XOF                      |
//! | [`ripemd`]    | RIPEMD-128, -160, -256 and -320, and HMAC over RIPEMD-160             |
//! | [`sha1`]      | SHA-1 (FIPS 180-4), for existing protocols only                       |
//! | [`sha2`]      | SHA-2 (FIPS 180-4), with HMAC and HKDF over it                        |
//! | [`sha3`]      | SHA-3 and SHAKE (FIPS 202), cSHAKE, KMAC, TupleHash and ParallelHash  |
//! | [`sm3`]       | SM3 (GB/T 32905-2016), with HMAC and HKDF over it                     |
//! | [`hmac`]      | HMAC (RFC 2104), generic over the hash                                |
//! | [`hkdf`]      | HKDF (RFC 5869), generic over the hash                                |
//! | [`pbkdf2`]    | PBKDF2 (RFC 8018 Section 5.2) over HMAC                               |
//! | [`scrypt`]    | scrypt (RFC 7914)                                                     |
//! | [`concatkdf`] | The NIST concatenation KDF (SP 800-56C Rev. 2 Section 4.1)            |
//! | [`x963kdf`]   | The ANSI X9.63 KDF (SEC 1 v2 Section 3.6.1)                           |
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
//! `alloc` gates [`scrypt`]'s `KDF` implementation, which allocates its working memory, and
//! [`blake3`]'s and [`sha3`]'s one-shots that return a `Vec`, and turns on `bouncycastle-core`'s
//! `alloc`; without it `scrypt` is the caller-supplied-memory function alone and the crate needs
//! no allocator. `std`, on by default, implies `alloc` and gates nothing of its own.

#![no_std]
// Docs link to the `Vec` one-shots, which a build without `alloc` does not have.
#![cfg_attr(not(feature = "alloc"), allow(rustdoc::broken_intra_doc_links))]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod blake2;
pub mod blake3;
pub mod concatkdf;
pub mod hkdf;
pub mod hmac;
pub mod pbkdf2;
pub mod ripemd;
pub mod scrypt;
pub mod sha1;
pub mod sha2;
pub mod sha3;
pub mod sm3;
mod stack_wipe;
pub mod x963kdf;
