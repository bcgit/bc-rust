//! Symmetric algorithms.
//!
//! | Module                     | Contents                                                         |
//! |----------------------------|------------------------------------------------------------------|
//! | [`aria`]                   | The ARIA block cipher (RFC 5794) and its modes                   |
//! | [`ascon`]                  | Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128 and Ascon-CXOF128 (NIST SP 800-232) |
//! | [`camellia`]               | The Camellia block cipher (RFC 3713) and its modes               |
//! | [`chacha20`]               | The ChaCha20 stream cipher (RFC 8439)                            |
//! | [`poly1305`]               | The Poly1305 one-time authenticator (RFC 8439)                   |
//! | [`chacha20_poly1305_aead`] | The ChaCha20-Poly1305 AEAD (RFC 8439)                            |
//! | [`kbkdf`]                  | The SP 800-108 key-based KDFs                                    |
//! | [`sm4`]                    | The SM4 block cipher (GB/T 32907-2016) and its modes             |
//! | [`tdes`]                   | Triple DES (SP 800-67r2) and its modes, for legacy data          |
//!
//! AES and the block cipher modes are crates of their own for now (`bouncycastle-aes`,
//! `bouncycastle-cipher`).
//!
//! # Usage Examples
//!
//! Each module above has its own.
//!
//! # Memory Usage
//!
//! Each module's docs give its sizes.
//!
//! # 🚨 Security Considerations 🚨
//!
//! Each module's docs carry the considerations for its algorithm.
//!
//! # Features
//!
//! `std`, on by default, gates the one-shots that return a `Vec` (in [`ascon`]).

#![no_std]
// Docs link to the `Vec` one-shots, which a build without `std` does not have.
#![cfg_attr(not(feature = "std"), allow(rustdoc::broken_intra_doc_links))]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

pub mod aria;
pub mod ascon;
pub mod camellia;
pub mod chacha20;
pub mod chacha20_poly1305_aead;
pub mod kbkdf;
pub mod poly1305;
pub mod sm4;
pub mod tdes;
