//! Constructions that combine primitives from more than one family.
//!
//! "Hybrid" is meant in both of its established senses: hybrid public-key encryption, a KEM
//! with a symmetric cipher, which is HPKE's own name (RFC 9180, "Hybrid Public Key
//! Encryption"), and post-quantum/traditional hybrids. HPKE, as the module [`hpke`], is the
//! crate's one member today.
//!
//! # Usage Examples
//!
//! See [the `hpke` module's](hpke#usage-examples).
//!
//! # Memory Usage
//!
//! See [the `hpke` module's table](hpke#memory-usage).
//!
//! # 🚨 Security Considerations 🚨
//!
//! Each construction has its own; see [the `hpke` module's](hpke#-security-considerations-).

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod hpke;
