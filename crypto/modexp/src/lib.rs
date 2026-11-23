//! Public-key algorithms built on modular exponentiation over the integers.
//!
//! The members share the fixed-width multi-precision arithmetic, prime generation and the rule
//! that strength follows the size of the modulus. RSA, as the module [`rsa`], is the crate's one
//! member today.
//!
//! # Usage Examples
//!
//! See [the `rsa` module's](rsa#usage-examples).
//!
//! # Memory Usage
//!
//! See [the `rsa` module's table](rsa#memory-usage).
//!
//! # 🚨 Security Considerations 🚨
//!
//! Each algorithm has its own; see [the `rsa` module's](rsa#-security-considerations-).
//!
//! # Features
//!
//! `alloc`, and `std`, which is on by default and implies it, turn on the features of those names
//! in `bouncycastle-core` and `bouncycastle-digest`: the allocating one-shots and `_boxed` finals
//! of the core traits. The crate has nothing of its own behind either, and without them needs no
//! allocator.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod rsa;
