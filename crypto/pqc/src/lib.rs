//! The post-quantum algorithms: ML-DSA signatures as per FIPS 204 and ML-KEM key encapsulation as
//! per FIPS 203, each in a standard and a low-memory form.
//!
//! | Algorithm | Standard   | Low-memory          |
//! |-----------|------------|---------------------|
//! | ML-DSA    | [`mldsa`]  | [`mldsa_lowmemory`] |
//! | ML-KEM    | [`mlkem`]  | [`mlkem_lowmemory`] |
//!
//! Use the standard module unless peak stack is the constraint. The low-memory module of an
//! algorithm keeps the standard one's algorithm and trait names and interoperates with it, holds
//! its private key as the seed, and runs in less stack at a cost in throughput; its docs give the
//! figures for both forms side by side.
//!
//! [`mldsa_common`] and [`mlkem_common`] hold what the two forms of an algorithm share. They are
//! not an API for callers: what a caller names from them, the two forms re-export.
//!
//! # Usage Examples
//!
//! Each of the four modules above has its own.
//!
//! # Memory Usage
//!
//! The key sizes and the peak stack of each operation are tabulated in each module's docs.
//!
//! # 🚨 Security Considerations 🚨
//!
//! Each module's docs carry the considerations for its algorithm: what a seed and a signing or
//! encapsulation randomness must be, and which items are `hazmat`.
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

pub mod mldsa;
pub mod mldsa_common;
pub mod mldsa_lowmemory;
pub mod mlkem;
pub mod mlkem_common;
pub mod mlkem_lowmemory;
