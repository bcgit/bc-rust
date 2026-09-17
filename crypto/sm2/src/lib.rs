//! SM2: the Chinese national-standard elliptic-curve Digital Signature Algorithm (GB/T
//! 32918.2-2016, mirrored by the IETF informational draft `draft-shen-sm2-ecdsa-02`). This crate
//! implements only the Digital Signature Algorithm ([`sm2`]'s §5) -- key generation ([`keys`]) and
//! signing/verification ([`sm2::SM2`]) -- built on [`bouncycastle_ec::sm2`]'s field/scalar/point
//! arithmetic, SEC 1 encoding, and comb/wNAF multipliers, and [`bouncycastle_sm3`] for the hash the
//! draft mandates throughout.
//!
//! # Scope
//!
//! `draft-shen-sm2-ecdsa-02` also describes an SM2 Key Exchange Protocol (§6) and an SM2 Public Key
//! Encryption scheme (§7); neither is implemented here. SM2's Digital Signature Algorithm is *not*
//! ECDSA -- it has its own signing equation and its own identity-binding `ZA` digest (see
//! [`za`]'s docs) -- despite both being built on the same family of elliptic-curve arithmetic that
//! `bouncycastle-ecdsa`'s curves use.
//!
//! # `ctx` carries the signer's identity
//!
//! Every SM2 signing/verification operation needs the signer's identity octet string `IDA` (the
//! draft's §5.1.2/§5.2.2 step 1). This crate repurposes [`bouncycastle_core::traits::Signer`]'s
//! `ctx` parameter to carry it -- see [`sm2`]'s module docs for the full reasoning and the
//! resulting requirement that `ctx` must be `Some`.
//!
//! # Memory Footprint
//!
//! The following table lists the size of the on-disk bytes encoding and the in-memory struct size
//! of the key objects:
//!
//! | Key Object | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |------------|-----------------|--------------------|------------------|--------------------|
//! | SM2        | 65              | 64                 | 32               | 32                 |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`; the
//! "on disk" sizes are [`keys::PK_LEN`]/[`keys::SK_LEN`]. These numbers are produced by
//! `mem_usage_benches`' `bench_sm2_mem_usage` binary's `print_struct_sizes()`; that binary is also
//! the stack-usage measurement harness (see its own doc comment for the `valgrind`/`massif`
//! invocation).
//!
//! # Security Considerations
//!
//! - **The private key `dA` and the per-message secret `k` are never handled in variable time.**
//!   `dA` lives in [`bouncycastle_ec::sm2_scalar::Sm2Scalar`] (a [`bouncycastle_utils::secret::Secret`]);
//!   every operation performed on it or on `k` -- inversion, multiplication, the fixed-base scalar
//!   multiplication `[k]G` -- is branch-free and does not index memory by their value.
//! - **`k` must never repeat across two signatures under the same key with different messages.** As
//!   with ECDSA, a repeated `k` leaks `dA` directly from two signatures' `(r, s)` pairs. Unlike
//!   `bouncycastle-ecdsa`'s curves, there is no deterministic (RFC 6979-style) default here: the
//!   draft only specifies randomised `k` generation (§5.1.3 step A3), so
//!   [`bouncycastle_core::traits::Signer::sign`] sources `k` from the library's default OS-backed
//!   RNG on every call -- see [`sm2`]'s module docs.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod extra_bits;
pub mod keys;
pub mod sm2;
pub mod za;
