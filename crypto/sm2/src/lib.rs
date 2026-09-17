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
//! # Usage Examples
//!
//! Every SM2 operation needs the signer's identity `IDA`, which `ZA` binds into the message hash;
//! this crate carries it in the `Signer`/`SignatureVerifier` traits' `ctx` parameter, and rejects
//! `None`. Signing draws a fresh `k` each call, so signatures are not reproducible:
//!
//! ```
//! use bouncycastle_core::traits::{SignatureVerifier, Signer};
//! use bouncycastle_sm2::keys::keygen;
//! use bouncycastle_sm2::sm2::SM2;
//!
//! let (pk, sk) = keygen()?;
//! let id = b"alice@example.com";
//! let message = b"the message to sign";
//!
//! let signature = SM2::sign(&sk, message, Some(id))?;
//! SM2::verify(&pk, message, Some(id), &signature)?;
//!
//! // The identity is part of what is signed: verifying under a different one fails.
//! assert!(SM2::verify(&pk, message, Some(b"bob@example.com"), &signature).is_err());
//! // And `ctx` is not optional here, unlike every other primitive in this workspace.
//! assert!(SM2::sign(&sk, message, None).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Streaming, for a message too large to hold at once. `ZA` is absorbed by `sign_init`, so only
//! the message itself passes through `sign_update`:
//!
//! ```
//! use bouncycastle_core::traits::{SignatureVerifier, Signer};
//! use bouncycastle_sm2::keys::keygen;
//! use bouncycastle_sm2::sm2::SM2;
//!
//! let (pk, sk) = keygen()?;
//! let id = b"alice@example.com";
//!
//! let mut signer = SM2::sign_init(&sk, Some(id))?;
//! signer.sign_update(b"the first chunk, ");
//! signer.sign_update(b"then the second");
//! let signature = signer.sign_final()?;
//!
//! let mut verifier = SM2::verify_init(&pk, Some(id))?;
//! verifier.verify_update(b"the first chunk, then the second");
//! verifier.verify_final(&signature)?;
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! Keys use the same SEC 1 encodings as `bouncycastle-ecdsa` -- `04 || X || Y` for a public key
//! (the 33-byte compressed form is also accepted on decode), a 32-byte big-endian integer for a
//! private key, with `dA` required to be in `[1, n-1]`:
//!
//! ```
//! use bouncycastle_core::traits::{SignaturePrivateKey, SignaturePublicKey};
//! use bouncycastle_sm2::keys::{SM2PrivateKey, SM2PublicKey, keygen};
//!
//! let (pk, sk) = keygen()?;
//!
//! assert_eq!(SM2PublicKey::from_bytes(&pk.encode())?, pk);
//! assert_eq!(SM2PrivateKey::from_bytes(&sk.encode())?, sk);
//! // A private key carries its own public key, so this costs nothing to ask for.
//! assert_eq!(sk.derive_pk(), pk);
//!
//! assert!(SM2PrivateKey::from_bytes(&[0u8; 32]).is_err());
//! # Ok::<(), bouncycastle_core::errors::SignatureError>(())
//! ```
//!
//! # Memory Footprint
//!
//! The following table lists the size of the on-disk bytes encoding and the in-memory struct size
//! of the key objects:
//!
//! | Key Object | PK size on disk | PK size in memory | SK size on disk | SK size in memory |
//! |------------|-----------------|--------------------|------------------|--------------------|
//! | SM2        | 65              | 64                 | 32               | 96                 |
//!
//! All values are in bytes. The "in memory" sizes are measured by rust's `std::mem::size_of`; the
//! "on disk" sizes are [`keys::PK_LEN`]/[`keys::SK_LEN`]. These numbers are produced by
//! `mem_usage_benches`' `bench_sm2_mem_usage` binary's `print_struct_sizes()`; that binary is also
//! the stack-usage measurement harness (see its own doc comment for the `valgrind`/`massif`
//! invocation).
//!
//! An `SM2PrivateKey` is 96 bytes in memory against a 32-byte encoding because it carries the
//! matching public key `PA` (two 32-byte field elements) alongside `dA`. That is not redundancy:
//! `ZA` mixes `PA` into every signature, so without it each `sign` would have to recompute
//! `[dA]G` and cost two fixed-base scalar multiplications instead of one. See
//! [`keys::SM2PrivateKey`]'s own docs.
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
