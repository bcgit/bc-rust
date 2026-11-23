//! Symmetric algorithms.
//!
//! | Module                     | Contents                                                         |
//! |----------------------------|------------------------------------------------------------------|
//! | [`aes`]                    | The AES block cipher (FIPS 197) and its modes                    |
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
//! The block cipher modules are built from the generic pieces at the crate root:
//!
//! * [`modes`] — block cipher modes of operation (NIST SP 800-38A, SP 800-38C and SP 800-38D).
//! * [`BlockCipherKey`] — the key object the block cipher modules alias: a permutation under a mode,
//!   handing out that mode's workers through the role traits of `bouncycastle_core::symmetric_key`.
//! * [`padding`] — block padding schemes, and the adapters that apply them to a block cipher mode.
//! * [`stream`] — a stream cipher over any keystream, and the helpers shared by stream ciphers that
//!   cannot be built that way.
//!
//! # Usage Examples
//!
//! Each module above has its own, as do [`modes`], [`padding`] and [`stream`].
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

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

// `tests/common/toy_block_cipher.rs` names `bouncycastle_symmetric::modes::ModeNames`, and is also
// `include!`d by unit tests here, where that path would otherwise not resolve.
#[cfg(test)]
extern crate self as bouncycastle_symmetric;

mod key;
pub mod modes;
pub mod padding;
pub mod stream;

pub use key::BlockCipherKey;

// The direction markers are `bouncycastle_core::direction`'s, re-exported so that
// `bouncycastle_symmetric::{Encrypting, Decrypting, Direction}` is the path the block cipher
// modules use; the MAC crates take them from `core`, which does not depend on this crate.
pub use bouncycastle_core::direction::{Decrypting, Direction, Encrypting};

pub(crate) mod sealed {
    /// Private supertrait of [`KeyStreamPolicy`](crate::stream::KeyStreamPolicy): only this
    /// crate's keystream types implement it, beside their definitions.
    pub trait Sealed {}
}

pub mod aes;
pub mod aria;
pub mod ascon;
pub mod camellia;
pub mod chacha20;
pub mod chacha20_poly1305_aead;
pub mod kbkdf;
pub mod poly1305;
pub mod sm4;
pub mod tdes;
