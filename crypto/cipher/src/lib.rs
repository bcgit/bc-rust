//! A utility crate for holding common building blocks for constructing symmetric ciphers on top of
//! different permutation functions, such as modes of operation and padding.
//!
//! * [`modes`] — block cipher modes of operation (NIST SP 800-38A, SP 800-38C and SP 800-38D).
//! * [`BlockCipherKey`] — the key object the block cipher crates alias: a permutation under a mode,
//!   handing out that mode's workers through the role traits of `bouncycastle_core::symmetric_key`.
//! * [`padding`] — block padding schemes, and the adapters that apply them to a block cipher mode.
//! * [`stream`] — a stream cipher over any keystream, and the helpers shared by stream ciphers that
//!   cannot be built that way.
//!
//! # Usage Examples
//!
//! See the [`modes`], [`padding`] and [`stream`] module docs.
//!
//! # Memory Usage
//!
//! See the "Memory Usage" section of each module.
//!
//! # 🚨 Security Considerations 🚨
//!
//! See the "Security Considerations" section of each module.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![no_std]

extern crate alloc;

// `tests/common/toy_block_cipher.rs` names `bouncycastle_cipher::modes::ModeNames`, and is also
// `include!`d by unit tests here, where that path would otherwise not resolve.
#[cfg(test)]
extern crate self as bouncycastle_cipher;

mod key;
pub mod modes;
pub mod padding;
pub mod stream;

pub use key::BlockCipherKey;

// The direction markers are `bouncycastle_core::direction`'s, re-exported so that
// `bouncycastle_cipher::{Encrypting, Decrypting, Direction}` stays the path the cipher crates
// use; the MAC crates take them from `core`, which does not depend on this crate.
pub use bouncycastle_core::direction::{Decrypting, Direction, Encrypting};
