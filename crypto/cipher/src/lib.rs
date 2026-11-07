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

/// Direction marker for a cipher value that encrypts.
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encrypting;

/// Direction marker for a cipher value that decrypts.
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decrypting;

pub(crate) mod sealed {
    /// Private supertrait of [`Direction`](super::Direction): only this module can name it, so
    /// only the two markers below can implement `Direction`.
    pub trait Sealed {}
    impl Sealed for super::Encrypting {}
    impl Sealed for super::Decrypting {}
    // The keystream types implement it beside their definitions, for `KeyStreamPolicy`.
}

/// Selects a type by direction: `Enc` for [`Encrypting`], `Dec` for [`Decrypting`].
///
/// A cipher whose two directions are distinct types cannot offer `Cipher<Dir>` as a plain type
/// alias, because an alias cannot choose between two types from one of its parameters. It is
/// written as a projection through this trait instead:
///
/// ```text
/// pub type AES_CBC_128<Dir, Pad> = <Dir as Direction>::Select<
///     PaddedBlockCipherEncryptor<Cbc<AES128Internal, Encrypting, 16>, Pad, 16, 16>,
///     PaddedBlockCipherDecryptor<Cbc<AES128Internal, Decrypting, 16>, Pad, 16, 16>,
/// >;
/// ```
///
/// Sealed: implemented for the two markers and for nothing else, so `Encrypting` and `Decrypting`
/// are the only values a `Dir` parameter can take, and a caller cannot project an alias onto a
/// type of their own:
///
/// ```compile_fail
/// use bouncycastle_cipher::Direction;
/// struct Sideways;
/// // error: the supertrait is private to bouncycastle_cipher
/// impl Direction for Sideways {
///     type Select<Enc, Dec> = Enc;
/// }
/// ```
pub trait Direction: sealed::Sealed {
    /// `Enc` for [`Encrypting`], `Dec` for [`Decrypting`].
    type Select<Enc, Dec>;

    /// `true` for [`Encrypting`]: the direction a permutation that decrypts only
    /// (`BlockPermutation::DECRYPT_ONLY`) refuses, at compile time, however the worker is made.
    const IS_ENCRYPTING: bool;
}

impl Direction for Encrypting {
    type Select<Enc, Dec> = Enc;
    const IS_ENCRYPTING: bool = true;
}

impl Direction for Decrypting {
    type Select<Enc, Dec> = Dec;
    const IS_ENCRYPTING: bool = false;
}
