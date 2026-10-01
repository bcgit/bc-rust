//! A utility crate for holding common building blocks for constructing symmetric ciphers on top of
//! different permutation functions, such as modes of operation and padding.
//!
//! * [`modes`] — block cipher modes of operation (NIST SP 800-38A, SP 800-38C and SP 800-38D).
//! * [`padding`] — block padding schemes, and the adapters that apply them to a block cipher mode.
//! * [`stream`] — a stream cipher over any keystream, and the helpers shared by stream ciphers that
//!   cannot be built that way.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]
#![no_std]

pub mod modes;
pub mod padding;
pub mod stream;

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

mod sealed {
    /// Private supertrait of [`Direction`](super::Direction): only this module can name it, so
    /// only the two markers below can implement `Direction`.
    pub trait Sealed {}
    impl Sealed for super::Encrypting {}
    impl Sealed for super::Decrypting {}
}

/// Selects a type by direction: `Enc` for [`Encrypting`], `Dec` for [`Decrypting`].
///
/// A cipher whose two directions are distinct types cannot offer `Cipher<Dir>` as a plain type
/// alias, because an alias cannot choose between two types from one of its parameters. It is
/// written as a projection through this trait instead:
///
/// ```text
/// pub type Ascon_AEAD128<Dir> =
///     <Dir as Direction>::Select<AsconAead128Encryptor, AsconAead128Decryptor>;
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
}

impl Direction for Encrypting {
    type Select<Enc, Dec> = Enc;
}

impl Direction for Decrypting {
    type Select<Enc, Dec> = Dec;
}
