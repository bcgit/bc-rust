//! The direction markers a keyed worker carries in its type: [`Encrypting`] for the forward
//! operation (encrypting, generating a tag, wrapping a key) and [`Decrypting`] for its inverse
//! (decrypting, verifying a tag, unwrapping). A worker type `Worker<Dir>` implements the forward
//! trait for `Encrypting` and the inverse trait for `Decrypting`, so a wrong-direction call is a
//! compile error and the two directions never share a method name on one type.

/// Direction marker for a worker that encrypts, generates a tag or wraps a key.
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encrypting;

/// Direction marker for a worker that decrypts, verifies a tag or unwraps a key.
///
/// Zero-sized: encoding the direction in the type costs no memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decrypting;

mod sealed {
    /// Private supertrait of [`Direction`](super::Direction): only this module can name it, so
    /// only the two markers above can implement `Direction`.
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
/// use bouncycastle_core::direction::Direction;
/// struct Sideways;
/// // error: the supertrait is private to bouncycastle_core
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
