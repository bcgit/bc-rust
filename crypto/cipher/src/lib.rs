//! A utility crate for holding common building blocks for constructing symmetric ciphers on top of
//! different permutation functions, such as modes of operation and padding.
//!
//! * [`modes`] — block cipher modes of operation (NIST SP 800-38A, SP 800-38C and SP 800-38D).
//! * [`padding`] — block padding schemes, and the adapters that apply them to a block cipher mode.
//! * [`stream`] — a stream cipher over any keystream, and the helpers shared by stream ciphers that
//!   cannot be built that way.
//!
//! # Usage Examples
//!
//! See the [`modes`], [`padding`] and [`stream`] module docs.
//!
//! # Suspending and resuming execution
//!
//! Every mode and adapter implements `SuspendableKeyed`, so a message in progress can be suspended
//! to a byte array and resumed later with the re-supplied key. The length of that array is the
//! type's `SUSPENDED_STATE_LEN`, and a wrong length is a compile error; the mechanism is
//! [`bouncycastle_utils::suspendable_state`]. A suspended state holds everything the message in
//! progress depends on except the key -- a chaining block, live keystream, a running MAC -- so
//! protect it as the plaintext it governs, and never resume one state twice.
//!
//! ```
//! use bouncycastle_cipher::modes::Cbc;
//! use bouncycastle_cipher::Encrypting;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherEncryptor, SuspendableKeyed};
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//!
//! type ToyCbc = Cbc<ToyBlockCipher, Encrypting, 16, 16>;
//! const STATE_LEN: usize = ToyCbc::SUSPENDED_STATE_LEN;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
//! let (mut enc, _iv) = ToyCbc::do_encrypt_init(&key).unwrap();
//! let mut first = [0x11u8; 16];
//! enc.do_encrypt_inplace(&mut first).unwrap();
//!
//! // Suspending consumes the cipher. The key is not in the state and is re-supplied to resume.
//! let state: [u8; STATE_LEN] = enc.suspend();
//! let mut enc = ToyCbc::from_suspended(state, &key).unwrap();
//! let mut second = [0x22u8; 16];
//! enc.do_encrypt_inplace(&mut second).unwrap();
//! ```
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
/// pub type AES_CBC_128<Dir, Pad> =
///     <Dir as Direction>::Select<PaddedBlockCipherEncryptor<...>, PaddedBlockCipherDecryptor<...>>;
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
