//! IETF ChaCha20, as specified in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).
//!
//! [`ChaCha20`] is a stream cipher: it implements the core stream-cipher traits and their
//! symmetric-cipher supertraits, generates its nonce and starts the block counter at zero. The raw
//! keystream, with a caller-chosen nonce and counter for protocols and test vectors, is
//! [`hazmat::ChaCha20KeyStream`].
//! Never reuse a nonce under the same key, or overlap counter ranges for that key/nonce.
//! This cipher provides no authentication; use ChaCha20-Poly1305 for authenticated encryption.
//! Only the RFC's 32-byte key and 12-byte nonce variant is supported.
//!
//! ```
//! use bouncycastle_chacha20::ChaCha20;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_core::{key_material::{KeyMaterial, KeyType}, traits::{StreamCipherEncryptor, StreamCipherDecryptor}};
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let mut message = *b"message";
//! let (_, nonce) = ChaCha20::<Encrypting>::encrypt_in_place(&key, &mut message).unwrap();
//! ChaCha20::<Decrypting>::decrypt_in_place(&key, &nonce, &mut message).unwrap();
//! assert_eq!(&message, b"message");
//! ```

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod hazmat;

use bouncycastle_cipher::stream::StreamCipher;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_cipher::{Decrypting, Encrypting};
// end of imports needed for docs

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// Keystream block length in bytes.
pub const BLOCK_LEN: usize = 64;

/// ChaCha20 with a generated 96-bit nonce and initial block counter zero. `Dir` is
/// [`Encrypting`] or [`Decrypting`].
///
/// A message may be at most `2^32` blocks of 64 bytes; a call that would run past that returns
/// [`SymmetricCipherError::DataLimitExceeded`](bouncycastle_core::errors::SymmetricCipherError::DataLimitExceeded)
/// and consumes nothing.
pub type ChaCha20<Dir> =
    StreamCipher<hazmat::ChaCha20KeyStream, Dir, KEY_LEN, NONCE_LEN, BLOCK_LEN>;
