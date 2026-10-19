//! IETF ChaCha20, as specified in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).
//!
//! [`ChaCha20`] is a stream cipher: it implements the core stream-cipher traits and their
//! symmetric-cipher supertraits, generates its nonce and starts the block counter at zero. The raw
//! keystream, with a caller-chosen nonce and counter for protocols and test vectors, is
//! [`hazmat::ChaCha20KeyStream`]. Only the RFC's 32-byte key and 12-byte nonce variant is
//! supported.
//!
//! # Usage Examples
//!
//! One-shot, in place:
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
//!
//! Streaming, in pieces of any length:
//!
//! ```
//! use bouncycastle_chacha20::ChaCha20;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{
//!     StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
//!     SymmetricCipherEncryptor,
//! };
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let mut data = [0x5au8; 100];
//! let (mut enc, nonce) = ChaCha20::<Encrypting>::do_encrypt_init(&key).unwrap();
//! for piece in data.chunks_mut(7) {
//!     enc.do_encrypt(piece).unwrap();
//! }
//! let mut dec = ChaCha20::<Decrypting>::do_decrypt_init(&key, &nonce).unwrap();
//! dec.do_decrypt(&mut data).unwrap();
//! assert_eq!(data, [0x5au8; 100]);
//! ```
//!
//! # Memory Usage
//!
//! | Type | In-memory size (bytes) | Suspended state size (bytes) |
//! |------|------------------------|------------------------------|
//! | [`ChaCha20`] | 144 | `ChaCha20::SUSPENDED_STATE_LEN` (95) |
//! | [`hazmat::ChaCha20KeyStream`] | 72 | -- |
//!
//! "In-memory size" is `core::mem::size_of` on a 64-bit target. There are no heap allocations and
//! no message-sized buffers, so this crate has no `mem_usage_benches` harness.
//!
//! # Security Considerations
//!
//! - Never reuse a nonce under the same key, or overlap counter ranges for that key and nonce
//!   through [`hazmat::ChaCha20KeyStream::start_at`]: the keystream repeats and the XOR of the two
//!   plaintexts is revealed.
//! - ChaCha20 provides no authentication: flipping a ciphertext bit flips the same plaintext bit.
//!   Use ChaCha20-Poly1305 unless the ciphertext is authenticated by other means.

#![no_std]
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
