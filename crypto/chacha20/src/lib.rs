//! IETF ChaCha20, as specified in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).
//!
//! [`ChaCha20Key`] is the key object: built once from 32 bytes of key material through
//! [`FromKeyMaterial`], it hands out [`ChaCha20`] stream ciphers through
//! [`SymmetricEncryptionKey`] / [`SymmetricDecryptionKey`], drawing the nonce from the RNG it is
//! given and starting the block counter at zero. The raw keystream, with a caller-chosen nonce
//! and counter for protocols and test vectors, is [`hazmat::ChaCha20KeyStream`]. Only the RFC's
//! 32-byte key and 12-byte nonce variant is supported.
//!
//! # Usage Examples
//!
//! One-shot, in place:
//!
//! ```
//! use bouncycastle_chacha20::ChaCha20Key;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let key = ChaCha20Key::from_key_material(&material).unwrap();
//! let mut message = *b"message";
//! let (_, nonce) = key.encrypt_inplace(&mut HashDRBG_SHA512::new_from_os(), &mut message).unwrap();
//! key.decrypt_inplace(&nonce, &mut message).unwrap();
//! assert_eq!(&message, b"message");
//! ```
//!
//! Streaming, in pieces of any length:
//!
//! ```
//! use bouncycastle_chacha20::ChaCha20Key;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//! let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();
//! let key = ChaCha20Key::from_key_material(&material).unwrap();
//! let mut data = [0x5au8; 100];
//! let (mut enc, nonce) = key.create_encryptor(&mut HashDRBG_SHA512::new_from_os()).unwrap();
//! for piece in data.chunks_mut(7) {
//!     enc.do_encrypt_inplace(piece).unwrap();
//! }
//! let mut dec = key.create_decryptor(&nonce);
//! dec.do_decrypt_inplace(&mut data).unwrap();
//! assert_eq!(data, [0x5au8; 100]);
//! ```
//!
//! # Memory Usage
//!
//! | Type | In-memory size (bytes) | Suspended state size (bytes) |
//! |------|------------------------|------------------------------|
//! | [`ChaCha20Key`] | 32 | -- |
//! | [`ChaCha20`] | 104 | `ChaCha20::SUSPENDED_STATE_LEN` (95) |
//! | [`hazmat::ChaCha20KeyStream`] | 32 | -- |
//!
//! "In-memory size" is `core::mem::size_of` on a 64-bit target. There are no heap allocations and
//! no message-sized buffers, so this crate has no `mem_usage_benches` harness.
//!
//! # 🚨 Security Considerations 🚨
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
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{Algorithm, RNG};
use hazmat::{ChaCha20KeyState, ChaCha20KeyStream};

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// Keystream block length in bytes.
pub const BLOCK_LEN: usize = 64;

/// ChaCha20 with a 96-bit nonce and initial block counter zero, as a [`ChaCha20Key`] makes it,
/// borrowing the key for `'k`. `Dir` is [`Encrypting`] or [`Decrypting`].
///
/// A message may be at most `2^32` blocks of 64 bytes; a call that would run past that returns
/// [`SymmetricCipherError::DataLimitExceeded`] and consumes nothing.
pub type ChaCha20<'k, Dir> = StreamCipher<ChaCha20KeyStream<'k>, Dir, NONCE_LEN, BLOCK_LEN>;

/// A ChaCha20 key: the 256-bit key of RFC 8439 Sec 2.3, validated once, from which the stream
/// cipher for each message is made. Built through [`FromKeyMaterial`] from material tagged
/// [`KeyType::SymmetricCipherKey`], unbound or bound to ChaCha20's [`Algorithm::ALG_NAME`], of
/// 256-bit strength; material bound to ChaCha20-Poly1305 is refused. The key words live in a
/// `Secret`, zeroized on drop; there is no `Debug` and no way to read them back.
#[derive(Clone)]
pub struct ChaCha20Key {
    state: ChaCha20KeyState,
}

impl FromKeyMaterial<KEY_LEN> for ChaCha20Key {
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`](bouncycastle_core::errors::KeyMaterialError::InvalidKeyType)
    ///   if the key is bound to another algorithm (`KeyMaterialTrait::set_algorithm`), or is not
    ///   a `SymmetricCipherKey`.
    /// * As [`ChaCha20KeyState::new`] otherwise.
    fn from_key_material(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        key.check_algorithm(ChaCha20KeyStream::ALG_NAME)?;
        Ok(Self { state: ChaCha20KeyState::new(key)? })
    }
}

impl SymmetricEncryptionKey<KEY_LEN, NONCE_LEN, 0> for ChaCha20Key {
    type Encryptor<'k>
        = ChaCha20<'k, Encrypting>
    where
        Self: 'k;

    fn create_encryptor<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; NONCE_LEN]), SymmetricCipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        rng.next_bytes_out(&mut nonce)?;
        Ok((ChaCha20::from_keystream(ChaCha20KeyStream::start_at(&self.state, &nonce, 0)), nonce))
    }
}

impl SymmetricDecryptionKey<KEY_LEN, NONCE_LEN, 0> for ChaCha20Key {
    type Decryptor<'k>
        = ChaCha20<'k, Decrypting>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Decryptor<'k> {
        ChaCha20::from_keystream(ChaCha20KeyStream::start_at(&self.state, nonce, 0))
    }
}
