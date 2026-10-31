//! The ECB role pair: what a key bound to ECB can produce. Here rather than in
//! [`crate::symmetric_key`] because ECB is not a confidentiality mode for data, so a key for it
//! is reached through `hazmat` as the mode itself is.

use crate::errors::SymmetricCipherError;
use crate::traits::{BlockCipherDecryptor, BlockCipherEncryptor};

/// A key that can begin an ECB encryption: the permutation applied block by block, with no init
/// data and nothing to draw, so construction takes nothing and cannot fail.
///
/// # 🚨 Security Considerations 🚨
/// Equal plaintext blocks give equal ciphertext blocks; see [`crate::hazmat`] for the supported
/// uses.
pub trait EcbEncryptionKey<const KEY_LEN: usize, const BLOCK_LEN: usize> {
    /// The streaming encryptor this key produces, borrowing the key for `'k`.
    type Encryptor<'k>: BlockCipherEncryptor<0, BLOCK_LEN>
    where
        Self: 'k;

    /// Begins an encryption.
    fn create_encryptor<'k>(&'k self) -> Self::Encryptor<'k>;

    /// One-shot: encrypts `data`, which must be a whole number of blocks, in place, and returns
    /// the number of bytes written.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataNotBlockAligned`] if `data.len()` is not a multiple of
    /// `BLOCK_LEN`; ECB itself refuses nothing.
    fn encrypt_inplace(&self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        let (blocks, []) = data.as_chunks_mut::<BLOCK_LEN>() else {
            return Err(SymmetricCipherError::DataNotBlockAligned);
        };
        self.create_encryptor().do_encrypt_blocks_inplace(blocks)
    }
}

/// A key that can begin an ECB decryption; see [`EcbEncryptionKey`].
pub trait EcbDecryptionKey<const KEY_LEN: usize, const BLOCK_LEN: usize> {
    /// The streaming decryptor this key produces, borrowing the key for `'k`.
    type Decryptor<'k>: BlockCipherDecryptor<0, BLOCK_LEN>
    where
        Self: 'k;

    /// Begins a decryption.
    fn create_decryptor<'k>(&'k self) -> Self::Decryptor<'k>;

    /// One-shot: decrypts `data`, which must be a whole number of blocks, in place, and returns
    /// the number of bytes written.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataNotBlockAligned`] if `data.len()` is not a multiple of
    /// `BLOCK_LEN`; ECB itself refuses nothing.
    fn decrypt_inplace(&self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        let (blocks, []) = data.as_chunks_mut::<BLOCK_LEN>() else {
            return Err(SymmetricCipherError::DataNotBlockAligned);
        };
        self.create_decryptor().do_decrypt_blocks_inplace(blocks)
    }
}
