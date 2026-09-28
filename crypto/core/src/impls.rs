//! Provides default impls for the core traits.
//!
// Objects in this file should be sorted alphabetically, regardless of whether they are a trait, struct, or enum.

use crate::errors::SymmetricCipherError;
use crate::key_material::KeyMaterial;
use crate::traits::{
    RNG, StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};

/// Every stream cipher is also a [`SymmetricCipherEncryptor`] with `FINAL_LEN = 0`.
///
/// The two traits describe the same operation at different granularities. [`StreamCipherEncryptor`]
/// is the in-place view -- one buffer, transformed where it lies -- and
/// [`SymmetricCipherEncryptor`] is the separate-output view that the padding adapters and the AEAD
/// ciphers share. A stream cipher can offer the second in terms of the first, because it changes
/// neither the length of its data nor anything at the end of the message: `update_out_len` is the
/// identity, `encrypt_out_len` is the identity, and `do_final` has nothing to produce, which is
/// exactly what `FINAL_LEN = 0` says.
///
/// The point of the blanket impl is that a caller can hold a CFB, CFB8 or CTR value through the
/// same trait as a padded CBC one, and write code that does not care which mode it was handed. It
/// applies to every present and future implementor, so a new stream mode gets the arbitrary-length
/// API by writing one method.
///
/// Note that both traits then offer `do_encrypt_init` and `do_encrypt_init_rng` with identical
/// signatures. Where both are in scope, a call needs qualifying --
/// `<Cfb<..> as StreamCipherEncryptor<..>>::do_encrypt_init(&key)` -- though either resolves to the
/// same function.
impl<T, const KEY_LEN: usize, const INIT_DATA_LEN: usize>
    SymmetricCipherEncryptor<KEY_LEN, INIT_DATA_LEN, 0> for T
where
    T: StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>,
{
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        Self::do_encrypt_init(key)
    }

    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        Self::do_encrypt_init_rng(key, rng)
    }

    /// A stream cipher buffers nothing, so every input byte produces exactly one output byte.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// Copies the plaintext into the output buffer and encrypts it there, so the caller's input is
    /// left untouched -- the one thing the in-place [`StreamCipherEncryptor::do_encrypt`] cannot
    /// offer.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is shorter than
    /// `plaintext`, checked before anything is consumed; otherwise whatever `do_encrypt` returns.
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.do_encrypt(out)?;
        Ok(plaintext.len())
    }

    /// Nothing is held back, so there is nothing to finish: an empty buffer, none of it output.
    ///
    /// `cargo mutants` reports the `[]` here as a surviving mutant against `[0; 0]` and `[1; 0]`.
    /// Those are the same value: a zero-length array has no element to differ in, so the three
    /// spellings are indistinguishable and no test can separate them. The mutants that *do* change
    /// behaviour -- returning 1 rather than 0 for the data length -- are caught.
    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        Ok(([], 0))
    }

    /// A stream cipher never changes the length of its data.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }
}

/// Every stream cipher is also a [`SymmetricCipherDecryptor`] with `FINAL_LEN = 0`. The mirror of
/// the [`StreamCipherEncryptor`] blanket impl above; see it for why this exists.
impl<T, const KEY_LEN: usize, const INIT_DATA_LEN: usize>
    SymmetricCipherDecryptor<KEY_LEN, INIT_DATA_LEN, 0> for T
where
    T: StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>,
{
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Self::do_decrypt_init(key, init_data)
    }

    /// A stream cipher holds nothing back, so every input byte can be released immediately.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// Copies the ciphertext into the output buffer and decrypts it there, leaving the caller's
    /// input untouched.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is shorter than
    /// `ciphertext`, checked before anything is consumed; otherwise whatever `do_decrypt` returns.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if plaintext.len() < ciphertext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(ciphertext.len()));
        }
        let out = &mut plaintext[..ciphertext.len()];
        out.copy_from_slice(ciphertext);
        self.do_decrypt(out)?;
        Ok(ciphertext.len())
    }

    /// Nothing is held back, and there is no padding or tag to check.
    ///
    /// `cargo mutants` reports the `[]` here as a surviving mutant against `[0; 0]` and `[1; 0]`.
    /// Those are the same value: a zero-length array has no element to differ in, so the three
    /// spellings are indistinguishable and no test can separate them. The mutants that *do* change
    /// behaviour -- returning 1 rather than 0 for the data length -- are caught.
    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        Ok(([], 0))
    }

    /// Exact rather than an upper bound: a stream cipher never changes the length of its data.
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}
