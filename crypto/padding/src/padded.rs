//! [`PaddedEncryptor`] / [`PaddedDecryptor`]: adapt a block-aligned [`BlockCipherEncryptor`] /
//! [`BlockCipherDecryptor`] to arbitrary-length data using a [`Padding`] scheme.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor, Padding, RNG};
use bouncycastle_utils::secret::Secret;
use core::array::from_mut;
use core::marker::PhantomData;

/// Blocks per inner-cipher call on the bulk path; the remainder is processed one at a time.
const GROUP: usize = 8;

/// Encrypts arbitrary-length data with a block cipher `E`, padding the final block with `P`.
///
/// Stream with [`do_update_out`](Self::do_update_out) then [`do_final`](Self::do_final), or use the
/// one-shot [`encrypt_out`](Self::encrypt_out). Output is always `plaintext_len / BLOCK_LEN + 1`
/// blocks. The buffered partial plaintext block is held in a [`Secret`].
pub struct PaddedEncryptor<
    E,
    P,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
> where
    E: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: Padding<BLOCK_LEN>,
{
    inner: E,
    /// Partial plaintext block; `buf_len < BLOCK_LEN` between calls.
    buf: Secret<[u8; BLOCK_LEN]>,
    buf_len: usize,
    _padding: PhantomData<P>,
}

impl<E, P, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    PaddedEncryptor<E, P, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    E: BlockCipherEncryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: Padding<BLOCK_LEN>,
{
    /// Begins a streaming encryption, returning the generated init data (e.g. IV).
    pub fn new(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        let (inner, init_data) = E::do_encrypt_init(key)?;
        Ok((Self::wrap(inner), init_data))
    }

    /// As [`new`](Self::new), but sources randomness from the provided RNG.
    pub fn new_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        let (inner, init_data) = E::do_encrypt_init_rng(key, rng)?;
        Ok((Self::wrap(inner), init_data))
    }

    fn wrap(inner: E) -> Self {
        Self { inner, buf: Secret::new(), buf_len: 0, _padding: PhantomData }
    }

    /// Exact number of bytes [`do_update_out`](Self::do_update_out) will write for `input_len` more bytes.
    pub const fn update_out_len(&self, input_len: usize) -> usize {
        (self.buf_len + input_len) / BLOCK_LEN * BLOCK_LEN
    }

    /// Encrypts all whole blocks available (buffered + `plaintext`) into `ciphertext`, buffering the
    /// remainder. `ciphertext` needs [`update_out_len`](Self::update_out_len) bytes; returns bytes written.
    pub fn do_update_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let out_len = self.update_out_len(plaintext.len());
        if ciphertext.len() < out_len {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("ciphertext", out_len));
        }
        // out_len is a multiple of BLOCK_LEN, so the remainder of this split is empty.
        let (mut out_blocks, _) = ciphertext[..out_len].as_chunks_mut::<BLOCK_LEN>();
        let mut plaintext = plaintext;

        // 1. Top up a previously buffered partial block.
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(plaintext.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&plaintext[..take]);
            self.buf_len += take;
            plaintext = &plaintext[take..];
            if self.buf_len < BLOCK_LEN {
                // All input absorbed into the partial block; nothing to emit (out_len == 0).
                return Ok(0);
            }
            // Block completed. out_len >= BLOCK_LEN here, so `split_first_mut` always succeeds.
            // The cipher works in place, so the block is encrypted inside the `Secret` and only
            // ciphertext is copied out of it.
            if let Some((first, rest)) = core::mem::take(&mut out_blocks).split_first_mut() {
                self.inner.do_encrypt_blocks(from_mut(&mut *self.buf))?;
                *first = *self.buf;
                out_blocks = rest;
            }
            self.buf_len = 0;
        }

        // 2. Bulk path: whole blocks are copied into the output and encrypted there, in place, in
        //    groups of GROUP then singly.
        let (in_blocks, remainder) = plaintext.as_chunks::<BLOCK_LEN>();
        debug_assert_eq!(in_blocks.len(), out_blocks.len());
        out_blocks.copy_from_slice(in_blocks);
        let (out_groups, out_tail) = out_blocks.as_chunks_mut::<GROUP>();
        for group in out_groups.iter_mut() {
            self.inner.do_encrypt_blocks(group)?;
        }
        for block in out_tail.iter_mut() {
            self.inner.do_encrypt_blocks(from_mut(block))?;
        }

        // 3. Buffer the trailing partial block (remainder.len() < BLOCK_LEN).
        self.buf[..remainder.len()].copy_from_slice(remainder);
        self.buf_len = remainder.len();
        Ok(out_len)
    }

    /// Pads and encrypts the buffered partial block, returning the final ciphertext block.
    ///
    /// The block is padded and encrypted inside the `Secret`, so what is copied out is ciphertext.
    pub fn do_final(self) -> Result<[u8; BLOCK_LEN], SymmetricCipherError> {
        let Self { mut inner, mut buf, buf_len, .. } = self;
        // buf_len < BLOCK_LEN is an invariant of this type, so pad() cannot fail here.
        P::pad(&mut buf, buf_len)?;
        inner.do_encrypt(&mut buf)?;
        Ok(*buf)
    }

    /// As [`do_final`](Self::do_final), writing the final block into `ciphertext`. Returns `BLOCK_LEN`.
    pub fn do_final_out(
        self,
        ciphertext: &mut [u8; BLOCK_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        *ciphertext = self.do_final()?;
        Ok(BLOCK_LEN)
    }

    /// Ciphertext length for a `plaintext_len`-byte plaintext: `(plaintext_len / BLOCK_LEN + 1) * BLOCK_LEN`.
    pub const fn encrypt_out_len(plaintext_len: usize) -> usize {
        (plaintext_len / BLOCK_LEN + 1) * BLOCK_LEN
    }

    /// One-shot encryption. `ciphertext` needs [`encrypt_out_len`](Self::encrypt_out_len) bytes.
    /// Returns the generated init data and bytes written.
    pub fn encrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; INIT_DATA_LEN], usize), SymmetricCipherError> {
        let (enc, init_data) = Self::new(key)?;
        let written = enc.finish_one_shot(plaintext, ciphertext)?;
        Ok((init_data, written))
    }

    /// As [`encrypt_out`](Self::encrypt_out), but sources randomness from the provided RNG.
    pub fn encrypt_out_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<([u8; INIT_DATA_LEN], usize), SymmetricCipherError> {
        let (enc, init_data) = Self::new_rng(key, rng)?;
        let written = enc.finish_one_shot(plaintext, ciphertext)?;
        Ok((init_data, written))
    }

    fn finish_one_shot(
        mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let needed = Self::encrypt_out_len(plaintext.len());
        if ciphertext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("ciphertext", needed));
        }
        let written = self.do_update_out(plaintext, ciphertext)?;
        // The final block always exists and is exactly BLOCK_LEN, so the total is `needed`.
        let last = self.do_final()?;
        ciphertext[written..needed].copy_from_slice(&last);
        Ok(needed)
    }
}

/// Decrypts data produced by a [`PaddedEncryptor`] with the matching cipher and padding.
///
/// Only the last block carries padding, so [`do_update_out`](Self::do_update_out) always withholds
/// the most recent complete block and [`do_final`](Self::do_final) unpads it. One-shot:
/// [`decrypt_out`](Self::decrypt_out).
pub struct PaddedDecryptor<
    D,
    P,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
> where
    D: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: Padding<BLOCK_LEN>,
{
    inner: D,
    /// Partial ciphertext block; `buf_len < BLOCK_LEN` between calls.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Most recent complete ciphertext block, withheld in case it is the last.
    held: Option<[u8; BLOCK_LEN]>,
    _padding: PhantomData<P>,
}

impl<D, P, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    PaddedDecryptor<D, P, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    D: BlockCipherDecryptor<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: Padding<BLOCK_LEN>,
{
    /// Begins a streaming decryption from the init data returned by the encryptor.
    pub fn new(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self {
            inner: D::do_decrypt_init(key, init_data)?,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            held: None,
            _padding: PhantomData,
        })
    }

    /// Exact number of bytes [`do_update_out`](Self::do_update_out) will write for `input_len` more bytes.
    pub const fn update_out_len(&self, input_len: usize) -> usize {
        let complete = self.held.is_some() as usize + (self.buf_len + input_len) / BLOCK_LEN;
        // All complete blocks but the most recent one are released.
        complete.saturating_sub(1) * BLOCK_LEN
    }

    /// Decrypts all complete blocks except the most recent into `plaintext`, buffering the remainder.
    /// `plaintext` needs [`update_out_len`](Self::update_out_len) bytes; returns bytes written.
    pub fn do_update_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        let out_len = self.update_out_len(ciphertext.len());
        if plaintext.len() < out_len {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("plaintext", out_len));
        }
        let (mut out_blocks, _) = plaintext[..out_len].as_chunks_mut::<BLOCK_LEN>();
        let mut ciphertext = ciphertext;

        // 1. Top up a previously buffered partial block.
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(ciphertext.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&ciphertext[..take]);
            self.buf_len += take;
            ciphertext = &ciphertext[take..];
            if self.buf_len < BLOCK_LEN {
                return Ok(0);
            }
            self.buf_len = 0;
            // The completed block becomes the held block; the previously held block, if any, is
            // now known not to be last and can be released. out_blocks has room for it by
            // construction of out_len, so `split_first_mut` succeeds.
            if let Some(prev) = self.held.replace(self.buf)
                && let Some((first, rest)) = core::mem::take(&mut out_blocks).split_first_mut()
            {
                *first = prev;
                self.inner.do_decrypt_blocks(from_mut(first))?;
                out_blocks = rest;
            }
        }

        // 2. Bulk path.
        let (in_blocks, remainder) = ciphertext.as_chunks::<BLOCK_LEN>();
        if let Some((last, release)) = in_blocks.split_last() {
            // Release the previously held block first (it precedes everything in `in_blocks`).
            if let Some(prev) = self.held.replace(*last)
                && let Some((first, rest)) = core::mem::take(&mut out_blocks).split_first_mut()
            {
                *first = prev;
                self.inner.do_decrypt_blocks(from_mut(first))?;
                out_blocks = rest;
            }
            // Then every block of this call except the new held one: copied into the output and
            // decrypted there, in place.
            debug_assert_eq!(release.len(), out_blocks.len());
            out_blocks.copy_from_slice(release);
            let (out_groups, out_tail) = out_blocks.as_chunks_mut::<GROUP>();
            for group in out_groups.iter_mut() {
                self.inner.do_decrypt_blocks(group)?;
            }
            for block in out_tail.iter_mut() {
                self.inner.do_decrypt_blocks(from_mut(block))?;
            }
        }

        // 3. Buffer the trailing partial block.
        self.buf[..remainder.len()].copy_from_slice(remainder);
        self.buf_len = remainder.len();
        Ok(out_len)
    }

    /// Decrypts and unpads the held final block. Returns the block and its data length; the rest is
    /// padding. `DecryptionFailed` if the ciphertext was empty or not block-aligned; `PaddingError`
    /// if the padding is malformed.
    pub fn do_final(self) -> Result<([u8; BLOCK_LEN], usize), SymmetricCipherError> {
        let Self { mut inner, buf_len, held, .. } = self;
        if buf_len != 0 {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let Some(mut block) = held else {
            return Err(SymmetricCipherError::DecryptionFailed);
        };
        inner.do_decrypt(&mut block)?;
        let data_len = P::unpad(&block)?;
        Ok((block, data_len))
    }

    /// As [`do_final`](Self::do_final), writing the block into `plaintext`. Returns its data length.
    pub fn do_final_out(
        self,
        plaintext: &mut [u8; BLOCK_LEN],
    ) -> Result<usize, SymmetricCipherError> {
        let (block, data_len) = self.do_final()?;
        *plaintext = block;
        Ok(data_len)
    }

    /// Upper bound on the plaintext recovered from `ciphertext_len` bytes: `ciphertext_len - 1`.
    pub const fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len.saturating_sub(1)
    }

    /// One-shot decryption. `plaintext` needs [`decrypt_out_max_len`](Self::decrypt_out_max_len)
    /// bytes. Returns bytes written.
    pub fn decrypt_out(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        if ciphertext.len() < BLOCK_LEN || !ciphertext.len().is_multiple_of(BLOCK_LEN) {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let needed = Self::decrypt_out_max_len(ciphertext.len());
        if plaintext.len() < needed {
            return Err(SymmetricCipherError::IncorrectOutputBufferLength("plaintext", needed));
        }
        let mut dec = Self::new(key, init_data)?;
        let written = dec.do_update_out(ciphertext, plaintext)?;
        let (last, data_len) = dec.do_final()?;
        // written == ciphertext.len() - BLOCK_LEN and data_len < BLOCK_LEN, so this fits in `needed`.
        plaintext[written..written + data_len].copy_from_slice(&last[..data_len]);
        Ok(written + data_len)
    }
}
