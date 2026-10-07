//! [`PaddedBlockCipherEncryptor`] / [`PaddedBlockCipherDecryptor`]: adapt a block-aligned [`BlockCipherEncryptor`] /
//! [`BlockCipherDecryptor`] to arbitrary-length data using a [`BlockCipherPadding`] scheme.
//!
//! The public API is the [`SymmetricCipherEncryptor`] / [`SymmetricCipherDecryptor`] traits, whose
//! shape was drawn from these two types; the one-shot methods are the traits' provided ones.
//! `FINAL_LEN` is `BLOCK_LEN`: the final output is the padded block -- or, under a scheme with
//! [`BlockCipherPadding::ALWAYS_PADS`] `false` (`NoPadding`) and an aligned message, nothing at
//! all, in which case `do_encrypt_final` reports 0 of the `FINAL_LEN` bytes as output.

use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, BlockCipherPadding, RNG,
    SuspendableKeyed, SymmetricCipherDecryptor, SymmetricCipherEncryptor, SymmetricCipherKey,
};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::suspendable_state::{
    Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, bounded_usize, resume_component,
    suspend_component,
};
use core::array::from_mut;
use core::marker::PhantomData;

/// Blocks per inner-cipher call on the bulk path; the remainder is processed one at a time.
const GROUP: usize = 8;

/// Encrypts arbitrary-length data with a block cipher `E`, padding the final block with `P`.
///
/// Stream with [`SymmetricCipherEncryptor::do_encrypt_out`] then
/// [`SymmetricCipherEncryptor::do_encrypt_final`], or use the one-shot
/// [`SymmetricCipherEncryptor::encrypt_out`]. Output is
/// `plaintext_len / BLOCK_LEN + 1` blocks for a scheme that always pads (PKCS7), and exactly the
/// input length for one that never does (`NoPadding`, which rejects an unaligned input at
/// `do_encrypt_final`). The buffered partial plaintext block is held in a [`Secret`].
#[derive(Clone)]
pub struct PaddedBlockCipherEncryptor<
    E,
    P,
    K,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
> where
    E: BlockCipherEncryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    encryptor: E,
    _padding: PhantomData<P>,
    /// Records `K`, which no other field mentions; without it `K` would be an unused parameter.
    _key: PhantomData<K>,
    /// Partial plaintext block; `buf_len < BLOCK_LEN` between calls.
    buf: Secret<[u8; BLOCK_LEN]>,
    buf_len: usize,
}

impl<E, P, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for PaddedBlockCipherEncryptor<E, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    E: BlockCipherEncryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    /// The inner cipher's name; padding does not change what the algorithm is.
    const ALG_NAME: &'static str = E::ALG_NAME;
    /// Padding does not change the strength of the inner cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = E::MAX_SECURITY_STRENGTH;
}

impl<E, P, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherEncryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
    for PaddedBlockCipherEncryptor<E, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    E: BlockCipherEncryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    fn do_encrypt_init(key: &K) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        let (encryptor, init_data) = E::do_encrypt_init(key)?;
        Ok((
            Self {
                encryptor,
                _padding: PhantomData,
                _key: PhantomData,
                buf: Secret::new(),
                buf_len: 0,
            },
            init_data,
        ))
    }

    fn do_encrypt_init_rng(
        key: &K,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        let (encryptor, init_data) = E::do_encrypt_init_rng(key, rng)?;
        Ok((
            Self {
                encryptor,
                _padding: PhantomData,
                _key: PhantomData,
                buf: Secret::new(),
                buf_len: 0,
            },
            init_data,
        ))
    }

    /// Whole blocks among the buffered bytes plus `input_len`.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        (self.buf_len + input_len) / BLOCK_LEN * BLOCK_LEN
    }

    /// Encrypts all whole blocks available (buffered + `plaintext`) into `ciphertext`, buffering the
    /// remainder.
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        ciphertext.fill(0);
        let out_len = self.do_encrypt_out_len(plaintext.len());
        if ciphertext.len() < out_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(out_len));
        }
        // out_len is a multiple of BLOCK_LEN, so the remainder of this split is empty.
        let (mut out_blocks, _) = ciphertext[..out_len].as_chunks_mut::<BLOCK_LEN>();

        // Turn this into a mutable pointer so that we can walk the pointer down the data.
        // Note only the pointer is mut, the data remains immutable `&[u8]`.
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
                self.encryptor.do_encrypt_blocks_inplace(from_mut(&mut *self.buf))?;
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
            self.encryptor.do_encrypt_blocks_inplace(group)?;
        }
        for block in out_tail.iter_mut() {
            self.encryptor.do_encrypt_blocks_inplace(from_mut(block))?;
        }

        // 3. Buffer the trailing partial block (remainder.len() < BLOCK_LEN).
        self.buf[..remainder.len()].copy_from_slice(remainder);
        self.buf_len = remainder.len();
        Ok(out_len)
    }

    /// Pads and encrypts the buffered partial block, returning the final ciphertext block and
    /// `BLOCK_LEN` -- or, when the scheme adds nothing to aligned data and nothing is buffered, an
    /// untouched buffer and 0: there is no final block.
    ///
    /// The block is padded and encrypted inside the `Secret`, so what is copied out is ciphertext.
    /// A scheme that adds no padding turns a buffered partial block into
    /// [`SymmetricCipherError::PaddingError`] here, which is the alignment check such a scheme
    /// exists to provide.
    fn do_encrypt_final(self) -> Result<([u8; BLOCK_LEN], usize), SymmetricCipherError> {
        let Self { encryptor: mut inner, mut buf, buf_len, .. } = self;
        if buf_len == 0 && !P::ALWAYS_PADS {
            return Ok(([0u8; BLOCK_LEN], 0));
        }
        P::pad(&mut buf, buf_len)?;
        inner.do_encrypt_inplace(&mut buf)?;
        Ok((*buf, BLOCK_LEN))
    }

    /// `(plaintext_len / BLOCK_LEN + 1) * BLOCK_LEN` -- always one extra block for the padding --
    /// for a scheme that always pads; `plaintext_len` itself for one that adds nothing (an
    /// unaligned length is rejected by `do_encrypt_final`, so this is exact for every accepted
    /// input).
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        if P::ALWAYS_PADS { (plaintext_len / BLOCK_LEN + 1) * BLOCK_LEN } else { plaintext_len }
    }
}

/// Decrypts data produced by a [`PaddedBlockCipherEncryptor`] with the matching cipher and padding.
///
/// Only the last block carries padding, so [`do_update_out`](Self::do_decrypt_out) always withholds
/// the most recent complete block and [`do_decrypt_final`](Self::do_decrypt_final) unpads it.
/// One-shot: [`decrypt_out`](Self::decrypt_out).
#[derive(Clone)]
pub struct PaddedBlockCipherDecryptor<
    D,
    P,
    K,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
> where
    D: BlockCipherDecryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    decryptor: D,
    _padding: PhantomData<P>,
    /// Records `K`, which no other field mentions; without it `K` would be an unused parameter.
    _key: PhantomData<K>,
    /// Partial ciphertext block; `buf_len < BLOCK_LEN` between calls.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Most recent complete ciphertext block, withheld in case it is the last.
    held: Option<[u8; BLOCK_LEN]>,
}

impl<D, P, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for PaddedBlockCipherDecryptor<D, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    D: BlockCipherDecryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    /// The inner cipher's name; padding does not change what the algorithm is.
    const ALG_NAME: &'static str = D::ALG_NAME;
    /// Padding does not change the strength of the inner cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = D::MAX_SECURITY_STRENGTH;
}

impl<D, P, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherDecryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
    for PaddedBlockCipherDecryptor<D, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    D: BlockCipherDecryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
    P: BlockCipherPadding<BLOCK_LEN>,
{
    fn do_decrypt_init(
        key: &K,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Ok(Self {
            decryptor: D::do_decrypt_init(key, init_data)?,
            _padding: PhantomData,
            _key: PhantomData,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            held: None,
        })
    }

    /// All complete blocks but the most recent one are released.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        let complete = self.held.is_some() as usize + (self.buf_len + input_len) / BLOCK_LEN;
        complete.saturating_sub(1) * BLOCK_LEN
    }

    /// Decrypts all complete blocks except the most recent into `plaintext`, buffering the remainder.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        let out_len = self.do_decrypt_out_len(ciphertext.len());
        if plaintext.len() < out_len {
            return Err(SymmetricCipherError::OutputBufferTooSmall(out_len));
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
                self.decryptor.do_decrypt_blocks_inplace(from_mut(first))?;
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
                self.decryptor.do_decrypt_blocks_inplace(from_mut(first))?;
                out_blocks = rest;
            }
            // Then every block of this call except the new held one: copied into the output and
            // decrypted there, in place.
            debug_assert_eq!(release.len(), out_blocks.len());
            out_blocks.copy_from_slice(release);
            let (out_groups, out_tail) = out_blocks.as_chunks_mut::<GROUP>();
            for group in out_groups.iter_mut() {
                self.decryptor.do_decrypt_blocks_inplace(group)?;
            }
            for block in out_tail.iter_mut() {
                self.decryptor.do_decrypt_blocks_inplace(from_mut(block))?;
            }
        }

        // 3. Buffer the trailing partial block.
        self.buf[..remainder.len()].copy_from_slice(remainder);
        self.buf_len = remainder.len();
        Ok(out_len)
    }

    /// Decrypts and unpads the held final block. Returns the block and its data length; the rest is
    /// padding. `DecryptionFailed` if the ciphertext was not block-aligned, or was empty under a
    /// scheme that always pads (a padded message is at least one block); `PaddingError` if the
    /// padding is malformed. Under a scheme that adds nothing, an empty ciphertext is the empty
    /// message and every held block is entirely data.
    fn do_decrypt_final(self) -> Result<([u8; BLOCK_LEN], usize), SymmetricCipherError> {
        let Self { decryptor: mut inner, buf_len, held, .. } = self;
        if buf_len != 0 {
            return Err(SymmetricCipherError::DecryptionFailed);
        }
        let Some(mut block) = held else {
            return if P::ALWAYS_PADS {
                Err(SymmetricCipherError::DecryptionFailed)
            } else {
                Ok(([0u8; BLOCK_LEN], 0))
            };
        };
        inner.do_decrypt_inplace(&mut block)?;
        let data_len = P::unpad(&block)?;
        Ok((block, data_len))
    }

    /// `ciphertext_len - 1` for a scheme that always pads (at least one byte of the final block is
    /// padding); `ciphertext_len` for one that adds nothing.
    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        if P::ALWAYS_PADS { ciphertext_len.saturating_sub(1) } else { ciphertext_len }
    }
}

impl<E, P, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    PaddedBlockCipherEncryptor<E, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    E: BlockCipherEncryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    /// The `N` of this type's [`SuspendableKeyed<N>`] impl: the version header, the inner
    /// cipher's state, the partial plaintext block and its length as a `u64`. See
    /// [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize =
        LIB_VERSION_LEN + <Self as SuspendableComponent>::STATE_LEN;
}

/// The suspended state is the inner cipher's followed by the buffered partial block. That block
/// is plaintext, so the state must be protected; see [`bouncycastle_utils::suspendable_state`].
impl<E, P, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    SuspendableComponent for PaddedBlockCipherEncryptor<E, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    E: BlockCipherEncryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    const STATE_LEN: usize = E::STATE_LEN + BLOCK_LEN + 8;
    type Key = E::Key;

    fn write_state(&self, out: &mut [u8]) {
        let (inner, rest) = out.split_at_mut(E::STATE_LEN);
        self.encryptor.write_state(inner);
        let mut w = CursorMut::new(rest);
        w.bytes(&*self.buf);
        w.u64(self.buf_len as u64);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        let (inner, rest) = state.split_at(E::STATE_LEN);
        let encryptor = E::read_state(inner, key)?;
        let mut r = Cursor::new(rest);
        let mut buf: Secret<[u8; BLOCK_LEN]> = Secret::new();
        (*buf).copy_from_slice(r.bytes(BLOCK_LEN));
        // A full block is encrypted as soon as it is full, so `buf_len < BLOCK_LEN` between calls.
        let buf_len = bounded_usize(r.u64(), BLOCK_LEN - 1)?;
        debug_assert!(r.is_done());
        Ok(Self { encryptor, _padding: PhantomData, _key: PhantomData, buf, buf_len })
    }
}

/// `N` must be [`PaddedBlockCipherEncryptor::SUSPENDED_STATE_LEN`]; anything else is a compile
/// error.
impl<
    E,
    P,
    K,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
    const N: usize,
> SuspendableKeyed<N> for PaddedBlockCipherEncryptor<E, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    E: BlockCipherEncryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    type Key = E::Key;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; N], key: &Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}

impl<D, P, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    PaddedBlockCipherDecryptor<D, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    D: BlockCipherDecryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    /// The `N` of this type's [`SuspendableKeyed<N>`] impl: the version header, the inner
    /// cipher's state, the partial ciphertext block and its length as a `u64`, a flag for
    /// whether a block is held back, and that block. See [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize =
        LIB_VERSION_LEN + <Self as SuspendableComponent>::STATE_LEN;
}

/// The suspended state is the inner cipher's, the buffered partial block, and the withheld
/// block if there is one (all ciphertext). See [`bouncycastle_utils::suspendable_state`].
impl<D, P, K, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    SuspendableComponent for PaddedBlockCipherDecryptor<D, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    D: BlockCipherDecryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    const STATE_LEN: usize = D::STATE_LEN + BLOCK_LEN + 8 + 1 + BLOCK_LEN;
    type Key = D::Key;

    fn write_state(&self, out: &mut [u8]) {
        let (inner, rest) = out.split_at_mut(D::STATE_LEN);
        self.decryptor.write_state(inner);
        let mut w = CursorMut::new(rest);
        w.bytes(&self.buf);
        w.u64(self.buf_len as u64);
        match &self.held {
            Some(block) => {
                w.u8(1);
                w.bytes(block);
            }
            None => {
                w.u8(0);
                w.bytes(&[0u8; BLOCK_LEN]);
            }
        }
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        let (inner, rest) = state.split_at(D::STATE_LEN);
        let decryptor = D::read_state(inner, key)?;
        let mut r = Cursor::new(rest);
        let buf = r.array::<BLOCK_LEN>();
        // A full block becomes the held block as soon as it is full, so `buf_len < BLOCK_LEN`.
        let buf_len = bounded_usize(r.u64(), BLOCK_LEN - 1)?;
        let held = match r.u8() {
            0 => {
                r.bytes(BLOCK_LEN);
                None
            }
            1 => Some(r.array::<BLOCK_LEN>()),
            _ => return Err(SuspendableError::InvalidData),
        };
        debug_assert!(r.is_done());
        Ok(Self { decryptor, _padding: PhantomData, _key: PhantomData, buf, buf_len, held })
    }
}

/// `N` must be [`PaddedBlockCipherDecryptor::SUSPENDED_STATE_LEN`]; anything else is a compile
/// error.
impl<
    D,
    P,
    K,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
    const N: usize,
> SuspendableKeyed<N> for PaddedBlockCipherDecryptor<D, P, K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    D: BlockCipherDecryptor<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent,
    P: BlockCipherPadding<BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    type Key = D::Key;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; N], key: &Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}
