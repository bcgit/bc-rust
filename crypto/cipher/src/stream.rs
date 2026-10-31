//! Stream ciphers built from a [`KeyStream`].
//!
//! [`StreamCipher`] turns any [`KeyStream`] into a [`StreamCipherEncryptor`] /
//! [`StreamCipherDecryptor`] pair, and with it the [`SymmetricCipherEncryptor`] /
//! [`SymmetricCipherDecryptor`] supertraits, as a block cipher mode turns an
//! [`ElectronicCodeBook`](bouncycastle_core::hazmat::ElectronicCodeBook) into a block cipher. A keystream
//! implementor writes the keystream; the nonce, the partly-used block held between calls and the
//! refusal to run past the end of the keystream are written once, here.
//!
//! A mode whose keystream depends on the data, such as CFB, implements the traits itself.
//!
//! # Suspending and resuming execution
//!
//! [`StreamCipher`] implements [`SuspendableKeyed`], so a message in progress can be suspended to a
//! byte array and resumed later over the re-supplied key state. The state is the keystream's own state
//! and the partly used keystream block, for any keystream that implements [`SuspendableComponent`].
//! The array length is `StreamCipher::SUSPENDED_STATE_LEN`; see [the crate
//! docs](crate#suspending-and-resuming-execution) for an example.
//!

use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::KeyStream;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, StreamCipherDecryptor, StreamCipherEncryptor, SuspendableKeyed,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::suspendable_state::{
    Cursor, CursorMut, LIB_VERSION_LEN, SuspendableComponent, bounded_usize, resume_component,
    suspend_component,
};
use core::marker::PhantomData;

/// A stream cipher over any [`KeyStream`], with the direction encoded in the type.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`].
///
/// `INIT_DATA_LEN` and `BLOCK_LEN` must both be non-zero, checked at compile time: a keystream
/// with no init data would repeat for every message under a key.
///
/// # State
///
/// The keystream, the current keystream block and how much of it has been used. A call can end
/// part-way through a keystream block, and the remainder is kept for the next call so the caller's
/// chunking is invisible in the output. Those bytes are live keystream for the next bytes of the
/// message, so the block is a [`Secret`] and is zeroized on drop.
///
/// # The keystream is finite, and running out is an error
///
/// A call that would need more keystream than [`KeyStream::remaining_blocks`] can still supply
/// returns [`SymmetricCipherError::DataLimitExceeded`] and consumes nothing: the check is made up front,
/// against the whole call, so a message is never half-processed before the cipher notices. Past
/// that point the keystream would repeat, which is the two-time-pad failure within one message.
#[derive(Clone)]
pub struct StreamCipher<KS, Dir, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN>,
{
    keystream: KS,
    /// The keystream block currently being consumed. Meaningful only while `used < BLOCK_LEN`.
    pending: Secret<[u8; BLOCK_LEN]>,
    /// Bytes of `pending` already consumed, `0..=BLOCK_LEN`. `BLOCK_LEN` means none is pending
    /// and the next byte needs a fresh keystream block.
    used: usize,
    _marker: PhantomData<Dir>,
}

impl<KS, Dir, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    StreamCipher<KS, Dir, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN>,
{
    /// Wraps a keystream that has already been constructed and positioned, such as one that
    /// starts part-way into its counter space (GCM's GCTR starts at `inc32(J0)`).
    ///
    /// # 🚨 Security Considerations 🚨
    /// This bypasses init-data generation: the keystream's nonce is whatever it was constructed
    /// with, and the caller is responsible for it never repeating under the key. A key's
    /// `create_encryptor` is the safe path.
    pub fn from_keystream(keystream: KS) -> Self {
        Self::check_shape();
        Self { keystream, pending: Secret::new(), used: BLOCK_LEN, _marker: PhantomData }
    }

    /// The wrapped keystream, for a construction that shares its key schedule with something
    /// else (CCM's CBC-MAC). Shared access only: producing keystream takes `&mut`, so this cannot
    /// be used to step the keystream behind this value's back.
    pub fn keystream(&self) -> &KS {
        &self.keystream
    }

    /// The compile-time shape check, run from every constructor.
    ///
    /// A keystream with no init data would produce the same keystream for every message under a
    /// key; the traits' init-data contract exists to prevent exactly that. A zero-length block
    /// could not carry any keystream at all.
    #[inline]
    fn check_shape() {
        const {
            assert!(
                INIT_DATA_LEN > 0,
                "a stream cipher needs init data, or it repeats its keystream for every message"
            );
            assert!(BLOCK_LEN > 0, "a keystream block must be at least one byte");
        };
    }

    /// The whole data path, shared by both directions: a keystream cipher's encryption and
    /// decryption are the same XOR, so there is one implementation and the direction is only a
    /// type.
    ///
    /// Splits into the bytes that finish an already-open keystream block, the whole blocks that
    /// follow -- handed to [`KeyStream::apply_blocks`] in one call, so the keystream batches them
    /// however suits it -- and the short tail, whose keystream block is generated into `pending`
    /// and kept for the next call.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataLimitExceeded`] if the keystream cannot cover the call; nothing
    /// is consumed in that case.
    fn apply(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        let pending_len = BLOCK_LEN - self.used;
        // Saturating: a keystream with no practical limit reports `u64::MAX` blocks.
        let capacity = (pending_len as u64)
            .saturating_add(self.keystream.remaining_blocks().saturating_mul(BLOCK_LEN as u64));
        if data.len() as u64 > capacity {
            // Keystream exhausted: this call would need more keystream than remains for this init
            // data, and continuing would repeat keystream.
            return Err(SymmetricCipherError::DataLimitExceeded);
        }

        let head_len = core::cmp::min(pending_len, data.len());
        let (head, rest) = data.split_at_mut(head_len);
        for (b, k) in head.iter_mut().zip(self.pending[self.used..].iter()) {
            *b ^= *k;
        }
        self.used += head_len;

        let (blocks, tail) = rest.as_chunks_mut::<BLOCK_LEN>();
        self.keystream.apply_blocks(blocks);

        if !tail.is_empty() {
            // `rest` is non-empty, so `head` used up every pending byte and `used == BLOCK_LEN`.
            // The keystream block is generated in place inside the `Secret` -- XORed into zeros --
            // so no copy of it is left on the stack unzeroized.
            *self.pending = [0u8; BLOCK_LEN];
            self.keystream.apply_blocks(core::slice::from_mut(&mut *self.pending));
            for (b, k) in tail.iter_mut().zip(self.pending.iter()) {
                *b ^= *k;
            }
            self.used = tail.len();
        }
        Ok(data.len())
    }
}

impl<KS, Dir, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for StreamCipher<KS, Dir, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN>,
{
    /// The keystream's name.
    const ALG_NAME: &'static str = KS::ALG_NAME;
    /// Wrapping a keystream does not change its strength.
    const MAX_SECURITY_STRENGTH: SecurityStrength = KS::MAX_SECURITY_STRENGTH;
}

impl<KS, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherEncryptor<INIT_DATA_LEN, 0>
    for StreamCipher<KS, Encrypting, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN>,
{
    /// Every input byte produces exactly one output byte.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// Copies `plaintext` into `ciphertext` and works in place there, so the caller's input is left
    /// untouched. The whole of `ciphertext` is zeroized first.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `ciphertext` is shorter than `plaintext`,
    /// checked before anything is consumed.
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        ciphertext.fill(0);
        if ciphertext.len() < plaintext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(plaintext.len()));
        }
        let out = &mut ciphertext[..plaintext.len()];
        out.copy_from_slice(plaintext);
        self.apply(out)?;
        Ok(plaintext.len())
    }

    /// Nothing is held back, so there is nothing to finish.
    fn do_encrypt_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        Ok(([], 0))
    }

    /// A stream cipher never changes the length of its data.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }
}

impl<KS, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize> StreamCipherEncryptor<INIT_DATA_LEN>
    for StreamCipher<KS, Encrypting, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN>,
{
    /// XORs the next `data.len()` keystream bytes into `data`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::DataLimitExceeded`] if the keystream cannot cover the call. Nothing
    /// is consumed in that case; see [`StreamCipher`].
    fn do_encrypt_inplace(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        self.apply(data)
    }
}

impl<KS, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherDecryptor<INIT_DATA_LEN, 0>
    for StreamCipher<KS, Decrypting, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN>,
{
    /// Nothing is held back, so every input byte can be released immediately.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// Copies `ciphertext` into `plaintext` and works in place there, so the caller's input is left
    /// untouched. The whole of `plaintext` is zeroized first.
    ///
    /// # Errors
    /// [`SymmetricCipherError::OutputBufferTooSmall`] if `plaintext` is shorter than `ciphertext`,
    /// checked before anything is consumed.
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        plaintext.fill(0);
        if plaintext.len() < ciphertext.len() {
            return Err(SymmetricCipherError::OutputBufferTooSmall(ciphertext.len()));
        }
        let out = &mut plaintext[..ciphertext.len()];
        out.copy_from_slice(ciphertext);
        self.apply(out)?;
        Ok(ciphertext.len())
    }

    /// Nothing is held back, so there is nothing to finish.
    fn do_decrypt_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        Ok(([], 0))
    }

    /// Exact rather than an upper bound: a stream cipher never changes the length of its data.
    fn decrypt_out_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}

impl<KS, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize> StreamCipherDecryptor<INIT_DATA_LEN>
    for StreamCipher<KS, Decrypting, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN>,
{
    /// The same XOR as encryption.
    ///
    /// # Errors
    /// As [`StreamCipherEncryptor::do_encrypt_inplace`].
    fn do_decrypt_inplace(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        self.apply(data)
    }
}

impl<'k, KS, Dir, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    StreamCipher<KS, Dir, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent<'k>,
{
    /// The `N` of this type's [`SuspendableKeyed<N>`] impl: the version header, the keystream's
    /// state, the pending keystream block and the `used` count as a `u64`. See
    /// [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize =
        LIB_VERSION_LEN + <Self as SuspendableComponent<'k>>::STATE_LEN;
}

/// The suspended state is the keystream's own state followed by the pending keystream block and
/// how much of it is used. The pending block is live keystream, which is why the whole state
/// must be protected and never resumed twice; see [`bouncycastle_utils::suspendable_state`].
impl<'k, KS, Dir, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize> SuspendableComponent<'k>
    for StreamCipher<KS, Dir, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent<'k>,
{
    const STATE_LEN: usize = KS::STATE_LEN + BLOCK_LEN + 8;
    type Key = KS::Key;

    fn write_state(&self, out: &mut [u8]) {
        let (ks, rest) = out.split_at_mut(KS::STATE_LEN);
        self.keystream.write_state(ks);
        let mut w = CursorMut::new(rest);
        w.bytes(&*self.pending);
        w.u64(self.used as u64);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], key: &'k Self::Key) -> Result<Self, SuspendableError> {
        Self::check_shape();
        let (ks, rest) = state.split_at(KS::STATE_LEN);
        let keystream = KS::read_state(ks, key)?;
        let mut r = Cursor::new(rest);
        // Read straight into the `Secret`, so no copy of the keystream block sits on the stack.
        let mut pending: Secret<[u8; BLOCK_LEN]> = Secret::new();
        (*pending).copy_from_slice(r.bytes(BLOCK_LEN));
        // `used` is `0..=BLOCK_LEN`, with `BLOCK_LEN` meaning nothing is pending.
        let used = bounded_usize(r.u64(), BLOCK_LEN)?;
        debug_assert!(r.is_done());
        Ok(Self { keystream, pending, used, _marker: PhantomData })
    }
}

/// `N` must be [`StreamCipher::SUSPENDED_STATE_LEN`]; anything else is a compile error.
impl<'k, KS, Dir, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize, const N: usize>
    SuspendableKeyed<'k, N> for StreamCipher<KS, Dir, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<INIT_DATA_LEN, BLOCK_LEN> + SuspendableComponent<'k>,
{
    type Key = KS::Key;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    /// The state carries no direction: one suspended by the other direction's worker is accepted
    /// and resumes over the same chaining value, which gives wrong output rather than an error.
    /// Only GCM, whose state means different things per direction, refuses the other one.
    fn from_suspended(state: [u8; N], key: &'k Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}
