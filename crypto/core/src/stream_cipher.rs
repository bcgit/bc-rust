//! Stream ciphers built from a [`KeyStream`], and the helpers a stream cipher that cannot be built
//! that way uses for the separate-output half of its API.
//!
//! [`StreamCipher`] turns any [`KeyStream`] into a [`StreamCipherEncryptor`] /
//! [`StreamCipherDecryptor`] pair, and with it the [`SymmetricCipherEncryptor`] /
//! [`SymmetricCipherDecryptor`] supertraits, as a block cipher mode turns an
//! [`ElectronicCodeBook`](crate::traits::ElectronicCodeBook) into a block cipher. A keystream
//! implementor writes the keystream; the nonce, the partly-used block held between calls and the
//! refusal to run past the end of the keystream are written once, here.
//!
//! A mode whose keystream depends on the data, such as CFB, implements the traits itself; the free
//! functions here are the parts of that implementation that are the same for every stream cipher.

use crate::errors::SymmetricCipherError;
use crate::key_material::KeyMaterial;
use crate::security_strength::SecurityStrength;
use crate::traits::{
    Algorithm, KeyStream, RNG, StreamCipherDecryptor, StreamCipherEncryptor,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

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

/// The separate-output `do_update_out` of a stream cipher, over its in-place data method: copies
/// `input` into `output` and applies `in_place` there, so the caller's input is left untouched.
/// Returns `input.len()`, since a stream cipher neither buffers nor changes the length of its data.
///
/// # Errors
/// [`SymmetricCipherError::OutputBufferTooSmall`] if `output` is shorter than `input`, checked
/// before anything is consumed; otherwise whatever `in_place` returns.
pub fn stream_update_out(
    input: &[u8],
    output: &mut [u8],
    in_place: impl FnOnce(&mut [u8]) -> Result<usize, SymmetricCipherError>,
) -> Result<usize, SymmetricCipherError> {
    if output.len() < input.len() {
        return Err(SymmetricCipherError::OutputBufferTooSmall(input.len()));
    }
    let out = &mut output[..input.len()];
    out.copy_from_slice(input);
    in_place(out)?;
    Ok(input.len())
}

/// The `do_final` of a stream cipher: nothing is held back, so there is nothing to finish -- an
/// empty buffer, none of it output, and no padding or tag to check.
///
/// `cargo mutants` reports the `[]` here as a surviving mutant against `[0; 0]` and `[1; 0]`.
/// Those are the same value: a zero-length array has no element to differ in, so the three
/// spellings are indistinguishable and no test can separate them. The mutants that *do* change
/// behaviour -- returning 1 rather than 0 for the data length -- are caught.
pub fn stream_do_final() -> Result<([u8; 0], usize), SymmetricCipherError> {
    Ok(([], 0))
}

/// A stream cipher over any [`KeyStream`], with the direction encoded in the type.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. `R` is the RNG
/// [`do_encrypt_init`](SymmetricCipherEncryptor::do_encrypt_init) draws the init data from, by its
/// [`Default`] -- which for an [`RNG`] is an OS-seeded instance. It is a parameter only because
/// this crate cannot name the library's DRBG; the crate that defines a cipher fixes it in a type
/// alias.
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
/// returns [`SymmetricCipherError::StateError`] and consumes nothing: the check is made up front,
/// against the whole call, so a message is never half-processed before the cipher notices. Past
/// that point the keystream would repeat, which is the two-time-pad failure within one message.
pub struct StreamCipher<
    KS,
    Dir,
    R,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
> where
    KS: KeyStream<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    keystream: KS,
    /// The keystream block currently being consumed. Meaningful only while `used < BLOCK_LEN`.
    pending: Secret<[u8; BLOCK_LEN]>,
    /// Bytes of `pending` already consumed, `0..=BLOCK_LEN`. `BLOCK_LEN` means none is pending
    /// and the next byte needs a fresh keystream block.
    used: usize,
    // `fn() -> R` rather than `R`: the value holds no RNG, so `R` must not affect `Send`/`Sync`.
    _marker: PhantomData<(Dir, fn() -> R)>,
}

impl<KS, Dir, R, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    StreamCipher<KS, Dir, R, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    /// Wraps a keystream that has already been constructed and positioned, such as one that
    /// starts part-way into its counter space (GCM's GCTR starts at `inc32(J0)`).
    ///
    /// # 🚨 Security 🚨
    /// This bypasses init-data generation: the keystream's nonce is whatever it was constructed
    /// with, and the caller is responsible for it never repeating under the key. The
    /// [`SymmetricCipherEncryptor`] constructors are the safe path.
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
    /// [`SymmetricCipherError::StateError`] if the keystream cannot cover the call; nothing is
    /// consumed in that case.
    fn apply(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        let pending_len = BLOCK_LEN - self.used;
        // Saturating: a keystream with no practical limit reports `u64::MAX` blocks.
        let capacity = (pending_len as u64)
            .saturating_add(self.keystream.remaining_blocks().saturating_mul(BLOCK_LEN as u64));
        if data.len() as u64 > capacity {
            return Err(SymmetricCipherError::StateError(
                "keystream exhausted: this call would need more keystream than remains for this \
                 init data, and continuing would repeat keystream",
            ));
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

impl<KS, Dir, R, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for StreamCipher<KS, Dir, R, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    /// The keystream's name.
    const ALG_NAME: &'static str = KS::ALG_NAME;
    /// Wrapping a keystream does not change its strength.
    const MAX_SECURITY_STRENGTH: SecurityStrength = KS::MAX_SECURITY_STRENGTH;
}

impl<KS, R, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherEncryptor<KEY_LEN, INIT_DATA_LEN, 0>
    for StreamCipher<KS, Encrypting, R, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    R: RNG + Default,
{
    /// Begins an encryption flow, drawing the init data from a default-constructed `R`.
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        let mut rng = R::default();
        Self::do_encrypt_init_rng(key, &mut rng)
    }

    /// As [`SymmetricCipherEncryptor::do_encrypt_init`], but draws the init data from `rng`.
    /// Never panics: `INIT_DATA_LEN == 0` is ruled out at compile time; see [`StreamCipher`].
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        Self::check_shape();
        const {
            assert!(
                KS::ENCRYPTION_APPROVED,
                "this keystream is approved for decryption only (KeyStream::ENCRYPTION_APPROVED is false)"
            )
        };
        let mut init_data = [0u8; INIT_DATA_LEN];
        rng.next_bytes_out(&mut init_data)?;
        let keystream = KS::new(key, &init_data)?;
        Ok((Self::from_keystream(keystream), init_data))
    }

    /// Every input byte produces exactly one output byte.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// See [`stream_update_out`].
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        stream_update_out(plaintext, ciphertext, |data| self.apply(data))
    }

    /// See [`stream_do_final`].
    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        stream_do_final()
    }

    /// A stream cipher never changes the length of its data.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }
}

impl<KS, R, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>
    for StreamCipher<KS, Encrypting, R, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
    R: RNG + Default,
{
    /// XORs the next `data.len()` keystream bytes into `data`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if the keystream cannot cover the call. Nothing is
    /// consumed in that case; see [`StreamCipher`].
    fn do_encrypt(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        self.apply(data)
    }
}

impl<KS, R, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherDecryptor<KEY_LEN, INIT_DATA_LEN, 0>
    for StreamCipher<KS, Decrypting, R, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    /// Begins a decryption flow from the init data returned by
    /// [`SymmetricCipherEncryptor::do_encrypt_init`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Self::check_shape();
        Ok(Self::from_keystream(KS::new(key, init_data)?))
    }

    /// Nothing is held back, so every input byte can be released immediately.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// See [`stream_update_out`].
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        stream_update_out(ciphertext, plaintext, |data| self.apply(data))
    }

    /// See [`stream_do_final`].
    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        stream_do_final()
    }

    /// Exact rather than an upper bound: a stream cipher never changes the length of its data.
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}

impl<KS, R, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>
    for StreamCipher<KS, Decrypting, R, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
where
    KS: KeyStream<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    /// The same XOR as encryption.
    ///
    /// # Errors
    /// As [`StreamCipherEncryptor::do_encrypt`].
    fn do_decrypt(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        self.apply(data)
    }
}
