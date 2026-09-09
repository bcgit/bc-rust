//! The Counter mode of operation (NIST SP 800-38A Sec 6.5).
//!
//! # The specification
//!
//! Sec 6.5 defines CTR against a sequence of counter blocks `T1, T2, ... Tn`. Quoting the
//! equations verbatim:
//!
//! ```text
//! CTR Encryption:  Oj = CIPH_K(Tj)        for j = 1, 2 ... n;
//!                  Cj = Pj XOR Oj         for j = 1, 2 ... n-1;
//!                  C*_n = P*_n XOR MSB_u(On).
//!
//! CTR Decryption:  Oj = CIPH_K(Tj)        for j = 1, 2 ... n;
//!                  Pj = Cj XOR Oj         for j = 1, 2 ... n-1;
//!                  P*_n = C*_n XOR MSB_u(On).
//! ```
//!
//! The cipher never touches the data: it is applied to the counter blocks alone, and the output
//! blocks are XORed with the plaintext. The last block may be partial, and Sec 6.5 says what to do
//! with it -- "the most significant u bits of the last output block are used for the exclusive-OR
//! operation; the remaining b-u bits of the last output block are discarded" -- so unlike CBC there
//! is no alignment requirement anywhere in the mode. [`Ctr`] therefore implements
//! [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`].
//!
//! **Encryption and decryption are the same operation.** Both compute `Oj = CIPH_K(Tj)` and XOR;
//! only the name of the input changes. The two directions are still separate types here, for the
//! same policy reason as in the other modes, and they share one implementation.
//!
//! # Where the counter comes from: the nonce is the init data
//!
//! Sec 6.5 requires that "each block in the sequence is different from every other block", and
//! that this holds "across all of the messages that are encrypted under the given key". Appendix
//! B.2 gives the construction this type uses, its second approach:
//!
//! > The leading b/2 bits (rounding up, if b is odd) of each counter block would be the message
//! > nonce, and the standard incrementing function would be applied to the remaining m bits to
//! > provide an index to the counter blocks for the message. Thus, if N is the message nonce for a
//! > given message, then the jth counter block is given by `Tj = N | [j]m`.
//!
//! So a counter block is a **nonce followed by a counter**, and this type splits the block by the
//! length of its init data: the init data is the nonce, and whatever is left of the block is the
//! counter.
//!
//! ```text
//! INIT_DATA_LEN bytes of nonce | CTR_LEN bytes of counter     (CTR_LEN = BLOCK_LEN - INIT_DATA_LEN)
//! ```
//!
//! For AES that means a 12-byte nonce gives a 4-byte counter, a 13-byte nonce a 3-byte counter, and
//! so on. `CTR_LEN` is capped at **4 bytes** and must be at least 1, both checked at compile time,
//! so for a 16-byte block `INIT_DATA_LEN` is 12, 13, 14 or 15. A longer counter is not useful here:
//! it would raise a per-message limit that is already far beyond any single message, at the cost of
//! nonce bits, which are the scarcer resource.
//!
//! ## The counter starts at zero, not at one
//!
//! B.2's formula is `Tj = N | [j]m` **for j = 1...n**, so read literally its first counter block is
//! `N | 1`. This type instead starts at 0, i.e. `Tj = N | [j - 1]m`, and the choice is deliberate.
//!
//! It is permitted. The normative requirement is Sec 6.5's -- "each block in the sequence is
//! different from every other block" -- which both indexings satisfy; B.2 is presented as one of
//! "Two examples of approaches", and Appendix B closes by saying "This recommendation allows other
//! methods and approaches for achieving the uniqueness property".
//!
//! It is also what the test vectors assume. NIST's ACVP `ACVP-AES-CTR` set gives each case a full
//! initial counter block, and of its 2138 functional cases **1853 end in four zero bytes** and
//! **none end in `00000001`**. Those 1853 are exactly a 12-byte nonce with the counter at zero, so
//! starting at zero makes them directly usable as known-answer tests -- see `acvp_ctr_tests.rs` --
//! and starting at one would leave this mode with no official vector coverage at all. The same
//! choice is what makes a message here identical to one from an implementation handed
//! `nonce || 00000000` as a whole-block IV, which is how CTR is usually driven in practice.
//!
//! One consequence: the counter takes `2^m` values rather than B.2's `n < 2^m`, so a message may be
//! a full `2^m` blocks.
//!
//! # The counter is finite, and running out is an error
//!
//! A `CTR_LEN`-byte counter has `2^(8 * CTR_LEN)` distinct values, so a message can be at most
//! that many blocks: 2^32 blocks (64 GiB) for a 4-byte counter, down to 256 blocks (4 KiB) for a
//! 1-byte one. Appendix B.1 is explicit that this is the bound -- counter blocks "satisfy the
//! uniqueness requirement within the given message provided that `n <= 2^m`" -- and past it the
//! counter would repeat, which for a keystream mode means reusing keystream: the two-time-pad
//! failure, within a single message.
//!
//! So [`Ctr`] **refuses** rather than wraps. A call that would need more keystream than the counter
//! can still supply returns [`SymmetricCipherError::StateError`] and consumes nothing -- the check
//! is made up front, against the whole call, so a message is never half-encrypted before the mode
//! notices. This is the failure the `Result` on the data methods exists for; the other modes in
//! this crate never return `Err` from them.
//!
//! # Everything is parallel
//!
//! Sec 6.5: "In both CTR encryption and CTR decryption, the forward cipher functions can be
//! performed in parallel". Counter blocks depend on nothing but the nonce and the index, so unlike
//! CBC and CFB there is no serial direction at all: **both** directions walk the block-aligned part
//! of the data in fours through [`ElectronicCodeBook::encrypt_4blocks`], then in pairs through
//! [`ElectronicCodeBook::encrypt_2blocks`]. Only the bytes that finish a partially-used keystream
//! block, and the short tail at the end, go one block at a time.
//!
//! Like the rest of CFB and CTR, only the **forward** cipher function is ever used, in both
//! directions, so a permutation that implements only `encrypt_block` works here.
//!
//! # Keystream that outlives a call
//!
//! A call can end part-way through a keystream block, and the remainder of that block is kept for
//! the next call so the caller's chunking is invisible in the output. Those bytes are unused
//! keystream: XORed with nothing, they reveal nothing about the message, but they *are* live
//! keystream for the next bytes of it, so the buffer is held in a `Secret` and zeroized on drop.
//! That is the difference from `Cfb`, whose retained bytes are `CIPH_K` of a public block and are
//! deliberately not wrapped.

use crate::iv::random_iv;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{
    Algorithm, ElectronicCodeBook, RNG, SecurityStrength, StreamCipherDecryptor,
    StreamCipherEncryptor,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_utils::secret::Secret;
use core::marker::PhantomData;

/// CTR mode over any [`ElectronicCodeBook`], with the direction encoded in the type.
///
/// The counter block is the init data (the nonce) followed by a counter filling the rest of the
/// block, so `INIT_DATA_LEN` chooses the counter length; see the module docs. `Dir` is
/// [`Encrypting`] or [`Decrypting`].
///
/// # The counter width is checked at compile time
///
/// The counter must be at least one byte and at most four, so on a 16-byte block the nonce is 12,
/// 13, 14 or 15 bytes. Both bounds are inline `const` assertions in the constructors, so a nonce
/// length outside that range is a **compile** error at the call site rather than a runtime `Err`.
///
/// A nonce as long as the block would leave no counter at all, and could not count:
///
/// ```compile_fail
/// use bouncycastle_aes::AES_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::StreamCipherEncryptor;
/// use bouncycastle_modes::{Ctr, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// // A 16-byte nonce on a 16-byte block leaves a zero-byte counter.
/// let _ = Ctr::<AES_128, Encrypting, 16, 16, 16>::do_encrypt_init(&key);
/// ```
///
/// ...and a nonce shorter than `BLOCK_LEN - 4` would ask for a counter wider than this type
/// supports:
///
/// ```compile_fail
/// use bouncycastle_aes::AES_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::StreamCipherEncryptor;
/// use bouncycastle_modes::{Ctr, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// // An 11-byte nonce would give a 5-byte counter, past the 4-byte cap.
/// let _ = Ctr::<AES_128, Encrypting, 16, 16, 11>::do_encrypt_init(&key);
/// ```
///
/// The permitted lengths all work:
///
/// ```
/// use bouncycastle_aes::AES_128;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::StreamCipherEncryptor;
/// use bouncycastle_modes::{Ctr, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// let _ = Ctr::<AES_128, Encrypting, 16, 16, 12>::do_encrypt_init(&key).unwrap(); // 4-byte counter
/// let _ = Ctr::<AES_128, Encrypting, 16, 16, 15>::do_encrypt_init(&key).unwrap(); // 1-byte counter
/// ```
///
/// # State
///
/// The permutation, the nonce, the next counter value, the current keystream block and how much of
/// it has been used. The nonce and the counter are both public, so they are plain fields; the
/// keystream block is live key material for the bytes not yet consumed, so it is a [`Secret`] and
/// is zeroized on drop.
pub struct Ctr<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    /// `N`: the message nonce, the leading bytes of every counter block.
    nonce: [u8; INIT_DATA_LEN],
    /// The counter of the *next* block to use, as an integer: `Tj = N | [next_counter]m`.
    ///
    /// Held as a `u64` rather than as the counter bytes so that exhaustion is representable. The
    /// counter field itself is at most 4 bytes, so it wraps to zero at `2^m` and a mode that read
    /// its state back out of those bytes could not tell "just started" from "completely used up".
    /// This counts to `BLOCK_LIMIT` and stops there.
    next_counter: u64,
    /// `Oj` for the block currently being consumed. Meaningful only while `used < BLOCK_LEN`.
    keystream: Secret<[u8; BLOCK_LEN]>,
    /// Bytes of `keystream` already consumed, `0..=BLOCK_LEN`. `BLOCK_LEN` means none is pending
    /// and the next byte needs a fresh cipher call.
    used: usize,
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
    Ctr<P, Dir, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Bytes of counter at the end of each block: whatever the nonce leaves.
    const CTR_LEN: usize = BLOCK_LEN - INIT_DATA_LEN;

    /// The number of counter blocks available, `2^(8 * CTR_LEN)`.
    ///
    /// `CTR_LEN <= 4` is asserted at construction, so this is at most `2^32` and cannot overflow
    /// the `u64`.
    const BLOCK_LIMIT: u64 = 1u64 << (8 * Self::CTR_LEN as u64);

    /// The compile-time shape check, run from both constructors.
    ///
    /// A zero-length counter could not count, and this type caps the counter at 4 bytes; see the
    /// module docs. Both are properties of the const parameters, so both are compile errors at the
    /// call site rather than a runtime `Err`.
    #[inline]
    fn check_shape() {
        const {
            assert!(
                INIT_DATA_LEN < BLOCK_LEN,
                "CTR needs at least one byte of counter: the nonce must be shorter than the block"
            );
            assert!(
                BLOCK_LEN - INIT_DATA_LEN <= 4,
                "CTR counter is capped at 4 bytes: the nonce must be at least BLOCK_LEN - 4 bytes"
            );
        };
    }

    /// `T1 = N | [0]m`: the nonce, then a zero counter. No keystream is pending.
    #[inline]
    fn start(perm: P, nonce: [u8; INIT_DATA_LEN]) -> Self {
        Self::check_shape();
        Self {
            perm,
            nonce,
            next_counter: 0,
            keystream: Secret::new(),
            used: BLOCK_LEN,
            _dir: PhantomData,
        }
    }

    /// `Tj = N | [j]m`: the nonce followed by the counter, big-endian, in the trailing `CTR_LEN`
    /// bytes.
    ///
    /// Taking the low `CTR_LEN` bytes of the big-endian `u64` is the `mod 2^m` of Appendix B.1's
    /// standard incrementing function, though the truncation never actually discards anything:
    /// [`Self::check_capacity`] refuses the call before `next_counter` could reach `2^m`.
    #[inline]
    fn counter_block(&self) -> [u8; BLOCK_LEN] {
        let mut t = [0u8; BLOCK_LEN];
        t[..INIT_DATA_LEN].copy_from_slice(&self.nonce);
        let be = self.next_counter.to_be_bytes();
        t[INIT_DATA_LEN..].copy_from_slice(&be[be.len() - Self::CTR_LEN..]);
        t
    }

    /// How many more bytes of keystream this instance can still produce.
    ///
    /// The pending tail of the current block, plus a whole block for every counter value left.
    #[inline]
    fn remaining_capacity(&self) -> u64 {
        let pending = (BLOCK_LEN - self.used) as u64;
        let blocks_left = Self::BLOCK_LIMIT - self.next_counter;
        pending + blocks_left * BLOCK_LEN as u64
    }

    /// Refuses a call that would run past the last counter block, before anything is consumed.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if `len` exceeds what the counter can still cover.
    #[inline]
    fn check_capacity(&self, len: usize) -> Result<(), SymmetricCipherError> {
        if len as u64 > self.remaining_capacity() {
            return Err(SymmetricCipherError::StateError(
                "CTR counter exhausted: this message would need more blocks than the counter has \
                 distinct values, and continuing would repeat keystream",
            ));
        }
        Ok(())
    }

    /// `Oj = CIPH_K(Tj)` into the keystream buffer, then `T` moves on. Only called when the current
    /// block is used up and capacity has already been checked.
    #[inline]
    fn refill(&mut self) {
        let mut block = self.counter_block();
        self.perm.encrypt_block(&mut block);
        (*self.keystream).copy_from_slice(&block);
        self.next_counter += 1;
        self.used = 0;
    }

    /// XORs `data` (shorter than a block, or the tail of a partly-used block) with the keystream,
    /// refilling as it goes. Used for the bytes that finish an open block and for the final tail.
    #[inline]
    fn apply_bytes(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            if self.used == BLOCK_LEN {
                self.refill();
            }
            *byte ^= self.keystream[self.used];
            self.used += 1;
        }
    }

    /// XORs `N` whole blocks with `N` counter blocks encrypted in one batched call.
    ///
    /// The counter blocks are built first -- they depend only on the nonce and the index, not on
    /// the data or on each other's cipher output -- so the `N` forward ciphers are independent.
    /// This is the parallelism Sec 6.5 describes, and it applies to both directions.
    #[inline]
    fn apply_batch<const N: usize>(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]; N],
        batch: impl Fn(&P, &mut [[u8; BLOCK_LEN]; N]),
    ) {
        let mut keystream = [[0u8; BLOCK_LEN]; N];
        for slot in keystream.iter_mut() {
            *slot = self.counter_block();
            self.next_counter += 1;
        }
        batch(&self.perm, &mut keystream);
        for (block, o) in blocks.iter_mut().zip(keystream.iter()) {
            for (b, o) in block.iter_mut().zip(o.iter()) {
                *b ^= *o;
            }
        }
        // The batch consumed whole blocks, so nothing is left pending.
        self.used = BLOCK_LEN;
    }

    /// XORs one whole block at a block boundary.
    #[inline]
    fn apply_one(&mut self, block: &mut [u8; BLOCK_LEN]) {
        let mut o = self.counter_block();
        self.perm.encrypt_block(&mut o);
        self.next_counter += 1;
        for (b, o) in block.iter_mut().zip(o.iter()) {
            *b ^= *o;
        }
        self.used = BLOCK_LEN;
    }

    /// The whole data path, shared by both directions: CTR encryption and decryption are the same
    /// operation (Sec 6.5), so there is one implementation and the direction is only a type.
    ///
    /// Splits into the bytes that finish an already-open keystream block, the whole blocks that
    /// follow, and the short tail. The middle goes through the batch paths; only the two ends go
    /// byte by byte.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if the counter cannot cover the call; nothing is
    /// consumed in that case.
    fn apply(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.check_capacity(data.len())?;

        let head_len = core::cmp::min(BLOCK_LEN - self.used, data.len());
        let (head, rest) = data.split_at_mut(head_len);
        self.apply_bytes(head);

        let (blocks, tail) = rest.as_chunks_mut::<BLOCK_LEN>();
        let (fours, rest_blocks) = blocks.as_chunks_mut::<4>();
        for four in fours.iter_mut() {
            self.apply_batch(four, P::encrypt_4blocks);
        }
        let (pairs, single) = rest_blocks.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.apply_batch(pair, P::encrypt_2blocks);
        }
        for block in single.iter_mut() {
            self.apply_one(block);
        }

        self.apply_bytes(tail);
        Ok(())
    }
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize> Algorithm
    for Ctr<P, Dir, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The underlying permutation's name. The mode is not appended: `&'static str`s cannot be
    /// concatenated in a `const`, and the mode is already in the type.
    const ALG_NAME: &'static str = P::ALG_NAME;
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
    StreamCipherEncryptor<KEY_LEN, INIT_DATA_LEN>
    for Ctr<P, Encrypting, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Begins an encryption flow, generating the nonce from the library's default OS-backed DRBG.
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::do_encrypt_init_rng(key, &mut rng)
    }

    /// As [`StreamCipherEncryptor::do_encrypt_init`], but takes the nonce from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        Self::check_shape();
        let perm = P::new(key)?;
        let nonce = random_iv::<INIT_DATA_LEN>(rng)?;
        Ok((Self::start(perm, nonce), nonce))
    }

    /// Encrypts `data`, of any length, in place: `Cj = Pj XOR CIPH_K(Tj)`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::StateError`] if the counter cannot cover the call. Nothing is
    /// consumed in that case; see the module docs.
    fn do_encrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.apply(data)
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
    StreamCipherDecryptor<KEY_LEN, INIT_DATA_LEN>
    for Ctr<P, Decrypting, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Begins a decryption flow from the nonce returned by
    /// [`StreamCipherEncryptor::do_encrypt_init`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Self::check_shape();
        let perm = P::new(key)?;
        Ok(Self::start(perm, *init_data))
    }

    /// Decrypts `data`, of any length, in place: `Pj = Cj XOR CIPH_K(Tj)`, the same operation as
    /// encryption (Sec 6.5).
    ///
    /// # Errors
    /// As [`StreamCipherEncryptor::do_encrypt`].
    fn do_decrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        self.apply(data)
    }
}
