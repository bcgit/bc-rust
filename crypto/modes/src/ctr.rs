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
//! is no alignment requirement anywhere in the mode, and the keystream `O1, O2, ...` does not depend
//! on the data at all. So the mode is a [`KeyStream`], [`CtrKeyStream`], and [`Ctr`] is that
//! keystream wrapped in [`StreamCipher`], which implements [`StreamCipherEncryptor`] /
//! [`StreamCipherDecryptor`] over it.
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
//! So [`Ctr`] **refuses** rather than wraps. [`CtrKeyStream`] reports how many counter values are
//! left, and a call that would need more keystream than that returns
//! [`SymmetricCipherError::StateError`] and consumes nothing -- [`StreamCipher`] makes the check up
//! front, against the whole call, so a message is never half-encrypted before the mode notices. This is the failure the `Result` on the data methods exists for; the other modes in
//! this crate never return `Err` from them.
//!
//! # Everything is parallel
//!
//! Sec 6.5: "In both CTR encryption and CTR decryption, the forward cipher functions can be
//! performed in parallel". Counter blocks depend on nothing but the nonce and the index, so unlike
//! CBC and CFB there is no serial direction at all: **both** directions walk the block-aligned part
//! of the data in fours through [`ElectronicCodeBook::encrypt_4blocks`], then in pairs through
//! [`ElectronicCodeBook::encrypt_2blocks`]. Only a leftover single block, and the keystream block
//! for a short tail at the end, go one block at a time.
//!
//! Like the rest of CFB and CTR, only the **forward** cipher function is ever used, in both
//! directions, so a permutation that implements only `encrypt_block` works here.
//!
//! # Keystream that outlives a call
//!
//! A call can end part-way through a keystream block. [`StreamCipher`] keeps the remainder for the
//! next call, in a `Secret`, so the caller's chunking is invisible in the output. Every transient
//! keystream block [`CtrKeyStream`]'s batch paths produce is held in a `Secret` too, since each is
//! live keystream until it has been XORed in.
//! That is the difference from `Cfb`, whose retained bytes are `CIPH_K` of a public block and are
//! deliberately not wrapped.

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::stream_cipher::StreamCipher;
use bouncycastle_core::traits::{Algorithm, ElectronicCodeBook, KeyStream};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_utils::secret::Secret;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
// end of imports needed for docs

/// CTR mode over any [`ElectronicCodeBook`], with the direction encoded in the type: the
/// [`CtrKeyStream`] wrapped in a [`StreamCipher`].
///
/// The counter block is the init data (the nonce) followed by a counter filling the rest of the
/// block, so `INIT_DATA_LEN` chooses the counter length; see the module docs. `Dir` is
/// [`Encrypting`](crate::Encrypting) or [`Decrypting`](crate::Decrypting).
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
/// use bouncycastle_aes::aes_internal::AES128Internal;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_modes::{Ctr, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// // A 16-byte nonce on a 16-byte block leaves a zero-byte counter.
/// let _ = Ctr::<AES128Internal, Encrypting, 16, 16, 16>::do_encrypt_init(&key);
/// ```
///
/// ...and a nonce shorter than `BLOCK_LEN - 4` would ask for a counter wider than this type
/// supports:
///
/// ```compile_fail
/// use bouncycastle_aes::aes_internal::AES128Internal;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_modes::{Ctr, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// // An 11-byte nonce would give a 5-byte counter, past the 4-byte cap.
/// let _ = Ctr::<AES128Internal, Encrypting, 16, 16, 11>::do_encrypt_init(&key);
/// ```
///
/// The permitted lengths all work:
///
/// ```
/// use bouncycastle_aes::aes_internal::AES128Internal;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::traits::SymmetricCipherEncryptor;
/// use bouncycastle_modes::{Ctr, Encrypting};
///
/// let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
/// let _ = Ctr::<AES128Internal, Encrypting, 16, 16, 12>::do_encrypt_init(&key).unwrap(); // 4-byte counter
/// let _ = Ctr::<AES128Internal, Encrypting, 16, 16, 15>::do_encrypt_init(&key).unwrap(); // 1-byte counter
/// ```
pub type Ctr<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize> =
    StreamCipher<
        CtrKeyStream<P, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>,
        Dir,
        HashDRBG_SHA512,
        KEY_LEN,
        INIT_DATA_LEN,
        BLOCK_LEN,
    >;

/// The CTR keystream `Oj = CIPH_K(Tj)` over any [`ElectronicCodeBook`], with `Tj = N | [j]m`;
/// see the module docs. Use it through [`Ctr`].
///
/// # 🚨 Security 🚨
/// A raw [`KeyStream`]: constructed directly, it takes the nonce from the caller and does not
/// refuse to run past the counter. See [`KeyStream`]'s security notes; it is deliberately not
/// re-exported from the crate root.
///
/// # State
///
/// The permutation, the nonce and the next counter value. The nonce and the counter are both
/// public, so they are plain fields; no keystream is kept between calls.
pub struct CtrKeyStream<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
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
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
    CtrKeyStream<P, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
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

    /// `T1 = N | [0]m`: the nonce, then a zero counter.
    #[inline]
    fn start(perm: P, nonce: [u8; INIT_DATA_LEN]) -> Self {
        Self::start_at(perm, nonce, 0)
    }

    /// As [`start`](Self::start), but the counter of the *next* block is `counter` instead of 0.
    ///
    /// GCM's GCTR (SP 800-38D Sec 6.5) runs the data through this mode starting at `inc32(J0)`,
    /// whose counter field is `2` -- see `gcm.rs`. Crate-private because the public API's contract
    /// is that a message starts at counter 0; only `gcm.rs` needs otherwise.
    #[inline]
    pub(crate) fn start_at(perm: P, nonce: [u8; INIT_DATA_LEN], counter: u64) -> Self {
        Self::check_shape();
        debug_assert!(
            counter < Self::BLOCK_LIMIT,
            "start_at must not be handed an already-exhausted counter"
        );
        Self { perm, nonce, next_counter: counter }
    }

    /// `Tj = N | [j]m`: the nonce followed by the counter `j`, big-endian, in the trailing
    /// `CTR_LEN` bytes.
    ///
    /// Taking the low `CTR_LEN` bytes of the big-endian `u64` is the `mod 2^m` of Appendix B.1's
    /// standard incrementing function, though the truncation never actually discards anything:
    /// [`StreamCipher`] refuses the call before the counter could reach `2^m`.
    #[inline]
    fn counter_block(nonce: &[u8; INIT_DATA_LEN], j: u64) -> [u8; BLOCK_LEN] {
        let mut t = [0u8; BLOCK_LEN];
        t[..INIT_DATA_LEN].copy_from_slice(nonce);
        let be = j.to_be_bytes();
        t[INIT_DATA_LEN..].copy_from_slice(&be[be.len() - Self::CTR_LEN..]);
        t
    }
}

/// XORs `Oj = CIPH_K(Tj)` into `blocks` for the next `blocks.len()` counter values, starting at
/// `*next` and advancing it past them, where `Tj = counter_block(j)`.
///
/// Shared by [`CtrKeyStream`] and CCM's keystream (SP 800-38C Sec 6.1 steps 5-7), which differ
/// only in how a counter block is formatted. Walks the blocks in fours through
/// [`ElectronicCodeBook::encrypt_4blocks`], then pairs, then a single block: the counter blocks
/// depend only on `j`, not on the data or on each other's cipher output, so the forward ciphers in
/// a batch are independent. This is the parallelism SP 800-38A Sec 6.5 describes, and it applies
/// to both directions.
///
/// The keystream scratch is one [`Secret`] per width and per call rather than per batch, so every
/// block of `Oj` is zeroized when this returns.
pub(crate) fn apply_counter_blocks<P, const KEY_LEN: usize, const BLOCK_LEN: usize>(
    perm: &P,
    next: &mut u64,
    counter_block: impl Fn(u64) -> [u8; BLOCK_LEN],
    blocks: &mut [[u8; BLOCK_LEN]],
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    let (fours, rest) = blocks.as_chunks_mut::<4>();
    let mut ks4: Secret<[[u8; BLOCK_LEN]; 4]> = Secret::new();
    for four in fours.iter_mut() {
        apply_batch(perm, next, &counter_block, four, &mut ks4, P::encrypt_4blocks);
    }
    let (pairs, single) = rest.as_chunks_mut::<2>();
    let mut ks2: Secret<[[u8; BLOCK_LEN]; 2]> = Secret::new();
    for pair in pairs.iter_mut() {
        apply_batch(perm, next, &counter_block, pair, &mut ks2, P::encrypt_2blocks);
    }
    let mut ks1: Secret<[[u8; BLOCK_LEN]; 1]> = Secret::new();
    for block in single.iter_mut() {
        apply_batch(perm, next, &counter_block, core::array::from_mut(block), &mut ks1, |p, b| {
            p.encrypt_block(&mut b[0])
        });
    }
}

/// One batch of [`apply_counter_blocks`]: builds `N` counter blocks into `keystream`, encrypts
/// them with one `batch` call, and XORs the result into `blocks`.
#[inline]
fn apply_batch<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const N: usize>(
    perm: &P,
    next: &mut u64,
    counter_block: &impl Fn(u64) -> [u8; BLOCK_LEN],
    blocks: &mut [[u8; BLOCK_LEN]; N],
    keystream: &mut [[u8; BLOCK_LEN]; N],
    batch: impl Fn(&P, &mut [[u8; BLOCK_LEN]; N]),
) where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    for slot in keystream.iter_mut() {
        *slot = counter_block(*next);
        *next += 1;
    }
    batch(perm, keystream);
    for (block, o) in blocks.iter_mut().zip(keystream.iter()) {
        for (b, o) in block.iter_mut().zip(o.iter()) {
            *b ^= *o;
        }
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize> Algorithm
    for CtrKeyStream<P, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
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
    KeyStream<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
    for CtrKeyStream<P, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Expands the key; the keystream starts at `T1 = N | [0]m`.
    fn new(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        Self::check_shape();
        let perm = P::new(key)?;
        Ok(Self::start(perm, *init_data))
    }

    /// A whole block for every counter value left.
    fn remaining_blocks(&self) -> u64 {
        Self::BLOCK_LIMIT - self.next_counter
    }

    /// `Cj = Pj XOR CIPH_K(Tj)` (or `Pj = Cj XOR CIPH_K(Tj)`, the same operation) for the next
    /// `blocks.len()` counter blocks; see `apply_counter_blocks`.
    fn apply_blocks(&mut self, blocks: &mut [[u8; BLOCK_LEN]]) {
        let nonce = &self.nonce;
        apply_counter_blocks(
            &self.perm,
            &mut self.next_counter,
            |j| Self::counter_block(nonce, j),
            blocks,
        );
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for `start_at`, which is `pub(crate)` and so cannot be reached from
    //! `tests/ctr_tests.rs` -- exactly the "high-risk code that cannot be reached through the
    //! public API" case QUALITY_AND_STYLE.md carves out for a unit test here rather than an
    //! integration test.

    use super::*;
    use crate::Encrypting;
    use bouncycastle_aes::aes_internal::AES128Internal;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::traits::{ElectronicCodeBook, StreamCipherEncryptor};

    type ToyKeyStream = CtrKeyStream<AES128Internal, 16, 16, 12>;
    type ToyCtr = Ctr<AES128Internal, Encrypting, 16, 16, 12>;

    fn key() -> KeyMaterial<16> {
        KeyMaterial::<16>::from_bytes_as_type(&[0x5Au8; 16], KeyType::SymmetricCipherKey)
            .expect("a valid AES-128 key")
    }

    /// `start_at(.., 2)` must produce the same keystream as `start` after its first two blocks
    /// (32 bytes) have been discarded. This is what lets GCM's GCTR (SP 800-38D Sec 6.5) begin at
    /// `inc32(J0)`, whose counter field is 2 -- see `gcm.rs`.
    #[test]
    fn start_at_matches_start_after_discarding_blocks() {
        let nonce = [0x11u8; 12];

        let mut from_start = ToyCtr::from_keystream(ToyKeyStream::start(
            AES128Internal::new(&key()).unwrap(),
            nonce,
        ));
        let mut discarded = [0u8; 32];
        from_start.do_encrypt(&mut discarded).unwrap();

        let mut from_start_at = ToyCtr::from_keystream(ToyKeyStream::start_at(
            AES128Internal::new(&key()).unwrap(),
            nonce,
            2,
        ));

        let mut a = [0x42u8; 48];
        let mut b = a;
        from_start.do_encrypt(&mut a).unwrap();
        from_start_at.do_encrypt(&mut b).unwrap();
        assert_eq!(a, b, "start_at(.., 2) must agree with start() past its first two blocks");
    }

    /// The capacity left after starting at counter 2 is exactly `2^32 - 2` blocks -- the SP
    /// 800-38D Sec 5.2.1.1 plaintext length bound (`len(P) <= 2^39 - 256` bits, i.e. `2^32 - 2`
    /// 128-bit blocks) that GCM relies on `Ctr`'s existing "counter exhausted" error to enforce.
    #[test]
    fn start_at_capacity_is_block_limit_minus_the_starting_counter() {
        let ks = ToyKeyStream::start_at(AES128Internal::new(&key()).unwrap(), [0u8; 12], 2);
        assert_eq!(ks.remaining_blocks(), ToyKeyStream::BLOCK_LIMIT - 2);
    }
}
