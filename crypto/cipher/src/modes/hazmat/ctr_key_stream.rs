//! The CTR keystream, [`CtrKeyStream`]: a raw [`KeyStream`], used through [`Ctr`].

use crate::modes::ctr::apply_counter_blocks;
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::{ElectronicCodeBook, KeyStream};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{Algorithm, SymmetricCipherKey};
use bouncycastle_utils::suspendable_state::{Cursor, CursorMut, SuspendableComponent};
use core::marker::PhantomData;

// Imports needed for docs
#[allow(unused_imports)]
use crate::modes::Ctr;
#[allow(unused_imports)]
use crate::stream::StreamCipher;
// end of imports needed for docs

/// The CTR keystream `Oj = CIPH_K(Tj)` over any [`ElectronicCodeBook`], with `Tj = N | [j]m`;
/// see the module docs. Use it through [`Ctr`].
///
/// # 🚨 Security Considerations 🚨
/// A raw [`KeyStream`]: constructed directly, it takes the nonce from the caller and does not
/// refuse to run past the counter. See [`KeyStream`]'s security notes and
/// [`bouncycastle_core::hazmat`] for the supported uses.
///
/// # State
///
/// The permutation, the nonce and the next counter value. The nonce and the counter are both
/// public, so they are plain fields; no keystream is kept between calls.
#[derive(Clone)]
pub struct CtrKeyStream<
    P,
    K,
    const KEY_LEN: usize,
    const BLOCK_LEN: usize,
    const INIT_DATA_LEN: usize,
> where
    P: ElectronicCodeBook<K, KEY_LEN, BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
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
    /// Records `K`, which no other field mentions; without it `K` would be an unused parameter.
    _key: PhantomData<K>,
}

impl<P, K, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
    CtrKeyStream<P, K, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<K, KEY_LEN, BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
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
        Self { perm, nonce, next_counter: counter, _key: PhantomData }
    }

    /// The nonce `N` of a suspended keystream, read out of the state [`SuspendableComponent`]
    /// writes without rebuilding the keystream: it is the leading `INIT_DATA_LEN` bytes. For a
    /// composite that needs the nonce before it can afford the key schedule (GCM derives `H` and
    /// the tag mask from it).
    pub(crate) fn nonce_from_state(state: &[u8]) -> [u8; INIT_DATA_LEN] {
        Cursor::new(state).array::<INIT_DATA_LEN>()
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

impl<P, K, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize> Algorithm
    for CtrKeyStream<P, K, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<K, KEY_LEN, BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    /// The underlying permutation's name. The mode is not appended: `&'static str`s cannot be
    /// concatenated in a `const`, and the mode is already in the type.
    const ALG_NAME: &'static str = P::ALG_NAME;
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, K, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
    KeyStream<K, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>
    for CtrKeyStream<P, K, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<K, KEY_LEN, BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    /// Expands the key; the keystream starts at `T1 = N | [0]m`.
    fn new(key: &K, init_data: &[u8; INIT_DATA_LEN]) -> Result<Self, SymmetricCipherError> {
        Self::check_shape();
        let perm = P::new(key.get_key())?;
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

/// The suspended state is the nonce and the next counter value; the permutation is rebuilt from
/// the re-supplied key. See [`bouncycastle_utils::suspendable_state`].
impl<P, K, const KEY_LEN: usize, const BLOCK_LEN: usize, const INIT_DATA_LEN: usize>
    SuspendableComponent for CtrKeyStream<P, K, KEY_LEN, BLOCK_LEN, INIT_DATA_LEN>
where
    P: ElectronicCodeBook<K, KEY_LEN, BLOCK_LEN>,
    K: SymmetricCipherKey<KEY_LEN>,
{
    const STATE_LEN: usize = INIT_DATA_LEN + 8;
    type Key = K;

    fn write_state(&self, out: &mut [u8]) {
        let mut w = CursorMut::new(out);
        w.bytes(&self.nonce);
        w.u64(self.next_counter);
        debug_assert!(w.is_done());
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        Self::check_shape();
        let perm = P::new(key.get_key()).map_err(|_| SuspendableError::InvalidData)?;
        let mut r = Cursor::new(state);
        let nonce = r.array::<INIT_DATA_LEN>();
        // The counter counts to `BLOCK_LIMIT` and stops there (that is the exhausted state, with
        // `remaining_blocks() == 0`); anything past it is not a state this type produces.
        let next_counter = r.u64();
        if next_counter > Self::BLOCK_LIMIT {
            return Err(SuspendableError::InvalidData);
        }
        debug_assert!(r.is_done());
        Ok(Self { perm, nonce, next_counter, _key: PhantomData })
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
    use bouncycastle_core::hazmat::ElectronicCodeBook;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::traits::StreamCipherEncryptor;
    use bouncycastle_core_test_framework::{ToyBlockCipher, ToyCipherKey};

    type ToyKeyStream = CtrKeyStream<ToyBlockCipher, ToyCipherKey, 16, 16, 12>;
    type ToyCtr = Ctr<ToyBlockCipher, Encrypting, ToyCipherKey, 16, 16, 12>;

    fn key() -> KeyMaterial<16> {
        KeyMaterial::<16>::from_bytes_as_type(&[0x5Au8; 16], KeyType::SymmetricCipherKey)
            .expect("a valid 16-byte key")
    }

    /// `start_at(.., 2)` must produce the same keystream as `start` after its first two blocks
    /// (32 bytes) have been discarded. This is what lets GCM's GCTR (SP 800-38D Sec 6.5) begin at
    /// `inc32(J0)`, whose counter field is 2 -- see `gcm.rs`.
    #[test]
    fn start_at_matches_start_after_discarding_blocks() {
        let nonce = [0x11u8; 12];

        let mut from_start = ToyCtr::from_keystream(ToyKeyStream::start(
            ToyBlockCipher::new(&key()).unwrap(),
            nonce,
        ));
        let mut discarded = [0u8; 32];
        from_start.do_encrypt_inplace(&mut discarded).unwrap();

        let mut from_start_at = ToyCtr::from_keystream(ToyKeyStream::start_at(
            ToyBlockCipher::new(&key()).unwrap(),
            nonce,
            2,
        ));

        let mut a = [0x42u8; 48];
        let mut b = a;
        from_start.do_encrypt_inplace(&mut a).unwrap();
        from_start_at.do_encrypt_inplace(&mut b).unwrap();
        assert_eq!(a, b, "start_at(.., 2) must agree with start() past its first two blocks");
    }

    /// The capacity left after starting at counter 2 is exactly `2^32 - 2` blocks -- the SP
    /// 800-38D Sec 5.2.1.1 plaintext length bound (`len(P) <= 2^39 - 256` bits, i.e. `2^32 - 2`
    /// 128-bit blocks) that GCM relies on `Ctr`'s existing "counter exhausted" error to enforce.
    #[test]
    fn start_at_capacity_is_block_limit_minus_the_starting_counter() {
        let ks = ToyKeyStream::start_at(ToyBlockCipher::new(&key()).unwrap(), [0u8; 12], 2);
        assert_eq!(ks.remaining_blocks(), ToyKeyStream::BLOCK_LIMIT - 2);
    }
}
