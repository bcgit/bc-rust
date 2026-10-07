//! The [`KeyStream`] trait: a keyed keystream generator.

use crate::errors::SymmetricCipherError;
use crate::traits::{Algorithm, SymmetricCipherKey};

// Imports needed for docs
#[allow(unused_imports)]
use crate::hazmat::ElectronicCodeBook;
#[allow(unused_imports)]
use crate::key_material::KeyType;
#[allow(unused_imports)]
use crate::traits::{BlockCipherEncryptor, StreamCipherDecryptor, StreamCipherEncryptor};
// end of imports needed for docs

/// A keyed keystream generator: the raw primitive under a stream cipher, as
/// [`ElectronicCodeBook`] is the raw primitive under a block cipher mode.
///
/// It is constructed from a key and init data and XORs successive keystream blocks into whatever
/// it is handed. It has no direction and no init-data policy: generating the nonce, buffering a
/// partly-used block between calls, and refusing a call that would run past the end of the
/// keystream all belong to `bouncycastle_cipher::stream::StreamCipher`, which turns any
/// `KeyStream` into a [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`] pair.
///
/// Only a keystream that is independent of the data fits: CTR does, CFB does not, since its next
/// keystream block is the encryption of the last ciphertext block.
///
/// # 🚨 Security Considerations 🚨
/// [`KeyStream::new`] takes the init data from the caller, so nothing stops a caller reusing a
/// nonce under a key -- which repeats the keystream and reveals the XOR of the two plaintexts --
/// and nothing stops it running past [`KeyStream::remaining_blocks`]. `StreamCipher` generates
/// the init data and enforces the limit; use it. See the [module docs](crate::hazmat) for the
/// supported uses of the raw trait.
///
/// Implementors hold the key in a zeroize-on-drop wrapper, as for [`ElectronicCodeBook`]. Any
/// keystream they produce into scratch space of their own is live key material until it has been
/// XORed in, and gets the same treatment.
pub trait KeyStream<
    K: SymmetricCipherKey<KEY_LEN>,
    const KEY_LEN: usize,
    const INIT_DATA_LEN: usize,
    const BLOCK_LEN: usize,
>: Algorithm + Sized
{
    /// Expands the key and positions the keystream at its first block for `init_data`.
    ///
    /// # Errors
    /// Rejects a key whose [`KeyType`] is not [`KeyType::SymmetricCipherKey`], and one whose
    /// security strength is below [`Algorithm::MAX_SECURITY_STRENGTH`], both as a
    /// [`SymmetricCipherError::KeyMaterialError`].
    fn new(key: &K, init_data: &[u8; INIT_DATA_LEN]) -> Result<Self, SymmetricCipherError>;

    /// How many more keystream blocks this value can produce before its keystream would repeat.
    /// A keystream with no practical limit returns `u64::MAX`.
    fn remaining_blocks(&self) -> u64;

    /// XORs the next `blocks.len()` keystream blocks into `blocks`, in place, and advances past
    /// them. A sequence of calls is equivalent to one call over the concatenation; how to batch
    /// the blocks is the implementor's decision, as for
    /// [`BlockCipherEncryptor::do_encrypt_blocks_inplace`].
    ///
    /// Infallible because the caller has already checked `blocks.len()` against
    /// [`Self::remaining_blocks`]. Asking for more is a programmer error, and the implementor may
    /// panic or repeat keystream.
    fn apply_blocks(&mut self, blocks: &mut [[u8; BLOCK_LEN]]);
}
