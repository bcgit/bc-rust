//! The Electronic Codebook mode of operation (NIST SP 800-38A Sec 6.1).
//!
//! **🚨 Security note: 🚨 ECB is not a confidentiality mode for data.** That is why it is under
//! [`hazmat`](crate::modes::hazmat); see [`bouncycastle_core::hazmat`] for the supported uses.
//!
//! "In ECB encryption, the forward cipher function is applied directly and independently to each
//! block of the plaintext. The resulting sequence of output blocks is the ciphertext. In ECB
//! decryption, the inverse cipher function is applied directly and independently to each block of
//! the ciphertext. The resulting sequence of output blocks is the plaintext."
//!
//! # Usage Examples
//!
//! ECB has the same shape with no IV: `encrypt` returns an empty array and `decrypt` takes one.
//! The codebook property that makes it unsuitable for data is visible in the ciphertext:
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_cipher::modes::hazmat::Ecb;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyEcb<Dir> = Ecb<ToyBlockCipher, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let mut data = [0x5Au8; 32]; // two equal blocks
//!
//! let (bytes_written, no_iv): (usize, [u8; 0]) = ToyEcb::<Encrypting>::encrypt_in_place(&key, &mut data).expect("encryption");
//! assert_eq!(no_iv.len(), 0, "ECB mode returns the IV as an empty array");
//! assert_eq!(data[..16], data[16..], "equal plaintext blocks give equal ciphertext blocks");
//!
//! ToyEcb::<Decrypting>::decrypt_in_place(&key, &[], &mut data).expect("decryption");
//! assert_eq!(data, [0x5Au8; 32]);
//! ```
//!
//! # A mode with no state
//!
//! This mode is a fixed permutation determined by the key acting on a single block.
//! There is no IV and no chaining.
//!
//! # Both directions are parallel
//!
//! Sec 6.1: "In ECB encryption and ECB decryption, multiple forward cipher functions and inverse
//! cipher functions can be computed in parallel".
//!
//! To take advantage of this parallelism, this mode batches both directions through the
//! permutation's four-block and pair methods ([`ElectronicCodeBook::encrypt_4blocks`] /
//! [`ElectronicCodeBook::encrypt_2blocks`] and their inverses), which may represent a speed-up over
//! iterating one block at a time, depending on the implementation of the underlying cipher.
//!
//! # Suspending and resuming execution
//!
//! [`Ecb`] implements [`SuspendableKeyed`], so a message in progress can be suspended to a byte
//! array and resumed later with the re-supplied key. The state is empty, since nothing carries over
//! between blocks, and resuming is re-expanding the key; it exists so the padded adapters over ECB
//! can be suspended. The array length is `Ecb::SUSPENDED_STATE_LEN`; see [the crate
//! docs](crate#suspending-and-resuming-execution) for an example.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## ECB is a building-block not a confidentiality mode for data
//!
//! SP 800-38A §6.1:
//!
//! > "In the ECB mode, under a given key, any given plaintext block always gets
//! > encrypted to the same ciphertext block. If this property is undesirable in a particular
//! > application, the ECB mode should not be used."
//!
//! While this _might_ be secure for encrypting plaintext that is cryptographically random,
//! it is certainly not ok for structured data (such as any file format with known and predictable
//! headers), or data with repeated blocks since it becomes trivial for an attacker to build lookup
//! tables of plaintext --> ciphertext pairs under this encryption key. ECB mode also does not prevent
//! an attacker from reordering, duplicating, or deleting blocks within a multi-block ciphertext or
//! between multiple messages encrypted under the same key.
//!
//! As such, ECB is exposed primarily as a building-block for the other, more secure, modes of
//! operation, and also for research and educational purposes.
//!
//! **ECB Mode should not be used in production!**

use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, RNG, SuspendableKeyed,
};
use bouncycastle_utils::suspendable_state::{
    LIB_VERSION_LEN, SuspendableComponent, resume_component, suspend_component,
};
use core::marker::PhantomData;

/// ECB mode over any permutation that impls [`ElectronicCodeBook`], with the direction encoded in the type.
///
/// **Not a confidentiality mode for data**: see the module docs and [`modes`](crate::modes)'s "Security
/// Considerations". Provided for interoperability and test vectors.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`BlockCipherEncryptor`] is implemented only for the
/// former and [`BlockCipherDecryptor`] only for the latter, so an `Ecb<_, Encrypting, _, _>` has no
/// decryption methods at all -- using one in the wrong direction is a compile error rather than a
/// runtime check.
///
/// # State
/// Only the permutation, which owns the key schedule and is responsible for keeping it in a
/// zeroize-on-drop wrapper. Nothing chains from one block to the next, so unlike `Cbc` and `Cfb`
/// there is no block of chaining value: `size_of::<Ecb<P, ..>>() == size_of::<P>()`.
#[derive(Clone)]
pub struct Ecb<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Ecb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The `N` of this type's [`SuspendableKeyed<N>`] impl: the version header alone, since ECB
    /// has no state between blocks. See [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize = LIB_VERSION_LEN;

    /// Expands the key. Both `_init` constructors are this; there is nothing else to set up.
    fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        Ok(Self { perm: P::new(key)?, _dir: PhantomData })
    }
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for Ecb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The underlying permutation's name. The mode is not appended: `&'static str`s cannot be
    /// concatenated in a `const`, and the mode is already in the type.
    const ALG_NAME: &'static str = P::ALG_NAME;
    /// A mode does not change the strength of the underlying cipher. (It does not make ECB
    /// suitable for data either; strength is about the key, not about the codebook property.)
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> BlockCipherEncryptor<KEY_LEN, 0, BLOCK_LEN>
    for Ecb<P, Encrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Expands the key. ECB has no initialization data (SP 800-38A Table D.2 lists the IV column
    /// as "Not applicable"), so the returned init data is the empty array.
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; 0]), SymmetricCipherError> {
        const {
            assert!(
                P::ENCRYPTION_APPROVED,
                "this permutation is approved for decryption only (ElectronicCodeBook::ENCRYPTION_APPROVED is false)"
            )
        };
        Ok((Self::new(key)?, []))
    }

    /// Always panics: ECB generates no init data, so there is nothing for an RNG to do.
    ///
    /// # Panics
    /// Unconditionally, as [`BlockCipherEncryptor::do_encrypt_init_rng`] requires of a mode whose
    /// `INIT_DATA_LEN` is 0. Reaching for the RNG-taking constructor means the caller expects a
    /// randomized mode, and ECB is not one -- SP 800-38A Table D.2 lists its IV column as "Not
    /// applicable" -- so silently ignoring the RNG would leave that mistaken expectation
    /// undisturbed. Use [`do_encrypt_init`](Self::do_encrypt_init), or a mode that has an IV.
    fn do_encrypt_init_rng(
        _key: &KeyMaterial<KEY_LEN>,
        _rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; 0]), SymmetricCipherError> {
        unimplemented!(
            "ECB has no initialization data, so it draws nothing from an RNG: use do_encrypt_init, \
             or a mode with an IV if a randomized ciphertext was wanted"
        )
    }

    /// The implementor hook (the flat `do_encrypt` is provided over it): `Cj = CIPH_K(Pj)` for every
    /// block, in place.
    ///
    /// Sec 6.1 allows the forward cipher functions to "be computed in parallel", so the blocks go
    /// to the permutation in fours, then pairs, then the remaining block singly. `as_chunks_mut`
    /// splits into exactly those shapes with no runtime length check. Never fails: ECB has no
    /// per-initialization data limit.
    fn do_encrypt_blocks(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError> {
        let len = blocks.len() * BLOCK_LEN;
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        for four in fours.iter_mut() {
            self.perm.encrypt_4blocks(four);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.perm.encrypt_2blocks(pair);
        }
        for block in tail.iter_mut() {
            self.perm.encrypt_block(block);
        }
        Ok(len)
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> BlockCipherDecryptor<KEY_LEN, 0, BLOCK_LEN>
    for Ecb<P, Decrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Expands the key. The init data is the empty array [`BlockCipherEncryptor::do_encrypt_init`]
    /// returned; there is nothing in it to use.
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        _init_data: &[u8; 0],
    ) -> Result<Self, SymmetricCipherError> {
        Self::new(key)
    }

    /// The implementor hook (the flat `do_decrypt` is provided over it): `Pj = CIPH^-1_K(Cj)` for
    /// every block, in place -- fours, then pairs, then the remaining block, as on the encrypt
    /// side. Never fails.
    fn do_decrypt_blocks(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError> {
        let len = blocks.len() * BLOCK_LEN;
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        for four in fours.iter_mut() {
            self.perm.decrypt_4blocks(four);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.perm.decrypt_2blocks(pair);
        }
        for block in tail.iter_mut() {
            self.perm.decrypt_block(block);
        }
        Ok(len)
    }
}

/// ECB carries nothing from one block to the next, so its suspended state is empty and resuming
/// is re-expanding the key. It is implemented so that the padded adapters over it, which do hold
/// a partial block, can be suspended. See [`bouncycastle_utils::suspendable_state`].
impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> SuspendableComponent
    for Ecb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    const STATE_LEN: usize = 0;
    type Key = KeyMaterial<KEY_LEN>;

    fn write_state(&self, out: &mut [u8]) {
        debug_assert!(out.is_empty());
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        debug_assert!(state.is_empty());
        Self::new(key).map_err(|_| SuspendableError::InvalidData)
    }
}

/// `N` must be [`Ecb::SUSPENDED_STATE_LEN`]; anything else is a compile error.
impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize, const N: usize> SuspendableKeyed<N>
    for Ecb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    type Key = KeyMaterial<KEY_LEN>;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; N], key: &Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}
