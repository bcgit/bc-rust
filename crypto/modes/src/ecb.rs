//! The Electronic Codebook mode of operation (NIST SP 800-38A Sec 6.1).
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
//! use bouncycastle_aes::aes_internal::AES128Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_modes::{Decrypting, Ecb, Encrypting};
//!
//! type Aes128Ecb<Dir> = Ecb<AES128Internal, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let mut data = [0x5Au8; 32]; // two equal blocks
//!
//! let (bytes_written, no_iv): (usize, [u8; 0]) = Aes128Ecb::<Encrypting>::encrypt_in_place(&key, &mut data).expect("encryption");
//! assert_eq!(no_iv.len(), 0, "EBC mode returns the IV as an empty array");
//! assert_eq!(data[..16], data[16..], "equal plaintext blocks give equal ciphertext blocks");
//!
//! Aes128Ecb::<Decrypting>::decrypt_in_place(&key, &[], &mut data).expect("decryption");
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

use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook, RNG,
};
use core::marker::PhantomData;

/// ECB mode over any permutation that impls [`ElectronicCodeBook`], with the direction encoded in the type.
///
/// **Not a confidentiality mode for data**: see the module docs and the crate's "Security
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
