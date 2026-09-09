//! The Electronic Codebook mode of operation (NIST SP 800-38A Sec 6.1).
//!
//! # The specification
//!
//! Sec 6.1 defines the mode in one equation each way, quoted verbatim:
//!
//! ```text
//! ECB Encryption:  Cj = CIPH_K(Pj)      for j = 1 ... n.
//! ECB Decryption:  Pj = CIPH^-1_K(Cj)   for j = 1 ... n.
//! ```
//!
//! "In ECB encryption, the forward cipher function is applied directly and independently to each
//! block of the plaintext. The resulting sequence of output blocks is the ciphertext. In ECB
//! decryption, the inverse cipher function is applied directly and independently to each block of
//! the ciphertext. The resulting sequence of output blocks is the plaintext."
//!
//! # A mode with no state
//!
//! There is no IV and no chaining: the mode *is* the keyed permutation applied block by block,
//! which is why the permutation trait itself is named [`ElectronicCodeBook`]. What this type adds is
//! the [`BlockCipherEncryptor`] / [`BlockCipherDecryptor`] shape shared with `Cbc` -- the direction
//! in the type, the streaming and one-shot methods with their compile-time length checks, and the
//! batching -- so ECB can stand wherever the other block modes can, including under the padding
//! layer and behind the CLI. (`Cfb` and `Cfb8` are stream ciphers and implement the stream traits
//! instead.) Its `INIT_DATA_LEN` is 0: [`BlockCipherEncryptor::do_encrypt_init`]
//! returns an empty array and draws nothing from the RNG, and
//! [`BlockCipherDecryptor::do_decrypt_init`] takes an empty one.
//!
//! # Why it is here at all
//!
//! Sec 6.1: "In the ECB mode, under a given key, any given plaintext block always gets encrypted to
//! the same ciphertext block. If this property is undesirable in a particular application, the ECB
//! mode should not be used." It is undesirable in nearly every application -- equal plaintext blocks
//! give equal ciphertext blocks, so the structure of the plaintext shows through the ciphertext, and
//! blocks can be reordered, repeated or removed without anything to detect it. ECB is provided for
//! interoperability with systems and specifications that use it, and for driving test vectors; it is
//! not a way to encrypt data. See the crate docs, "Security Considerations".
//!
//! # Both directions are parallel
//!
//! Sec 6.1: "In ECB encryption and ECB decryption, multiple forward cipher functions and inverse
//! cipher functions can be computed in parallel." Unlike CBC and CFB, whose encryption is serial,
//! both directions here batch through the permutation's eight-block and pair methods
//! ([`ElectronicCodeBook::encrypt_8blocks`] / [`ElectronicCodeBook::encrypt_2blocks`] and their
//! inverses), then finish the remaining block singly.

use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, ElectronicCodeBook, RNG,
    SecurityStrength,
};
use core::marker::PhantomData;

/// ECB mode over any [`ElectronicCodeBook`], with the direction encoded in the type.
///
/// **Not a confidentiality mode for data**: see the module docs and the crate's "Security
/// Considerations". Provided for interoperability and test vectors.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`BlockCipherEncryptor`] is implemented only for the
/// former and [`BlockCipherDecryptor`] only for the latter, so an `Ecb<_, Encrypting, _, _>` has no
/// decryption methods at all -- using one in the wrong direction is a compile error rather than a
/// runtime check.
///
/// There is no initialization data, so `INIT_DATA_LEN == 0`.
///
/// # State
///
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

    /// As [`BlockCipherEncryptor::do_encrypt_init`]. Nothing is drawn from `rng`: there is no IV to
    /// generate, so this exists only to satisfy the trait and is identical to the plain constructor.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        _rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; 0]), SymmetricCipherError> {
        Self::do_encrypt_init(key)
    }

    /// The implementor hook (the flat `do_encrypt` is provided over it): `Cj = CIPH_K(Pj)` for every
    /// block, in place.
    ///
    /// Sec 6.1 allows the forward cipher functions to "be computed in parallel", so the blocks go
    /// to the permutation in eights, then pairs, then the remaining block singly. `as_chunks_mut`
    /// splits into exactly those shapes with no runtime length check. Never fails: ECB has no
    /// per-initialization data limit.
    fn do_encrypt_blocks(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<(), SymmetricCipherError> {
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        for eight in eights.iter_mut() {
            self.perm.encrypt_8blocks(eight);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.perm.encrypt_2blocks(pair);
        }
        for block in tail.iter_mut() {
            self.perm.encrypt_block(block);
        }
        Ok(())
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
    /// every block, in place -- eights, then pairs, then the remaining block, as on the encrypt
    /// side. Never fails.
    fn do_decrypt_blocks(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<(), SymmetricCipherError> {
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        for eight in eights.iter_mut() {
            self.perm.decrypt_8blocks(eight);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.perm.decrypt_2blocks(pair);
        }
        for block in tail.iter_mut() {
            self.perm.decrypt_block(block);
        }
        Ok(())
    }
}
