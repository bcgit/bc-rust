//! The Cipher Block Chaining mode of operation (NIST SP 800-38A Sec 6.2).
//!
//! # The specification
//!
//! SP 800-38A Sec 6.2 defines the mode as, quoting verbatim:
//!
//! ```text
//! CBC Encryption:  C1 = CIPH_K(P1 XOR IV);
//!                  Cj = CIPH_K(Pj XOR Cj-1)      for j = 2 ... n.
//!
//! CBC Decryption:  P1 = CIPH^-1_K(C1) XOR IV;
//!                  Pj = CIPH^-1_K(Cj) XOR Cj-1   for j = 2 ... n.
//! ```
//!
//! The `j = 1` and `j >= 2` cases differ only in that the first one uses the IV where the others
//! use the previous ciphertext block. So this implementation keeps a single `chain` field holding
//! "whatever gets XORed next", initialised to the IV and replaced by each ciphertext block as it
//! is produced or consumed. That is the equivalence being used, and it is why there is no special
//! case for the first block anywhere below.
//!
//! # Parallel decryption
//!
//! Sec 6.2 notes that in CBC decryption "the input blocks for the inverse cipher function, i.e.,
//! the ciphertext blocks, are immediately available, so that multiple inverse cipher operations can
//! be performed in parallel", whereas in encryption "the input block to each forward cipher
//! operation (except the first) depends on the result of the previous forward cipher operation, so
//! the forward cipher operations cannot be performed in parallel".
//!
//! This implementation uses that: decryption walks the ciphertext two blocks at a time and hands
//! both to [`BlockPermutation::decrypt_blocks2`], which a bit-sliced engine computes for barely
//! more than the cost of one block. Encryption cannot, and does not.

use crate::iv::random_iv;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{
    BlockCipher, BlockCipherDecryptor, BlockCipherEncryptor, BlockPermutation, RNG,
    SecurityStrength,
};
use bouncycastle_rng::HashDRBG_SHA512;
use core::marker::PhantomData;

/// CBC mode over any [`BlockPermutation`], with the direction encoded in the type.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`BlockCipherEncryptor`] is implemented only for the
/// former and [`BlockCipherDecryptor`] only for the latter, so a `Cbc<_, Encrypting, _, _>` has no
/// decryption methods at all -- using one in the wrong direction is a compile error rather than a
/// runtime check.
///
/// The initialization data is one block, so `INIT_DATA_LEN == BLOCK_LEN`.
///
/// # State
///
/// Two fields: the permutation (which owns the key schedule, and is responsible for keeping it in
/// a zeroize-on-drop wrapper) and one block of chaining value. The chaining value is an IV or a
/// ciphertext block, both of which are public, so it is deliberately not wrapped in a `Secret`.
pub struct Cbc<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    /// `Cj-1`, initialised to the IV. See the module docs on why there is only one field for both.
    chain: [u8; BLOCK_LEN],
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Cbc<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    /// `Cj = CIPH_K(Pj XOR Cj-1)`, then `Cj` becomes the next chaining value.
    #[inline]
    fn encrypt_one(&mut self, plaintext: &[u8; BLOCK_LEN], ciphertext: &mut [u8; BLOCK_LEN]) {
        for (out, (p, chain)) in ciphertext.iter_mut().zip(plaintext.iter().zip(self.chain.iter()))
        {
            *out = *p ^ *chain;
        }
        self.perm.encrypt_block(ciphertext);
        self.chain = *ciphertext;
    }

    /// `Pj = CIPH^-1_K(Cj) XOR Cj-1`, then `Cj` becomes the next chaining value.
    #[inline]
    fn decrypt_one(&mut self, ciphertext: &[u8; BLOCK_LEN], plaintext: &mut [u8; BLOCK_LEN]) {
        *plaintext = *ciphertext;
        self.perm.decrypt_block(plaintext);
        for (out, chain) in plaintext.iter_mut().zip(self.chain.iter()) {
            *out ^= *chain;
        }
        self.chain = *ciphertext;
    }

    /// Decrypts two consecutive blocks with one [`BlockPermutation::decrypt_blocks2`] call.
    ///
    /// Writing the pair as `Cj, Cj+1` with `Cj-1` the incoming chaining value, Sec 6.2 gives
    ///
    /// ```text
    /// Pj   = CIPH^-1_K(Cj)   XOR Cj-1
    /// Pj+1 = CIPH^-1_K(Cj+1) XOR Cj
    /// ```
    ///
    /// Neither inverse cipher depends on the other's *output* -- only on ciphertext, which is
    /// already in hand -- so computing them together changes nothing. The two XOR operands do
    /// differ, and the second one is `Cj`, so both are read out of `ciphertext` before the
    /// chaining value is advanced to `Cj+1`.
    #[inline]
    fn decrypt_pair(
        &mut self,
        ciphertext: &[[u8; BLOCK_LEN]; 2],
        plaintext: &mut [[u8; BLOCK_LEN]; 2],
    ) {
        *plaintext = *ciphertext;
        self.perm.decrypt_blocks2(plaintext);

        let (first, rest) = plaintext.split_at_mut(1);
        for (out, chain) in first[0].iter_mut().zip(self.chain.iter()) {
            *out ^= *chain; // XOR Cj-1
        }
        for (out, prev) in rest[0].iter_mut().zip(ciphertext[0].iter()) {
            *out ^= *prev; // XOR Cj
        }

        self.chain = ciphertext[1];
    }
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> BlockCipher
    for Cbc<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = <P as BlockCipher>::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    BlockCipherEncryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN> for Cbc<P, Encrypting, KEY_LEN, BLOCK_LEN>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    /// Begins an encryption flow, generating the IV from the library's default OS-backed DRBG.
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; BLOCK_LEN]), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::do_encrypt_init_rng(key, &mut rng)
    }

    /// As [`BlockCipherEncryptor::do_encrypt_init`], but takes the IV from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; BLOCK_LEN]), SymmetricCipherError> {
        let perm = P::new(key)?;
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((Self { perm, chain: iv, _dir: PhantomData }, iv))
    }

    /// The implementor hook (the flat `do_encrypt[_out]` are provided over it).
    ///
    /// Strictly serial: `Cj` is the input to block `j + 1`, so there is no pair path here. See the
    /// module docs.
    fn do_encrypt_blocks_out<const N: usize>(
        &mut self,
        plaintext: &[[u8; BLOCK_LEN]; N],
        ciphertext: &mut [[u8; BLOCK_LEN]; N],
    ) -> Result<usize, SymmetricCipherError> {
        for (p, c) in plaintext.iter().zip(ciphertext.iter_mut()) {
            self.encrypt_one(p, c);
        }
        Ok(N * BLOCK_LEN)
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    BlockCipherDecryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN> for Cbc<P, Decrypting, KEY_LEN, BLOCK_LEN>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    /// Begins a decryption flow from the IV returned by
    /// [`BlockCipherEncryptor::do_encrypt_init`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; BLOCK_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        let perm = P::new(key)?;
        Ok(Self { perm, chain: *init_data, _dir: PhantomData })
    }

    /// The implementor hook (the flat `do_decrypt[_out]` are provided over it).
    ///
    /// Walks the input in pairs so the permutation's two-block path is used, with an at-most-one
    /// block remainder for odd `N`. `as_chunks` splits into exactly that shape with no runtime
    /// length check and no indexing arithmetic; `N` is a compile-time constant, so for even `N` the
    /// tail loop is empty and for `N = 1` the pair loop is.
    fn do_decrypt_blocks_out<const N: usize>(
        &mut self,
        ciphertext: &[[u8; BLOCK_LEN]; N],
        plaintext: &mut [[u8; BLOCK_LEN]; N],
    ) -> Result<usize, SymmetricCipherError> {
        let (ct_pairs, ct_tail) = ciphertext.as_chunks::<2>();
        let (pt_pairs, pt_tail) = plaintext.as_chunks_mut::<2>();

        for (ct_pair, pt_pair) in ct_pairs.iter().zip(pt_pairs.iter_mut()) {
            self.decrypt_pair(ct_pair, pt_pair);
        }
        for (c, p) in ct_tail.iter().zip(pt_tail.iter_mut()) {
            self.decrypt_one(c, p);
        }

        Ok(N * BLOCK_LEN)
    }
}
