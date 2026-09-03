//! The Cipher Feedback mode of operation (NIST SP 800-38A Sec 6.3), full-block segment only.
//!
//! # The specification
//!
//! Sec 6.3 defines CFB against a segment size `s` with `1 <= s <= b`, where `b` is the block size.
//! Quoting the equations verbatim:
//!
//! ```text
//! CFB Encryption:  I1 = IV;
//!                  Ij = LSB_{b-s}(I_{j-1}) | C#_{j-1}   for j = 2 ... n;
//!                  Oj = CIPH_K(Ij)                      for j = 1, 2 ... n;
//!                  C#_j = P#_j XOR MSB_s(Oj)            for j = 1, 2 ... n.
//!
//! CFB Decryption:  I1 = IV;
//!                  Ij = LSB_{b-s}(I_{j-1}) | C#_{j-1}   for j = 2 ... n;
//!                  Oj = CIPH_K(Ij)                      for j = 1, 2 ... n;
//!                  P#_j = C#_j XOR MSB_s(Oj)            for j = 1, 2 ... n.
//! ```
//!
//! # This type is the `s = b` specialisation
//!
//! [`Cfb`] implements **only** `s = b`, the variant Sec 6.3 says is "sometimes incorporated into
//! the name of the mode", i.e. CFB128 for a 128-bit block. That is the only segment size which is
//! block-aligned, and so the only one that fits [`BlockCipherEncryptor`] /
//! [`BlockCipherDecryptor`]. Substituting `s = b` collapses the equations exactly:
//!
//! * `LSB_{b-s}(I_{j-1})` becomes `LSB_0(I_{j-1})`, the empty bit string, so the concatenation
//!   leaves `Ij = C_{j-1}`. Sec 6.3's alternative description agrees: the previous input block
//!   "circularly shift[s] s positions to the left, and then the ciphertext segment replaces the s
//!   least significant bits of the result" -- shifting a whole block by its own width and replacing
//!   every bit of it is just assignment.
//! * `MSB_s(Oj)` becomes `MSB_b(Oj)`, which is `Oj`. No part of the output block is discarded, so
//!   there are no wasted cipher calls: one forward cipher per block, the same as CBC.
//!
//! leaving
//!
//! ```text
//! I1 = IV;  Ij = C_{j-1} (j >= 2);  Oj = CIPH_K(Ij);  Cj = Pj XOR Oj  /  Pj = Cj XOR Oj
//! ```
//!
//! As in `Cbc`, the `j = 1` and `j >= 2` cases differ only in what gets fed to the cipher, so a
//! single `chain` field holds `Ij` -- the IV to start with, then each ciphertext block as it is
//! produced or consumed. That is why no code below special-cases the first block.
//!
//! CFB1 and CFB8 (the `s = 1` and `s = 8` variants, which SP 800-38A Appendix F.3 also gives
//! vectors for) are deliberately **not** here: they are not block-aligned, so they belong to a
//! `StreamCipher`-shaped API rather than this one.
//!
//! # Decryption uses the *forward* cipher function
//!
//! This is the thing about CFB that surprises a reader used to CBC: both directions apply
//! `CIPH_K`. Sec 6.3 is explicit -- "In CFB decryption, the IV is the first input block, and each
//! successive input block is formed as in CFB encryption [...] The *forward cipher* function is
//! applied to each input block to produce the output blocks."
//!
//! So [`Cfb<P, Decrypting, ..>`](Cfb) never calls [`BlockPermutation::decrypt_block`] or
//! [`BlockPermutation::decrypt_blocks2`]. A permutation could implement only the forward direction
//! and still work here; `cfb_tests.rs` pins that with a toy whose inverse panics. The mode XORs a
//! keystream in both directions, and the two directions differ only in which of the two buffers
//! becomes the next chaining value.
//!
//! # Parallel decryption
//!
//! Sec 6.3: "In CFB encryption, like CBC encryption, the input block to each forward cipher
//! function (except the first) depends on the result of the previous forward cipher function;
//! therefore, multiple forward cipher operations cannot be performed in parallel. In CFB
//! decryption, the required forward cipher operations can be performed in parallel if the input
//! blocks are first constructed (in series) from the IV and the ciphertext."
//!
//! Constructing them "in series" is trivial here: with `s = b` the input blocks *are* the IV
//! followed by the ciphertext blocks, already in hand. Decryption therefore walks the ciphertext in
//! pairs through [`BlockPermutation::encrypt_blocks2`], which a bit-sliced engine computes for
//! barely more than the cost of one block. Encryption cannot, and does not.

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

/// CFB mode over any [`BlockPermutation`], with the direction encoded in the type.
///
/// The segment size is the full block (`s = b`, i.e. CFB128 for AES); see the module docs for why
/// the other segment sizes are out of scope.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`BlockCipherEncryptor`] is implemented only for the
/// former and [`BlockCipherDecryptor`] only for the latter, so a `Cfb<_, Encrypting, _, _>` has no
/// decryption methods at all -- using one in the wrong direction is a compile error rather than a
/// runtime check.
///
/// The initialization data is one block, so `INIT_DATA_LEN == BLOCK_LEN`.
///
/// # State
///
/// The same two fields as `Cbc`, and the same size: the permutation (which owns the key schedule,
/// and is responsible for keeping it in a zeroize-on-drop wrapper) and one block holding `Ij`. `Ij`
/// is an IV or a ciphertext block, both of which are public, so it is deliberately not wrapped in a
/// `Secret`.
///
/// Note what is *not* stored: the output block `Oj`. It is recomputed from `chain` on each call and
/// lives only in a local, so no keystream outlives the call that used it.
pub struct Cfb<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    /// `Ij`: the IV, then `C_{j-1}`. See the module docs on why there is only one field for both.
    chain: [u8; BLOCK_LEN],
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Cfb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    /// `Oj = CIPH_K(Ij)`, the keystream block for the current position.
    ///
    /// The forward cipher function, in both directions -- see the module docs.
    #[inline]
    fn keystream(&self) -> [u8; BLOCK_LEN] {
        let mut o = self.chain;
        self.perm.encrypt_block(&mut o);
        o
    }

    /// `Cj = Pj XOR Oj`, then `Cj` becomes the next input block.
    #[inline]
    fn encrypt_one(&mut self, plaintext: &[u8; BLOCK_LEN], ciphertext: &mut [u8; BLOCK_LEN]) {
        let o = self.keystream();
        for (out, (p, o)) in ciphertext.iter_mut().zip(plaintext.iter().zip(o.iter())) {
            *out = *p ^ *o;
        }
        // I_{j+1} = Cj. Serial: this is the input to the next cipher call.
        self.chain = *ciphertext;
    }

    /// `Pj = Cj XOR Oj`, then `Cj` -- the *ciphertext*, not the recovered plaintext -- becomes the
    /// next input block.
    #[inline]
    fn decrypt_one(&mut self, ciphertext: &[u8; BLOCK_LEN], plaintext: &mut [u8; BLOCK_LEN]) {
        let o = self.keystream();
        for (out, (c, o)) in plaintext.iter_mut().zip(ciphertext.iter().zip(o.iter())) {
            *out = *c ^ *o;
        }
        // `I_{j+1} = C#_j` of the spec equations: the ciphertext segment is what is fed back.
        // Feeding back the plaintext instead would still decrypt the first block correctly and
        // nothing after it, which is why `cfb_tests.rs` checks exactly that.
        self.chain = *ciphertext;
    }

    /// Decrypts two consecutive blocks with one [`BlockPermutation::encrypt_blocks2`] call.
    ///
    /// Writing the pair as `Cj, Cj+1` with `Ij` the incoming chaining value, the `s = b` equations
    /// give
    ///
    /// ```text
    /// Ij   = chain        Oj   = CIPH_K(Ij)     Pj   = Cj   XOR Oj
    /// Ij+1 = Cj           Oj+1 = CIPH_K(Ij+1)   Pj+1 = Cj+1 XOR Oj+1
    /// ```
    ///
    /// Both input blocks are known before either cipher call -- `Ij` is already held and `Ij+1` is
    /// just `Cj`, which the caller supplied -- so the two forward ciphers are independent and
    /// computing them together changes nothing. This is precisely the parallelism Sec 6.3 describes,
    /// with the input blocks "first constructed (in series) from the IV and the ciphertext".
    #[inline]
    fn decrypt_pair(
        &mut self,
        ciphertext: &[[u8; BLOCK_LEN]; 2],
        plaintext: &mut [[u8; BLOCK_LEN]; 2],
    ) {
        // The two input blocks, constructed in series: Ij (already held) and Ij+1 (= Cj).
        let mut o = [self.chain, ciphertext[0]];
        self.perm.encrypt_blocks2(&mut o);

        for ((out, c), o) in plaintext.iter_mut().zip(ciphertext.iter()).zip(o.iter()) {
            for ((out, c), o) in out.iter_mut().zip(c.iter()).zip(o.iter()) {
                *out = *c ^ *o;
            }
        }

        // I_{j+2} = Cj+1.
        self.chain = ciphertext[1];
    }
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> BlockCipher
    for Cfb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = <P as BlockCipher>::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    BlockCipherEncryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN> for Cfb<P, Encrypting, KEY_LEN, BLOCK_LEN>
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
        // `I1 = IV`.
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((Self { perm, chain: iv, _dir: PhantomData }, iv))
    }

    /// The implementor hook (the flat `do_encrypt[_out]` are provided over it).
    ///
    /// Strictly serial: `Oj+1 = CIPH_K(Cj)` and `Cj` is the *output* of the previous cipher call, so
    /// there is no pair path here. See the module docs.
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
    BlockCipherDecryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN> for Cfb<P, Decrypting, KEY_LEN, BLOCK_LEN>
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
        // `I1 = IV`, exactly as on the encrypt side.
        Ok(Self { perm, chain: *init_data, _dir: PhantomData })
    }

    /// The implementor hook (the flat `do_decrypt[_out]` are provided over it).
    ///
    /// Walks the input in pairs so the permutation's two-block *forward* path is used, with an
    /// at-most-one block remainder for odd `N`. `as_chunks` splits into exactly that shape with no
    /// runtime length check and no indexing arithmetic; `N` is a compile-time constant, so for even
    /// `N` the tail loop is empty and for `N = 1` the pair loop is.
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
