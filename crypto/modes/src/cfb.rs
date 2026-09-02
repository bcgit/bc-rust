//! The Cipher Feedback mode of operation (NIST SP 800-38A Sec 6.3), full-block segment only.
//!
//! # The specification
//!
//! Sec 6.3 defines CFB with a segment size parameter `s`, "such that 1 <= s <= b", where `b` is the
//! block size. Quoting the general definition verbatim:
//!
//! ```text
//! CFB Encryption:  I1 = IV;
//!                  Ij = LSB_{b-s}(Ij-1) | C#j-1     for j = 2 ... n;
//!                  Oj = CIPH_K(Ij)                  for j = 1, 2 ... n;
//!                  C#j = P#j XOR MSB_s(Oj)          for j = 1, 2 ... n.
//!
//! CFB Decryption:  I1 = IV;
//!                  Ij = LSB_{b-s}(Ij-1) | C#j-1     for j = 2 ... n;
//!                  Oj = CIPH_K(Ij)                  for j = 1, 2 ... n;
//!                  P#j = C#j XOR MSB_s(Oj)          for j = 1, 2 ... n.
//! ```
//!
//! # This implementation is `s = b` only
//!
//! [`Cfb`] implements the **full-block segment** case, `s = b` -- "the 128-bit CFB mode" in Sec
//! 6.3's naming, for a 128-bit block. That is the only value of `s` that is block-aligned, and so
//! the only one that fits the `BlockCipherEncryptor` / `BlockCipherDecryptor` contract. See the
//! crate docs for why CFB1 and CFB8 are out of scope.
//!
//! Substituting `s = b` collapses the equations exactly:
//!
//! * `LSB_{b-s}(Ij-1)` is `LSB_0(...)`, the empty bit string, so the concatenation
//!   `LSB_0(Ij-1) | C#j-1` is just `C#j-1`. Hence `Ij = Cj-1`.
//! * `MSB_s(Oj)` is `MSB_b(Oj)`, the whole output block, so `MSB_b(Oj) = Oj`.
//!
//! leaving
//!
//! ```text
//! I1 = IV;  Ij = Cj-1  (j >= 2);  Oj = CIPH_K(Ij);  Cj = Pj XOR Oj  /  Pj = Cj XOR Oj
//! ```
//!
//! Sec 6.3's prose description of the feedback agrees: "the bits of the first input block
//! circularly shift s positions to the left, and then the ciphertext segment replaces the s least
//! significant bits of the result". At `s = b` a circular shift by `b` is the identity and the
//! ciphertext replaces all `b` bits, giving `Ij = Cj-1` again.
//!
//! As in [`crate::Cbc`], the `j = 1` and `j >= 2` cases differ only in what `Ij` is, so a single
//! `chain` field holds "the next input block", initialised to the IV and replaced by each
//! ciphertext block. There is no special case for the first block below.
//!
//! # Both directions use the *forward* cipher function
//!
//! This is the thing to notice. In the equations above, decryption computes `Oj = CIPH_K(Ij)` --
//! `CIPH_K`, not `CIPH^-1_K`. Sec 6.3 says so in prose too: "The *forward cipher* function is
//! applied to each input block to produce the output blocks. The s most significant bits of the
//! output blocks are exclusive-ORed with the corresponding ciphertext segments to recover the
//! plaintext segments."
//!
//! So `Cfb<P, Decrypting, ..>` never calls [`BlockPermutation::decrypt_block`] or
//! [`BlockPermutation::decrypt_blocks2`], and a permutation with no working inverse at all would
//! still work in both directions of this mode. That is asserted directly by
//! `cfb_decryption_never_calls_the_inverse_cipher` in `tests/cfb_tests.rs`, which runs CFB over a
//! permutation whose `decrypt_block` panics.
//!
//! It also means CFB, unlike CBC, needs only half of a block cipher -- which is part of why the
//! mode is attractive for ciphers whose inverse is expensive.
//!
//! # Parallel decryption
//!
//! Sec 6.3: "In CFB encryption, like CBC encryption, the input block to each forward cipher
//! function (except the first) depends on the result of the previous forward cipher function;
//! therefore, multiple forward cipher operations cannot be performed in parallel. In CFB
//! decryption, the required forward cipher operations can be performed in parallel if the input
//! blocks are first constructed (in series) from the IV and the ciphertext."
//!
//! Decryption exploits that: the input blocks are `Ij = Cj-1`, all of which are ciphertext already
//! in hand, so a pair of them can go to [`BlockPermutation::encrypt_blocks2`] in one call. The
//! "constructed in series" caveat is what the code below does when it builds `[chain, Cj]` before
//! the call. Encryption is serial -- `Ij+1 = Cj = Pj XOR Oj` needs `Oj` first -- and does not pair.

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

/// CFB mode with a full-block segment (`s = b`) over any [`BlockPermutation`], with the direction
/// encoded in the type.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`BlockCipherEncryptor`] is implemented only for the
/// former and [`BlockCipherDecryptor`] only for the latter, so using one in the wrong direction is
/// a compile error rather than a runtime check.
///
/// The initialization data is one block, so `INIT_DATA_LEN == BLOCK_LEN`.
///
/// # Segment size
///
/// This is the `s = BLOCK_LEN * 8` variant of SP 800-38A Sec 6.3 -- "CFB128" for AES. The
/// sub-block segment sizes (CFB1, CFB8) are not block-aligned and are not implemented here; see
/// the module docs.
///
/// # State
///
/// Two fields, the same shape as [`crate::Cbc`]: the permutation (which owns the key schedule and
/// is responsible for keeping it in a zeroize-on-drop wrapper) and one block holding the next
/// input block `Ij`. `Ij` is an IV or a ciphertext block, both public, so it is deliberately not
/// wrapped in a `Secret`.
pub struct Cfb<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    /// `Ij`: the IV for `j = 1`, then `Cj-1`. See the module docs on why one field covers both.
    chain: [u8; BLOCK_LEN],
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Cfb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
{
    /// `Cj = Pj XOR CIPH_K(Ij)`, then `Cj` becomes the next input block.
    ///
    /// Serial: the next input block is the ciphertext produced here, so this cannot be batched.
    #[inline]
    fn encrypt_one(&mut self, plaintext: &[u8; BLOCK_LEN], ciphertext: &mut [u8; BLOCK_LEN]) {
        let mut keystream = self.chain; // Ij
        self.perm.encrypt_block(&mut keystream); // Oj = CIPH_K(Ij)

        for (out, (p, o)) in ciphertext.iter_mut().zip(plaintext.iter().zip(keystream.iter())) {
            *out = *p ^ *o; // Cj = Pj XOR Oj
        }

        self.chain = *ciphertext; // Ij+1 = Cj
    }

    /// `Pj = Cj XOR CIPH_K(Ij)`, then `Cj` becomes the next input block.
    ///
    /// Note `encrypt_block`: the *forward* cipher function, as Sec 6.3 requires of CFB decryption.
    /// See the module docs.
    #[inline]
    fn decrypt_one(&mut self, ciphertext: &[u8; BLOCK_LEN], plaintext: &mut [u8; BLOCK_LEN]) {
        let mut keystream = self.chain; // Ij
        self.perm.encrypt_block(&mut keystream); // Oj = CIPH_K(Ij)

        for (out, (c, o)) in plaintext.iter_mut().zip(ciphertext.iter().zip(keystream.iter())) {
            *out = *c ^ *o; // Pj = Cj XOR Oj
        }

        self.chain = *ciphertext; // Ij+1 = Cj
    }

    /// Decrypts two consecutive blocks with one [`BlockPermutation::encrypt_blocks2`] call.
    ///
    /// Writing the pair as `Cj, Cj+1` with `Ij` the incoming input block, Sec 6.3 at `s = b` gives
    ///
    /// ```text
    /// Ij   (the chaining value)      Oj   = CIPH_K(Ij)     Pj   = Cj   XOR Oj
    /// Ij+1 = Cj                      Oj+1 = CIPH_K(Ij+1)   Pj+1 = Cj+1 XOR Oj+1
    /// ```
    ///
    /// Both input blocks are known before either cipher call: `Ij` is held in `chain` and `Ij+1` is
    /// `Cj`, which is ciphertext already in hand. That is exactly the "input blocks are first
    /// constructed (in series)" condition Sec 6.3 attaches to parallel CFB decryption, and it is
    /// what the array literal below does. Neither forward cipher depends on the other's output, so
    /// computing them together cannot change the result.
    ///
    /// Still the forward function, in both slots.
    #[inline]
    fn decrypt_pair(
        &mut self,
        ciphertext: &[[u8; BLOCK_LEN]; 2],
        plaintext: &mut [[u8; BLOCK_LEN]; 2],
    ) {
        // [Ij, Ij+1] = [chain, Cj] -- constructed in series, then transformed together.
        let mut keystream = [self.chain, ciphertext[0]];
        self.perm.encrypt_blocks2(&mut keystream);

        for ((out, c), o) in plaintext.iter_mut().zip(ciphertext.iter()).zip(keystream.iter()) {
            for (out_byte, (c_byte, o_byte)) in out.iter_mut().zip(c.iter().zip(o.iter())) {
                *out_byte = *c_byte ^ *o_byte; // Pj = Cj XOR Oj
            }
        }

        self.chain = ciphertext[1]; // Ij+2 = Cj+1
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
    ///
    /// Sec 5.3 puts CFB under the same requirement as CBC -- the IV "must be unpredictable" -- so
    /// this is the same generated-not-accepted treatment.
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

    fn do_encrypt_blocks<const N: usize>(
        &mut self,
        plaintext: &[[u8; BLOCK_LEN]; N],
    ) -> Result<[[u8; BLOCK_LEN]; N], SymmetricCipherError> {
        let mut ciphertext = [[0u8; BLOCK_LEN]; N];
        self.do_encrypt_blocks_out(plaintext, &mut ciphertext)?;
        Ok(ciphertext)
    }

    /// The real implementation; the by-value variant above is a wrapper over it.
    ///
    /// Strictly serial: `Ij+1 = Cj`, and `Cj` is not known until `Oj` has been computed. Sec 6.3
    /// says as much ("like CBC encryption ... cannot be performed in parallel"), so there is no
    /// pair path here.
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
        Ok(Self { perm, chain: *init_data, _dir: PhantomData })
    }

    fn do_decrypt_blocks<const N: usize>(
        &mut self,
        ciphertext: &[[u8; BLOCK_LEN]; N],
    ) -> Result<[[u8; BLOCK_LEN]; N], SymmetricCipherError> {
        let mut plaintext = [[0u8; BLOCK_LEN]; N];
        self.do_decrypt_blocks_out(ciphertext, &mut plaintext)?;
        Ok(plaintext)
    }

    /// The real implementation; the by-value variant above is a wrapper over it.
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
