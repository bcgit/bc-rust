//! The Cipher Feedback mode of operation (NIST SP 800-38A Sec 6.3), full-block segment, as a stream
//! cipher.
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
//! the name of the mode", i.e. CFB128 for a 128-bit block. Substituting `s = b` collapses the
//! equations exactly:
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
//! The other segment sizes are **different, non-interoperable modes**, not variants of this one:
//! with `s < b` the shift register keeps `b - s` bits of the previous input block, which `s = b`
//! never does, so the ciphertexts diverge immediately. `s = 8` is [`Cfb8`](crate::Cfb8), in its own
//! type for exactly that reason; `s = 1` is not provided. SP 800-38A Appendix F.3 gives vectors for
//! all three.
//!
//! # A stream cipher, not a block cipher
//!
//! CFB is a keystream mode: the cipher never touches the data, only `Ij`, and the data is XORed
//! with the output block byte for byte. So the data need not arrive in whole blocks, and [`Cfb`]
//! implements [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`] -- any length, in place,
//! chunked however the caller likes -- rather than the block-aligned `BlockCipherEncryptor` /
//! `BlockCipherDecryptor` that `Cbc` implements. The chunking is invisible in the output because
//! the state carries the unused part of `Oj` from one call to the next; see
//! [One buffer, three roles](#one-buffer-three-roles).
//!
//! ## The final partial segment
//!
//! Sec 5.2 requires "the total number of bits in the plaintext" to be "a multiple of a parameter,
//! denoted s", so a message whose length is not a multiple of the block does not have an
//! `s = b` segmentation at all, and Appendix A puts padding it "outside the scope of this
//! recommendation". This implementation instead accepts any length and treats the last `r < b`
//! bytes as a short final segment:
//!
//! ```text
//! C#_n = P#_n XOR MSB_{8r}(On)
//! ```
//!
//! That is, it takes the `s = 8r` step of the Sec 6.3 equations for the last segment only and
//! discards the rest of `On`, exactly as Sec 6.3 discards `b - s` bits of every output block when
//! `s < b`. Since no input block is formed after the last segment, the `LSB_{b-s} | C#` feedback
//! rule, which is where `s < b` and `s = b` differ, is never exercised by the short segment, so
//! the result is well defined and unambiguous. It is also the behaviour of the streaming CFB128
//! implementations in common use (OpenSSL's `EVP_aes_*_cfb128`, for one), so ciphertexts
//! interoperate at every length. A whole number of blocks is still the only length Sec 5.2
//! defines, and the only one the Appendix F.3 and ACVP vectors cover.
//!
//! # One buffer, three roles
//!
//! The whole state beyond the permutation is one block, `buf`, and a byte count, `used`. Within
//! segment `j`, `buf[..used]` holds the ciphertext bytes produced (or consumed) so far and
//! `buf[used..]` holds the bytes of `Oj` not yet used. Both are needed and they fit in one block
//! because each ciphertext byte is written over the keystream byte that produced it: `Cj[i] =
//! Pj[i] XOR Oj[i]`, and `Oj[i]` is never needed again, while `Cj[i]` is exactly what the next
//! input block wants in position `i` (`I_{j+1} = Cj`). When `used == BLOCK_LEN` the buffer *is*
//! `I_{j+1}`, and the next byte encrypts it in place into `O_{j+1}`. So the same 16 bytes are the
//! input block, then the output block, then the next input block, and no copy is ever made.
//!
//! Between calls the buffer therefore holds `Ij` or `Cj` -- both public -- and, mid-segment, the
//! unused tail of `Oj`. Those keystream bytes have not been XORed with anything, so they reveal
//! nothing about the message, and they are `CIPH_K` of a public block, which a secure permutation
//! makes worthless without the key. They are not key material and the buffer is not wrapped in a
//! `Secret`; the key schedule itself lives in the permutation, which is responsible for zeroizing
//! it.
//!
//! # Decryption uses the *forward* cipher function
//!
//! This is the thing about CFB that surprises a reader used to CBC: both directions apply
//! `CIPH_K`. Sec 6.3 is explicit -- "In CFB decryption, the IV is the first input block, and each
//! successive input block is formed as in CFB encryption [...] The *forward cipher* function is
//! applied to each input block to produce the output blocks."
//!
//! So [`Cfb<P, Decrypting, ..>`](Cfb) never calls [`ElectronicCodeBook::decrypt_block`],
//! [`ElectronicCodeBook::decrypt_2blocks`] or [`ElectronicCodeBook::decrypt_blocks8`]. A
//! permutation could implement only the forward direction and still work here; `cfb_tests.rs` pins
//! that with a toy whose inverse panics. The mode XORs a keystream in both directions, and the two
//! directions differ only in which of the two values -- the byte that came in, or the byte that
//! went out -- is the ciphertext to be fed back.
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
//! followed by the ciphertext blocks, already in hand. Decryption therefore walks the
//! block-aligned part of the data in eights through [`ElectronicCodeBook::encrypt_blocks8`] and
//! pairs through [`ElectronicCodeBook::encrypt_2blocks`], which a bit-sliced engine computes for
//! barely more than the cost of one block. Encryption cannot, and does not. Only the bytes that
//! complete an open segment, and the bytes that open the final short one, go singly.

use crate::iv::random_iv;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{
    Algorithm, ElectronicCodeBook, RNG, SecurityStrength, StreamCipherDecryptor,
    StreamCipherEncryptor,
};
use bouncycastle_rng::HashDRBG_SHA512;
use core::marker::PhantomData;

/// CFB mode over any [`ElectronicCodeBook`], as a stream cipher, with the direction encoded in the
/// type.
///
/// The segment size is the full block (`s = b`, i.e. CFB128 for AES); see the module docs for why
/// the other segment sizes are out of scope, and for how a message that is not a whole number of
/// blocks is handled.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`StreamCipherEncryptor`] is implemented only for the
/// former and [`StreamCipherDecryptor`] only for the latter, so a `Cfb<_, Encrypting, _, _>` has no
/// decryption methods at all -- using one in the wrong direction is a compile error rather than a
/// runtime check.
///
/// The initialization data is one block, so `INIT_DATA_LEN == BLOCK_LEN`.
///
/// # State
///
/// The permutation (which owns the key schedule, and is responsible for keeping it in a
/// zeroize-on-drop wrapper), one block, and a byte count. The block is `Ij`, `Oj` and `I_{j+1}` in
/// turn -- see the module docs, "One buffer, three roles" -- which is what lets a call end at any
/// byte and the next one pick up where it left off. That is one `usize` more than `Cbc` carries;
/// the module docs explain why the unused keystream it may hold between calls is not wrapped in a
/// `Secret`.
pub struct Cfb<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    /// `buf[..used]` is the ciphertext of the current segment so far, i.e. the head of `I_{j+1}`;
    /// `buf[used..]` is the unused tail of `Oj`. When `used == BLOCK_LEN` the whole buffer is the
    /// next input block (initially `I1 = IV`) and no keystream is pending.
    buf: [u8; BLOCK_LEN],
    /// Bytes of the current segment already processed, `0..=BLOCK_LEN`.
    used: usize,
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Cfb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// `I1 = IV`, with no segment open: the first byte in either direction will compute `O1`.
    #[inline]
    fn start(perm: P, iv: [u8; BLOCK_LEN]) -> Self {
        Self { perm, buf: iv, used: BLOCK_LEN, _dir: PhantomData }
    }

    /// Makes the next keystream byte available: if the current segment is complete, `buf` is the
    /// next input block, so `Oj = CIPH_K(Ij)` is computed in place and a new segment opened.
    ///
    /// The forward cipher function, in both directions -- see the module docs.
    #[inline]
    fn refill_if_used_up(&mut self) {
        if self.used == BLOCK_LEN {
            self.perm.encrypt_block(&mut self.buf);
            self.used = 0;
        }
    }

    /// Encrypts fewer than a block's worth of bytes, byte by byte, within the open segment or
    /// opening a new one: `Cj[i] = Pj[i] XOR Oj[i]`, then `Cj[i]` takes the place of `Oj[i]` in the
    /// buffer as the `i`th byte of `I_{j+1}`.
    ///
    /// Correct for any length, but only called with what the block path cannot take: the bytes that
    /// complete a segment left open by an earlier call, and the final short segment.
    #[inline]
    fn encrypt_bytes(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.refill_if_used_up();
            *byte ^= self.buf[self.used];
            self.buf[self.used] = *byte;
            self.used += 1;
        }
    }

    /// The decrypting counterpart of [`Self::encrypt_bytes`]: `Pj[i] = Cj[i] XOR Oj[i]`, and it is
    /// the *ciphertext* byte `Cj[i]` -- the one that came in, not the one going out -- that is fed
    /// back into the buffer.
    #[inline]
    fn decrypt_bytes(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.refill_if_used_up();
            // `I_{j+1} = C#_j` of the spec equations: the ciphertext segment is what is fed back.
            // Feeding back the plaintext instead would still decrypt the first block correctly and
            // nothing after it, which is why `cfb_tests.rs` checks exactly that.
            let c = *byte;
            *byte ^= self.buf[self.used];
            self.buf[self.used] = c;
            self.used += 1;
        }
    }

    /// Encrypts one whole block at a segment boundary (`used == BLOCK_LEN`, so `buf` is `Ij`):
    /// `Oj = CIPH_K(Ij)` in place, `Cj = Pj XOR Oj`, then `Cj` becomes `I_{j+1}` -- which leaves
    /// `used == BLOCK_LEN` again, so consecutive calls need no bookkeeping.
    #[inline]
    fn encrypt_one(&mut self, block: &mut [u8; BLOCK_LEN]) {
        debug_assert_eq!(self.used, BLOCK_LEN, "the block path needs a segment boundary");
        self.perm.encrypt_block(&mut self.buf);
        for (b, o) in block.iter_mut().zip(self.buf.iter()) {
            *b ^= *o;
        }
        // I_{j+1} = Cj. Serial: this is the input to the next cipher call.
        self.buf = *block;
    }

    /// Decrypts one whole block at a segment boundary. `Cj` is overwritten by `Pj`, so it is copied
    /// first to become `I_{j+1}`.
    #[inline]
    fn decrypt_one(&mut self, block: &mut [u8; BLOCK_LEN]) {
        debug_assert_eq!(self.used, BLOCK_LEN, "the block path needs a segment boundary");
        let cj = *block;
        self.perm.encrypt_block(&mut self.buf);
        for (b, o) in block.iter_mut().zip(self.buf.iter()) {
            *b ^= *o;
        }
        self.buf = cj;
    }

    /// Decrypts two consecutive blocks with one [`ElectronicCodeBook::encrypt_2blocks`] call.
    ///
    /// Writing the pair as `Cj, Cj+1` with `Ij` the incoming input block, the `s = b` equations
    /// give
    ///
    /// ```text
    /// Ij   = buf          Oj   = CIPH_K(Ij)     Pj   = Cj   XOR Oj
    /// Ij+1 = Cj           Oj+1 = CIPH_K(Ij+1)   Pj+1 = Cj+1 XOR Oj+1
    /// ```
    ///
    /// Both input blocks are known before either cipher call -- `Ij` is already held and `Ij+1` is
    /// just `Cj`, which the caller supplied -- so the two forward ciphers are independent and
    /// computing them together changes nothing. This is precisely the parallelism Sec 6.3 describes,
    /// with the input blocks "first constructed (in series) from the IV and the ciphertext".
    ///
    /// In place: the two input blocks are the keystream buffer, so the ciphertext is never
    /// overwritten before it has been read, and only `Cj+1` needs copying for the next input block.
    #[inline]
    fn decrypt_pair(&mut self, blocks: &mut [[u8; BLOCK_LEN]; 2]) {
        debug_assert_eq!(self.used, BLOCK_LEN, "the block path needs a segment boundary");
        // The two input blocks, constructed in series: Ij (already held) and Ij+1 (= Cj).
        let mut o = [self.buf, blocks[0]];
        self.perm.encrypt_2blocks(&mut o);

        // I_{j+2} = Cj+1, read before the XOR below turns it into Pj+1.
        self.buf = blocks[1];

        for (block, o) in blocks.iter_mut().zip(o.iter()) {
            for (b, o) in block.iter_mut().zip(o.iter()) {
                *b ^= *o;
            }
        }
    }

    /// Decrypts eight consecutive blocks with one [`ElectronicCodeBook::encrypt_blocks8`] call.
    ///
    /// The same construction as [`Self::decrypt_pair`] widened to eight: the input blocks are the
    /// incoming input block followed by the first seven ciphertext blocks, all known before any
    /// cipher call, so the eight forward ciphers are independent (Sec 6.3's parallel decryption).
    /// `I_{j+8} = Cj+7` is read before the XOR turns it into `Pj+7`.
    #[inline]
    fn decrypt_eight(&mut self, blocks: &mut [[u8; BLOCK_LEN]; 8]) {
        debug_assert_eq!(self.used, BLOCK_LEN, "the block path needs a segment boundary");
        let mut o =
            [self.buf, blocks[0], blocks[1], blocks[2], blocks[3], blocks[4], blocks[5], blocks[6]];
        self.perm.encrypt_blocks8(&mut o);
        self.buf = blocks[7];
        for (block, o) in blocks.iter_mut().zip(o.iter()) {
            for (b, o) in block.iter_mut().zip(o.iter()) {
                *b ^= *o;
            }
        }
    }

    /// Splits `data` into the bytes that complete the currently open segment (none, if a segment
    /// boundary has been reached), the whole blocks that follow, and the short tail that opens the
    /// final segment. After the head has been processed `used == BLOCK_LEN`, which is what the
    /// block path requires; the tail is shorter than a block, so it opens at most one segment.
    #[inline]
    fn split<'a>(
        &self,
        data: &'a mut [u8],
    ) -> (&'a mut [u8], &'a mut [[u8; BLOCK_LEN]], &'a mut [u8]) {
        let head_len = core::cmp::min(BLOCK_LEN - self.used, data.len());
        let (head, rest) = data.split_at_mut(head_len);
        let (blocks, tail) = rest.as_chunks_mut::<BLOCK_LEN>();
        (head, blocks, tail)
    }
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for Cfb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The underlying permutation's name. The mode is not appended: `&'static str`s cannot be
    /// concatenated in a `const`, and the mode is already in the type.
    const ALG_NAME: &'static str = P::ALG_NAME;
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> StreamCipherEncryptor<KEY_LEN, BLOCK_LEN>
    for Cfb<P, Encrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Begins an encryption flow, generating the IV from the library's default OS-backed DRBG.
    fn do_encrypt_init(
        key: &KeyMaterial<KEY_LEN>,
    ) -> Result<(Self, [u8; BLOCK_LEN]), SymmetricCipherError> {
        let mut rng = HashDRBG_SHA512::new_from_os();
        Self::do_encrypt_init_rng(key, &mut rng)
    }

    /// As [`StreamCipherEncryptor::do_encrypt_init`], but takes the IV from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; BLOCK_LEN]), SymmetricCipherError> {
        let perm = P::new(key)?;
        // `I1 = IV`.
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((Self::start(perm, iv), iv))
    }

    /// Encrypts `data`, of any length, in place.
    ///
    /// Strictly serial: `Oj+1 = CIPH_K(Cj)` and `Cj` is the *output* of the previous cipher call, so
    /// there is no pair path here; the block-aligned middle goes one cipher call per block, and
    /// only the bytes that complete an open segment or open the final short one go singly. See the
    /// module docs. Never fails: CFB has no per-IV data limit.
    fn do_encrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        let (head, blocks, tail) = self.split(data);
        self.encrypt_bytes(head);
        for block in blocks.iter_mut() {
            self.encrypt_one(block);
        }
        self.encrypt_bytes(tail);
        Ok(())
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> StreamCipherDecryptor<KEY_LEN, BLOCK_LEN>
    for Cfb<P, Decrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Begins a decryption flow from the IV returned by
    /// [`StreamCipherEncryptor::do_encrypt_init`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; BLOCK_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        let perm = P::new(key)?;
        // `I1 = IV`, exactly as on the encrypt side.
        Ok(Self::start(perm, *init_data))
    }

    /// Decrypts `data`, of any length, in place.
    ///
    /// Walks the block-aligned middle in eights through the permutation's *forward* eight-block
    /// path, then in pairs through its forward pair path, then the remaining block singly.
    /// `as_chunks_mut` splits into exactly those shapes with no runtime length check and no
    /// indexing arithmetic. The bytes that complete an open segment, and the final short segment,
    /// go singly. Never fails: CFB has no per-IV data limit.
    fn do_decrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        let (head, blocks, tail) = self.split(data);
        self.decrypt_bytes(head);
        let (eights, rest) = blocks.as_chunks_mut::<8>();
        for eight in eights.iter_mut() {
            self.decrypt_eight(eight);
        }
        let (pairs, single) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.decrypt_pair(pair);
        }
        for block in single.iter_mut() {
            self.decrypt_one(block);
        }
        self.decrypt_bytes(tail);
        Ok(())
    }
}
