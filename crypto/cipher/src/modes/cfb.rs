//! The Cipher Feedback mode of operation (NIST SP 800-38A §6.3), full-block segment, as a stream
//! cipher.
//!
//! CFB and CFB8 are the same construction at two segment sizes, resulting in different,
//! non-interoperable modes. See [`cfb8`]
//!
//! # A stream cipher, implemented over a block cipher
//!
//! CFB is a keystream mode: the cipher never touches the data, it produces a keystream, and the data
//! is XORed with it byte for byte. While this mode operates over a block permutation primitive,
//! the chunking is invisible in the caller because the state carries the unused part of a block
//! from one call to the next.
//!
//! Since this does not require the input data to be block-aligned (ie to be a length that is a
//! multiple of the block size of the underlying permutation), this implementation treats the final
//! bytes of the message as a short final block and only extracts as much key stream material from
//! the final block as required to encrypt it. This avoids needing padding, and avoids any ciphertext
//! expansion.
//!
//! Note that NIST SP 800-38A §5.2 "Representation of the Plaintext and the Ciphertext" only presents
//! definitions for block-aligned ciphertexts, and these are the only one the Appendix F.3 and ACVP
//! test vectors cover.
//!
//! # Decryption uses the *forward* cipher function
//!
//! As a stream cipher producing an XOR key stream, the forward (encryption) and reverse (decryption)
//! are the same: both directions apply `CIPH_K`.
//!
//! So [`Cfb<P, Decrypting, ..>`](Cfb) is implemented over a permutation that impls [`ElectronicCodeBook`],
//! but never calls [`ElectronicCodeBook::decrypt_block`]. A permutation that implements only the
//! forward direction would still work here. The two directions differ only in which of the two
//! values -- the byte that came in, or the byte that went out -- is the ciphertext to be fed back into
//! the next block.
//!
//! # Parallel decryption
//!
//! Sec 6.3: "In CFB encryption, like CBC encryption, the input block to each forward cipher
//! function (except the first) depends on the result of the previous forward cipher function;
//! therefore, multiple forward cipher operations cannot be performed in parallel. In CFB
//! decryption, the required forward cipher operations can be performed in parallel if the input
//! blocks are first constructed (in series) from the IV and the ciphertext."
//!
//! This implementation follows: encryption handles blocks singly via [`ElectronicCodeBook::encrypt_block`],
//! while decryption can batch-process two or four blocks at a time via
//! [`ElectronicCodeBook::encrypt_2blocks`] or [`ElectronicCodeBook::encrypt_4blocks`], which may
//! yield a performance gain, depending on the implementation of the underlying permutation.
//!
//! # Usage Examples
//!
//! The direction is part of the type: [`Cfb<P, Encrypting, ..>`](Cfb) implements
//! [`StreamCipherEncryptor`] and nothing else, and [`Cfb<P, Decrypting, ..>`](Cfb) implements
//! [`StreamCipherDecryptor`] and nothing else.
//!
//! They take a `&mut [u8]` of any length; there is no padding layer and the ciphertext is exactly
//! as long as the plaintext:
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{StreamCipherDecryptor, StreamCipherEncryptor};
//! use bouncycastle_cipher::modes::{Cfb, Cfb8};
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyCfb<Dir> = Cfb<ToyBlockCipher, Dir, 16, 16>;
//! type ToyCfb8<Dir> = Cfb8<ToyBlockCipher, Dir, 16, 16>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! // Start with the plaintext.
//! let plaintext = b"the quick brown fox!!";
//! let mut data = *plaintext;
//!
//! let (bytes_written, iv) = ToyCfb::<Encrypting>::encrypt_in_place(&key, &mut data).expect("encryption");
//! assert_eq!(bytes_written, plaintext.len());
//!
//! // `data` now contains the ciphertext
//!
//! ToyCfb::<Decrypting>::decrypt_in_place(&key, &iv, &mut data).expect("decryption");
//! assert_eq!(data, *b"the quick brown fox!!");
//! ```
//!
//! Streaming works with chunks of any size:
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{
//!     StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor, SymmetricCipherEncryptor
//! };
//! use bouncycastle_cipher::modes::Cfb;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyCfb<Dir> = Cfb<ToyBlockCipher, Dir, 16, 16>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let mut data = [0x5Au8; 40];
//!
//! let (mut encryptor, iv) = ToyCfb::<Encrypting>::do_encrypt_init(&key).expect("init");
//!
//! // Just to prove that this can handle arbitrary sizes, we'll feed in
//! //  7 bytes, then 33: neither is a whole block.
//! let bytes_written = encryptor.do_encrypt(&mut data[..7]).expect("first chunk");
//! assert_eq!(bytes_written, 7);
//!
//! let bytes_written = encryptor.do_encrypt(&mut data[7..]).expect("the rest");
//! assert_eq!(bytes_written, 33);
//!
//! // Decrypting in a different chunking must also agree.
//! let mut decryptor = ToyCfb::<Decrypting>::do_decrypt_init(&key, &iv).expect("init");
//! decryptor.do_decrypt(&mut data[..19]).expect("first chunk");
//! decryptor.do_decrypt(&mut data[19..]).expect("the rest");
//! assert_eq!(data, [0x5Au8; 40]);
//! ```
//!
//! # Memory Usage
//!
//! The state consists of the underlying permutation struct, one block, `buf`, and a byte count, `used`.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## IV integrity
//!
//! NIST SP 800-38A Appendix D:
//!
//! > "for the CBC mode, the decryption of the first ciphertext block is vulnerable to the
//! > (deliberate) introduction of bit errors in specific bit positions of the IV if the integrity of
//! > the IV is not protected".
//!
//! Under CBC a flipped IV bit flips exactly that bit of the first decrypted plaintext block.
//!
//! Tampered IVs in CFB damage the initial block too, but unpredictably rather than controllably:
//! the IV is the first thing fed to the cipher, so this results in random errors instead of
//! predictable ones. See NIST SP 800-38A Appendix D: Error Properties for more info.
//!
//! ## Key stream leakage
//!
//! Every keystream block is `CIPH_K` of a public input -- the IV, then the previous ciphertext
//! block (Sec 6.3) -- so leaked keystream reveals nothing a known-plaintext attacker could not
//! already compute, and recovering the key from it is the block cipher's problem, not the mode's.
//! That means leaking the key stream is likely catastrophic for the confidentiality of the message
//! being protected, but does not compromise the symmetric key.
//!
//! That said, CFB mode is not an RNG, hash function, XOF, or MAC, and primitives intended for those
//! purposes should be used.
//!
//! ## Key stream reuse
//!
//! Reusing the same key stream is equivalent to encrypting two messages with the same key and IV.
//! Two messages encrypted under one key with the same IV share their first keystream block, and
//! because each later input block is the previous ciphertext block (Sec 6.3), they keep sharing
//! keystream until the first block at which their plaintexts differ.
//! Even if the adversary cannot recover the plaintext, simply knowing that two messages are identical
//! on their first N blocks often constitutes a catastrophic loss of security for many applications.
//! For example, this is enough to know if two users have downloaded the same file or a different file,
//! or potentially how much a file was modified between versions.
//!
//! This reinforces the general advice to always generate cryptographically random IVs unique for
//! each encryption operation.

use crate::modes::iv::random_iv;
use crate::stream::{stream_do_final, stream_update_out};
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, RNG, StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use bouncycastle_rng::HashDRBG_SHA512;
use core::marker::PhantomData;

// Imports needed for docs
#[allow(unused_imports)]
use crate::modes::cfb8;
// End imports needed for docs

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
pub struct Cfb<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    /// `buf[..used]` is the ciphertext of the current segment so far, i.e. the head of `I_{j+1}`;
    /// `buf[used..]` is the unused tail of `Oj`. When `used == BLOCK_LEN` the whole buffer is the
    /// next input block (initially `I1 = IV`) and no keystream is pending.
    //
    // # One buffer, three roles
    //
    // Within segment `j`, `buf[..used]` holds the ciphertext bytes produced (or consumed) so far and
    // `buf[used..]` holds the bytes of `Oj` not yet used. Both are needed and they fit in one block
    // because each ciphertext byte is written over the keystream byte that produced it.
    // When `used == BLOCK_LEN` the buffer holds `I_{j+1}`, and the next byte encrypts it in place
    // into `O_{j+1}`. So the same 16 bytes are the input block, then the output block, then the
    // next input block, and no copy is ever made.
    //
    // Since `buf` holds either plaintext or ciphertext, but never any keymaterial, it is not
    // necessary to tag it as `Secret<>`.
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

    /// Decrypts four consecutive blocks with one [`ElectronicCodeBook::encrypt_4blocks`] call.
    ///
    /// The same construction as [`Self::decrypt_pair`] widened to four: the input blocks are the
    /// incoming input block followed by the first three ciphertext blocks, all known before any
    /// cipher call, so the four forward ciphers are independent (Sec 6.3's parallel decryption).
    /// `I_{j+4} = Cj+3` is read before the XOR turns it into `Pj+3`.
    #[inline]
    fn decrypt_four(&mut self, blocks: &mut [[u8; BLOCK_LEN]; 4]) {
        debug_assert_eq!(self.used, BLOCK_LEN, "the block path needs a segment boundary");
        let mut o = [self.buf, blocks[0], blocks[1], blocks[2]];
        self.perm.encrypt_4blocks(&mut o);
        self.buf = blocks[3];
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

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherEncryptor<KEY_LEN, BLOCK_LEN, 0> for Cfb<P, Encrypting, KEY_LEN, BLOCK_LEN>
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

    /// As [`SymmetricCipherEncryptor::do_encrypt_init`], but takes the IV from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; BLOCK_LEN]), SymmetricCipherError> {
        let perm = P::new(key)?;
        // `I1 = IV`.
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((Self::start(perm, iv), iv))
    }

    /// Every input byte produces exactly one output byte.
    fn do_encrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// See [`stream_update_out`].
    fn do_encrypt_out(
        &mut self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        stream_update_out(plaintext, ciphertext, |data| self.do_encrypt(data))
    }

    /// See [`stream_do_final`].
    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        stream_do_final()
    }

    /// A stream cipher never changes the length of its data.
    fn encrypt_out_len(plaintext_len: usize) -> usize {
        plaintext_len
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> StreamCipherEncryptor<KEY_LEN, BLOCK_LEN>
    for Cfb<P, Encrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Encrypts `data`, of any length, in place.
    ///
    /// Strictly serial: `Oj+1 = CIPH_K(Cj)` and `Cj` is the *output* of the previous cipher call, so
    /// there is no pair path here; the block-aligned middle goes one cipher call per block, and
    /// only the bytes that complete an open segment or open the final short one go singly. See the
    /// module docs. Never fails: CFB has no per-IV data limit.
    ///
    /// Infallible -- cannot produce an error.
    fn do_encrypt(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        let len = data.len();
        let (head, blocks, tail) = self.split(data);
        self.encrypt_bytes(head);
        for block in blocks.iter_mut() {
            self.encrypt_one(block);
        }
        self.encrypt_bytes(tail);
        Ok(len)
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherDecryptor<KEY_LEN, BLOCK_LEN, 0> for Cfb<P, Decrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Begins a decryption flow from the IV returned by
    /// [`SymmetricCipherEncryptor::do_encrypt_init`].
    fn do_decrypt_init(
        key: &KeyMaterial<KEY_LEN>,
        init_data: &[u8; BLOCK_LEN],
    ) -> Result<Self, SymmetricCipherError> {
        let perm = P::new(key)?;
        // `I1 = IV`, exactly as on the encrypt side.
        Ok(Self::start(perm, *init_data))
    }

    /// Nothing is held back, so every input byte can be released immediately.
    fn do_decrypt_out_len(&self, input_len: usize) -> usize {
        input_len
    }

    /// See [`stream_update_out`].
    fn do_decrypt_out(
        &mut self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, SymmetricCipherError> {
        stream_update_out(ciphertext, plaintext, |data| self.do_decrypt(data))
    }

    /// See [`stream_do_final`].
    fn do_final(self) -> Result<([u8; 0], usize), SymmetricCipherError> {
        stream_do_final()
    }

    /// Exact rather than an upper bound: a stream cipher never changes the length of its data.
    fn decrypt_out_max_len(ciphertext_len: usize) -> usize {
        ciphertext_len
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> StreamCipherDecryptor<KEY_LEN, BLOCK_LEN>
    for Cfb<P, Decrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Decrypts `data`, of any length, in place.
    ///
    /// Walks the block-aligned middle in fours through the permutation's *forward* four-block
    /// path, then in pairs through its forward pair path, then the remaining block singly.
    /// `as_chunks_mut` splits into exactly those shapes with no runtime length check and no
    /// indexing arithmetic. The bytes that complete an open segment, and the final short segment,
    /// go singly. Never fails: CFB has no per-IV data limit.
    fn do_decrypt(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        let len = data.len();
        let (head, blocks, tail) = self.split(data);
        self.decrypt_bytes(head);
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        for four in fours.iter_mut() {
            self.decrypt_four(four);
        }
        let (pairs, single) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.decrypt_pair(pair);
        }
        for block in single.iter_mut() {
            self.decrypt_one(block);
        }
        self.decrypt_bytes(tail);
        Ok(len)
    }
}
