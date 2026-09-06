//! The Cipher Feedback mode of operation (NIST SP 800-38A Sec 6.3), 8-bit segment.
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
//! # This type is the `s = 8` specialisation
//!
//! [`Cfb8`] implements **only** `s = 8`, "the 8-bit CFB mode" of Sec 6.3, universally called CFB8.
//! A segment is one byte, so with `s = 8` the equations become, for each byte of the message:
//!
//! ```text
//! I1 = IV;  Ij = LSB_{b-8}(I_{j-1}) | C_{j-1};  Oj = CIPH_K(Ij);  Cj = Pj XOR MSB_8(Oj)
//! ```
//!
//! * `LSB_{b-8}(I_{j-1}) | C_{j-1}` keeps all but the leading byte of the previous input block and
//!   appends the ciphertext byte. Sec 6.3's alternative description is the shift register this
//!   implements literally: "the bits of the first input block circularly shift s positions to the
//!   left, and then the ciphertext segment replaces the s least significant bits of the result".
//!   [`Cfb8::shift_in`] is `rotate_left(1)` followed by writing the ciphertext byte into the last
//!   position -- those two sentences, in that order.
//! * `MSB_8(Oj)` is the **first byte** of the output block. The other `b - 8` bytes are discarded,
//!   as Sec 6.3 says of the general case: "The remaining b-s bits of the first output block are
//!   discarded."
//!
//! # One cipher call per byte
//!
//! Discarding `b - 8` of every `b` output bytes is what CFB8 costs: a full forward cipher for each
//! byte of the message, so on a 16-byte block it does **16 times** the cipher work of
//! [`Cfb`](crate::Cfb) for the same data. That is inherent to the mode, not to this implementation.
//! Use it when a byte-granular, self-synchronising stream is genuinely required or an existing
//! format demands it; otherwise prefer `Cfb`, which discards nothing.
//!
//! CFB8 is a **different, non-interoperable mode** from CFB128, not a variant of it: the two differ
//! from the very first byte of ciphertext, because CFB8 forms its second input block by shifting
//! whereas `s = b` replaces the block outright. `cfb8_tests.rs` pins that they disagree.
//!
//! # A stream cipher
//!
//! Every byte is a whole segment, so a CFB8 message has no alignment requirement at all: Sec 5.2
//! asks only that "the total number of bits in the plaintext" be "a multiple of a parameter,
//! denoted s", and with `s = 8` every byte string qualifies. [`Cfb8`] therefore implements
//! [`StreamCipherEncryptor`] / [`StreamCipherDecryptor`] and needs no padding layer, no
//! finalization step and -- unlike [`Cfb`](crate::Cfb), whose segment is a whole block -- no
//! partial-segment state: a call can end after any byte because every byte ends a segment.
//!
//! # Decryption uses the *forward* cipher function
//!
//! As in CFB128, both directions apply `CIPH_K`. Sec 6.3: "In CFB decryption, the IV is the first
//! input block, and each successive input block is formed as in CFB encryption [...] The *forward
//! cipher* function is applied to each input block to produce the output blocks." So
//! [`Cfb8<P, Decrypting, ..>`](Cfb8) never calls [`ElectronicCodeBook::decrypt_block`] or its batch
//! forms; `cfb8_tests.rs` pins that with a toy whose inverse panics.
//!
//! # Parallel decryption
//!
//! Sec 6.3: "In CFB encryption, like CBC encryption, the input block to each forward cipher
//! function (except the first) depends on the result of the previous forward cipher function;
//! therefore, multiple forward cipher operations cannot be performed in parallel. In CFB
//! decryption, the required forward cipher operations can be performed in parallel if the input
//! blocks are first constructed (in series) from the IV and the ciphertext."
//!
//! Decryption knows every ciphertext byte before it starts, so it can build the shift register's
//! successive states in series -- byte shuffling, no cipher calls -- and then run the forward
//! ciphers together. This implementation does exactly that, in eights through
//! [`ElectronicCodeBook::encrypt_blocks8`] and then pairs through
//! [`ElectronicCodeBook::encrypt_blocks2`], which is where a bit-sliced engine earns back a large
//! part of what the mode costs. Encryption cannot: `Ij` needs `C_{j-1}`, which is the output of the
//! previous cipher call.

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

/// CFB8 mode over any [`ElectronicCodeBook`], with the direction encoded in the type.
///
/// The segment size is one byte (`s = 8`); see the module docs, and note that this is **not**
/// interoperable with [`Cfb`](crate::Cfb), which is `s = b`.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`StreamCipherEncryptor`] is implemented only for the
/// former and [`StreamCipherDecryptor`] only for the latter, so a `Cfb8<_, Encrypting, _, _>` has
/// no decryption methods at all -- using one in the wrong direction is a compile error rather than
/// a runtime check.
///
/// The initialization data is one block, so `INIT_DATA_LEN == BLOCK_LEN`.
///
/// # State
///
/// Two fields, the same size as `Cbc`: the permutation (which owns the key schedule, and is
/// responsible for keeping it in a zeroize-on-drop wrapper) and one block holding the shift
/// register `Ij`. `Ij` is built from the IV and ciphertext bytes, both of which are public, so it
/// is deliberately not wrapped in a `Secret`.
///
/// Note what is *not* stored: the output block `Oj`. It is recomputed from the register on each
/// byte and lives only in a local, so no keystream outlives the call that used it. No partial
/// segment is stored either, because a segment is one byte.
pub struct Cfb8<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    /// `Ij`: the IV, then the shift register. See the module docs.
    chain: [u8; BLOCK_LEN],
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Cfb8<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// `I_{j+1} = LSB_{b-8}(Ij) | Cj`: shift the register one byte left and put the ciphertext byte
    /// in the least significant position.
    ///
    /// This is Sec 6.3's alternative description verbatim -- "the bits of the first input block
    /// circularly shift s positions to the left, and then the ciphertext segment replaces the s
    /// least significant bits of the result" -- so the rotate is the spec's rotate, and overwriting
    /// the last byte is what discards the byte the rotate carried round.
    #[inline]
    fn shift_in(&mut self, ciphertext_byte: u8) {
        self.chain.rotate_left(1);
        // BLOCK_LEN is non-zero for any permutation: a zero-length block has no cipher.
        self.chain[BLOCK_LEN - 1] = ciphertext_byte;
    }

    /// `MSB_8(Oj)`, the one keystream byte this segment uses: `Oj = CIPH_K(Ij)`, first byte kept,
    /// the other `b - 8` discarded as Sec 6.3 requires.
    ///
    /// The forward cipher function, in both directions -- see the module docs.
    #[inline]
    fn keystream_byte(&self) -> u8 {
        let mut o = self.chain;
        self.perm.encrypt_block(&mut o);
        o[0]
    }

    /// Decrypts `N` consecutive bytes with one batched forward-cipher call.
    ///
    /// The input blocks are built in series first -- each is the previous one shifted with the
    /// previous *ciphertext* byte appended, which decryption already has -- so the `N` forward
    /// ciphers are independent. This is precisely the parallelism Sec 6.3 describes, with the input
    /// blocks "first constructed (in series) from the IV and the ciphertext".
    ///
    /// `batch` is the permutation's `N`-block method; the scratch array holds the input blocks on
    /// the way in and the output blocks on the way out.
    #[inline]
    fn decrypt_batch<const N: usize>(
        &mut self,
        bytes: &mut [u8; N],
        batch: impl Fn(&P, &mut [[u8; BLOCK_LEN]; N]),
    ) {
        let mut blocks = [[0u8; BLOCK_LEN]; N];
        for (block, c) in blocks.iter_mut().zip(bytes.iter()) {
            *block = self.chain;
            // I_{j+1} = LSB(Ij) | C#_j: the ciphertext byte is what is fed back, and on this side
            // it is the byte that came in, before the XOR below turns it into plaintext.
            self.shift_in(*c);
        }
        batch(&self.perm, &mut blocks);
        for (byte, o) in bytes.iter_mut().zip(blocks.iter()) {
            *byte ^= o[0];
        }
    }
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for Cfb8<P, Dir, KEY_LEN, BLOCK_LEN>
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
    for Cfb8<P, Encrypting, KEY_LEN, BLOCK_LEN>
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
        Ok((Self { perm, chain: iv, _dir: PhantomData }, iv))
    }

    /// Encrypts `data`, of any length, in place: `Cj = Pj XOR MSB_8(CIPH_K(Ij))` for each byte,
    /// then `Cj` shifts into the register.
    ///
    /// Strictly serial, one forward cipher per byte: `I_{j+1}` needs `Cj`, which is the result of
    /// the XOR that the cipher call produced. See the module docs. Never fails: CFB has no per-IV
    /// data limit.
    fn do_encrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        for byte in data.iter_mut() {
            *byte ^= self.keystream_byte();
            self.shift_in(*byte);
        }
        Ok(())
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> StreamCipherDecryptor<KEY_LEN, BLOCK_LEN>
    for Cfb8<P, Decrypting, KEY_LEN, BLOCK_LEN>
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
        Ok(Self { perm, chain: *init_data, _dir: PhantomData })
    }

    /// Decrypts `data`, of any length, in place: `Pj = Cj XOR MSB_8(CIPH_K(Ij))` for each byte,
    /// with the *ciphertext* byte -- the one that came in, not the plaintext going out -- shifted
    /// into the register.
    ///
    /// Walks the data in eights through the permutation's *forward* eight-block path, then in pairs
    /// through its forward pair path, then the remaining bytes singly (Sec 6.3's parallel
    /// decryption; see the module docs). Never fails: CFB has no per-IV data limit.
    fn do_decrypt(&mut self, data: &mut [u8]) -> Result<(), SymmetricCipherError> {
        let (eights, rest) = data.as_chunks_mut::<8>();
        for eight in eights.iter_mut() {
            self.decrypt_batch(eight, P::encrypt_blocks8);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.decrypt_batch(pair, P::encrypt_blocks2);
        }
        for byte in tail.iter_mut() {
            let c = *byte;
            *byte ^= self.keystream_byte();
            self.shift_in(c);
        }
        Ok(())
    }
}
