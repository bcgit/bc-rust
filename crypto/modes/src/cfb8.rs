//! The Cipher Feedback mode of operation (NIST SP 800-38A Sec 6.3), 8-bit segment.
//!
//! CFB and CBF8 are the same construction at two segment sizes, resulting in different,
//! non-interoperable modes. See [`cfb`] for the primary docs on this mode.
//!
//! The difference is the segment size `s` of Sec 6.3. `Cfb` uses `s = b`: each cipher call yields a
//! whole block of keystream, and the next input block is simply the previous ciphertext block.
//! `Cfb8` uses `s = 8` bits: each call to the underlying block permutation yields one keystream byte,
//! the other `b - 8` are discarded, and the input block is a shift register. NIST SP 800-38A
//! Sec 6.3:
//!
//! > "the bits of the first input block circularly shift s positions to the left, and then the
//! ciphertext segment replaces the s least significant bits of the result".
//!
//! The smaller segment is not a security gain, but it makes the mode self-synchronising
//! at byte granularity: after a dropped or inserted byte the shift register refills from ciphertext
//! and decryption recovers `b/s` bytes later on its own, where `Cfb` and every other mode need the
//! alignment "restored externally".
//!
//! # One cipher call per byte
//!
//! Using only one byte from each invocation of the underlying block cipher dramatically reduces
//! performance, so on a typical 16-byte block cipher it does **16 times** the cipher work of
//! [`cfb`] for the same data. That is inherent to the mode, not to this implementation.
//!
//! # 🚨 Security Considerations 🚨
//!
//! CFB and CFB8 largely share their security considerations, with only a few differences.
//! Therefore, everything in the Security Considerations of [`crate::cfb`] applies here as well.
//!
//! ## Increased attack precision
//!
//! In CFB, the security implications happen at a block granularity, whereas in CFB8 they happen at
//! a byte granularity.
//! This means, for example, key and IV reuse now tells a passive attacker at which exact byte
//! two messages begin to differ.
//!
//! ## Self-synchronization cuts both ways
//!
//! The self-synchronization property, while providing great robustness, also allows attackers to
//! drop or insert content, including content taken from other messages under the same key. This
//! results in `b/s` bytes of garbage (16 with AES) and then a fully recovered plaintext stream
//! thereafter, possibly now decrypting a different document than the one before the cut.
//! This means that, for example, a malicious cut right before a long random number, such as an account
//! number or ID number, could still yield a syntactically-correct message and therefore be completely
//! undetectable.

use crate::iv::random_iv;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::stream_cipher::{stream_do_final, stream_update_out};
use bouncycastle_core::traits::{
    Algorithm, ElectronicCodeBook, RNG, StreamCipherDecryptor, StreamCipherEncryptor,
    SymmetricCipherDecryptor, SymmetricCipherEncryptor,
};
use bouncycastle_rng::HashDRBG_SHA512;
use core::marker::PhantomData;

// Imports needed for docs
#[allow(unused_imports)]
use crate::cfb;
// End imports needed for docs

/// CFB8 mode over any [`ElectronicCodeBook`], with the direction encoded in the type.
///
/// The segment size is one byte (`s = 8`); see the module docs, and note that this is **not**
/// interoperable with [`cfb`], which is `s = b`.
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

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherEncryptor<KEY_LEN, BLOCK_LEN, 0> for Cfb8<P, Encrypting, KEY_LEN, BLOCK_LEN>
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
        const {
            assert!(
                P::ENCRYPTION_APPROVED,
                "this permutation is approved for decryption only (ElectronicCodeBook::ENCRYPTION_APPROVED is false)"
            )
        };
        let perm = P::new(key)?;
        // `I1 = IV`.
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((Self { perm, chain: iv, _dir: PhantomData }, iv))
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
    for Cfb8<P, Encrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Encrypts `data`, of any length, in place: `Cj = Pj XOR MSB_8(CIPH_K(Ij))` for each byte,
    /// then `Cj` shifts into the register.
    ///
    /// Strictly serial, one forward cipher per byte: `I_{j+1}` needs `Cj`, which is the result of
    /// the XOR that the cipher call produced. See the module docs. Never fails: CFB has no per-IV
    /// data limit.
    fn do_encrypt(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        for byte in data.iter_mut() {
            *byte ^= self.keystream_byte();
            self.shift_in(*byte);
        }
        Ok(data.len())
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    SymmetricCipherDecryptor<KEY_LEN, BLOCK_LEN, 0> for Cfb8<P, Decrypting, KEY_LEN, BLOCK_LEN>
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
        Ok(Self { perm, chain: *init_data, _dir: PhantomData })
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
    for Cfb8<P, Decrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// Decrypts `data`, of any length, in place: `Pj = Cj XOR MSB_8(CIPH_K(Ij))` for each byte,
    /// with the *ciphertext* byte -- the one that came in, not the plaintext going out -- shifted
    /// into the register.
    ///
    /// Walks the data in fours through the permutation's *forward* four-block path, then in pairs
    /// through its forward pair path, then the remaining bytes singly (Sec 6.3's parallel
    /// decryption; see the module docs). Never fails: CFB has no per-IV data limit.
    fn do_decrypt(&mut self, data: &mut [u8]) -> Result<usize, SymmetricCipherError> {
        let len = data.len();
        let (fours, rest) = data.as_chunks_mut::<4>();
        for four in fours.iter_mut() {
            self.decrypt_batch(four, P::encrypt_4blocks);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.decrypt_batch(pair, P::encrypt_2blocks);
        }
        for byte in tail.iter_mut() {
            let c = *byte;
            *byte ^= self.keystream_byte();
            self.shift_in(c);
        }
        Ok(len)
    }
}
