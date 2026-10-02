//! The Cipher Block Chaining mode of operation (NIST SP 800-38A Sec 6.2).
//!
//! # Parallel decryption
//!
//! Sec 6.2 notes that in CBC decryption "the input blocks for the inverse cipher function, i.e.,
//! the ciphertext blocks, are immediately available, so that multiple inverse cipher operations can
//! be performed in parallel", whereas in encryption "the input block to each forward cipher
//! operation (except the first) depends on the result of the previous forward cipher operation, so
//! the forward cipher operations cannot be performed in parallel".
//!
//! This implementation uses that: decryption walks the ciphertext four blocks at a time through
//! [`ElectronicCodeBook::decrypt_4blocks`], then any remaining pair through
//! [`ElectronicCodeBook::decrypt_2blocks`], then the last block singly. A bit-sliced engine
//! computes two or four blocks (AES, on `u32` or `u64` planes) for barely more than the cost of
//! one. Encryption cannot, and does not.
//!
//! # Usage Examples
//!
//! The direction is part of the type: [`Cbc<P, Encrypting, ..>`](Cbc) implements
//! [`BlockCipherEncryptor`] and nothing else, and [`Cbc<P, Decrypting, ..>`](Cbc) implements
//! [`BlockCipherDecryptor`] and nothing else.
//! The IV is generated and returned; there is no API for supplying one.
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_cipher::modes::Cbc;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyCbc<Dir> = Cbc<ToyBlockCipher, Dir, 16, 16>;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! // 48 bytes: three whole blocks. A length that is not a multiple of 16 would not compile.
//! let plaintext: [u8; 48] = *b"The quick brown fox jumps over the lazy dog. OK!";
//!
//! // One shot, in place: encrypts under a freshly generated IV, which is returned.
//! let mut data = plaintext;
//! let (_, iv) = ToyCbc::<Encrypting>::encrypt_in_place(&key, &mut data).expect("encryption");
//! assert_ne!(data, plaintext);
//!
//! ToyCbc::<Decrypting>::decrypt_in_place(&key, &iv, &mut data).expect("decryption");
//! assert_eq!(data, plaintext);
//! ```
//!
//! Streaming, for data that arrives in pieces. A sequence of calls is equivalent to one call over
//! the concatenation:
//!
//! ```
//! use bouncycastle_core_test_framework::ToyBlockCipher;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_cipher::modes::Cbc;
//! use bouncycastle_cipher::{Decrypting, Encrypting};
//!
//! type ToyCbc<Dir> = Cbc<ToyBlockCipher, Dir, 16, 16>;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x07; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//!
//! let (mut encryptor, iv) =
//!     ToyCbc::<Encrypting>::do_encrypt_init(&key).expect("encrypt init");
//! let mut first = [0xAAu8; 16];
//! let mut rest = [0xBBu8; 32];
//! encryptor.do_encrypt(&mut first).expect("block 1");
//! encryptor.do_encrypt(&mut rest).expect("blocks 2-3");
//!
//! let mut decryptor = ToyCbc::<Decrypting>::do_decrypt_init(&key, &iv).expect("decrypt init");
//! decryptor.do_decrypt(&mut first).unwrap();
//! decryptor.do_decrypt(&mut rest).unwrap();
//! assert_eq!(first, [0xAAu8; 16]);
//! assert_eq!(rest, [0xBBu8; 32]);
//! ```
//!
//! # Suspending and resuming execution
//!
//! [`Cbc`] implements [`SuspendableKeyed`], so a message in progress can be suspended to a byte
//! array and resumed later with the re-supplied key. The state is the chaining block; the
//! permutation is rebuilt from the key. The array length is `Cbc::SUSPENDED_STATE_LEN`; see [the
//! crate docs](crate#suspending-and-resuming-execution) for an example.
//!
//! # 🚨 Security Considerations 🚨
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
//! So, while the IV need not be secret, best-practice is to authenticate it along with the ciphertext,
//! or use an authenticated (AEAD) mode such as GCM.

use crate::modes::iv::random_iv;
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::ElectronicCodeBook;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, RNG, SuspendableKeyed,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_utils::suspendable_state::{
    LIB_VERSION_LEN, SuspendableComponent, resume_component, suspend_component,
};
use core::marker::PhantomData;

/// CBC mode over any [`ElectronicCodeBook`], with the direction encoded in the type.
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
#[derive(Clone)]
pub struct Cbc<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    perm: P,
    /// `Cj-1`, initialised to the IV. See the module docs on why there is only one field for both.
    chain: [u8; BLOCK_LEN],
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Cbc<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    /// The `N` of this type's [`SuspendableKeyed<N>`] impl: the version header and the chaining
    /// block. See [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize = LIB_VERSION_LEN + BLOCK_LEN;

    /// `Cj = CIPH_K(Pj XOR Cj-1)` in place, then `Cj` becomes the next chaining value.
    #[inline]
    fn encrypt_one(&mut self, block: &mut [u8; BLOCK_LEN]) {
        for (b, chain) in block.iter_mut().zip(self.chain.iter()) {
            *b ^= *chain; // Pj XOR Cj-1
        }
        self.perm.encrypt_block(block); // Cj = CIPH_K(..)
        self.chain = *block;
    }

    /// `Pj = CIPH^-1_K(Cj) XOR Cj-1` in place, then `Cj` becomes the next chaining value.
    ///
    /// `Cj` is overwritten by `Pj`, so it is copied first: it is the next chaining value.
    #[inline]
    fn decrypt_one(&mut self, block: &mut [u8; BLOCK_LEN]) {
        let cj = *block;
        self.perm.decrypt_block(block); // CIPH^-1_K(Cj)
        for (b, chain) in block.iter_mut().zip(self.chain.iter()) {
            *b ^= *chain; // XOR Cj-1
        }
        self.chain = cj;
    }

    /// Decrypts two consecutive blocks with one [`ElectronicCodeBook::decrypt_2blocks`] call.
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
    /// differ, and the second one is `Cj`, so both ciphertext blocks are copied out before the
    /// permutation overwrites them, and the chaining value is then advanced to `Cj+1`.
    #[inline]
    fn decrypt_pair(&mut self, blocks: &mut [[u8; BLOCK_LEN]; 2]) {
        let [cj, cj1] = *blocks;
        self.perm.decrypt_2blocks(blocks);

        let [pj, pj1] = blocks;
        for (b, chain) in pj.iter_mut().zip(self.chain.iter()) {
            *b ^= *chain; // XOR Cj-1
        }
        for (b, prev) in pj1.iter_mut().zip(cj.iter()) {
            *b ^= *prev; // XOR Cj
        }

        self.chain = cj1;
    }

    /// Decrypts four consecutive blocks with one [`ElectronicCodeBook::decrypt_4blocks`] call.
    ///
    /// The same argument as [`Self::decrypt_pair`], four wide: `Pj+k = CIPH^-1_K(Cj+k) XOR Cj+k-1`
    /// for `k = 0..4`, with `Cj-1` the incoming chaining value. No inverse cipher depends on
    /// another's output, so all four run together; the ciphertexts are copied out first because
    /// the permutation overwrites them and each is the next block's XOR operand, and the chaining
    /// value advances to `Cj+3`.
    #[inline]
    fn decrypt_four(&mut self, blocks: &mut [[u8; BLOCK_LEN]; 4]) {
        let cts = *blocks;
        self.perm.decrypt_4blocks(blocks);

        let mut prev = self.chain;
        for (pj, cj) in blocks.iter_mut().zip(cts.iter()) {
            for (b, chain) in pj.iter_mut().zip(prev.iter()) {
                *b ^= *chain; // XOR Cj+k-1
            }
            prev = *cj;
        }
        self.chain = prev;
    }
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for Cbc<P, Dir, KEY_LEN, BLOCK_LEN>
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
    BlockCipherEncryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN> for Cbc<P, Encrypting, KEY_LEN, BLOCK_LEN>
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

    /// As [`BlockCipherEncryptor::do_encrypt_init`], but takes the IV from the provided RNG.
    fn do_encrypt_init_rng(
        key: &KeyMaterial<KEY_LEN>,
        rng: &mut dyn RNG,
    ) -> Result<(Self, [u8; BLOCK_LEN]), SymmetricCipherError> {
        let perm = P::new(key)?;
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((Self { perm, chain: iv, _dir: PhantomData }, iv))
    }

    /// The implementor hook (the flat `do_encrypt` is provided over it).
    ///
    /// Strictly serial: `Cj` is the input to block `j + 1`, so there is no pair path here. See the
    /// module docs. Never fails: CBC has no per-IV data limit.
    fn do_encrypt_blocks(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError> {
        for block in blocks.iter_mut() {
            self.encrypt_one(block);
        }
        Ok(blocks.len() * BLOCK_LEN)
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    BlockCipherDecryptor<KEY_LEN, BLOCK_LEN, BLOCK_LEN> for Cbc<P, Decrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
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

    /// The implementor hook (the flat `do_decrypt` is provided over it).
    ///
    /// Walks the input in fours through `decrypt_4blocks`, then pairs through `decrypt_2blocks`,
    /// then the at-most-one block left over: Sec 6.2's parallelism, in the units the permutation
    /// offers. `as_chunks_mut` splits into exactly those shapes with no runtime length check and no
    /// indexing arithmetic. Never fails: CBC has no per-IV data limit.
    fn do_decrypt_blocks(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError> {
        let len = blocks.len() * BLOCK_LEN;
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        for four in fours.iter_mut() {
            self.decrypt_four(four);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.decrypt_pair(pair);
        }
        for block in tail.iter_mut() {
            self.decrypt_one(block);
        }
        Ok(len)
    }
}

/// The suspended state is the chaining block `Cj-1`, in both directions; the permutation is
/// rebuilt from the re-supplied key. See [`bouncycastle_utils::suspendable_state`].
impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> SuspendableComponent
    for Cbc<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN>,
{
    const STATE_LEN: usize = BLOCK_LEN;
    type Key = KeyMaterial<KEY_LEN>;

    fn write_state(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.chain);
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        let perm = P::new(key).map_err(|_| SuspendableError::InvalidData)?;
        let mut chain = [0u8; BLOCK_LEN];
        chain.copy_from_slice(state);
        Ok(Self { perm, chain, _dir: PhantomData })
    }
}

/// `N` must be [`Cbc::SUSPENDED_STATE_LEN`]; anything else is a compile error.
impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize, const N: usize> SuspendableKeyed<N>
    for Cbc<P, Dir, KEY_LEN, BLOCK_LEN>
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
