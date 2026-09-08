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
//! [`BlockPermutation::decrypt_4blocks`], then any remaining pair through
//! [`BlockPermutation::decrypt_2blocks`], then the last block singly. A bit-sliced engine
//! computes two or four blocks (AES, on `u32` or `u64` planes) for barely more than the cost of
//! one. Encryption cannot, and does not.
//!
//! # Usage Examples
//!
//! The direction is part of the type: [`Cbc<'k, P, Encrypting, ..>`](Cbc) implements
//! [`BlockCipherEncryptor`] and nothing else, and [`Cbc<'k, P, Decrypting, ..>`](Cbc) implements
//! [`BlockCipherDecryptor`] and nothing else.
//! The IV is drawn from the RNG and returned; there is no API for supplying one.
//!
//! The pair is reached through a mode-bound key -- [`CBC<Blocks>`] on a key type such as
//! `bouncycastle_aes::AES128Key<CBC<Blocks>>` for whole blocks, [`CBC<Pad>`](CBC) for the padded
//! form -- whose role traits carry the one-shots. The key holds the mode's key state and calls the
//! mode traits shown here, which is the route over the toy permutation:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_core::hazmat::{BlockDecryptMode, BlockEncryptMode, ElectronicCodeBook, Mode};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_cipher::modes::{Blocks, CBC};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let state = <CBC<Blocks> as Mode<ToyBlockCipher>>::key_state(ToyBlockCipher::new(&key).unwrap());
//! let mut rng = HashDRBG_SHA512::new_from_os();
//!
//! // Three whole blocks: the workers take `&mut [[u8; 16]]`, so a partial block cannot be
//! // expressed.
//! let plaintext: [[u8; 16]; 3] =
//!     [*b"The quick brown ", *b"fox jumps over t", *b"he lazy dog. OK!"];
//!
//! // In place, under a freshly drawn IV, which is returned.
//! let mut data = plaintext;
//! let (mut enc, iv) = CBC::<Blocks>::encrypt_init(&state, &mut rng).expect("iv draw");
//! enc.do_encrypt_blocks_inplace(&mut data).expect("encryption");
//! assert_ne!(data, plaintext);
//!
//! CBC::<Blocks>::decrypt_init(&state, &iv).do_decrypt_blocks_inplace(&mut data).expect("decryption");
//! assert_eq!(data, plaintext);
//! ```
//!
//! Streaming, for data that arrives in pieces. A sequence of calls is equivalent to one call over
//! the concatenation:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_core::hazmat::{BlockDecryptMode, BlockEncryptMode, ElectronicCodeBook, Mode};
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_cipher::modes::{Blocks, CBC};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let key = KeyMaterial128::from_bytes_as_type(&[0x07; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let state = <CBC<Blocks> as Mode<ToyBlockCipher>>::key_state(ToyBlockCipher::new(&key).unwrap());
//!
//! let (mut encryptor, iv) =
//!     CBC::<Blocks>::encrypt_init(&state, &mut HashDRBG_SHA512::new_from_os()).expect("iv draw");
//! let mut first = [[0xAAu8; 16]];
//! let mut rest = [[0xBBu8; 16]; 2];
//! encryptor.do_encrypt_blocks_inplace(&mut first).expect("block 1");
//! encryptor.do_encrypt_blocks_inplace(&mut rest).expect("blocks 2-3");
//!
//! let mut decryptor = CBC::<Blocks>::decrypt_init(&state, &iv);
//! decryptor.do_decrypt_blocks_inplace(&mut first).unwrap();
//! decryptor.do_decrypt_blocks_inplace(&mut rest).unwrap();
//! assert_eq!(first, [[0xAAu8; 16]]);
//! assert_eq!(rest, [[0xBBu8; 16]; 2]);
//! ```
//!
//! # Suspending and resuming execution
//!
//! [`Cbc`] implements [`SuspendableKeyed`], so a message in progress can be suspended to a byte
//! array and resumed later over the re-supplied key state. The state is the chaining block; the
//! permutation is the key's. The array length is `Cbc::SUSPENDED_STATE_LEN`; see [the
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
use crate::modes::{Blocks, ModeNames};
use crate::padding::{PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    BlockDecryptMode, BlockEncryptMode, BlockPermutation, ElectronicCodeBook, Mode,
    SymmetricDecryptMode, SymmetricEncryptMode,
};
use bouncycastle_core::key_material::KeyType;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, BlockCipherPadding, RNG,
    SuspendableKeyed,
};
use bouncycastle_utils::suspendable_state::{
    LIB_VERSION_LEN, SuspendableComponent, resume_component, suspend_component,
};
use core::marker::PhantomData;

/// The CBC mode type: the `M` of a mode-bound key such as `AES128Key<CBC<PKCS7>>`. `X` is the
/// padding scheme, which puts the key on the symmetric path with the padded adapter as its
/// worker, or [`Blocks`], which puts it on the block path with [`Cbc`] itself. Its key state is
/// the keyed permutation alone: CBC derives nothing from the key.
///
/// [`PKCS7`]: crate::padding::PKCS7
pub struct CBC<X>(core::marker::PhantomData<X>);

impl<P: Clone + ModeNames, X> Mode<P> for CBC<X> {
    type KeyState = P;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    fn key_state(perm: P) -> Self::KeyState {
        perm
    }
}

impl<P, Pad, const KEY_LEN: usize, const BLOCK_LEN: usize>
    SymmetricEncryptMode<P, KEY_LEN, BLOCK_LEN, BLOCK_LEN> for CBC<Pad>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
    Pad: BlockCipherPadding<BLOCK_LEN>,
{
    type Encryptor<'k>
        = PaddedBlockCipherEncryptor<Cbc<'k, P, Encrypting, BLOCK_LEN>, Pad, BLOCK_LEN, BLOCK_LEN>
    where
        P: 'k;

    fn encrypt_init<'k>(
        state: &'k Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; BLOCK_LEN]), SymmetricCipherError> {
        const {
            assert!(
                P::ENCRYPTION_APPROVED,
                "this permutation is approved for decryption only (ElectronicCodeBook::ENCRYPTION_APPROVED is false)"
            )
        };
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((PaddedBlockCipherEncryptor::from_inner(Cbc::from_perm(state, iv)), iv))
    }
}

impl<P, Pad, const KEY_LEN: usize, const BLOCK_LEN: usize>
    SymmetricDecryptMode<P, KEY_LEN, BLOCK_LEN, BLOCK_LEN> for CBC<Pad>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
    Pad: BlockCipherPadding<BLOCK_LEN>,
{
    type Decryptor<'k>
        = PaddedBlockCipherDecryptor<Cbc<'k, P, Decrypting, BLOCK_LEN>, Pad, BLOCK_LEN, BLOCK_LEN>
    where
        P: 'k;

    fn decrypt_init<'k>(
        state: &'k Self::KeyState,
        init_data: &[u8; BLOCK_LEN],
    ) -> Self::Decryptor<'k> {
        PaddedBlockCipherDecryptor::from_inner(Cbc::from_perm(state, *init_data))
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    BlockEncryptMode<P, KEY_LEN, BLOCK_LEN, BLOCK_LEN> for CBC<Blocks>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    type Encryptor<'k>
        = Cbc<'k, P, Encrypting, BLOCK_LEN>
    where
        P: 'k;

    fn encrypt_init<'k>(
        state: &'k Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; BLOCK_LEN]), SymmetricCipherError> {
        const {
            assert!(
                P::ENCRYPTION_APPROVED,
                "this permutation is approved for decryption only (ElectronicCodeBook::ENCRYPTION_APPROVED is false)"
            )
        };
        let iv = random_iv::<BLOCK_LEN>(rng)?;
        Ok((Cbc::from_perm(state, iv), iv))
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize>
    BlockDecryptMode<P, KEY_LEN, BLOCK_LEN, BLOCK_LEN> for CBC<Blocks>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    type Decryptor<'k>
        = Cbc<'k, P, Decrypting, BLOCK_LEN>
    where
        P: 'k;

    fn decrypt_init<'k>(
        state: &'k Self::KeyState,
        init_data: &[u8; BLOCK_LEN],
    ) -> Self::Decryptor<'k> {
        Cbc::from_perm(state, *init_data)
    }
}

/// CBC mode over any [`ElectronicCodeBook`], with the direction encoded in the type.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`BlockCipherEncryptor`] is implemented only for the
/// former and [`BlockCipherDecryptor`] only for the latter, so a `Cbc<'k, _, Encrypting, _, _>` has no
/// decryption methods at all -- using one in the wrong direction is a compile error rather than a
/// runtime check.
///
/// The initialization data is one block, so `INIT_DATA_LEN == BLOCK_LEN`.
///
/// # State
///
/// Two fields: a reference to the permutation, whose key schedule stays in the key, and one block
/// of chaining value. The chaining value is an IV or a
/// ciphertext block, both of which are public, so it is deliberately not wrapped in a `Secret`.
#[derive(Clone)]
pub struct Cbc<'k, P, Dir, const BLOCK_LEN: usize>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    perm: &'k P,
    /// `Cj-1`, initialised to the IV. See the module docs on why there is only one field for both.
    chain: [u8; BLOCK_LEN],
    _dir: PhantomData<Dir>,
}

impl<'k, P, Dir, const BLOCK_LEN: usize> Cbc<'k, P, Dir, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// The `N` of this type's [`SuspendableKeyed<'k, N>`] impl: the version header and the chaining
    /// block. See [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize = LIB_VERSION_LEN + BLOCK_LEN;

    /// `C0 = IV`, over an already-keyed permutation: what the [`CBC`] mode impls build.
    pub(crate) fn from_perm(perm: &'k P, iv: [u8; BLOCK_LEN]) -> Self {
        Self { perm, chain: iv, _dir: PhantomData }
    }

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

    /// Decrypts two consecutive blocks with one [`BlockPermutation::decrypt_2blocks`] call.
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

    /// Decrypts four consecutive blocks with one [`BlockPermutation::decrypt_4blocks`] call.
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

impl<'k, P, Dir, const BLOCK_LEN: usize> Algorithm for Cbc<'k, P, Dir, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// The permutation's name for this mode, [`ModeNames::CBC_ALG_NAME`].
    const ALG_NAME: &'static str = P::CBC_ALG_NAME;
    /// A mode does not change the strength of the underlying cipher.
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<'k, P, const BLOCK_LEN: usize> BlockCipherEncryptor<BLOCK_LEN, BLOCK_LEN>
    for Cbc<'k, P, Encrypting, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// The implementor hook.
    ///
    /// Strictly serial: `Cj` is the input to block `j + 1`, so there is no pair path here. See the
    /// module docs. Never fails: CBC has no per-IV data limit.
    fn do_encrypt_blocks_inplace(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError> {
        for block in blocks.iter_mut() {
            self.encrypt_one(block);
        }
        Ok(blocks.len() * BLOCK_LEN)
    }
}

impl<'k, P, const BLOCK_LEN: usize> BlockCipherDecryptor<BLOCK_LEN, BLOCK_LEN>
    for Cbc<'k, P, Decrypting, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    /// The implementor hook.
    ///
    /// Walks the input in fours through `decrypt_4blocks`, then pairs through `decrypt_2blocks`,
    /// then the at-most-one block left over: Sec 6.2's parallelism, in the units the permutation
    /// offers. `as_chunks_mut` splits into exactly those shapes with no runtime length check and no
    /// indexing arithmetic. Never fails: CBC has no per-IV data limit.
    fn do_decrypt_blocks_inplace(
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

/// The suspended state is the chaining block `Cj-1`, in both directions; the permutation is the
/// key's, re-supplied by reference. See [`bouncycastle_utils::suspendable_state`].
impl<'k, P, Dir, const BLOCK_LEN: usize> SuspendableComponent<'k> for Cbc<'k, P, Dir, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    const STATE_LEN: usize = BLOCK_LEN;
    type Key = P;

    fn write_state(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.chain);
    }

    fn read_state(state: &[u8], key: &'k Self::Key) -> Result<Self, SuspendableError> {
        let perm = key;
        let mut chain = [0u8; BLOCK_LEN];
        chain.copy_from_slice(state);
        Ok(Self { perm, chain, _dir: PhantomData })
    }
}

/// `N` must be [`Cbc::SUSPENDED_STATE_LEN`]; anything else is a compile error.
impl<'k, P, Dir, const BLOCK_LEN: usize, const N: usize> SuspendableKeyed<'k, N>
    for Cbc<'k, P, Dir, BLOCK_LEN>
where
    P: BlockPermutation<BLOCK_LEN> + ModeNames,
{
    type Key = P;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    /// The state carries no direction: one suspended by the other direction's worker is accepted
    /// and resumes over the same chaining value, which gives wrong output rather than an error.
    /// Only GCM, whose state means different things per direction, refuses the other one.
    fn from_suspended(state: [u8; N], key: &'k Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}
