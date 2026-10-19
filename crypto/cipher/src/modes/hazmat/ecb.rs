//! The Electronic Codebook mode of operation (NIST SP 800-38A Sec 6.1).
//!
//! **🚨 Security note: 🚨 ECB is not a confidentiality mode for data.** That is why it is under
//! [`hazmat`](crate::modes::hazmat); see [`bouncycastle_core::hazmat`] for the supported uses.
//!
//! "In ECB encryption, the forward cipher function is applied directly and independently to each
//! block of the plaintext. The resulting sequence of output blocks is the ciphertext. In ECB
//! decryption, the inverse cipher function is applied directly and independently to each block of
//! the ciphertext. The resulting sequence of output blocks is the plaintext."
//!
//! # Usage Examples
//!
//! ECB has the same shape with no IV and no RNG: a key bound to [`ECB<Blocks>`] (the `hazmat`
//! role pair) hands out its workers infallibly, and [`ECB<Pad>`](ECB) puts the padded form on the
//! symmetric pair with an empty init array. The codebook property that makes it unsuitable for
//! data is visible in the ciphertext:
//!
//! ```
//! # mod toy { include!("../../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_core::hazmat::{EcbDecryptMode, EcbEncryptMode, ElectronicCodeBook, Mode};
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::{BlockCipherDecryptor, BlockCipherEncryptor};
//! use bouncycastle_cipher::modes::hazmat::ECB;
//! use bouncycastle_cipher::modes::Blocks;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let state = <ECB<Blocks> as Mode<ToyBlockCipher>>::key_state(ToyBlockCipher::new(&key).unwrap());
//! let mut data = [0x5Au8; 32]; // two equal blocks
//!
//! ECB::<Blocks>::encrypt_init(&state).do_encrypt_inplace(&mut data).expect("encryption");
//! assert_eq!(data[..16], data[16..], "equal plaintext blocks give equal ciphertext blocks");
//!
//! ECB::<Blocks>::decrypt_init(&state).do_decrypt_inplace(&mut data).expect("decryption");
//! assert_eq!(data, [0x5Au8; 32]);
//! ```
//!
//! # A mode with no state
//!
//! This mode is a fixed permutation determined by the key acting on a single block.
//! There is no IV and no chaining.
//!
//! # Both directions are parallel
//!
//! Sec 6.1: "In ECB encryption and ECB decryption, multiple forward cipher functions and inverse
//! cipher functions can be computed in parallel".
//!
//! To take advantage of this parallelism, this mode batches both directions through the
//! permutation's four-block and pair methods ([`ElectronicCodeBook::encrypt_4blocks`] /
//! [`ElectronicCodeBook::encrypt_2blocks`] and their inverses), which may represent a speed-up over
//! iterating one block at a time, depending on the implementation of the underlying cipher.
//!
//! # Suspending and resuming execution
//!
//! [`Ecb`] implements [`SuspendableKeyed`], so a message in progress can be suspended to a byte
//! array and resumed later with the re-supplied key. The state is empty, since nothing carries over
//! between blocks, and resuming is re-expanding the key; it exists so the padded adapters over ECB
//! can be suspended. The array length is `Ecb::SUSPENDED_STATE_LEN`; see [the crate
//! docs](crate#suspending-and-resuming-execution) for an example.
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## ECB is a building-block not a confidentiality mode for data
//!
//! SP 800-38A §6.1:
//!
//! > "In the ECB mode, under a given key, any given plaintext block always gets
//! > encrypted to the same ciphertext block. If this property is undesirable in a particular
//! > application, the ECB mode should not be used."
//!
//! While this _might_ be secure for encrypting plaintext that is cryptographically random,
//! it is certainly not ok for structured data (such as any file format with known and predictable
//! headers), or data with repeated blocks since it becomes trivial for an attacker to build lookup
//! tables of plaintext --> ciphertext pairs under this encryption key. ECB mode also does not prevent
//! an attacker from reordering, duplicating, or deleting blocks within a multi-block ciphertext or
//! between multiple messages encrypted under the same key.
//!
//! As such, ECB is exposed primarily as a building-block for the other, more secure, modes of
//! operation, and also for research and educational purposes.
//!
//! **ECB Mode should not be used in production!**

use crate::modes::{Blocks, ModeNames};
use crate::padding::{PaddedBlockCipherDecryptor, PaddedBlockCipherEncryptor};
use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{SuspendableError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    EcbDecryptMode, EcbEncryptMode, ElectronicCodeBook, Mode, SymmetricDecryptMode,
    SymmetricEncryptMode,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{
    Algorithm, BlockCipherDecryptor, BlockCipherEncryptor, BlockCipherPadding, RNG,
    SuspendableKeyed,
};
use bouncycastle_utils::suspendable_state::{
    LIB_VERSION_LEN, SuspendableComponent, resume_component, suspend_component,
};
use core::marker::PhantomData;

/// The ECB mode type: the `M` of a mode-bound key such as `AES128Key<ECB<Blocks>>`. `X` is
/// [`Blocks`], which puts the key on the ECB key path of [`bouncycastle_core::hazmat`] with
/// [`Ecb`] itself as its worker, or a padding scheme, which puts it on the symmetric path with
/// the padded adapter over `Ecb`; that path's constructor takes an RNG, which ECB, having no init
/// data, draws nothing from. Its key state is the keyed permutation alone.
///
/// **Not a confidentiality mode for data**, whichever form; see [`Ecb`].
pub struct ECB<X>(core::marker::PhantomData<X>);

impl<P: Clone + ModeNames, X> Mode<P> for ECB<X> {
    type KeyState = P;
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;
    const ALG_NAME: &'static str = P::ECB_ALG_NAME;

    fn key_state(perm: P) -> Self::KeyState {
        perm
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> EcbEncryptMode<P, KEY_LEN, BLOCK_LEN>
    for ECB<Blocks>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    type Encryptor = Ecb<P, Encrypting, KEY_LEN, BLOCK_LEN>;

    fn encrypt_init(state: &Self::KeyState) -> Self::Encryptor {
        Ecb::from_perm(state.clone())
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> EcbDecryptMode<P, KEY_LEN, BLOCK_LEN>
    for ECB<Blocks>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
{
    type Decryptor = Ecb<P, Decrypting, KEY_LEN, BLOCK_LEN>;

    fn decrypt_init(state: &Self::KeyState) -> Self::Decryptor {
        Ecb::from_perm(state.clone())
    }
}

impl<P, Pad, const KEY_LEN: usize, const BLOCK_LEN: usize>
    SymmetricEncryptMode<P, KEY_LEN, 0, BLOCK_LEN> for ECB<Pad>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
    Pad: BlockCipherPadding<BLOCK_LEN>,
{
    type Encryptor = PaddedBlockCipherEncryptor<
        Ecb<P, Encrypting, KEY_LEN, BLOCK_LEN>,
        Pad,
        KEY_LEN,
        0,
        BLOCK_LEN,
    >;

    /// ECB has no init data, so nothing is drawn from `rng` and the init data is the empty
    /// array.
    fn encrypt_init(
        state: &Self::KeyState,
        _rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor, [u8; 0]), SymmetricCipherError> {
        Ok((PaddedBlockCipherEncryptor::from_inner(Ecb::from_perm(state.clone())), []))
    }
}

impl<P, Pad, const KEY_LEN: usize, const BLOCK_LEN: usize>
    SymmetricDecryptMode<P, KEY_LEN, 0, BLOCK_LEN> for ECB<Pad>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames + Clone,
    Pad: BlockCipherPadding<BLOCK_LEN>,
{
    type Decryptor = PaddedBlockCipherDecryptor<
        Ecb<P, Decrypting, KEY_LEN, BLOCK_LEN>,
        Pad,
        KEY_LEN,
        0,
        BLOCK_LEN,
    >;

    fn decrypt_init(state: &Self::KeyState, _init_data: &[u8; 0]) -> Self::Decryptor {
        PaddedBlockCipherDecryptor::from_inner(Ecb::from_perm(state.clone()))
    }
}

/// ECB mode over any permutation that impls [`ElectronicCodeBook`], with the direction encoded in the type.
///
/// **Not a confidentiality mode for data**: see the module docs and [`modes`](crate::modes)'s "Security
/// Considerations". Provided for interoperability and test vectors.
///
/// `Dir` is [`Encrypting`] or [`Decrypting`]. [`BlockCipherEncryptor`] is implemented only for the
/// former and [`BlockCipherDecryptor`] only for the latter, so an `Ecb<_, Encrypting, _, _>` has no
/// decryption methods at all -- using one in the wrong direction is a compile error rather than a
/// runtime check.
///
/// # State
/// Only the permutation, which owns the key schedule and is responsible for keeping it in a
/// zeroize-on-drop wrapper. Nothing chains from one block to the next, so unlike `Cbc` and `Cfb`
/// there is no block of chaining value: `size_of::<Ecb<P, ..>>() == size_of::<P>()`.
#[derive(Clone)]
pub struct Ecb<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    perm: P,
    _dir: PhantomData<Dir>,
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Ecb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    /// The `N` of this type's [`SuspendableKeyed<N>`] impl: the version header alone, since ECB
    /// has no state between blocks. See [`bouncycastle_utils::suspendable_state`].
    pub const SUSPENDED_STATE_LEN: usize = LIB_VERSION_LEN;

    /// Expands the key. Both `_init` constructors are this; there is nothing else to set up.
    fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        key.check_algorithm(Self::ALG_NAME)?;
        Ok(Self::from_perm(P::new(key)?))
    }

    /// Over an already-keyed permutation: what the [`ECB`] mode impls build.
    pub(crate) fn from_perm(perm: P) -> Self {
        Self { perm, _dir: PhantomData }
    }
}

impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> Algorithm
    for Ecb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    /// The permutation's name for this mode, [`ModeNames::ECB_ALG_NAME`].
    const ALG_NAME: &'static str = P::ECB_ALG_NAME;
    /// A mode does not change the strength of the underlying cipher. (It does not make ECB
    /// suitable for data either; strength is about the key, not about the codebook property.)
    const MAX_SECURITY_STRENGTH: SecurityStrength = P::MAX_SECURITY_STRENGTH;
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> BlockCipherEncryptor<0, BLOCK_LEN>
    for Ecb<P, Encrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    /// The implementor hook (the flat `do_encrypt_inplace` is provided over it):
    /// `Cj = CIPH_K(Pj)` for every block, in place.
    ///
    /// Sec 6.1 allows the forward cipher functions to "be computed in parallel", so the blocks go
    /// to the permutation in fours, then pairs, then the remaining block singly. `as_chunks_mut`
    /// splits into exactly those shapes with no runtime length check. Never fails: ECB has no
    /// per-initialization data limit.
    fn do_encrypt_blocks_inplace(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError> {
        let len = blocks.len() * BLOCK_LEN;
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        for four in fours.iter_mut() {
            self.perm.encrypt_4blocks(four);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.perm.encrypt_2blocks(pair);
        }
        for block in tail.iter_mut() {
            self.perm.encrypt_block(block);
        }
        Ok(len)
    }
}

impl<P, const KEY_LEN: usize, const BLOCK_LEN: usize> BlockCipherDecryptor<0, BLOCK_LEN>
    for Ecb<P, Decrypting, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    /// The implementor hook (the flat `do_decrypt_inplace` is provided over it):
    /// `Pj = CIPH^-1_K(Cj)` for every block, in place -- fours, then pairs, then the remaining
    /// block, as on the encrypt side. Never fails.
    fn do_decrypt_blocks_inplace(
        &mut self,
        blocks: &mut [[u8; BLOCK_LEN]],
    ) -> Result<usize, SymmetricCipherError> {
        let len = blocks.len() * BLOCK_LEN;
        let (fours, rest) = blocks.as_chunks_mut::<4>();
        for four in fours.iter_mut() {
            self.perm.decrypt_4blocks(four);
        }
        let (pairs, tail) = rest.as_chunks_mut::<2>();
        for pair in pairs.iter_mut() {
            self.perm.decrypt_2blocks(pair);
        }
        for block in tail.iter_mut() {
            self.perm.decrypt_block(block);
        }
        Ok(len)
    }
}

/// ECB carries nothing from one block to the next, so its suspended state is empty and resuming
/// is re-expanding the key. It is implemented so that the padded adapters over it, which do hold
/// a partial block, can be suspended. See [`bouncycastle_utils::suspendable_state`].
impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize> SuspendableComponent
    for Ecb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    const STATE_LEN: usize = 0;
    type Key = KeyMaterial<KEY_LEN>;

    fn write_state(&self, out: &mut [u8]) {
        debug_assert!(out.is_empty());
    }

    fn read_state(state: &[u8], key: &Self::Key) -> Result<Self, SuspendableError> {
        debug_assert!(state.is_empty());
        Self::new(key).map_err(|_| SuspendableError::InvalidData)
    }
}

/// `N` must be [`Ecb::SUSPENDED_STATE_LEN`]; anything else is a compile error.
impl<P, Dir, const KEY_LEN: usize, const BLOCK_LEN: usize, const N: usize> SuspendableKeyed<N>
    for Ecb<P, Dir, KEY_LEN, BLOCK_LEN>
where
    P: ElectronicCodeBook<KEY_LEN, BLOCK_LEN> + ModeNames,
{
    type Key = KeyMaterial<KEY_LEN>;

    fn suspend(self) -> [u8; N] {
        suspend_component(&self)
    }

    fn from_suspended(state: [u8; N], key: &Self::Key) -> Result<Self, SuspendableError> {
        resume_component(&state, key)
    }
}
