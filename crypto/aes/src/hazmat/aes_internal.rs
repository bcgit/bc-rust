//! The raw AES permutation: CIPHER() and INVCIPHER() (FIPS 197 Sec 5.1 and Sec 5.3).
//!
//! Under [`hazmat`](crate::hazmat) because [`AESInternal`] transforms exactly one block: it is
//! the primitive under the modes in this crate, not a cipher for data.
//!
//! # Usage Examples
//!
//! ## Encrypting and decrypting a single block
//!
//! ```
//! use bouncycastle_aes::hazmat::AES128Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! let aes = AES128Internal::new(&key).expect("a valid AES-128 key");
//!
//! // Sample plaintext from FIPS 197 Appendix B.
//! let mut block: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//!                            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
//! aes.encrypt_block(&mut block);
//!
//! // `block` now contains the ciphertext.
//! // Double-check it against the sample ciphertext from FIPS 197 Appdx B.
//! assert_eq!(block, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
//!                    0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);
//!
//! // The same value decrypts, from the same instantiated aes object.
//! aes.decrypt_block(&mut block);
//!
//! // `block` now contains the original plaintext again.
//! assert_eq!(block, [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//!                    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34]);
//! ```
//!
//! ## Two or four blocks at a time
//!
//! The bit-sliced state is generic over its word width, and each 16 bits of width holds one
//! block: `u16` planes hold one block, `u32` planes two and `u64` planes four (see the
//! `bitslice` module in the source). The round functions cost about the same whatever the
//! width, so on a 64-bit machine four independent blocks cost little more than one. Where a
//! caller has them, [`BlockPermutation::encrypt_4blocks`] is 3.0x the throughput of four
//! [`BlockPermutation::encrypt_block`] calls on x86-64 (3.7x for decryption), and
//! [`BlockPermutation::encrypt_2blocks`] 1.75x that of two (1.95x for decryption); the crate
//! docs have the table and the benches record the numbers:
//!
//! ```
//! use bouncycastle_aes::hazmat::AES256Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
//!
//! let key = KeyMaterial::<32>::from_bytes_as_type(&[0x01; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let aes = AES256Internal::new(&key).expect("a valid AES-256 key");
//!
//! let mut pair = [[0u8; 16], [1u8; 16]];
//! aes.encrypt_2blocks(&mut pair);
//! aes.decrypt_2blocks(&mut pair);
//! assert_eq!(pair, [[0u8; 16], [1u8; 16]]);
//!
//! let mut four = [[0u8; 16], [1u8; 16], [2u8; 16], [3u8; 16]];
//! aes.encrypt_4blocks(&mut four);
//! aes.decrypt_4blocks(&mut four);
//! assert_eq!(four, [[0u8; 16], [1u8; 16], [2u8; 16], [3u8; 16]]);
//! ```

use crate::bitslice::Block;
use crate::hazmat::engine::{DefaultEngine, Engine};
use crate::{AES128Params, AES192Params, AES256Params, AESParams};
use bouncycastle_cipher::modes::ModeNames;
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
use core::marker::PhantomData;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::hazmat::ElectronicCodeBook;
#[allow(unused_imports)]
use bouncycastle_utils::secret::Secret;
// End imports needed for docs

/// The AES keyed permutation, parameterised by key length.
///
/// Use the aliases [`AES128Internal`], [`AES192Internal`] and [`AES256Internal`] rather than naming this directly.
/// `P` is sealed to the three parameter sets of FIPS 197 Table 3, so no fourth instantiation
/// exists.
///
/// The only state is the key schedule, held by the engine `E` in a [`Secret`] so that it is
/// zeroized on drop and redacted from `Debug`. There is no direction flag and no initialisation
/// state: a constructed value is always ready to use in either direction, so there is no
/// `init()` or `reset()`.
///
/// `E` is the [`Engine`] that expands the key and runs the rounds. It defaults to
/// [`DefaultEngine`], which is the right choice unless a test compares engines or a caller has a
/// reason to pin one; see [`crate::hazmat::engine`].
pub struct AESInternal<P: AESParams, E: Engine<P> = DefaultEngine<P>> {
    engine: E,
    _params: PhantomData<P>,
}

// Written out rather than derived: a derive would demand `P: Clone` of the parameter-set marker.
impl<P: AESParams, E: Engine<P>> Clone for AESInternal<P, E> {
    fn clone(&self) -> Self {
        Self { engine: self.engine.clone(), _params: PhantomData }
    }
}

// Written out rather than derived so that `P`, a marker type, need not be `PartialEq`. Equality
// is the engine's, which is over the expanded key and decided in constant time (see [`Engine`]).
impl<P: AESParams, E: Engine<P>> PartialEq for AESInternal<P, E> {
    fn eq(&self, other: &Self) -> bool {
        self.engine == other.engine
    }
}

impl<P: AESParams, E: Engine<P>> Eq for AESInternal<P, E> {}

/// AES-128: 16-byte key, 10 rounds (FIPS 197 Table 3).
#[allow(non_camel_case_types)]
pub type AES128Internal = AESInternal<AES128Params>;
/// AES-192: 24-byte key, 12 rounds (FIPS 197 Table 3).
#[allow(non_camel_case_types)]
pub type AES192Internal = AESInternal<AES192Params>;
/// AES-256: 32-byte key, 14 rounds (FIPS 197 Table 3).
#[allow(non_camel_case_types)]
pub type AES256Internal = AESInternal<AES256Params>;

impl<P: AESParams, E: Engine<P>> AESInternal<P, E> {
    /// Checks a key is fit to use before it is expanded.
    ///
    /// The key must be tagged [`KeyType::SymmetricCipherKey`], must be exactly `P::KEY_LEN` bytes
    /// of the buffer, and must carry a [`SecurityStrength`] at least equal to its own length --
    /// which is what a key of this length from a correctly-instantiated RNG or KDF will have.
    /// The checks exist to catch a key that arrived from somewhere it should not have: a seed
    /// reused as a cipher key, or a 32-byte buffer holding material only derived at the 128-bit
    /// strength.
    ///
    /// Takes `&dyn KeyMaterialTrait` so the three constructors, whose `KeyMaterial<N>` capacities
    /// differ, can share one implementation.
    fn validate(key: &dyn KeyMaterialTrait) -> Result<(), SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "AES requires a key of type KeyType::SymmetricCipherKey.",
            )
            .into());
        }
        if key.key_len() != P::KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        if key.security_strength() < SecurityStrength::from_bytes(P::KEY_LEN) {
            return Err(KeyMaterialError::SecurityStrength(
                "The provided key has a lower security strength than the AES key length implies.",
            )
            .into());
        }
        Ok(())
    }

    /// Encrypts one block in place.
    ///
    /// This is the right call when only one block is available -- CBC and CFB encryption, whose
    /// blocks are serially dependent. Where two or four independent blocks are available, which
    /// for a mode of operation means CTR or the decryption direction of CBC and CFB, prefer
    /// [`Self::encrypt_2blocks`] or [`Self::encrypt_4blocks`]: every [`Engine`] runs them for
    /// little more than the cost of one block.
    ///
    /// Infallible: a constructed [`AESInternal`] is always usable and every input length is fixed.
    pub(crate) fn encrypt_block(&self, block: &mut Block) {
        self.engine.encrypt_block(block);
    }

    /// Decrypts one block in place. See [`Self::encrypt_block`].
    pub(crate) fn decrypt_block(&self, block: &mut Block) {
        self.engine.decrypt_block(block);
    }

    /// Encrypts two independent blocks in place. See [`Self::encrypt_block`] for when to use
    /// which.
    pub(crate) fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        self.engine.encrypt_2blocks(blocks);
    }

    /// Decrypts two independent blocks in place. See [`Self::encrypt_block`].
    pub(crate) fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        self.engine.decrypt_2blocks(blocks);
    }

    /// Encrypts four independent blocks in place. See [`Self::encrypt_block`] for when to use
    /// which.
    pub(crate) fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        self.engine.encrypt_4blocks(blocks);
    }

    /// Decrypts four independent blocks in place. See [`Self::encrypt_block`].
    pub(crate) fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        self.engine.decrypt_4blocks(blocks);
    }
}

// The three constructors and `Algorithm` impls below are written out longhand rather than
// generated with `macro_rules!`: `cargo mutants` cannot see into macro bodies, so a macro would
// hide the key checks and the security-strength constants from mutation testing (see CLAUDE.md).
// Each `new` differs only in the `KeyMaterial<N>` capacity it accepts, which is what makes a
// wrong-length key a compile error at the call site rather than a runtime error.

impl<E: Engine<AES128Params>> AESInternal<AES128Params, E> {
    /// Expands a 16-byte key into an AES-128 schedule.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not [`KeyType::SymmetricCipherKey`].
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    pub(crate) fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        // `validate` has checked the length, so this cannot fail; it maps to the same error
        // rather than panicking.
        let key: &[u8; 16] =
            key.ref_to_bytes().try_into().map_err(|_| KeyMaterialError::InvalidLength)?;
        Ok(Self { engine: E::expand(key), _params: PhantomData })
    }
}

impl<E: Engine<AES192Params>> AESInternal<AES192Params, E> {
    /// Expands a 24-byte key into an AES-192 schedule. See [`AES128Internal::new`] for the error cases.
    pub(crate) fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        // `validate` has checked the length, so this cannot fail; it maps to the same error
        // rather than panicking.
        let key: &[u8; 24] =
            key.ref_to_bytes().try_into().map_err(|_| KeyMaterialError::InvalidLength)?;
        Ok(Self { engine: E::expand(key), _params: PhantomData })
    }
}

impl<E: Engine<AES256Params>> AESInternal<AES256Params, E> {
    /// Expands a 32-byte key into an AES-256 schedule. See [`AES128Internal::new`] for the error cases.
    pub(crate) fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        // `validate` has checked the length, so this cannot fail; it maps to the same error
        // rather than panicking.
        let key: &[u8; 32] =
            key.ref_to_bytes().try_into().map_err(|_| KeyMaterialError::InvalidLength)?;
        Ok(Self { engine: E::expand(key), _params: PhantomData })
    }
}

impl<E: Engine<AES128Params>> Algorithm for AESInternal<AES128Params, E> {
    const ALG_NAME: &'static str = AES128Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl<E: Engine<AES192Params>> Algorithm for AESInternal<AES192Params, E> {
    const ALG_NAME: &'static str = AES192Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl<E: Engine<AES256Params>> Algorithm for AESInternal<AES256Params, E> {
    const ALG_NAME: &'static str = AES256Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

// The `Algorithm` impls above name the permutation. Each mode over it is a different algorithm,
// reported under the name of its public alias (`AES_CBC_128` and so on).

impl<E: Engine<AES128Params>> ModeNames for AESInternal<AES128Params, E> {
    const CBC_ALG_NAME: &'static str = "AES_CBC_128";
    const CCM_ALG_NAME: &'static str = "AES_CCM_128";
    const CFB_ALG_NAME: &'static str = "AES_CFB_128";
    const CFB8_ALG_NAME: &'static str = "AES_CFB8_128";
    const CMAC_ALG_NAME: &'static str = "AES_CMAC_128";
    const CTR_ALG_NAME: &'static str = "AES_CTR_128";
    const ECB_ALG_NAME: &'static str = "AES_ECB_128";
    const GCM_ALG_NAME: &'static str = "AES_GCM_128";
    const GMAC_ALG_NAME: &'static str = "AES_GMAC_128";
}

impl<E: Engine<AES192Params>> ModeNames for AESInternal<AES192Params, E> {
    const CBC_ALG_NAME: &'static str = "AES_CBC_192";
    const CCM_ALG_NAME: &'static str = "AES_CCM_192";
    const CFB_ALG_NAME: &'static str = "AES_CFB_192";
    const CFB8_ALG_NAME: &'static str = "AES_CFB8_192";
    const CMAC_ALG_NAME: &'static str = "AES_CMAC_192";
    const CTR_ALG_NAME: &'static str = "AES_CTR_192";
    const ECB_ALG_NAME: &'static str = "AES_ECB_192";
    const GCM_ALG_NAME: &'static str = "AES_GCM_192";
    const GMAC_ALG_NAME: &'static str = "AES_GMAC_192";
}

impl<E: Engine<AES256Params>> ModeNames for AESInternal<AES256Params, E> {
    const CBC_ALG_NAME: &'static str = "AES_CBC_256";
    const CCM_ALG_NAME: &'static str = "AES_CCM_256";
    const CFB_ALG_NAME: &'static str = "AES_CFB_256";
    const CFB8_ALG_NAME: &'static str = "AES_CFB8_256";
    const CMAC_ALG_NAME: &'static str = "AES_CMAC_256";
    const CTR_ALG_NAME: &'static str = "AES_CTR_256";
    const ECB_ALG_NAME: &'static str = "AES_ECB_256";
    const GCM_ALG_NAME: &'static str = "AES_GCM_256";
    const GMAC_ALG_NAME: &'static str = "AES_GMAC_256";
}
