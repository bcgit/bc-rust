//! CIPHER() and INVCIPHER() (FIPS 197 Sec 5.1 and Sec 5.3)
//!
//! # Usage
//! ## Encrypting and decrypting a single block
//!
//! ```
//! use bouncycastle_aes::aes_internal::AES128Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::ElectronicCodeBook;
//!
//! let key = KeyMaterial::<16>::from_bytes_as_type(
//!     &[0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
//!       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
//!     KeyType::SymmetricCipherKey,
//! ).expect("a 16-byte symmetric cipher key");
//!
//! let aes = AES128Internal::new(&key).expect("a valid AES-128 key");
//!
//! // FIPS 197 Appendix B.
//! let mut block: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
//!                            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];
//! aes.encrypt_block(&mut block);
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
//! `bitslice` module in the source). The round functions cost about the same whatever the width, so on a
//! 64-bit machine four independent blocks cost little more than one. Where a caller has them,
//! [`ElectronicCodeBook::encrypt_4blocks`] is about three times the throughput of four
//! [`ElectronicCodeBook::encrypt_block`] calls on x86-64, and
//! [`ElectronicCodeBook::encrypt_2blocks`] about 1.6 times that of two (the crate's benches
//! record the ratios):
//!
//! ```
//! use bouncycastle_aes::aes_internal::AES256Internal;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::traits::ElectronicCodeBook;
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

use crate::bitslice::{Block, PlaneWord, Planes};
use crate::round::{add_round_key, inv_mix_columns, inv_shift_rows, mix_columns, shift_rows};
use crate::sbox::{inv_sbox, sbox};
use crate::schedule::{AES128Params, AES192Params, AES256Params, AESParams, expand, round_key};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, SecurityStrength};
use bouncycastle_utils::secret::Secret;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::traits::ElectronicCodeBook;
// End imports needed for docs

/// The AES block length in bytes: 16 (FIPS 197 Sec 3.4, `Nb` = 4 words).
pub const BLOCK_LEN: usize = 16;

/// The AES keyed permutation, parameterised by key length.
///
/// This needs to be pub for the type aliases to work, but this is only a building-block for
/// higher-level primitives and is not intended to be used directly.
///
/// Use the aliases [`AES128Internal`], [`AES192Internal`] and [`AES256Internal`] rather than naming this directly.
/// `P` is sealed to the three parameter sets of FIPS 197 Sec 6.1, so no fourth instantiation
/// exists.
///
/// The only state is the key schedule, held in a [`Secret`] so that it is zeroized on drop and
/// redacted from `Debug`. There is no direction flag and no initialisation state: both directions
/// work from the same schedule (see the `inv_cipher` method), and a constructed value is always
/// ready to use, so there is no `init()` or `reset()`.
pub struct AESInternal<P: AESParams> {
    schedule: Secret<P::Schedule>,
}

/// AES-128: 16-byte key, 10 rounds (FIPS 197 Sec 6.1).
/// This needs to be pub for the type aliases to work, but this is only a building-block for
/// higher-level primitives and is not intended to be used directly.
#[allow(non_camel_case_types)]
pub type AES128Internal = AESInternal<AES128Params>;
/// AES-192: 24-byte key, 12 rounds (FIPS 197 Sec 6.1).
/// This needs to be pub for the type aliases to work, but this is only a building-block for
/// higher-level primitives and is not intended to be used directly.
#[allow(non_camel_case_types)]
pub type AES192Internal = AESInternal<AES192Params>;
/// AES-256: 32-byte key, 14 rounds (FIPS 197 Sec 6.1).
/// This needs to be pub for the type aliases to work, but this is only a building-block for
/// higher-level primitives and is not intended to be used directly.
#[allow(non_camel_case_types)]
pub type AES256Internal = AESInternal<AES256Params>;

impl<P: AESParams> AESInternal<P> {
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

    /// CIPHER() on every block in the state at once (FIPS 197 Sec 5.1, Algorithm 1).
    ///
    /// `T` is the plane width, and so the number of blocks: one, two or four. The body is the
    /// same at every width; see [`crate::bitslice`].
    ///
    /// Algorithm 1 line by line: line 3 is the initial ADDROUNDKEY() with `w[0..3]`; lines 4-9 are
    /// the `Nr - 1` full rounds; lines 10-13 are the final round, which omits MIXCOLUMNS().
    fn cipher<T: PlaneWord>(&self, q: &mut Planes<T>) {
        // line 3: state = state XOR w[0..3]
        add_round_key(q, &round_key::<P, T>(&self.schedule, 0));

        // lines 4-9: for round from 1 to Nr - 1
        for round in 1..P::NR {
            sbox(q); // line 5, SUBBYTES()
            shift_rows(q); // line 6, SHIFTROWS()
            mix_columns(q); // line 7, MIXCOLUMNS()
            add_round_key(q, &round_key::<P, T>(&self.schedule, round)); // line 8
        }

        // lines 10-12: the final round has no MIXCOLUMNS()
        sbox(q);
        shift_rows(q);
        add_round_key(q, &round_key::<P, T>(&self.schedule, P::NR));
    }

    /// INVCIPHER() on every block in the state at once (FIPS 197 Sec 5.3, Algorithm 3).
    ///
    /// This is the **straight** inverse cipher of Algorithm 3, not the equivalent inverse cipher
    /// of Sec 5.3.5. That matters: Algorithm 3 applies INVMIXCOLUMNS() *after* ADDROUNDKEY(),
    /// which lets it use the ordinary key schedule, whereas Sec 5.3.5 reorders the round to put
    /// the two the other way round and needs a separate schedule with INVMIXCOLUMNS() applied to
    /// each round key (Algorithm 5, KEYEXPANSIONEIC()).
    ///
    /// Following Algorithm 3 is therefore what allows one [`AESInternal`] value to encrypt *and* decrypt
    /// from a single stored schedule, with no second copy and no transformation at construction
    /// time -- which is the whole reason this crate can offer both directions at 176-240 bytes of
    /// state.
    ///
    /// Line by line: line 3 is ADDROUNDKEY() with the last round key; lines 4-9 are the
    /// `Nr - 1` full inverse rounds; lines 10-13 are the final one, which omits INVMIXCOLUMNS().
    fn inv_cipher<T: PlaneWord>(&self, q: &mut Planes<T>) {
        // line 3: state = state XOR w[4*Nr .. 4*Nr+3]
        add_round_key(q, &round_key::<P, T>(&self.schedule, P::NR));

        // lines 4-9: for round from Nr - 1 down to 1
        for round in (1..P::NR).rev() {
            inv_shift_rows(q); // line 5, INVSHIFTROWS()
            inv_sbox(q); // line 6, INVSUBBYTES()
            add_round_key(q, &round_key::<P, T>(&self.schedule, round)); // line 7
            inv_mix_columns(q); // line 8, INVMIXCOLUMNS()
        }

        // lines 10-12: the final inverse round has no INVMIXCOLUMNS()
        inv_shift_rows(q);
        inv_sbox(q);
        add_round_key(q, &round_key::<P, T>(&self.schedule, 0));
    }

    /// Encrypts the blocks a `T`-wide state holds, in place: transpose in, [`Self::cipher`],
    /// transpose out.
    #[inline(always)]
    fn encrypt<T: PlaneWord>(&self, blocks: &mut T::Blocks) {
        let mut q = T::pack(blocks);
        self.cipher(&mut q);
        T::unpack(&q, blocks);
    }

    /// Decrypts the blocks a `T`-wide state holds, in place: transpose in, [`Self::inv_cipher`],
    /// transpose out.
    #[inline(always)]
    fn decrypt<T: PlaneWord>(&self, blocks: &mut T::Blocks) {
        let mut q = T::pack(blocks);
        self.inv_cipher(&mut q);
        T::unpack(&q, blocks);
    }

    /// Encrypts one block in place, on `u16` planes.
    ///
    /// This is the right call when only one block is available -- CBC and CFB encryption, whose
    /// blocks are serially dependent -- and it does no wasted work: the `u16` state holds
    /// exactly one block. Where two or four independent blocks are available, which for a mode
    /// of operation means CTR or the decryption direction of CBC and CFB, prefer
    /// [`Self::encrypt_2blocks`] or [`Self::encrypt_4blocks`], which cost little more per call.
    ///
    /// Infallible: a constructed [`AESInternal`] is always usable and every input length is fixed.
    pub(crate) fn encrypt_block(&self, block: &mut Block) {
        self.encrypt::<u16>(core::array::from_mut(block));
    }

    /// Decrypts one block in place, on `u16` planes. See [`Self::encrypt_block`].
    pub(crate) fn decrypt_block(&self, block: &mut Block) {
        self.decrypt::<u16>(core::array::from_mut(block));
    }

    /// Encrypts two independent blocks in place, on `u32` planes, for about the cost of one.
    /// See [`Self::encrypt_block`] for when to use which.
    pub(crate) fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        self.encrypt::<u32>(blocks);
    }

    /// Decrypts two independent blocks in place, on `u32` planes. See [`Self::encrypt_block`].
    pub(crate) fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        self.decrypt::<u32>(blocks);
    }

    /// Encrypts four independent blocks in place, on `u64` planes, for about the cost of one.
    /// See [`Self::encrypt_block`] for when to use which.
    pub(crate) fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        self.encrypt::<u64>(blocks);
    }

    /// Decrypts four independent blocks in place, on `u64` planes. See [`Self::encrypt_block`].
    pub(crate) fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        self.decrypt::<u64>(blocks);
    }
}

// The three constructors and `Algorithm` impls below are written out longhand rather than
// generated with `macro_rules!`: `cargo mutants` cannot see into macro bodies, so a macro would
// hide the key checks and the security-strength constants from mutation testing (see CLAUDE.md).
// Each `new` differs only in the `KeyMaterial<N>` capacity it accepts, which is what makes a
// wrong-length key a compile error at the call site rather than a runtime error.

impl AES128Internal {
    /// Expands a 16-byte key into an AES-128 schedule.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not [`KeyType::SymmetricCipherKey`].
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    pub(crate) fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<AES128Params>(key.ref_to_bytes()) })
    }
}

impl AES192Internal {
    /// Expands a 24-byte key into an AES-192 schedule. See [`AES128Internal::new`] for the error cases.
    pub(crate) fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<AES192Params>(key.ref_to_bytes()) })
    }
}

impl AES256Internal {
    /// Expands a 32-byte key into an AES-256 schedule. See [`AES128Internal::new`] for the error cases.
    pub(crate) fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<AES256Params>(key.ref_to_bytes()) })
    }
}

impl Algorithm for AES128Internal {
    const ALG_NAME: &'static str = AES128Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Algorithm for AES192Internal {
    const ALG_NAME: &'static str = AES192Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl Algorithm for AES256Internal {
    const ALG_NAME: &'static str = AES256Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_sizes_match_the_documented_memory_table() {
        // The "Memory Usage" table in the crate docs quotes these, and the whole point of the
        // crate is that they are this small: 4 * (Nr + 1) words of schedule, nothing else, and no
        // tables anywhere. If the representation grows, the docs are wrong -- fix both.
        assert_eq!(size_of::<AES128Internal>(), 176, "AES-128: 4 * (10 + 1) words");
        assert_eq!(size_of::<AES192Internal>(), 208, "AES-192: 4 * (12 + 1) words");
        assert_eq!(size_of::<AES256Internal>(), 240, "AES-256: 4 * (14 + 1) words");
    }

    #[test]
    fn test_engine_size_is_exactly_the_schedule() {
        // No round counter, no direction flag, no initialised marker: the schedule is all there
        // is, which is what makes both directions available from one value at no extra cost.
        assert_eq!(size_of::<AES128Internal>(), size_of::<<AES128Params as AESParams>::Schedule>());
        assert_eq!(size_of::<AES192Internal>(), size_of::<<AES192Params as AESParams>::Schedule>());
        assert_eq!(size_of::<AES256Internal>(), size_of::<<AES256Params as AESParams>::Schedule>());
    }

    #[test]
    fn test_alg_names() {
        assert_eq!(<AES128Internal as Algorithm>::ALG_NAME, "AES-128");
        assert_eq!(<AES192Internal as Algorithm>::ALG_NAME, "AES-192");
        assert_eq!(<AES256Internal as Algorithm>::ALG_NAME, "AES-256");
    }

    #[test]
    fn test_max_security_strength_matches_the_key_length() {
        assert_eq!(
            <AES128Internal as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(AES128Params::KEY_LEN)
        );
        assert_eq!(
            <AES192Internal as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(AES192Params::KEY_LEN)
        );
        assert_eq!(
            <AES256Internal as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(AES256Params::KEY_LEN)
        );
    }
}
