//! Camellia key objects: a key bound to one Camellia variant and one mode, validated and expanded
//! once, from which the mode's encryptors and decryptors are made.
//!
//! [`Camellia128Key<M>`], [`Camellia192Key<M>`] and [`Camellia256Key<M>`] are one type each per
//! mode `M`, as `AES128Key<M>` and friends are in `bouncycastle-aes`: the key holds the mode's
//! per-key state, the workers it hands out borrow it, and which role pair a key carries is decided
//! by its mode: the symmetric pair for the stream modes and the padded block modes (`CFB`, `CFB8`,
//! `CTR`, `CBC<PKCS7>`, `ECB<PKCS7>`), the block pair for `CBC<Blocks>`. The four modes this crate
//! aliases as `Camellia_*` are among them; a key under any other mode has no role here.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_camellia::Camellia256Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
//! use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = Camellia256Key::<CBC<PKCS7>>::from_key_material(&material)
//!     .expect("a valid Camellia-256 key");
//!
//! let (iv, ciphertext) = key.encrypt(&mut rng, b"a message of no particular length").unwrap();
//! assert_eq!(key.decrypt(&iv, &ciphertext).unwrap(), b"a message of no particular length");
//! ```
//!
//! # Memory Usage
//!
//! A key is its mode's per-key state: the expanded schedule, 208, 272 or 272 bytes for
//! Camellia-128, -192 and -256; the four aliased modes keep nothing else per key. The cost is paid
//! per key, not per message.

use crate::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal, CamelliaInternal,
};
use crate::schedule::{Camellia128Params, Camellia192Params, Camellia256Params, CamelliaParams};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{
    BlockDecryptMode, BlockEncryptMode, Mode, ModeKey, SymmetricDecryptMode, SymmetricEncryptMode,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey,
    SymmetricEncryptionKey,
};
use bouncycastle_core::traits::RNG;

// Imports needed for docs
#[allow(unused_imports)]
use bouncycastle_core::errors::KeyMaterialError;
// end of imports needed for docs

/// A Camellia key for the mode `M`, parameterised by key length. Use the aliases
/// [`Camellia128Key`], [`Camellia192Key`] and [`Camellia256Key`] rather than naming this directly.
///
/// The only state is the mode's per-key state, which holds the expanded schedule in a `Secret`
/// and so is zeroized on drop; the key has no `Debug` and no way to read the material back.
pub struct CamelliaKey<P: CamelliaParams, M: Mode<CamelliaInternal<P>>> {
    state: M::KeyState,
}

/// A Camellia-128 key for the mode `M`: 16 bytes of material, expanded to the 18-round subkeys.
#[allow(non_camel_case_types)]
pub type Camellia128Key<M> = CamelliaKey<Camellia128Params, M>;
/// A Camellia-192 key for the mode `M`: 24 bytes of material, expanded to the 24-round subkeys.
#[allow(non_camel_case_types)]
pub type Camellia192Key<M> = CamelliaKey<Camellia192Params, M>;
/// A Camellia-256 key for the mode `M`: 32 bytes of material, expanded to the 24-round subkeys.
#[allow(non_camel_case_types)]
pub type Camellia256Key<M> = CamelliaKey<Camellia256Params, M>;

// Written out rather than derived so that `M`, a marker type, need not be `Clone`.
impl<P: CamelliaParams, M: Mode<CamelliaInternal<P>>> Clone for CamelliaKey<P, M> {
    fn clone(&self) -> Self {
        Self { state: self.state.clone() }
    }
}

// Likewise for equality: two keys are equal when their mode states are, which every state over
// the engine decides in constant time, so the comparison follows the material without exposing it.
impl<P: CamelliaParams, M: Mode<CamelliaInternal<P>>> PartialEq for CamelliaKey<P, M>
where
    M::KeyState: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<P, M> Eq for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: Mode<CamelliaInternal<P>>,
    M::KeyState: Eq,
{
}

// The constructors are implemented per key length rather than once over `P`, because stable Rust
// cannot name `KeyMaterial<{ P::KEY_LEN }>` in a generic signature; the fixed-capacity argument
// is what makes a wrong-length key a compile error rather than a runtime one.

impl<M: Mode<Camellia128Internal>> FromKeyMaterial<16> for Camellia128Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 16-byte key. The checks are the permutation's: every mode with a
    /// role here asks for the `SymmetricCipherKey` it requires.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not a `SymmetricCipherKey`.
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    fn from_key_material(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Ok(Self { state: M::key_state(Camellia128Internal::new(key)?) })
    }
}

impl<M: Mode<Camellia192Internal>> FromKeyMaterial<24> for Camellia192Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 24-byte key; the errors are those of the 16-byte form, at 24
    /// bytes and 192 bits.
    fn from_key_material(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Ok(Self { state: M::key_state(Camellia192Internal::new(key)?) })
    }
}

impl<M: Mode<Camellia256Internal>> FromKeyMaterial<32> for Camellia256Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 32-byte key; the errors are those of the 16-byte form, at 32
    /// bytes and 256 bits.
    fn from_key_material(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Ok(Self { state: M::key_state(Camellia256Internal::new(key)?) })
    }
}

impl<P: CamelliaParams, M: Mode<CamelliaInternal<P>>> ModeKey<CamelliaInternal<P>, M>
    for CamelliaKey<P, M>
{
    fn state(&self) -> &M::KeyState {
        &self.state
    }
}

// The role impls forward to the mode traits `M` implements over this permutation: the symmetric
// pair and the block pair, which between them cover the four modes this crate aliases. A key
// under any other mode has no role here.

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: SymmetricEncryptMode<CamelliaInternal<P>, KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
{
    type Encryptor<'k>
        = M::Encryptor<'k>
    where
        Self: 'k;

    fn create_encryptor<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        M::encrypt_init(&self.state, rng)
    }
}

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: SymmetricDecryptMode<CamelliaInternal<P>, KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, init_data: &[u8; INIT_DATA_LEN]) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state, init_data)
    }
}

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    BlockEncryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: BlockEncryptMode<CamelliaInternal<P>, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    type Encryptor<'k>
        = M::Encryptor<'k>
    where
        Self: 'k;

    fn create_encryptor<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; INIT_DATA_LEN]), SymmetricCipherError> {
        M::encrypt_init(&self.state, rng)
    }
}

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    BlockDecryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: BlockDecryptMode<CamelliaInternal<P>, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, init_data: &[u8; INIT_DATA_LEN]) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state, init_data)
    }
}
