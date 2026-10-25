//! The TDEA key objects: a key bundle checked and expanded once, under a mode, handing out that
//! mode's workers through the role traits.
//!
//! [`TDESKey<P, M>`] is generic over the engine `P` -- the three-key [`TDESInternal`] or the
//! decryption-only two-key [`TDES2Internal`] -- and the mode `M`, exactly as `AESKey<P, M>` is in
//! `bouncycastle-aes`. [`TDES3Key<M>`] and [`TDES2Key<M>`] name the two engines. The key holds
//! the mode's key state (for every TDEA mode, the keyed permutation itself) and its workers borrow
//! it, so `create_encryptor` and `create_decryptor` copy no schedule.
//!
//! Which roles a key carries is decided by its mode: `CBC<Blocks>` puts it on the block role pair,
//! `CBC<PKCS7>` on the symmetric pair, `ECB<Blocks>` on the ECB pair under `hazmat`, and `CFB`,
//! `CFB8` and `CTR<6, 8>` on the symmetric pair with stream-cipher workers. A `TDES2Key` carries
//! the same roles, but every encrypting worker over it is a compile error at the call site: the
//! modes check [`ElectronicCodeBook::ENCRYPTION_APPROVED`] when they make one, and two-key TDEA
//! is disallowed for encryption. See [`TDES2Internal`].
//!
//! [`ElectronicCodeBook::ENCRYPTION_APPROVED`]: bouncycastle_core::hazmat::ElectronicCodeBook::ENCRYPTION_APPROVED

use crate::hazmat::{TDES2Internal, TDESInternal};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    BlockDecryptMode, BlockEncryptMode, EcbDecryptMode, EcbDecryptionKey, EcbEncryptMode,
    EcbEncryptionKey, ElectronicCodeBook, Mode, ModeKey, SymmetricDecryptMode,
    SymmetricEncryptMode,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey,
    SymmetricEncryptionKey,
};
use bouncycastle_core::traits::RNG;

mod sealed {
    pub trait Sealed {}
}

/// The engines a [`TDESKey`] can be built over: [`TDESInternal`] and [`TDES2Internal`]. Sealed,
/// since the key's constructors are written per engine.
pub trait TDESEngine: sealed::Sealed {}

impl sealed::Sealed for TDESInternal {}
impl TDESEngine for TDESInternal {}
impl sealed::Sealed for TDES2Internal {}
impl TDESEngine for TDES2Internal {}

/// A TDEA key bundle under the mode `M`, over the engine `P`; see the module docs.
///
/// Built once by [`FromKeyMaterial::from_key_material`], which runs every check the bundle must
/// pass (the key type, length and strength of the material, then the distinct-component and
/// weak-key rules of SP 800-67r2 Sec 3.1 and 3.3.2, as [`TDESInternal::new`] documents) and
/// expands the schedules. Every worker the key hands out afterwards borrows the result.
pub struct TDESKey<P: TDESEngine, M: Mode<P>> {
    state: M::KeyState,
}

/// A three-key TDEA key bundle (24 bytes, `Key1 || Key2 || Key3`) under the mode `M`.
#[allow(non_camel_case_types)]
pub type TDES3Key<M> = TDESKey<TDESInternal, M>;

/// A two-key TDEA key bundle (16 bytes, `Key1 || Key2`, with `Key3 = Key1`) under the mode `M`,
/// **for decryption only**: `create_encryptor` over it does not compile. See [`TDES2Internal`].
#[allow(non_camel_case_types)]
pub type TDES2Key<M> = TDESKey<TDES2Internal, M>;

// Written out rather than derived so that `M`, a marker type, need not be `Clone`.
impl<P: TDESEngine, M: Mode<P>> Clone for TDESKey<P, M> {
    fn clone(&self) -> Self {
        Self { state: self.state.clone() }
    }
}

// Likewise for equality: two keys are equal when their mode states are, which every state over
// the engine decides in constant time, so the comparison follows the material without exposing it.
impl<P: TDESEngine, M: Mode<P>> PartialEq for TDESKey<P, M>
where
    M::KeyState: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<P: TDESEngine, M: Mode<P>> Eq for TDESKey<P, M> where M::KeyState: Eq {}

/// Every TDEA mode is a cipher mode, so the material must be a `SymmetricCipherKey`; the engine's
/// constructor checks that too, but this is the error the role contract names.
fn check_key_type(
    key: &dyn KeyMaterialTrait,
    expected: KeyType,
) -> Result<(), SymmetricCipherError> {
    if key.key_type() != expected {
        return Err(KeyMaterialError::InvalidKeyType(
            "The key is not of the KeyType this mode requires.",
        )
        .into());
    }
    Ok(())
}

// The constructors are per engine rather than once over `P`, because stable Rust cannot name
// `KeyMaterial<{ P::KEY_LEN }>` in a generic signature; the fixed-capacity argument is what makes
// a wrong-length bundle a compile error rather than a runtime one.
impl<M: Mode<TDESInternal>> FromKeyMaterial<{ crate::KEY_LEN }> for TDES3Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Checks and expands a 24-byte `Key1 || Key2 || Key3` bundle.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not of [`Self::KEY_TYPE`].
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 112 bits.
    /// * [`KeyMaterialError::WeakKey`] if the three components are not pairwise distinct, or any
    ///   of them is a weak, semi-weak or possibly weak DEA key; see [`TDESInternal::new`].
    fn from_key_material(
        key: &KeyMaterial<{ crate::KEY_LEN }>,
    ) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        Ok(Self { state: M::key_state(TDESInternal::new(key)?) })
    }
}

impl<M: Mode<TDES2Internal>> FromKeyMaterial<{ crate::KEY_LEN_2KEY }> for TDES2Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Checks and expands a 16-byte `Key1 || Key2` bundle.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not of [`Self::KEY_TYPE`].
    /// * [`KeyMaterialError::WeakKey`] if `Key1 = Key2`, or either component is a weak, semi-weak
    ///   or possibly weak DEA key; see [`TDES2Internal::new`]. No strength is too low for two-key
    ///   TDEA, whose own rating is below the lowest level modelled.
    fn from_key_material(
        key: &KeyMaterial<{ crate::KEY_LEN_2KEY }>,
    ) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        Ok(Self { state: M::key_state(TDES2Internal::new(key)?) })
    }
}

impl<P: TDESEngine, M: Mode<P>> ModeKey<P, M> for TDESKey<P, M> {
    fn state(&self) -> &M::KeyState {
        &self.state
    }
}

// The role impls forward to whichever mode traits `M` implements over this engine, so which
// roles a key type carries is decided by its mode, as for `AESKey`.
impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for TDESKey<P, M>
where
    P: TDESEngine,
    M: SymmetricEncryptMode<P, KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
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
    SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for TDESKey<P, M>
where
    P: TDESEngine,
    M: SymmetricDecryptMode<P, KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
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
    BlockEncryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for TDESKey<P, M>
where
    P: TDESEngine,
    M: BlockEncryptMode<P, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
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
    BlockDecryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for TDESKey<P, M>
where
    P: TDESEngine,
    M: BlockDecryptMode<P, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, init_data: &[u8; INIT_DATA_LEN]) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state, init_data)
    }
}

impl<P, M, const KEY_LEN: usize, const BLOCK_LEN: usize> EcbEncryptionKey<KEY_LEN, BLOCK_LEN>
    for TDESKey<P, M>
where
    P: TDESEngine,
    M: EcbEncryptMode<P, KEY_LEN, BLOCK_LEN>,
{
    type Encryptor<'k>
        = M::Encryptor<'k>
    where
        Self: 'k;

    fn create_encryptor<'k>(&'k self) -> Self::Encryptor<'k> {
        M::encrypt_init(&self.state)
    }
}

impl<P, M, const KEY_LEN: usize, const BLOCK_LEN: usize> EcbDecryptionKey<KEY_LEN, BLOCK_LEN>
    for TDESKey<P, M>
where
    P: TDESEngine,
    M: EcbDecryptMode<P, KEY_LEN, BLOCK_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state)
    }
}
