//! ARIA key objects. The docs are on [`ARIAKey`], which the crate root re-exports with its
//! per-length aliases.

use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal, ARIAInternal};
use crate::schedule::{ARIA128Params, ARIA192Params, ARIA256Params, ARIAParams};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    BlockDecryptMode, BlockEncryptMode, Mode, ModeKey, SymmetricDecryptMode, SymmetricEncryptMode,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial, SymmetricDecryptionKey,
    SymmetricEncryptionKey,
};
use bouncycastle_core::traits::RNG;

/// An ARIA key for the mode `M`, parameterised by key length: a key bound to one ARIA variant and
/// one mode, validated and expanded once, from which the mode's encryptors and decryptors are made.
/// Use the aliases [`ARIA128Key`], [`ARIA192Key`] and [`ARIA256Key`] rather than naming this
/// directly.
///
/// The key holds the mode's per-key state, the workers it hands out borrow it, and which role pair
/// a key carries is decided by its mode, as for `AES128Key<M>` and friends in `bouncycastle-aes`:
/// the symmetric pair for every mode that implements the symmetric mode traits over the
/// permutation -- the stream modes `CFB`, `CFB8` and `CTR<N>` at any nonce length `N`, and the
/// padded block modes `CBC<PKCS7>`, `CBC<NoPadding>`, `ECB<PKCS7>` and `ECB<NoPadding>` -- and the
/// block pair for `CBC<Blocks>`. The four modes this crate aliases as `ARIA_*` are among them; a
/// key under any other mode (`ECB<Blocks>`, the AEAD and MAC modes) has no role here.
///
/// The only state is the mode's per-key state, which holds the expanded schedule in a `Secret`
/// and so is zeroized on drop; the key has no `Debug` and no way to read the material back.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aria::ARIA256Key;
/// use bouncycastle_cipher::modes::CBC;
/// use bouncycastle_cipher::padding::PKCS7;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
/// use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
/// let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
///     .expect("a 32-byte symmetric cipher key");
/// let key = ARIA256Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid ARIA-256 key");
///
/// let (iv, ciphertext) = key.encrypt(&mut rng, b"a message of no particular length").unwrap();
/// assert_eq!(key.decrypt(&iv, &ciphertext).unwrap(), b"a message of no particular length");
/// ```
///
/// # Memory Usage
///
/// A key is its mode's per-key state: the expanded schedule, 208, 240 or 272 bytes for ARIA-128,
/// -192 and -256; the four aliased modes keep nothing else per key. The cost is paid per key, not
/// per message.
pub struct ARIAKey<P: ARIAParams, M: Mode<ARIAInternal<P>>> {
    state: M::KeyState,
}

/// An ARIA-128 key for the mode `M`: 16 bytes of material, expanded to a 12-round schedule.
#[allow(non_camel_case_types)]
pub type ARIA128Key<M> = ARIAKey<ARIA128Params, M>;
/// An ARIA-192 key for the mode `M`: 24 bytes of material, expanded to a 14-round schedule.
#[allow(non_camel_case_types)]
pub type ARIA192Key<M> = ARIAKey<ARIA192Params, M>;
/// An ARIA-256 key for the mode `M`: 32 bytes of material, expanded to a 16-round schedule.
#[allow(non_camel_case_types)]
pub type ARIA256Key<M> = ARIAKey<ARIA256Params, M>;

// Written out rather than derived so that `M`, a marker type, need not be `Clone`.
impl<P: ARIAParams, M: Mode<ARIAInternal<P>>> Clone for ARIAKey<P, M> {
    fn clone(&self) -> Self {
        Self { state: self.state.clone() }
    }
}

// Likewise for equality: two keys are equal when their mode states are, which every state over
// the engine decides in constant time, so the comparison follows the material without exposing it.
impl<P: ARIAParams, M: Mode<ARIAInternal<P>>> PartialEq for ARIAKey<P, M>
where
    M::KeyState: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<P: ARIAParams, M: Mode<ARIAInternal<P>>> Eq for ARIAKey<P, M> where M::KeyState: Eq {}

/// The key-type check the mode asks for (`Mode::KEY_TYPE`), ahead of the permutation's own
/// validation.
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

// The constructors are implemented per key length rather than once over `P`, because stable Rust
// cannot name `KeyMaterial<{ P::KEY_LEN }>` in a generic signature; the fixed-capacity argument
// is what makes a wrong-length key a compile error rather than a runtime one.

impl<M: Mode<ARIA128Internal>> FromKeyMaterial<16> for ARIA128Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 16-byte key: the key type the mode asks for, then the
    /// permutation's own checks. Every mode with a role here asks for a `SymmetricCipherKey`, so
    /// under a MAC mode, which asks for a `MACKey`, no material passes both.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not of [`Self::KEY_TYPE`], or not a
    ///   `SymmetricCipherKey`.
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    fn from_key_material(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        Ok(Self { state: M::key_state(ARIA128Internal::new(key)?) })
    }
}

impl<M: Mode<ARIA192Internal>> FromKeyMaterial<24> for ARIA192Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 24-byte key; the errors are those of the 16-byte form, at 24
    /// bytes and 192 bits.
    fn from_key_material(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        Ok(Self { state: M::key_state(ARIA192Internal::new(key)?) })
    }
}

impl<M: Mode<ARIA256Internal>> FromKeyMaterial<32> for ARIA256Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 32-byte key; the errors are those of the 16-byte form, at 32
    /// bytes and 256 bits.
    fn from_key_material(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        Ok(Self { state: M::key_state(ARIA256Internal::new(key)?) })
    }
}

impl<P: ARIAParams, M: Mode<ARIAInternal<P>>> ModeKey<ARIAInternal<P>, M> for ARIAKey<P, M> {
    fn state(&self) -> &M::KeyState {
        &self.state
    }
}

// The role impls forward to the mode traits `M` implements over this permutation: the symmetric
// pair and the block pair, which between them cover every mode the key docs list -- the four
// this crate aliases, `ECB<PKCS7>`, `ECB<NoPadding>` and `CTR<N>` at any nonce length. A key
// under a mode that implements neither pair (the MAC and AEAD modes) has no role here.

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: SymmetricEncryptMode<ARIAInternal<P>, KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
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
    SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: SymmetricDecryptMode<ARIAInternal<P>, KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
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
    BlockEncryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: BlockEncryptMode<ARIAInternal<P>, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
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
    BlockDecryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: BlockDecryptMode<ARIAInternal<P>, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, init_data: &[u8; INIT_DATA_LEN]) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state, init_data)
    }
}
