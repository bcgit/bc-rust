//! SM4 key objects: a key bound to one mode, validated and expanded once, from which the mode's
//! encryptors and decryptors are made.
//!
//! [`SM4Key<M>`] is one type per mode `M`, as `AES128Key<M>` is in `bouncycastle-aes`: the key
//! holds the mode's per-key state, the workers it hands out borrow it, and which role pair a key
//! carries is decided by its mode: the symmetric pair for the stream modes and the padded block
//! modes (`CFB`, `CFB8`, `CTR`, `CBC<PKCS7>`, `ECB<PKCS7>`), the block pair for `CBC<Blocks>`,
//! and the AEAD pair for `GCM`. The five modes this crate aliases as `SM4_*` are among them; a
//! key under any other mode has no role here.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_sm4::SM4Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey};
//! use bouncycastle_core::symmetric_key::SymmetricEncryptionKey;
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .expect("a 16-byte symmetric cipher key");
//! let key = SM4Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid SM4 key");
//!
//! let (iv, ciphertext) = key.encrypt(&mut rng, b"a message of no particular length").unwrap();
//! assert_eq!(key.decrypt(&iv, &ciphertext).unwrap(), b"a message of no particular length");
//! ```
//!
//! # Memory Usage
//!
//! A key is its mode's per-key state: the 128-byte round-key schedule, which the four
//! unauthenticated aliased modes keep alone, plus the 16-byte hash subkey under `GCM`, 144 bytes.
//! The cost is paid per key, not per message.

use crate::hazmat::SM4Internal;
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    AeadDecryptMode, AeadEncryptMode, BlockDecryptMode, BlockEncryptMode, Mode, ModeKey,
    SymmetricDecryptMode, SymmetricEncryptMode,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial,
    SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::RNG;

/// An SM4 key for the mode `M`: 16 bytes of material, expanded to the 32 round keys.
///
/// The only state is the mode's per-key state, which holds the expanded schedule in a `Secret`
/// and so is zeroized on drop; the key has no `Debug` and no way to read the material back.
pub struct SM4Key<M: Mode<SM4Internal>> {
    state: M::KeyState,
}

// Written out rather than derived so that `M`, a marker type, need not be `Clone`.
impl<M: Mode<SM4Internal>> Clone for SM4Key<M> {
    fn clone(&self) -> Self {
        Self { state: self.state.clone() }
    }
}

// Likewise for equality: two keys are equal when their mode states are, which every state over
// the engine decides in constant time, so the comparison follows the material without exposing it.
impl<M: Mode<SM4Internal>> PartialEq for SM4Key<M>
where
    M::KeyState: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<M: Mode<SM4Internal>> Eq for SM4Key<M> where M::KeyState: Eq {}

impl<M: Mode<SM4Internal>> FromKeyMaterial<{ crate::KEY_LEN }> for SM4Key<M> {
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
    fn from_key_material(
        key: &KeyMaterial<{ crate::KEY_LEN }>,
    ) -> Result<Self, SymmetricCipherError> {
        if key.key_type() != M::KEY_TYPE {
            return Err(KeyMaterialError::InvalidKeyType(
                "The key is not of the KeyType this mode requires.",
            )
            .into());
        }
        Ok(Self { state: M::key_state(SM4Internal::new(key)?) })
    }
}

impl<M: Mode<SM4Internal>> ModeKey<SM4Internal, M> for SM4Key<M> {
    fn state(&self) -> &M::KeyState {
        &self.state
    }
}

// The role impls forward to the mode traits `M` implements over this permutation: the symmetric
// pair, the block pair and the AEAD pair, which between them cover the five modes this crate
// aliases. A key under any other mode has no role here.

impl<M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for SM4Key<M>
where
    M: SymmetricEncryptMode<SM4Internal, KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
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

impl<M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for SM4Key<M>
where
    M: SymmetricDecryptMode<SM4Internal, KEY_LEN, INIT_DATA_LEN, FINAL_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, init_data: &[u8; INIT_DATA_LEN]) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state, init_data)
    }
}

impl<M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    BlockEncryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for SM4Key<M>
where
    M: BlockEncryptMode<SM4Internal, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
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

impl<M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    BlockDecryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for SM4Key<M>
where
    M: BlockDecryptMode<SM4Internal, KEY_LEN, INIT_DATA_LEN, BLOCK_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, init_data: &[u8; INIT_DATA_LEN]) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state, init_data)
    }
}

impl<M, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize, const FINAL_LEN: usize>
    AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for SM4Key<M>
where
    M: AeadEncryptMode<SM4Internal, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    type Encryptor<'k>
        = M::Encryptor<'k>
    where
        Self: 'k;

    fn create_encryptor<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor<'k>, [u8; NONCE_LEN]), SymmetricCipherError> {
        M::encrypt_init(&self.state, rng)
    }

    fn create_encryptor_nonce<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Encryptor<'k> {
        M::encrypt_init_nonce(&self.state, nonce)
    }

    // Forwarded rather than left to the trait's provided body so that a mode can override it,
    // as the AES key does.
    fn encrypt_detached_in_place(
        &self,
        rng: &mut dyn RNG,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), SymmetricCipherError> {
        M::encrypt_detached_in_place(&self.state, rng, aad, buf)
    }

    fn encrypt_detached_in_place_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        M::encrypt_detached_in_place_nonce(&self.state, nonce, aad, buf)
    }
}

impl<M, const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize, const FINAL_LEN: usize>
    AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for SM4Key<M>
where
    M: AeadDecryptMode<SM4Internal, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state, nonce)
    }

    fn decrypt_detached_in_place(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), SymmetricCipherError> {
        M::decrypt_detached_in_place(&self.state, nonce, aad, buf, tag)
    }
}
