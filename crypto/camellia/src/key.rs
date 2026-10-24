//! Camellia key objects: a key bound to one Camellia variant and one mode, validated and expanded once,
//! from which the mode's encryptors and decryptors are made.
//!
//! [`Camellia128Key<M>`], [`Camellia192Key<M>`] and [`Camellia256Key<M>`] are one type each per mode `M`, as
//! `AES128Key<M>` and friends are in `bouncycastle-aes`: the key holds the mode's per-key state,
//! the workers it hands out borrow it, and which role pair a key carries is decided by its mode --
//! the symmetric pair for the stream modes and the padded block modes (`CFB`, `CFB8`, `CTR`,
//! `CBC<PKCS7>`, `ECB<PKCS7>`), the block pair for `CBC<Blocks>`, the `hazmat` ECB pair for
//! `ECB<Blocks>`, the AEAD pairs for `GCM`, `CCM` and `CCM_Packet`, and the MAC pair for `CMAC`.
//! This crate names the workers of the first four modes as the `Camellia_*` aliases; the others are
//! reached by naming the mode.
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_camellia::Camellia256Key;
//! use bouncycastle_cipher::modes::CBC;
//! use bouncycastle_cipher::padding::PKCS7;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricDecryptionKey, SymmetricEncryptionKey};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = Camellia256Key::<CBC<PKCS7>>::from_key_material(&material).expect("a valid Camellia-256 key");
//!
//! let (iv, ciphertext) = key.encrypt(&mut rng, b"a message of no particular length").unwrap();
//! assert_eq!(key.decrypt(&iv, &ciphertext).unwrap(), b"a message of no particular length");
//! ```
//!
//! # Memory Usage
//!
//! A key is its mode's per-key state: the expanded schedule, 208, 272 or 272 bytes for Camellia-128,
//! -192 and -256, plus whatever the mode keeps per key (16 bytes of hash subkey under `GCM`, 32
//! bytes of subkeys under `CMAC`). The cost is paid per key, not per message.

use crate::hazmat::{
    Camellia128Internal, Camellia192Internal, Camellia256Internal, CamelliaInternal,
};
use crate::schedule::{Camellia128Params, Camellia192Params, Camellia256Params, CamelliaParams};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, AeadDecryptMode, AeadEncryptMode,
    BlockDecryptMode, BlockEncryptMode, EcbDecryptMode, EcbDecryptionKey, EcbEncryptMode,
    EcbEncryptionKey, MacMode, Mode, ModeKey, SymmetricDecryptMode, SymmetricEncryptMode,
    do_hazardous_operations,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, AeadDecryptionKey, AeadEncryptionKey,
    BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial, MacGenerationKey, MacVerificationKey,
    SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::RNG;

/// An Camellia key for the mode `M`, parameterised by key length. Use the aliases [`Camellia128Key`],
/// [`Camellia192Key`] and [`Camellia256Key`] rather than naming this directly.
///
/// The only state is the mode's per-key state, which holds the expanded schedule in a `Secret`
/// and so is zeroized on drop; the key has no `Debug` and no way to read the material back.
pub struct CamelliaKey<P: CamelliaParams, M: Mode<CamelliaInternal<P>>> {
    state: M::KeyState,
}

/// An Camellia-128 key for the mode `M`: 16 bytes of material, expanded to the 18-round subkeys.
#[allow(non_camel_case_types)]
pub type Camellia128Key<M> = CamelliaKey<Camellia128Params, M>;
/// An Camellia-192 key for the mode `M`: 24 bytes of material, expanded to the 24-round subkeys.
#[allow(non_camel_case_types)]
pub type Camellia192Key<M> = CamelliaKey<Camellia192Params, M>;
/// An Camellia-256 key for the mode `M`: 32 bytes of material, expanded to the 24-round subkeys.
#[allow(non_camel_case_types)]
pub type Camellia256Key<M> = CamelliaKey<Camellia256Params, M>;

// Written out rather than derived so that `M`, a marker type, need not be `Clone`.
impl<P: CamelliaParams, M: Mode<CamelliaInternal<P>>> Clone for CamelliaKey<P, M> {
    fn clone(&self) -> Self {
        Self { state: self.state.clone() }
    }
}

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

/// The permutation accepts only a `SymmetricCipherKey`, so a MAC mode's key -- already checked to
/// be the `MACKey` the mode asks for -- is handed to it as a copy retagged at the same strength,
/// used for nothing else. The strength check in the permutation's constructor still applies.
fn as_cipher_key<const N: usize>(
    key: &KeyMaterial<N>,
) -> Result<KeyMaterial<N>, SymmetricCipherError> {
    let mut cipher_key =
        KeyMaterial::<N>::from_bytes_as_type(key.ref_to_bytes(), KeyType::SymmetricCipherKey)?;
    do_hazardous_operations(&mut cipher_key, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(key.security_strength())
    })?;
    Ok(cipher_key)
}

// The constructors are implemented per key length rather than once over `P`, because stable Rust
// cannot name `KeyMaterial<{ P::KEY_LEN }>` in a generic signature; the fixed-capacity argument
// is what makes a wrong-length key a compile error rather than a runtime one.

impl<M: Mode<Camellia128Internal>> FromKeyMaterial<16> for Camellia128Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 16-byte key.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not of [`Self::KEY_TYPE`]: the
    ///   `SymmetricCipherKey` a cipher mode asks for, or the `MACKey` a MAC mode does.
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    fn from_key_material(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => Camellia128Internal::new(key)?,
            _ => Camellia128Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

impl<M: Mode<Camellia192Internal>> FromKeyMaterial<24> for Camellia192Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 24-byte key; the errors are those of the 16-byte form, at 24
    /// bytes and 192 bits.
    fn from_key_material(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => Camellia192Internal::new(key)?,
            _ => Camellia192Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

impl<M: Mode<Camellia256Internal>> FromKeyMaterial<32> for Camellia256Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 32-byte key; the errors are those of the 16-byte form, at 32
    /// bytes and 256 bits.
    fn from_key_material(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => Camellia256Internal::new(key)?,
            _ => Camellia256Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

impl<P: CamelliaParams, M: Mode<CamelliaInternal<P>>> ModeKey<CamelliaInternal<P>, M>
    for CamelliaKey<P, M>
{
    fn state(&self) -> &M::KeyState {
        &self.state
    }
}

// The role impls forward to whichever mode traits `M` implements over this permutation, so which
// roles a key type carries is decided by its mode, exactly as for `AESKey`.

impl<
    P,
    M,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
> AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: AeadEncryptMode<CamelliaInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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

    // Forwarded rather than left to the trait's provided body so that a mode can override it.
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

impl<
    P,
    M,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
> AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: AeadDecryptMode<CamelliaInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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

impl<
    P,
    M,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
> AeadDeclaredEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: AeadDeclaredEncryptMode<CamelliaInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    type Encryptor<'k>
        = M::Encryptor<'k>
    where
        Self: 'k;

    fn create_encryptor<'k>(
        &'k self,
        rng: &mut dyn RNG,
        aad_len: usize,
        payload_len: usize,
    ) -> Result<(Self::Encryptor<'k>, [u8; NONCE_LEN]), SymmetricCipherError> {
        M::encrypt_init(&self.state, rng, aad_len, payload_len)
    }

    fn create_encryptor_nonce<'k>(
        &'k self,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self::Encryptor<'k>, SymmetricCipherError> {
        M::encrypt_init_nonce(&self.state, nonce, aad_len, payload_len)
    }

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

impl<
    P,
    M,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
> AeadDeclaredDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: AeadDeclaredDecryptMode<CamelliaInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(
        &'k self,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self::Decryptor<'k>, SymmetricCipherError> {
        M::decrypt_init(&self.state, nonce, aad_len, payload_len)
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

impl<P, M, const KEY_LEN: usize, const BLOCK_LEN: usize> EcbEncryptionKey<KEY_LEN, BLOCK_LEN>
    for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: EcbEncryptMode<CamelliaInternal<P>, KEY_LEN, BLOCK_LEN>,
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
    for CamelliaKey<P, M>
where
    P: CamelliaParams,
    M: EcbDecryptMode<CamelliaInternal<P>, KEY_LEN, BLOCK_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state)
    }
}

impl<P: CamelliaParams, M: MacMode<CamelliaInternal<P>>> MacGenerationKey for CamelliaKey<P, M> {
    type Generator<'k>
        = M::Worker<'k>
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        M::mac_init(&self.state)
    }
}

impl<P: CamelliaParams, M: MacMode<CamelliaInternal<P>>> MacVerificationKey for CamelliaKey<P, M> {
    type Verifier<'k>
        = M::Worker<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        M::mac_init(&self.state)
    }
}
