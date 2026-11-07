//! ARIA key objects. The docs are on [`ARIAKey`], which the crate root re-exports with its
//! per-length aliases.

use crate::hazmat::{ARIA128Internal, ARIA192Internal, ARIA256Internal, ARIAInternal};
use crate::schedule::{ARIA128Params, ARIA192Params, ARIA256Params, ARIAParams};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, AeadDecryptMode, AeadEncryptMode,
    BlockDecryptMode, BlockEncryptMode, EcbDecryptMode, EcbDecryptionKey, EcbEncryptMode,
    EcbEncryptionKey, KeyUnwrapMode, KeyWrapMode, MacMode, Mode, SymmetricDecryptMode,
    SymmetricEncryptMode, do_hazardous_operations,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, AeadDecryptionKey, AeadEncryptionKey,
    BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey,
    MacGenerationKey, MacVerificationKey, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::RNG;

/// An ARIA key for the mode `M`, parameterised by key length: a key bound to one ARIA variant and
/// one mode, validated and expanded once, from which the mode's encryptors and decryptors are made.
/// Use the aliases [`ARIA128Key`], [`ARIA192Key`] and [`ARIA256Key`] rather than naming this
/// directly.
///
/// The key holds the mode's per-key state, the workers it hands out borrow it, and which role pair
/// a key carries is decided by its mode, exactly as for `AES128Key<M>` and friends in
/// `bouncycastle-aes`: the symmetric pair for every mode that implements the symmetric mode
/// traits over the permutation -- the stream modes `CFB`, `CFB8` and `CTR<N>` at any nonce
/// length `N`, and the padded block modes `CBC<PKCS7>`, `CBC<NoPadding>`, `ECB<PKCS7>` and
/// `ECB<NoPadding>` -- the block pair for `CBC<Blocks>`, the `hazmat` ECB pair for `ECB<Blocks>`,
/// the AEAD pairs for `GCM`, `CCM` and `CCM_Packet`, the MAC pair for `CMAC`, the key-wrap pair
/// for `KW` and `KWP`, and GMAC's nonce-bound generator and verifier as inherent methods. The
/// crate names the workers of CBC, CFB, CFB8, CTR, GCM, CCM, CMAC, GMAC, KW and KWP as the
/// `ARIA_*` aliases; the rest are reached by naming the mode.
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
/// -192 and -256, plus whatever the mode keeps per key (16 bytes of hash subkey under `GCM` and
/// `GMAC`, 32 bytes of subkeys under `CMAC`). The cost is paid per key, not per message.
pub struct ARIAKey<P: ARIAParams, M: Mode<ARIAInternal<P>>> {
    pub(crate) state: M::KeyState,
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

/// The permutation accepts only a `SymmetricCipherKey`, so a MAC mode's key -- already checked to
/// be the `MACKey` the mode asks for -- is handed to it as a copy retagged at the same strength,
/// used for nothing else. The strength check in the permutation's constructor still applies.
fn as_cipher_key<const N: usize>(
    key: &KeyMaterial<N>,
) -> Result<KeyMaterial<N>, SymmetricCipherError> {
    let mut cipher_key =
        KeyMaterial::<N>::from_bytes_as_type(key.ref_to_bytes(), KeyType::SymmetricCipherKey)?;
    // The type is set again inside the hazardous block on purpose: `from_bytes_as_type` tags
    // all-zero material `Zeroized` regardless of the type asked for, and a MAC key that is
    // deliberately all zeros (made under `do_hazardous_operations`) must stay usable, as `AESKey`
    // keeps it.
    do_hazardous_operations(&mut cipher_key, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(key.security_strength())
    })?;
    Ok(cipher_key)
}

// The constructors are implemented per key length rather than once over `P`, because stable Rust
// cannot name `KeyMaterial<{ P::KEY_LEN }>` in a generic signature; the fixed-capacity argument
// is what makes a wrong-length key a compile error rather than a runtime one.

impl<M: Mode<ARIA128Internal>> FromKeyMaterial<16> for ARIA128Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 16-byte key: the key type the mode asks for, then the
    /// permutation's own checks.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not of [`Self::KEY_TYPE`]: the
    ///   `SymmetricCipherKey` a cipher mode asks for, or the `MACKey` a MAC mode does.
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    fn from_key_material(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => ARIA128Internal::new(key)?,
            _ => ARIA128Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

impl<M: Mode<ARIA192Internal>> FromKeyMaterial<24> for ARIA192Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 24-byte key; the errors are those of the 16-byte form, at 24
    /// bytes and 192 bits.
    fn from_key_material(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => ARIA192Internal::new(key)?,
            _ => ARIA192Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

impl<M: Mode<ARIA256Internal>> FromKeyMaterial<32> for ARIA256Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 32-byte key; the errors are those of the 16-byte form, at 32
    /// bytes and 256 bits.
    fn from_key_material(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => ARIA256Internal::new(key)?,
            _ => ARIA256Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

// The role impls forward to whichever mode traits `M` implements over this permutation, so which
// roles a key type carries is decided by its mode, exactly as for `AESKey`. They are per crate
// rather than a blanket in `core` because the key state leaves the key only through here.

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

impl<
    P,
    M,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
> AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: AeadEncryptMode<ARIAInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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

    // Forwarded rather than left to the trait's provided body so that a mode can override it:
    // CCM's streaming worker is fixed-frame, and its in-place one-shot goes another way.
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
> AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: AeadDecryptMode<ARIAInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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
> AeadDeclaredEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: AeadDeclaredEncryptMode<ARIAInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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

    // Forwarded so that the mode's own in-place path is the one that runs.
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
> AeadDeclaredDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: AeadDeclaredDecryptMode<ARIAInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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

impl<P, M, const KEY_LEN: usize, const BLOCK_LEN: usize> EcbEncryptionKey<KEY_LEN, BLOCK_LEN>
    for ARIAKey<P, M>
where
    P: ARIAParams,
    M: EcbEncryptMode<ARIAInternal<P>, KEY_LEN, BLOCK_LEN>,
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
    for ARIAKey<P, M>
where
    P: ARIAParams,
    M: EcbDecryptMode<ARIAInternal<P>, KEY_LEN, BLOCK_LEN>,
{
    type Decryptor<'k>
        = M::Decryptor<'k>
    where
        Self: 'k;

    fn create_decryptor<'k>(&'k self) -> Self::Decryptor<'k> {
        M::decrypt_init(&self.state)
    }
}

impl<P: ARIAParams, M: MacMode<ARIAInternal<P>>> MacGenerationKey for ARIAKey<P, M> {
    type Generator<'k>
        = M::Worker<'k>
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        M::mac_init(&self.state)
    }
}

impl<P: ARIAParams, M: MacMode<ARIAInternal<P>>> MacVerificationKey for ARIAKey<P, M> {
    type Verifier<'k>
        = M::Worker<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        M::mac_init(&self.state)
    }
}

impl<P, M, const KEK_LEN: usize> KeyWrappingKey<KEK_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: KeyWrapMode<ARIAInternal<P>, KEK_LEN>,
{
    type Wrapper<'k>
        = M::Wrapper<'k>
    where
        Self: 'k;

    fn create_wrapper<'k>(&'k self) -> Self::Wrapper<'k> {
        M::wrap_init(&self.state)
    }
}

impl<P, M, const KEK_LEN: usize> KeyUnwrappingKey<KEK_LEN> for ARIAKey<P, M>
where
    P: ARIAParams,
    M: KeyUnwrapMode<ARIAInternal<P>, KEK_LEN>,
{
    type Unwrapper<'k>
        = M::Unwrapper<'k>
    where
        Self: 'k;

    fn create_unwrapper<'k>(&'k self) -> Self::Unwrapper<'k> {
        M::unwrap_init(&self.state)
    }
}
