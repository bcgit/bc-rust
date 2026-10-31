// A key object over any 16-byte toy permutation: the shape `AESKey<P, M>` has in the `aes` crate,
// written here so the modes can be driven through the key path without a real cipher. The role
// impls forward to whichever mode traits `M` implements over `P`, exactly as the AES key's do.
//
// Pulled in with `#[path]` from the tests and `include!`d by the doc examples, so every item is
// `pub`, and the site that pulls it in allows the unused ones.

use bouncycastle_cipher::modes::{GCM_NONCE_LEN, GMAC, Gmac, ModeNames};
use bouncycastle_cipher::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, AeadDecryptMode, AeadEncryptMode,
    BlockDecryptMode, BlockEncryptMode, BlockPermutation, EcbDecryptMode, EcbDecryptionKey,
    EcbEncryptMode, EcbEncryptionKey, ElectronicCodeBook, KeyUnwrapMode, KeyWrapMode, MacMode,
    Mode, ModeKey, NonceMacMode, SymmetricDecryptMode, SymmetricEncryptMode,
    do_hazardous_operations,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, AeadDecryptionKey, AeadEncryptionKey,
    BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey,
    MacGenerationKey, MacVerificationKey, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::RNG;

/// Key and block length of every toy permutation these keys are built over.
pub const TOY_KEY_LEN: usize = 16;

/// A key over the permutation `P` for the mode `M`: the mode's per-key state and nothing else.
pub struct ToyKey<P, M: Mode<P>> {
    state: M::KeyState,
}

impl<P, M: Mode<P>> Clone for ToyKey<P, M> {
    fn clone(&self) -> Self {
        Self { state: self.state.clone() }
    }
}

impl<P, M: Mode<P>> ToyKey<P, M> {
    /// A key over an already-keyed permutation, for tests that build the permutation themselves.
    pub fn from_perm(perm: P) -> Self {
        Self { state: M::key_state(perm) }
    }

    /// The mode's per-key state, for tests of the workers' `from_key_state` routes.
    pub fn state(&self) -> &M::KeyState {
        &self.state
    }
}

impl<P, M: Mode<P>> ModeKey<P, M> for ToyKey<P, M> {
    fn state(&self) -> &M::KeyState {
        &self.state
    }
}

/// The permutation takes only a `SymmetricCipherKey`, so a MAC mode's `MACKey` is retagged for it
/// at the same strength, as the AES key does.
fn as_cipher_key(
    key: &KeyMaterial<TOY_KEY_LEN>,
) -> Result<KeyMaterial<TOY_KEY_LEN>, SymmetricCipherError> {
    let mut cipher_key = KeyMaterial::<TOY_KEY_LEN>::from_bytes_as_type(
        key.ref_to_bytes(),
        KeyType::SymmetricCipherKey,
    )?;
    do_hazardous_operations(&mut cipher_key, |k| {
        k.set_key_type(KeyType::SymmetricCipherKey)?;
        k.set_security_strength(key.security_strength())
    })?;
    Ok(cipher_key)
}

impl<P, M> FromKeyMaterial<TOY_KEY_LEN> for ToyKey<P, M>
where
    P: ElectronicCodeBook<TOY_KEY_LEN, TOY_KEY_LEN>,
    M: Mode<P>,
{
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    fn from_key_material(key: &KeyMaterial<TOY_KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        if key.key_type() != M::KEY_TYPE {
            return Err(KeyMaterialError::InvalidKeyType(
                "The key is not of the KeyType this mode requires.",
            )
            .into());
        }
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => P::new(key)?,
            _ => P::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

// ---- the role impls, forwarded to the mode -----------------------------------------------------

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for ToyKey<P, M>
where
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
    SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for ToyKey<P, M>
where
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
    BlockEncryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for ToyKey<P, M>
where
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
    BlockDecryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for ToyKey<P, M>
where
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
    for ToyKey<P, M>
where
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
    for ToyKey<P, M>
where
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

impl<
    P,
    M,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
> AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for ToyKey<P, M>
where
    M: AeadEncryptMode<P, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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
> AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for ToyKey<P, M>
where
    M: AeadDecryptMode<P, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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
> AeadDeclaredEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for ToyKey<P, M>
where
    M: AeadDeclaredEncryptMode<P, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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
> AeadDeclaredDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for ToyKey<P, M>
where
    M: AeadDeclaredDecryptMode<P, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
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

impl<P, M: MacMode<P>> MacGenerationKey for ToyKey<P, M> {
    type Generator<'k>
        = M::Worker<'k>
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        M::mac_init(&self.state)
    }
}

impl<P, M: MacMode<P>> MacVerificationKey for ToyKey<P, M> {
    type Verifier<'k>
        = M::Worker<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        M::mac_init(&self.state)
    }
}

impl<P, M, const KEK_LEN: usize> KeyWrappingKey<KEK_LEN> for ToyKey<P, M>
where
    M: KeyWrapMode<P, KEK_LEN>,
{
    type Wrapper<'k>
        = M::Wrapper<'k>
    where
        Self: 'k;

    fn create_wrapper<'k>(&'k self) -> Self::Wrapper<'k> {
        M::wrap_init(&self.state)
    }
}

impl<P, M, const KEK_LEN: usize> KeyUnwrappingKey<KEK_LEN> for ToyKey<P, M>
where
    M: KeyUnwrapMode<P, KEK_LEN>,
{
    type Unwrapper<'k>
        = M::Unwrapper<'k>
    where
        Self: 'k;

    fn create_unwrapper<'k>(&'k self) -> Self::Unwrapper<'k> {
        M::unwrap_init(&self.state)
    }
}

// ---- GMAC's pair, inherent on the key as it is on the AES key ----------------------------------

impl<P, const TAG_LEN: usize> ToyKey<P, GMAC<TAG_LEN>>
where
    P: BlockPermutation<16> + ModeNames + Clone,
{
    pub fn create_generator<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<(Gmac<'k, P, Encrypting, TAG_LEN>, [u8; GCM_NONCE_LEN]), SymmetricCipherError> {
        GMAC::<TAG_LEN>::generate_init(&self.state, rng)
    }

    pub fn create_generator_nonce<'k>(
        &'k self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<'k, P, Encrypting, TAG_LEN> {
        GMAC::<TAG_LEN>::generate_init_nonce(&self.state, nonce)
    }

    pub fn create_verifier<'k>(
        &'k self,
        nonce: &[u8; GCM_NONCE_LEN],
    ) -> Gmac<'k, P, Decrypting, TAG_LEN> {
        GMAC::<TAG_LEN>::verify_init(&self.state, nonce)
    }
}

/// An RNG for the tests that need one and do not care which: the OS-seeded DRBG the trait
/// constructors used to reach for themselves.
pub fn os_rng() -> bouncycastle_rng::HashDRBG_SHA512 {
    bouncycastle_rng::HashDRBG_SHA512::new_from_os()
}
