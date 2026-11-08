//! The key object every block cipher crate aliases: a key bound to one permutation and one mode,
//! validated and expanded once, from which the mode's workers are made. The docs are on
//! [`BlockCipherKey`], which the crate root re-exports.

use bouncycastle_core::errors::{KeyMaterialError, MACError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    AeadDeclaredDecryptMode, AeadDeclaredEncryptMode, AeadDecryptMode, AeadEncryptMode,
    BlockDecryptMode, BlockEncryptMode, EcbDecryptMode, EcbDecryptionKey, EcbEncryptMode,
    EcbEncryptionKey, KeyExpansion, KeyUnwrapMode, KeyWrapMode, MacMode, Mode, NonceMacMode,
    SymmetricDecryptMode, SymmetricEncryptMode, do_hazardous_operations,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDeclaredDecryptionKey, AeadDeclaredEncryptionKey, AeadDecryptionKey, AeadEncryptionKey,
    BlockDecryptionKey, BlockEncryptionKey, FromKeyMaterial, KeyUnwrappingKey, KeyWrappingKey,
    MacGenerationKey, MacVerificationKey, NonceMacGenerationKey, NonceMacVerificationKey,
    SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::RNG;

/// A block cipher key for the permutation `P` under the mode `M`: one type per cipher, key
/// length and mode, so a key is bound to all three by the Rust type rather than by the length of
/// a byte buffer and the call site. The cipher crates alias it per key length, `AES128Key<M>`,
/// `ARIA256Key<M>`, `SM4Key<M>` and so on, and those aliases are what a caller names.
///
/// Validation and key expansion happen once, in [`from_key_material`](FromKeyMaterial), and every
/// message under the key starts from the stored schedule, which the workers borrow rather than
/// copy; the mode may keep more per key (GCM and GMAC the hash subkey, CMAC its subkeys). Using
/// one key under two modes is two constructions on two key types; the accidental version does
/// not compile. A MAC mode's key takes `KeyType::MACKey` material, a cipher mode's
/// `KeyType::SymmetricCipherKey`.
///
/// Which workers a key hands out is decided by its mode, through the mode traits `M` implements
/// over `P` in [`bouncycastle_core::hazmat`]: the symmetric pair for the stream modes and the
/// padded block modes (`CFB`, `CFB8`, `CTR<N>` at any nonce length, `CBC<PKCS7>`,
/// `CBC<NoPadding>`, `ECB<PKCS7>`, `ECB<NoPadding>`), the block pair for `CBC<Blocks>`, the
/// `hazmat` ECB pair for `ECB<Blocks>`, the AEAD pairs for `GCM`, `CCM` and `CCM_Packet`, the MAC
/// pair for `CMAC`, the key-wrap pair for `KW` and `KWP`, and for `GMAC`, whose tag is
/// nonce-bound, the inherent [`create_generator`](Self::create_generator) /
/// [`create_verifier`](Self::create_verifier) pair. A permutation that implements a mode's
/// traits carries that mode's roles; there is no per-cipher opt-in.
///
/// The only state is the mode's per-key state, which holds the expanded schedule in a `Secret`
/// and so is zeroized on drop; the key has no `Debug` and no way to read the material back. A
/// caller who needs the bytes again keeps the `KeyMaterial`. Two keys compare equal in constant
/// time when their mode state does, which the permutations implement over the schedule.
///
/// # Usage Examples
///
/// This crate has no permutation of its own, so the examples are on the aliases: `AES128Key` in
/// `bouncycastle-aes` shows GCM, `ARIA256Key` in `bouncycastle-aria` CBC with padding, and the
/// `*_GMAC_128` aliases the nonce-bound MAC pair. The shape is always
///
/// ```text
/// let key = AES256Key::<GCM>::from_key_material(&material)?;   // once
/// let (mut enc, nonce) = key.create_encryptor(&mut rng)?;      // per message
/// ```
///
/// # Memory Usage
///
/// A key is its mode's per-key state: the expanded schedule, whose size each cipher crate states
/// on its alias, plus what the mode keeps per key. The cost is paid per key, not per message.
pub struct BlockCipherKey<P, M: Mode<P>> {
    state: M::KeyState,
}

impl<P, M: Mode<P>> Clone for BlockCipherKey<P, M> {
    fn clone(&self) -> Self {
        Self { state: self.state.clone() }
    }
}

impl<P, M: Mode<P>> PartialEq for BlockCipherKey<P, M>
where
    M::KeyState: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

impl<P, M: Mode<P>> Eq for BlockCipherKey<P, M> where M::KeyState: Eq {}

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
/// `from_bytes_as_type` tags all-zero material `Zeroized` whatever type is asked for, so the type
/// is set again inside the hazardous block: a MAC key deliberately made all zeros would otherwise
/// be refused by the permutation.
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

impl<P, M, const KEY_LEN: usize> FromKeyMaterial<KEY_LEN> for BlockCipherKey<P, M>
where
    P: KeyExpansion<KEY_LEN>,
    M: Mode<P>,
{
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a `KEY_LEN`-byte key.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not of [`Self::KEY_TYPE`]: the
    ///   `SymmetricCipherKey` a cipher mode asks for, or the `MACKey` a MAC mode does.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below the
    ///   permutation's.
    fn from_key_material(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => P::new(key)?,
            _ => P::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

// The role impls forward to whichever mode traits `M` implements over `P`, so which roles a key
// type carries is decided by its mode and its permutation together.

impl<
    P,
    M,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
> AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for BlockCipherKey<P, M>
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
> AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for BlockCipherKey<P, M>
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
> AeadDeclaredEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for BlockCipherKey<P, M>
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
> AeadDeclaredDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for BlockCipherKey<P, M>
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

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricEncryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for BlockCipherKey<P, M>
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

    fn create_encryptor_nonce<'k>(
        &'k self,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Self::Encryptor<'k> {
        M::encrypt_init_nonce(&self.state, init_data)
    }
}

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const FINAL_LEN: usize>
    SymmetricDecryptionKey<KEY_LEN, INIT_DATA_LEN, FINAL_LEN> for BlockCipherKey<P, M>
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
    BlockEncryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for BlockCipherKey<P, M>
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

    fn create_encryptor_nonce<'k>(
        &'k self,
        init_data: &[u8; INIT_DATA_LEN],
    ) -> Self::Encryptor<'k> {
        M::encrypt_init_nonce(&self.state, init_data)
    }
}

impl<P, M, const KEY_LEN: usize, const INIT_DATA_LEN: usize, const BLOCK_LEN: usize>
    BlockDecryptionKey<KEY_LEN, INIT_DATA_LEN, BLOCK_LEN> for BlockCipherKey<P, M>
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
    for BlockCipherKey<P, M>
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
    for BlockCipherKey<P, M>
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

impl<P, M, const MAC_LEN: usize> MacGenerationKey<MAC_LEN> for BlockCipherKey<P, M>
where
    M: MacMode<P, MAC_LEN>,
{
    type Generator<'k>
        = M::Generator<'k>
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        M::generate_init(&self.state)
    }
}

impl<P, M, const MAC_LEN: usize> MacVerificationKey<MAC_LEN> for BlockCipherKey<P, M>
where
    M: MacMode<P, MAC_LEN>,
{
    type Verifier<'k>
        = M::Verifier<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        M::verify_init(&self.state)
    }
}

impl<P, M, const NONCE_LEN: usize, const MAC_LEN: usize> NonceMacGenerationKey<NONCE_LEN, MAC_LEN>
    for BlockCipherKey<P, M>
where
    M: NonceMacMode<P, NONCE_LEN, MAC_LEN>,
{
    type Generator<'k>
        = M::Generator<'k>
    where
        Self: 'k;

    fn create_generator<'k>(
        &'k self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Generator<'k>, [u8; NONCE_LEN]), MACError> {
        M::generate_init(&self.state, rng)
    }

    fn create_generator_nonce<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Generator<'k> {
        M::generate_init_nonce(&self.state, nonce)
    }
}

impl<P, M, const NONCE_LEN: usize, const MAC_LEN: usize> NonceMacVerificationKey<NONCE_LEN, MAC_LEN>
    for BlockCipherKey<P, M>
where
    M: NonceMacMode<P, NONCE_LEN, MAC_LEN>,
{
    type Verifier<'k>
        = M::Verifier<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self, nonce: &[u8; NONCE_LEN]) -> Self::Verifier<'k> {
        M::verify_init(&self.state, nonce)
    }
}

impl<P, M, const KEK_LEN: usize> KeyWrappingKey<KEK_LEN> for BlockCipherKey<P, M>
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

impl<P, M, const KEK_LEN: usize> KeyUnwrappingKey<KEK_LEN> for BlockCipherKey<P, M>
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
