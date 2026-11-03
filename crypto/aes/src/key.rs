//! AES key objects: a key bound to one AES variant and one mode, validated and expanded once,
//! from which the mode's encryptors and decryptors are made.
//!
//! [`AES128Key<M>`], [`AES192Key<M>`] and [`AES256Key<M>`] are one type each per mode `M`, so a key
//! is bound to its AES variant and its mode by the Rust type rather than by the length of a byte
//! buffer and the call site. Validation and key expansion happen once, in the constructor, and
//! every message under the key starts from the stored schedule (and, for GCM, the stored hash
//! subkey, or for CMAC the stored subkeys). Using one key under two modes is two
//! `from_key_material` calls on two key types; the accidental version does not compile. A MAC
//! mode's key takes `KeyType::MACKey` material, a cipher mode's `KeyType::SymmetricCipherKey`.
//! Which workers a key hands out is decided by its mode: the AEAD and MAC role traits for the
//! modes that fit them, and for `GMAC`, whose tag is nonce-bound, an inherent pair (see
//! [`crate::gmac`]).
//!
//! # Usage Examples
//!
//! ```
//! use bouncycastle_aes::AES256Key;
//! use bouncycastle_cipher::modes::GCM;
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
//! use bouncycastle_core::traits::{AEADCipherDecryptor, AEADCipherEncryptor, SymmetricCipherEncryptor};
//! use bouncycastle_rng::HashDRBG_SHA512;
//!
//! let mut rng = HashDRBG_SHA512::new_from_os();   // one RNG, held across messages
//! let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//! let key = AES256Key::<GCM>::from_key_material(&material).expect("a valid AES-256 key");
//!
//! // Streaming: the nonce is drawn from `rng` and returned; the Result is for that draw only.
//! let (mut enc, nonce) = key.create_encryptor(&mut rng).expect("nonce draw");
//! enc.do_update_aad(b"header").expect("aad");
//! let mut ciphertext = [0u8; 14];
//! enc.do_encrypt_out(b"attack at dawn", &mut ciphertext).expect("encryption");
//! let (_, tag) = enc.do_encrypt_final_detached_out(&mut [0u8; 16]).expect("the tag");
//!
//! // Decryption from the same key is infallible to set up; the nonce type follows from the key.
//! let mut dec = key.create_decryptor(&nonce);
//! dec.do_update_aad(b"header").expect("aad");
//! // ... feed `ciphertext`, then check `tag` with `do_decrypt_final_detached_out`.
//!
//! // One-shots take the same path.
//! let (n, nonce) = key
//!     .encrypt_with_aad_out(&mut rng, b"header", b"attack at dawn", &mut [0u8; 30])
//!     .expect("one-shot");
//! assert_eq!(n, 14 + 16);
//! ```
//!
//! The nonce a decryptor takes is the array the key's mode fixes, so a nonce of another length is
//! a compile error rather than a runtime one:
//!
//! ```compile_fail
//! # use bouncycastle_aes::AES128Key;
//! # use bouncycastle_cipher::modes::GCM;
//! # use bouncycastle_core::symmetric_key::{AeadDecryptionKey, FromKeyMaterial};
//! # use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! # let km = KeyMaterial128::from_bytes_as_type(&[1; 16], KeyType::SymmetricCipherKey).unwrap();
//! let key = AES128Key::<GCM>::from_key_material(&km).unwrap();
//! let dec = key.create_decryptor(&[0u8; 16]);   // GCM's nonce is 12 bytes
//! ```
//!
//! # Memory Usage
//!
//! A key is its mode's per-key state: the expanded schedule, 176, 208 or 240 bytes for AES-128,
//! -192 and -256, plus 16 bytes of hash subkey under `GCM` or `GMAC`, or 32 bytes of subkeys
//! under `CMAC`.
//! The cost is paid per key, not per message, and replaces the per-message validation and
//! expansion of the `KeyMaterial` path.

use crate::hazmat::{AES128Internal, AES192Internal, AES256Internal, AESInternal};
use crate::{AES128Params, AES192Params, AES256Params, AESParams};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{
    AeadDecryptMode, AeadEncryptMode, AeadPacketDecryptMode, AeadPacketEncryptMode, MacMode, Mode,
    do_hazardous_operations,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, AeadPacketDecryptionKey, AeadPacketEncryptionKey,
    FromKeyMaterial, MacGenerationKey, MacVerificationKey,
};
use bouncycastle_core::traits::RNG;

/// An AES key for the mode `M`, parameterised by key length. Use the aliases [`AES128Key`],
/// [`AES192Key`] and [`AES256Key`] rather than naming this directly.
///
/// The only state is the mode's per-key state, which holds the expanded schedule in a `Secret`
/// and so is zeroized on drop; the key has no `Debug` and no way to read the material back. A
/// caller who needs the bytes again keeps the `KeyMaterial`.
pub struct AESKey<P: AESParams, M: Mode<AESInternal<P>>> {
    pub(crate) state: M::KeyState,
}

/// An AES-128 key for the mode `M`: 16 bytes of material, expanded to a 10-round schedule.
#[allow(non_camel_case_types)]
pub type AES128Key<M> = AESKey<AES128Params, M>;
/// An AES-192 key for the mode `M`: 24 bytes of material, expanded to a 12-round schedule.
#[allow(non_camel_case_types)]
pub type AES192Key<M> = AESKey<AES192Params, M>;
/// An AES-256 key for the mode `M`: 32 bytes of material, expanded to a 14-round schedule.
#[allow(non_camel_case_types)]
pub type AES256Key<M> = AESKey<AES256Params, M>;

// Written out rather than derived so that `M`, a marker type, need not be `Clone`.
impl<P: AESParams, M: Mode<AESInternal<P>>> Clone for AESKey<P, M> {
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

impl<M: Mode<AES128Internal>> FromKeyMaterial<16> for AES128Key<M> {
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
            KeyType::SymmetricCipherKey => AES128Internal::new(key)?,
            _ => AES128Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

impl<M: Mode<AES192Internal>> FromKeyMaterial<24> for AES192Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 24-byte key; the errors are those of the 16-byte form, at 24
    /// bytes and 192 bits.
    fn from_key_material(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => AES192Internal::new(key)?,
            _ => AES192Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

impl<M: Mode<AES256Internal>> FromKeyMaterial<32> for AES256Key<M> {
    const KEY_TYPE: KeyType = M::KEY_TYPE;

    /// Validates and expands a 32-byte key; the errors are those of the 16-byte form, at 32
    /// bytes and 256 bits.
    fn from_key_material(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        check_key_type(key, M::KEY_TYPE)?;
        let perm = match M::KEY_TYPE {
            KeyType::SymmetricCipherKey => AES256Internal::new(key)?,
            _ => AES256Internal::new(&as_cipher_key(key)?)?,
        };
        Ok(Self { state: M::key_state(perm) })
    }
}

// The role impls forward to whichever mode traits `M` implements over this permutation, so which
// roles a key type carries is decided by its mode. They are per crate rather than a blanket in
// `core` because the key state leaves the key only through here.

impl<
    P,
    M,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
> AeadEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for AESKey<P, M>
where
    P: AESParams,
    M: AeadEncryptMode<AESInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    type Encryptor = M::Encryptor;

    fn create_encryptor(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor, [u8; NONCE_LEN]), SymmetricCipherError> {
        M::encrypt_init(&self.state, rng)
    }

    fn create_encryptor_nonce(&self, nonce: &[u8; NONCE_LEN]) -> Self::Encryptor {
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
> AeadDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for AESKey<P, M>
where
    P: AESParams,
    M: AeadDecryptMode<AESInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    type Decryptor = M::Decryptor;

    fn create_decryptor(&self, nonce: &[u8; NONCE_LEN]) -> Self::Decryptor {
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
> AeadPacketEncryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for AESKey<P, M>
where
    P: AESParams,
    M: AeadPacketEncryptMode<AESInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    type Encryptor = M::Encryptor;

    fn create_encryptor(
        &self,
        rng: &mut dyn RNG,
        aad_len: usize,
        payload_len: usize,
    ) -> Result<(Self::Encryptor, [u8; NONCE_LEN]), SymmetricCipherError> {
        M::encrypt_init(&self.state, rng, aad_len, payload_len)
    }

    fn create_encryptor_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self::Encryptor, SymmetricCipherError> {
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
> AeadPacketDecryptionKey<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN> for AESKey<P, M>
where
    P: AESParams,
    M: AeadPacketDecryptMode<AESInternal<P>, KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>,
{
    type Decryptor = M::Decryptor;

    fn create_decryptor(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self::Decryptor, SymmetricCipherError> {
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

impl<P: AESParams, M: MacMode<AESInternal<P>>> MacGenerationKey for AESKey<P, M> {
    type Generator = M::Worker;

    fn create_generator(&self) -> Self::Generator {
        M::mac_init(&self.state)
    }
}

impl<P: AESParams, M: MacMode<AESInternal<P>>> MacVerificationKey for AESKey<P, M> {
    type Verifier = M::Worker;

    fn create_verifier(&self) -> Self::Verifier {
        M::mac_init(&self.state)
    }
}
