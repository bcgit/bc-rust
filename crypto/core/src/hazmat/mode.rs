//! The mode traits: how a mode turns a keyed permutation into a key state, and a key state into
//! an encryptor or decryptor. These are what a mode type such as `GCM` implements, and what the
//! role traits in [`crate::symmetric_key`] forward to. They take a bare key state, which is why
//! they are hazmat: the safe route to an encryptor is `key.create_encryptor(rng)`.
//!
//! There are two shapes of constructor. [`AeadEncryptMode`] / [`AeadDecryptMode`] are handed a
//! nonce and nothing else, which is every mode that can take its message as it comes. A mode that
//! must commit to the lengths before its first byte -- CCM, whose `B0` carries the payload length
//! and whose AAD is length-prefixed -- implements [`AeadPacketEncryptMode`] /
//! [`AeadPacketDecryptMode`] instead, whose constructors take the AAD and payload lengths and
//! whose workers then need no buffer for either. A MAC mode -- CMAC -- implements [`MacMode`],
//! whose worker takes no nonce and serves both roles.

use crate::errors::SymmetricCipherError;
use crate::key_material::KeyType;
use crate::symmetric_key::{AeadDecryptWorker, AeadEncryptWorker};
use crate::traits::{MAC, RNG};

/// A mode's per-key state over the permutation `P`.
///
/// Implemented by a mode type for every permutation it can run over. The key object stores
/// `KeyState` and nothing else, so a mode that derives something from the key once -- GCM's hash
/// subkey -- keeps it here and pays for it per key rather than per message.
pub trait Mode<P> {
    /// What the mode keeps per key: the permutation plus anything derived from it once. A mode
    /// with nothing to derive sets `type KeyState = P`. Sensitive, and held so that it is zeroized
    /// on drop as the schedule it contains is.
    type KeyState: Clone;

    /// The [`KeyType`] a key for this mode must carry: [`KeyType::SymmetricCipherKey`] for a
    /// cipher mode, [`KeyType::MACKey`] for a MAC mode. The key's constructor checks it.
    const KEY_TYPE: KeyType;

    /// Builds the per-key state from an already-keyed permutation.
    fn key_state(perm: P) -> Self::KeyState;
}

// `KEY_LEN` is on these traits only while the cipher traits still carry it: the permutation bound
// a mode impl needs, `P: ElectronicCodeBook<KEY_LEN, ..>`, must be tied to the impl's trait. It
// goes when the constructors leave the cipher traits.

/// The encryption side of an AEAD mode over `P`: the mode's own constructor for its encryptor.
pub trait AeadEncryptMode<
    P,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>: Mode<P>
{
    /// The streaming encryptor this mode produces over `P`.
    type Encryptor: AeadEncryptWorker<NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins an encryption from `state` under a nonce drawn from `rng`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails; nothing else can.
    fn encrypt_init(
        state: &Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor, [u8; NONCE_LEN]), SymmetricCipherError>;

    /// Begins an encryption from `state` under a nonce the caller supplies. Infallible, as
    /// [`AeadDecryptMode::decrypt_init`] is: the state is keyed and the nonce length is in the
    /// type. The caller takes on the obligation [`encrypt_init`](Self::encrypt_init) discharges
    /// for it: the nonce must never repeat under this key.
    fn encrypt_init_nonce(state: &Self::KeyState, nonce: &[u8; NONCE_LEN]) -> Self::Encryptor;

    /// Encrypts `buf` in place from `state` under `aad` and a nonce drawn from `rng`, returning
    /// the nonce and the detached tag. Provided by streaming `buf` through
    /// [`encrypt_init`](Self::encrypt_init)'s encryptor a chunk at a time; a mode whose worker
    /// runs in place natively overrides it.
    ///
    /// # Errors
    /// As [`encrypt_init`](Self::encrypt_init), or any error of the encryptor's streaming methods.
    fn encrypt_detached_in_place(
        state: &Self::KeyState,
        rng: &mut dyn RNG,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), SymmetricCipherError> {
        let (enc, nonce) = Self::encrypt_init(state, rng)?;
        let tag = crate::provided::encrypt_detached_in_place(enc, aad, buf)?;
        Ok((nonce, tag))
    }

    /// As [`encrypt_detached_in_place`](Self::encrypt_detached_in_place) under a nonce the caller
    /// supplies, over [`encrypt_init_nonce`](Self::encrypt_init_nonce).
    ///
    /// # Errors
    /// Any error of the encryptor's streaming methods.
    fn encrypt_detached_in_place_nonce(
        state: &Self::KeyState,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        crate::provided::encrypt_detached_in_place(Self::encrypt_init_nonce(state, nonce), aad, buf)
    }
}

/// The decryption side of an AEAD mode over `P`: the mode's own constructor for its decryptor.
pub trait AeadDecryptMode<
    P,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>: Mode<P>
{
    /// The streaming decryptor this mode produces over `P`.
    type Decryptor: AeadDecryptWorker<NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins the decryption of a message encrypted under `nonce` from `state`. Infallible: the
    /// state is already keyed and the nonce length is in the type.
    fn decrypt_init(state: &Self::KeyState, nonce: &[u8; NONCE_LEN]) -> Self::Decryptor;

    /// Decrypts `buf` in place from `state` under `nonce` and `aad`, and checks `tag`. On any
    /// error `buf` is left zeroized, since the plaintext was written into it before the tag could
    /// be checked. Provided over [`decrypt_init`](Self::decrypt_init) as
    /// [`AeadEncryptMode::encrypt_detached_in_place`] is over its constructor.
    ///
    /// # Errors
    /// [`SymmetricCipherError::AEADTagCheckFailed`] if the tag does not verify, or any error of
    /// the decryptor's streaming methods.
    fn decrypt_detached_in_place(
        state: &Self::KeyState,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), SymmetricCipherError> {
        crate::provided::decrypt_detached_in_place(Self::decrypt_init(state, nonce), aad, buf, tag)
    }
}

/// The encryption side of an AEAD mode over `P` whose worker must know the AAD and payload
/// lengths before its first byte. The constructors take both; the worker then accepts exactly
/// that much of each, in any chunking, and holds nothing back.
pub trait AeadPacketEncryptMode<
    P,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>: Mode<P>
{
    /// The streaming encryptor this mode produces over `P`.
    type Encryptor: AeadEncryptWorker<NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins an encryption of `payload_len` bytes under `aad_len` bytes of AAD, from `state`
    /// under a nonce drawn from `rng`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails, or the mode's own refusal of
    /// a length it cannot encode.
    fn encrypt_init(
        state: &Self::KeyState,
        rng: &mut dyn RNG,
        aad_len: usize,
        payload_len: usize,
    ) -> Result<(Self::Encryptor, [u8; NONCE_LEN]), SymmetricCipherError>;

    /// As [`encrypt_init`](Self::encrypt_init) under a nonce the caller supplies, who takes on
    /// the obligation that it never repeat under this key.
    ///
    /// # Errors
    /// The mode's own refusal of a length it cannot encode.
    fn encrypt_init_nonce(
        state: &Self::KeyState,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self::Encryptor, SymmetricCipherError>;

    /// Encrypts `buf` in place from `state` under `aad` and a nonce drawn from `rng`, returning
    /// the nonce and the detached tag. Provided by streaming `buf` through the encryptor a chunk
    /// at a time; a mode whose worker runs in place natively overrides it.
    ///
    /// # Errors
    /// As [`encrypt_init`](Self::encrypt_init), or any error of the encryptor's streaming methods.
    fn encrypt_detached_in_place(
        state: &Self::KeyState,
        rng: &mut dyn RNG,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<([u8; NONCE_LEN], [u8; TAG_LEN]), SymmetricCipherError> {
        let (enc, nonce) = Self::encrypt_init(state, rng, aad.len(), buf.len())?;
        let tag = crate::provided::encrypt_detached_in_place(enc, aad, buf)?;
        Ok((nonce, tag))
    }

    /// As [`encrypt_detached_in_place`](Self::encrypt_detached_in_place) under a nonce the caller
    /// supplies.
    ///
    /// # Errors
    /// As [`encrypt_init_nonce`](Self::encrypt_init_nonce), or any error of the encryptor's
    /// streaming methods.
    fn encrypt_detached_in_place_nonce(
        state: &Self::KeyState,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; TAG_LEN], SymmetricCipherError> {
        let enc = Self::encrypt_init_nonce(state, nonce, aad.len(), buf.len())?;
        crate::provided::encrypt_detached_in_place(enc, aad, buf)
    }
}

/// The decryption side of an AEAD mode over `P` whose worker must know the AAD and payload
/// lengths before its first byte; see [`AeadPacketEncryptMode`].
pub trait AeadPacketDecryptMode<
    P,
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
    const FINAL_LEN: usize,
>: Mode<P>
{
    /// The streaming decryptor this mode produces over `P`.
    type Decryptor: AeadDecryptWorker<NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins the decryption of `payload_len` bytes of ciphertext under `aad_len` bytes of AAD,
    /// encrypted under `nonce`, from `state`.
    ///
    /// # Errors
    /// The mode's own refusal of a length it cannot encode.
    fn decrypt_init(
        state: &Self::KeyState,
        nonce: &[u8; NONCE_LEN],
        aad_len: usize,
        payload_len: usize,
    ) -> Result<Self::Decryptor, SymmetricCipherError>;

    /// Decrypts `buf` in place from `state` under `nonce` and `aad`, and checks `tag`. On any
    /// error after construction `buf` is left zeroized, since the plaintext was written into it
    /// before the tag could be checked.
    ///
    /// # Errors
    /// As [`decrypt_init`](Self::decrypt_init), [`SymmetricCipherError::AEADTagCheckFailed`] if
    /// the tag does not verify, or any error of the decryptor's streaming methods.
    fn decrypt_detached_in_place(
        state: &Self::KeyState,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<(), SymmetricCipherError> {
        let dec = Self::decrypt_init(state, nonce, aad.len(), buf.len())?;
        crate::provided::decrypt_detached_in_place(dec, aad, buf, tag)
    }
}

/// A MAC mode over `P`: the mode's own constructor for its worker, which generates and verifies
/// alike. The role traits [`crate::symmetric_key::MacGenerationKey`] and
/// [`crate::symmetric_key::MacVerificationKey`] forward to it.
pub trait MacMode<P>: Mode<P> {
    /// The streaming MAC worker this mode produces over `P`.
    type Worker: MAC;

    /// Begins a MAC over a new message from `state`. Infallible: the state is keyed and there is
    /// nothing to draw.
    fn mac_init(state: &Self::KeyState) -> Self::Worker;
}
