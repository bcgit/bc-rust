//! The mode traits: how a mode turns a keyed permutation into a key state, and a key state into
//! an encryptor or decryptor. These are what a mode type such as `GCM` implements, and what the
//! role traits in [`crate::symmetric_key`] forward to. They take a bare key state, which is why
//! they are hazmat: the safe route to an encryptor is `key.create_encryptor(rng)`.

use crate::errors::SymmetricCipherError;
use crate::key_material::KeyType;
use crate::traits::{AEADCipherDecryptor, AEADCipherEncryptor, RNG};

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

// `KEY_LEN` is on these traits only while the cipher traits still carry it, so that `Encryptor`
// and `Decryptor` can be bounded by them; it goes when their constructors do.

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
    type Encryptor: AEADCipherEncryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins an encryption from `state` under a nonce drawn from `rng`.
    ///
    /// # Errors
    /// [`SymmetricCipherError::RNGError`] if the nonce draw fails; nothing else can.
    fn encrypt_init(
        state: &Self::KeyState,
        rng: &mut dyn RNG,
    ) -> Result<(Self::Encryptor, [u8; NONCE_LEN]), SymmetricCipherError>;
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
    type Decryptor: AEADCipherDecryptor<KEY_LEN, NONCE_LEN, TAG_LEN, FINAL_LEN>;

    /// Begins the decryption of a message encrypted under `nonce` from `state`. Infallible: the
    /// state is already keyed and the nonce length is in the type.
    fn decrypt_init(state: &Self::KeyState, nonce: &[u8; NONCE_LEN]) -> Self::Decryptor;
}
