//! Core error types to be used in Result return types.
//! Errors defined in this module are typically one-to-one with traits defined in [`crate::traits`].
//!
//! Most errors are self-explanatory, but additional description is available on some.
//!
//! All error enums exported from this crate are tagged `#[non_exhaustive]` to indicate that they
//! are highly likely to gain more branches in the future; therefore, the compiler is to treat it as
//! an error if a caller matches exhaustively against the current set of variants.
//!
//! Every error type here implements [`Display`](core::fmt::Display) and [`core::error::Error`].

use core::error::Error;
use core::fmt;

///
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashError {
    ///
    GenericError(&'static str),
    ///
    InvalidLength(&'static str),
    ///
    InvalidState(&'static str),
    ///
    InvalidInput(&'static str),
    ///
    KeyMaterialError(KeyMaterialError),
}

///
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyMaterialError {
    ///
    ActingOnZeroizedKey,
    ///
    GenericError(&'static str),
    ///
    HazardousOperationNotPermitted,
    ///
    InputDataLongerThanKeyCapacity,
    ///
    InvalidKeyType(&'static str),
    ///
    InvalidLength,
    ///
    SecurityStrength(&'static str),
    /// The key is one the algorithm's specification says to avoid: a weak or semi-weak key, or a
    /// key bundle whose components are not distinct (e.g. a TDEA bundle that collapses to single DES).
    WeakKey(&'static str),
}

///
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KDFError {
    ///
    GenericError(&'static str),
    ///
    HashError(HashError),
    ///
    InvalidLength(&'static str),
    ///
    KeyMaterialError(KeyMaterialError),
    ///
    MACError(MACError),
}

///
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KEMError {
    ///
    GenericError(&'static str),
    ///
    ConsistencyCheckFailed(&'static str),
    ///
    EncodingError(&'static str),
    ///
    DecapsulationFailed,
    ///
    DecodingError(&'static str),
    /// The public key given to encapsulation is unusable, for example a point of small order.
    InvalidPublicKey(&'static str),
    ///
    KeyGenError(&'static str),
    ///
    KeyMaterialError(KeyMaterialError),
    ///
    RNGError(RNGError),
    /// The KDF an algorithm derives its output through refused the derivation.
    KDFError(KDFError),
}

/// Errors of the key-transport roles ([`crate::key_transport_key`]).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyTransportError {
    /// The key is longer than the algorithm can carry under these parameters.
    KeyTooLong,
    /// The ciphertext did not decrypt to a key, for whatever reason: the one error a recipient
    /// reports, so that the causes cannot be told apart.
    DecryptionFailed,
    /// The key to transport is not usable, or the recovered key could not be typed.
    KeyMaterialError(KeyMaterialError),
    /// The RNG refused or failed to deliver, or is weaker than the algorithm requires.
    RNGError(RNGError),
}

/// Errors of public-key message encryption: a scheme that encrypts a message the caller supplies
/// under a public key, such as SM2 encryption in `bouncycastle-ec`.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKeyEncryptionError {
    /// The ciphertext did not decrypt, for whatever reason: the one error a recipient reports,
    /// so that the causes cannot be told apart.
    DecryptionFailed,
    /// Encryption produced no ciphertext within the attempts the algorithm allows itself. The
    /// algorithm's docs say how likely that is.
    EncryptionFailed,
    /// The length of the message or ciphertext is outside the range the algorithm is defined
    /// on.
    InvalidInputLength(&'static str),
    /// The caller's output buffer is too small. The usize is the minimum length the buffer
    /// needs for the same call to succeed.
    OutputBufferTooSmall(usize),
    /// The RNG refused or failed to deliver, or is weaker than the algorithm requires.
    RNGError(RNGError),
}

/// Errors of the key-agreement traits ([`crate::agreement_key`], [`crate::traits::KeyAgreement`]).
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyAgreementError {
    /// A failure the other variants do not describe, with a message.
    GenericError(&'static str),
    /// The primitive produced no shared secret: for ECC CDH, SP 800-56Ar3 Section 5.7.1.2
    /// step 2, the computed point is the point at infinity.
    AgreementFailed,
    /// The public and private key of a pair do not belong together.
    ConsistencyCheckFailed,
    /// An encoded key was not of the expected length or form, or failed the validation its
    /// decoding carries (a public key off the curve, a private key outside `[1, n - 1]`). The
    /// length is part of the form: there is no separate length variant.
    DecodingError(&'static str),
    /// The shared secret or derived key could not be typed or labelled as the algorithm asks.
    KeyMaterialError(KeyMaterialError),
    /// The RNG refused or failed to deliver, or is weaker than the algorithm requires.
    RNGError(RNGError),
    /// The KDF an algorithm derives its output through refused the derivation.
    KDFError(KDFError),
}

///
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MACError {
    ///
    GenericError(&'static str),
    ///
    HashError(HashError),
    /// A run-time-length buffer or tag that is not the construction's length: an output buffer
    /// shorter than the tag, or a tag offered for verification at another length.
    InvalidLength(&'static str),
    ///
    InvalidState(&'static str),
    ///
    KeyMaterialError(KeyMaterialError),
    /// The RNG a nonce was to be drawn from failed or is too weak.
    RNGError(RNGError),
    /// The tag is not the MAC of the message under the key.
    VerificationFailed,
}

///
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RNGError {
    ///
    GenericError(&'static str),

    /// Attempting to extract output before the RNG has been seeded.
    Uninitialized,

    /// The RNG has been seeded, but not sufficiently to support the requested generation operation.
    /// This includes uses in SP 800-90A mode where more output is requested than the security strength
    /// to which the RNG has been initialized.
    InsufficientSeedEntropy,

    /// Indicates that the RNG cannot produce any more output until it has been reseeded with fresh entropy.
    ReseedRequired,

    /// Thrown my algorithms attempting to use an RNG instance, for example for key generation or
    /// other randomness required by the algorithm, but the provided RNG is at a lower security strength
    /// than the algorithm requires.
    SecurityStrengthInsufficientForAlgorithm,

    ///
    KeyMaterialError(KeyMaterialError),
}

/// Errors from [`Suspendable`](crate::traits::Suspendable). Defined in `bouncycastle-utils` next
/// to the version-header helpers that raise it, and re-exported here with the other error types.
pub use bouncycastle_utils::suspendable_state::SuspendableError;

///
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureError {
    ///
    GenericError(&'static str),
    /// The public and private key of a pair do not belong together.
    ConsistencyCheckFailed,
    /// The algorithm bounds its rejection-sampling loop (FIPS 204 Section 6.2 allows ML-DSA to)
    /// and the bound was reached without a signature; nothing was written. The hedged variant
    /// draws fresh randomness on a retry; the deterministic variant fails the same way again.
    RejectionLimitExceeded,
    /// The pre-hash is weaker than the parameter set (FIPS 204 Section 5.4 for HashML-DSA).
    PreHashTooWeak,
    /// A value the algorithm computed failed the check the algorithm makes on its own results
    /// before releasing them, such as a point that is not on the curve, or an RSA result that
    /// the public exponent does not take back to its input. No message causes it: it means a
    /// fault in the computation, or a private key whose parts do not belong together, and
    /// nothing was written.
    ComputationFault,
    ///
    EncodingError(&'static str),
    ///
    DecodingError(&'static str),
    ///
    KeyGenError(&'static str),
    ///
    KeyMaterialError(KeyMaterialError),
    ///
    LengthError(&'static str),
    ///
    SignatureVerificationFailed,
    ///
    RNGError(RNGError),
}

///
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SymmetricCipherError {
    ///
    GenericError(&'static str),
    ///
    AEADTagCheckFailed,
    ///
    DecryptionFailed,
    /// The caller's output buffer is too small for what this call would write. The usize is the
    /// minimum length the buffer needs for the same call to succeed on a retry; the call consumed
    /// no input and left the cipher's state untouched, so retrying with a buffer at least that
    /// long produces exactly what the refused call would have.
    OutputBufferTooSmall(usize),
    /// The cipher has no keystream or counter space left under its current init data: this call
    /// would need more than remains, and continuing would repeat keystream. The call consumed no
    /// input and left the cipher's state untouched, so the bytes that still fit can be processed
    /// in a shorter call; the rest needs a fresh encryption under new init data.
    DataLimitExceeded,
    /// The data is not a whole number of blocks, for a block cipher operation that takes only
    /// whole blocks: a misaligned block-cipher ciphertext is malformed. Nothing was processed.
    DataNotBlockAligned,
    /// The length of the input is outside the range of lengths the algorithm is defined on, for
    /// example a key-wrap plaintext or ciphertext that is too short. Only returned by APIs that
    /// take variable-length input; lengths fixed at compile time are validated at compile time.
    InvalidInputLength(&'static str),
    ///
    KeyMaterialError(KeyMaterialError),
    ///
    PaddingError(PaddingError),
    ///
    RNGError(RNGError),
    ///
    StateError(&'static str),
}

/// Errors from a [`crate::traits::BlockCipherPadding`] scheme.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PaddingError {
    /// `pad()` was asked to pad more data than fits in a block alongside at least one byte of padding.
    /// The usize is the maximum permitted data length (`BLOCK_LEN - 1`).
    DataLengthTooLong(usize),
    /// `unpad()` found the block does not carry well-formed padding. Deliberately carries no detail
    /// about *how* the padding was malformed.
    InvalidPadding,
    /// `pad()` was asked to add padding by a scheme that adds none (`NoPadding`): the data was not
    /// a whole number of blocks, and the caller must align it.
    PaddingNotPermitted,
}

/*** Promotion functions ***/
impl From<PaddingError> for SymmetricCipherError {
    fn from(e: PaddingError) -> SymmetricCipherError {
        Self::PaddingError(e)
    }
}

impl From<KeyMaterialError> for SymmetricCipherError {
    fn from(e: KeyMaterialError) -> SymmetricCipherError {
        Self::KeyMaterialError(e)
    }
}

impl From<RNGError> for SymmetricCipherError {
    fn from(e: RNGError) -> SymmetricCipherError {
        Self::RNGError(e)
    }
}

impl From<RNGError> for PublicKeyEncryptionError {
    fn from(e: RNGError) -> PublicKeyEncryptionError {
        Self::RNGError(e)
    }
}

impl From<KeyMaterialError> for HashError {
    fn from(e: KeyMaterialError) -> HashError {
        Self::KeyMaterialError(e)
    }
}

impl From<HashError> for KDFError {
    fn from(e: HashError) -> KDFError {
        Self::HashError(e)
    }
}

impl From<MACError> for KDFError {
    fn from(e: MACError) -> KDFError {
        Self::MACError(e)
    }
}

impl From<KeyMaterialError> for KDFError {
    fn from(e: KeyMaterialError) -> KDFError {
        Self::KeyMaterialError(e)
    }
}

/// An encoded key was refused by [`PrivateKey::from_bytes`](crate::traits::PrivateKey::from_bytes)
/// or [`PublicKey::from_bytes`](crate::traits::PublicKey::from_bytes): it was not of the expected
/// length or form, or failed the validation its decoding carries (a public key off the curve, a
/// private key outside `[1, n - 1]`). The length is part of the form. The message says which.
///
/// It converts into each role's error as that error's `DecodingError`, so a function that
/// returns [`KEMError`], [`KeyAgreementError`] or [`SignatureError`] decodes a key with `?`.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyDecodingError(pub &'static str);

impl From<KeyDecodingError> for KEMError {
    fn from(e: KeyDecodingError) -> Self {
        Self::DecodingError(e.0)
    }
}

impl From<KeyDecodingError> for KeyAgreementError {
    fn from(e: KeyDecodingError) -> Self {
        Self::DecodingError(e.0)
    }
}

impl From<KeyDecodingError> for SignatureError {
    fn from(e: KeyDecodingError) -> Self {
        Self::DecodingError(e.0)
    }
}

impl From<KeyMaterialError> for KEMError {
    fn from(e: KeyMaterialError) -> KEMError {
        Self::KeyMaterialError(e)
    }
}

impl From<RNGError> for KEMError {
    fn from(e: RNGError) -> KEMError {
        Self::RNGError(e)
    }
}

impl From<KDFError> for KEMError {
    fn from(e: KDFError) -> KEMError {
        Self::KDFError(e)
    }
}

impl From<KeyMaterialError> for KeyAgreementError {
    fn from(e: KeyMaterialError) -> KeyAgreementError {
        Self::KeyMaterialError(e)
    }
}

impl From<RNGError> for KeyAgreementError {
    fn from(e: RNGError) -> KeyAgreementError {
        Self::RNGError(e)
    }
}

impl From<KDFError> for KeyAgreementError {
    fn from(e: KDFError) -> KeyAgreementError {
        Self::KDFError(e)
    }
}

impl From<KeyMaterialError> for MACError {
    fn from(e: KeyMaterialError) -> MACError {
        Self::KeyMaterialError(e)
    }
}

impl From<HashError> for MACError {
    fn from(e: HashError) -> MACError {
        Self::HashError(e)
    }
}

impl From<RNGError> for MACError {
    fn from(e: RNGError) -> MACError {
        Self::RNGError(e)
    }
}

impl From<KeyMaterialError> for RNGError {
    fn from(e: KeyMaterialError) -> RNGError {
        Self::KeyMaterialError(e)
    }
}

impl From<KeyMaterialError> for SignatureError {
    fn from(e: KeyMaterialError) -> SignatureError {
        Self::KeyMaterialError(e)
    }
}

impl From<RNGError> for SignatureError {
    fn from(e: RNGError) -> SignatureError {
        Self::RNGError(e)
    }
}

impl From<KeyMaterialError> for KeyTransportError {
    fn from(e: KeyMaterialError) -> Self {
        Self::KeyMaterialError(e)
    }
}

impl From<RNGError> for KeyTransportError {
    fn from(e: RNGError) -> Self {
        Self::RNGError(e)
    }
}

/*** Display and Error ***/
// Each message is fixed text plus, at most, the variant's `&'static str`, so no message carries
// anything derived from a key, a plaintext or a secret input. A wrapping variant names itself and
// leaves the inner error to `source()`.

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(m) => f.write_str(m),
            Self::InvalidLength(m) => write!(f, "invalid length: {m}"),
            Self::InvalidState(m) => write!(f, "invalid state: {m}"),
            Self::InvalidInput(m) => write!(f, "invalid input: {m}"),
            Self::KeyMaterialError(_) => f.write_str("key material error"),
        }
    }
}

impl Error for HashError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::KeyMaterialError(e) => Some(e),
            Self::GenericError(_)
            | Self::InvalidLength(_)
            | Self::InvalidState(_)
            | Self::InvalidInput(_) => None,
        }
    }
}

impl fmt::Display for KeyMaterialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActingOnZeroizedKey => f.write_str("operation on a zeroized key"),
            Self::GenericError(m) => f.write_str(m),
            Self::HazardousOperationNotPermitted => {
                f.write_str("hazardous operation not permitted")
            }
            Self::InputDataLongerThanKeyCapacity => {
                f.write_str("input data longer than the key capacity")
            }
            Self::InvalidKeyType(m) => write!(f, "invalid key type: {m}"),
            Self::InvalidLength => f.write_str("invalid key length"),
            Self::SecurityStrength(m) => write!(f, "insufficient security strength: {m}"),
            Self::WeakKey(m) => write!(f, "weak key: {m}"),
        }
    }
}

impl Error for KeyMaterialError {}

impl fmt::Display for KDFError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(m) => f.write_str(m),
            Self::HashError(_) => f.write_str("hash error"),
            Self::InvalidLength(m) => write!(f, "invalid length: {m}"),
            Self::KeyMaterialError(_) => f.write_str("key material error"),
            Self::MACError(_) => f.write_str("MAC error"),
        }
    }
}

impl Error for KDFError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::HashError(e) => Some(e),
            Self::KeyMaterialError(e) => Some(e),
            Self::MACError(e) => Some(e),
            Self::GenericError(_) | Self::InvalidLength(_) => None,
        }
    }
}

impl fmt::Display for KEMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(m) => f.write_str(m),
            Self::ConsistencyCheckFailed(m) => {
                write!(f, "key pair consistency check failed: {m}")
            }
            Self::EncodingError(m) => write!(f, "encoding error: {m}"),
            Self::DecapsulationFailed => f.write_str("decapsulation failed"),
            Self::DecodingError(m) => write!(f, "decoding error: {m}"),
            Self::InvalidPublicKey(m) => write!(f, "invalid public key: {m}"),
            Self::KeyGenError(m) => write!(f, "key generation failed: {m}"),
            Self::KeyMaterialError(_) => f.write_str("key material error"),
            Self::RNGError(_) => f.write_str("RNG error"),
            Self::KDFError(_) => f.write_str("KDF error"),
        }
    }
}

impl Error for KEMError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::KeyMaterialError(e) => Some(e),
            Self::RNGError(e) => Some(e),
            Self::KDFError(e) => Some(e),
            Self::GenericError(_)
            | Self::ConsistencyCheckFailed(_)
            | Self::EncodingError(_)
            | Self::DecapsulationFailed
            | Self::DecodingError(_)
            | Self::InvalidPublicKey(_)
            | Self::KeyGenError(_) => None,
        }
    }
}

impl fmt::Display for KeyTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyTooLong => f.write_str("key too long for the algorithm"),
            Self::DecryptionFailed => f.write_str("decryption failed"),
            Self::KeyMaterialError(_) => f.write_str("key material error"),
            Self::RNGError(_) => f.write_str("RNG error"),
        }
    }
}

impl Error for KeyTransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::KeyMaterialError(e) => Some(e),
            Self::RNGError(e) => Some(e),
            Self::KeyTooLong | Self::DecryptionFailed => None,
        }
    }
}

impl fmt::Display for PublicKeyEncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecryptionFailed => f.write_str("decryption failed"),
            Self::EncryptionFailed => f.write_str("encryption failed"),
            Self::InvalidInputLength(m) => write!(f, "invalid input length: {m}"),
            Self::OutputBufferTooSmall(_) => f.write_str("output buffer too small"),
            Self::RNGError(_) => f.write_str("RNG error"),
        }
    }
}

impl Error for PublicKeyEncryptionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::RNGError(e) => Some(e),
            Self::DecryptionFailed
            | Self::EncryptionFailed
            | Self::InvalidInputLength(_)
            | Self::OutputBufferTooSmall(_) => None,
        }
    }
}

impl fmt::Display for KeyAgreementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(m) => f.write_str(m),
            Self::AgreementFailed => f.write_str("key agreement produced no shared secret"),
            Self::ConsistencyCheckFailed => f.write_str("key pair consistency check failed"),
            Self::DecodingError(m) => write!(f, "decoding error: {m}"),
            Self::KeyMaterialError(_) => f.write_str("key material error"),
            Self::RNGError(_) => f.write_str("RNG error"),
            Self::KDFError(_) => f.write_str("KDF error"),
        }
    }
}

impl Error for KeyAgreementError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::KeyMaterialError(e) => Some(e),
            Self::RNGError(e) => Some(e),
            Self::KDFError(e) => Some(e),
            Self::GenericError(_)
            | Self::AgreementFailed
            | Self::ConsistencyCheckFailed
            | Self::DecodingError(_) => None,
        }
    }
}

impl fmt::Display for MACError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(m) => f.write_str(m),
            Self::HashError(_) => f.write_str("hash error"),
            Self::InvalidLength(m) => write!(f, "invalid length: {m}"),
            Self::InvalidState(m) => write!(f, "invalid state: {m}"),
            Self::KeyMaterialError(_) => f.write_str("key material error"),
            Self::RNGError(_) => f.write_str("RNG error"),
            Self::VerificationFailed => f.write_str("MAC verification failed"),
        }
    }
}

impl Error for MACError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::HashError(e) => Some(e),
            Self::KeyMaterialError(e) => Some(e),
            Self::RNGError(e) => Some(e),
            Self::GenericError(_)
            | Self::InvalidLength(_)
            | Self::InvalidState(_)
            | Self::VerificationFailed => None,
        }
    }
}

impl fmt::Display for RNGError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(m) => f.write_str(m),
            Self::Uninitialized => f.write_str("RNG not seeded"),
            Self::InsufficientSeedEntropy => {
                f.write_str("RNG seeded with insufficient entropy for the request")
            }
            Self::ReseedRequired => f.write_str("RNG reseed required"),
            Self::SecurityStrengthInsufficientForAlgorithm => {
                f.write_str("RNG security strength insufficient for the algorithm")
            }
            Self::KeyMaterialError(_) => f.write_str("key material error"),
        }
    }
}

impl Error for RNGError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::KeyMaterialError(e) => Some(e),
            Self::GenericError(_)
            | Self::Uninitialized
            | Self::InsufficientSeedEntropy
            | Self::ReseedRequired
            | Self::SecurityStrengthInsufficientForAlgorithm => None,
        }
    }
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(m) => f.write_str(m),
            Self::ConsistencyCheckFailed => f.write_str("key pair consistency check failed"),
            Self::RejectionLimitExceeded => f.write_str("signing rejection limit exceeded"),
            Self::PreHashTooWeak => f.write_str("pre-hash too weak for the parameter set"),
            Self::ComputationFault => f.write_str("computation fault detected"),
            Self::EncodingError(m) => write!(f, "encoding error: {m}"),
            Self::DecodingError(m) => write!(f, "decoding error: {m}"),
            Self::KeyGenError(m) => write!(f, "key generation failed: {m}"),
            Self::KeyMaterialError(_) => f.write_str("key material error"),
            Self::LengthError(m) => write!(f, "invalid length: {m}"),
            Self::SignatureVerificationFailed => f.write_str("signature verification failed"),
            Self::RNGError(_) => f.write_str("RNG error"),
        }
    }
}

impl Error for SignatureError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::KeyMaterialError(e) => Some(e),
            Self::RNGError(e) => Some(e),
            Self::GenericError(_)
            | Self::ConsistencyCheckFailed
            | Self::RejectionLimitExceeded
            | Self::PreHashTooWeak
            | Self::ComputationFault
            | Self::EncodingError(_)
            | Self::DecodingError(_)
            | Self::KeyGenError(_)
            | Self::LengthError(_)
            | Self::SignatureVerificationFailed => None,
        }
    }
}

impl fmt::Display for SymmetricCipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GenericError(m) => f.write_str(m),
            Self::AEADTagCheckFailed => f.write_str("AEAD tag check failed"),
            Self::DecryptionFailed => f.write_str("decryption failed"),
            // The length is left out: on a padded decryption it depends on the plaintext.
            Self::OutputBufferTooSmall(_) => f.write_str("output buffer too small"),
            Self::DataLimitExceeded => {
                f.write_str("data limit exceeded under the current init data")
            }
            Self::DataNotBlockAligned => f.write_str("data not a whole number of blocks"),
            Self::InvalidInputLength(m) => write!(f, "invalid input length: {m}"),
            Self::KeyMaterialError(_) => f.write_str("key material error"),
            Self::PaddingError(_) => f.write_str("padding error"),
            Self::RNGError(_) => f.write_str("RNG error"),
            Self::StateError(m) => write!(f, "invalid state: {m}"),
        }
    }
}

impl Error for SymmetricCipherError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::KeyMaterialError(e) => Some(e),
            Self::PaddingError(e) => Some(e),
            Self::RNGError(e) => Some(e),
            Self::GenericError(_)
            | Self::AEADTagCheckFailed
            | Self::DecryptionFailed
            | Self::OutputBufferTooSmall(_)
            | Self::DataLimitExceeded
            | Self::DataNotBlockAligned
            | Self::InvalidInputLength(_)
            | Self::StateError(_) => None,
        }
    }
}

impl fmt::Display for PaddingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataLengthTooLong(max) => {
                write!(f, "data too long to pad: at most {max} bytes")
            }
            Self::InvalidPadding => f.write_str("invalid padding"),
            Self::PaddingNotPermitted => {
                f.write_str("data not a whole number of blocks and the scheme adds no padding")
            }
        }
    }
}

impl Error for PaddingError {}

impl fmt::Display for KeyDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "key decoding failed: {}", self.0)
    }
}

impl Error for KeyDecodingError {}
