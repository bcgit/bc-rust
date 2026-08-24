//! Signature factory for creating instances of algorithms that implement signature traits.
//!
//! As with all Factory objects, this constructs algorithms from strings and defaults.
//! Supported objects are encapsulated in enums that pass operations through to the underlying types.
//!
//! # Design note on traits
//!
//! The core [`Signer`] and [`SignatureVerifier`] traits are parameterized by const-generic key and
//! signature sizes (`SK_LEN`, `SIG_LEN`, `PK_LEN`). A single enum that wraps ML-DSA-44/65/87 cannot
//! implement those traits with one fixed set of const parameters. This module therefore:
//!
//! * Wraps public/private keys in [`SignaturePublicKey`] / [`SignaturePrivateKey`] enums
//! * Wraps streaming sign/verify engines in [`SignatureSigner`] / [`SignatureVerifierEngine`] enums
//! * Exposes inherent methods on those enums with the same shape as the core traits, dispatching
//!   to the underlying ML-DSA types
//!
//! Example usage:
//! ```
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_factory::signature_factory::SignatureFactory;
//! use bouncycastle_mldsa::ML_DSA_65_NAME;
//!
//! let factory = SignatureFactory::new(ML_DSA_65_NAME).unwrap();
//! assert_eq!(factory.algorithm_name(), ML_DSA_65_NAME);
//! // keygen/sign/verify pass through to the underlying ML-DSA types;
//! // see the crate tests for full round-trip examples (they need a larger stack).
//! ```

use crate::{AlgorithmFactory, DEFAULT, DEFAULT_128_BIT, DEFAULT_256_BIT, FactoryError};
use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{
    SignaturePrivateKey as SignaturePrivateKeyTrait, SignaturePublicKey as SignaturePublicKeyTrait,
    SignatureVerifier as _, Signer as _, RNG,
};
use bouncycastle_mldsa as mldsa;
use bouncycastle_mldsa::{
    MLDSA44, MLDSA65, MLDSA87, MLDSATrait, ML_DSA_44_NAME, ML_DSA_65_NAME, ML_DSA_87_NAME,
};

/*** Defaults ***/
/// Default signature algorithm name (192-bit class / ML-DSA-65).
pub const DEFAULT_SIGNATURE_NAME: &str = ML_DSA_65_NAME;
/// Default signature algorithm at the 128-bit security level.
pub const DEFAULT_128BIT_SIGNATURE_NAME: &str = ML_DSA_44_NAME;
/// Default signature algorithm at the 256-bit security level.
pub const DEFAULT_256BIT_SIGNATURE_NAME: &str = ML_DSA_87_NAME;

/// Wrapper for all supported signature public keys.
pub enum SignaturePublicKey {
    /// ML-DSA-44 public key.
    MLDSA44(mldsa::MLDSA44PublicKey),
    /// ML-DSA-65 public key.
    MLDSA65(mldsa::MLDSA65PublicKey),
    /// ML-DSA-87 public key.
    MLDSA87(mldsa::MLDSA87PublicKey),
}

impl SignaturePublicKey {
    /// Encode the public key to its standard byte encoding.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::MLDSA44(pk) => pk.encode().to_vec(),
            Self::MLDSA65(pk) => pk.encode().to_vec(),
            Self::MLDSA87(pk) => pk.encode().to_vec(),
        }
    }

    /// Decode a public key from bytes for the named algorithm.
    pub fn from_bytes(alg_name: &str, bytes: &[u8]) -> Result<Self, FactoryError> {
        match alg_name {
            ML_DSA_44_NAME => Ok(Self::MLDSA44(
                mldsa::MLDSA44PublicKey::from_bytes(bytes).map_err(signature_err)?,
            )),
            ML_DSA_65_NAME => Ok(Self::MLDSA65(
                mldsa::MLDSA65PublicKey::from_bytes(bytes).map_err(signature_err)?,
            )),
            ML_DSA_87_NAME => Ok(Self::MLDSA87(
                mldsa::MLDSA87PublicKey::from_bytes(bytes).map_err(signature_err)?,
            )),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{alg_name}\" is not a known Signature"
            ))),
        }
    }

    /// Algorithm name for this key.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MLDSA44(_) => ML_DSA_44_NAME,
            Self::MLDSA65(_) => ML_DSA_65_NAME,
            Self::MLDSA87(_) => ML_DSA_87_NAME,
        }
    }
}

/// Wrapper for all supported signature private keys.
pub enum SignaturePrivateKey {
    /// ML-DSA-44 private key.
    MLDSA44(mldsa::MLDSA44PrivateKey),
    /// ML-DSA-65 private key.
    MLDSA65(mldsa::MLDSA65PrivateKey),
    /// ML-DSA-87 private key.
    MLDSA87(mldsa::MLDSA87PrivateKey),
}

impl SignaturePrivateKey {
    /// Encode the private key to its standard byte encoding.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::MLDSA44(sk) => sk.encode().to_vec(),
            Self::MLDSA65(sk) => sk.encode().to_vec(),
            Self::MLDSA87(sk) => sk.encode().to_vec(),
        }
    }

    /// Decode a private key from bytes for the named algorithm.
    pub fn from_bytes(alg_name: &str, bytes: &[u8]) -> Result<Self, FactoryError> {
        match alg_name {
            ML_DSA_44_NAME => Ok(Self::MLDSA44(
                mldsa::MLDSA44PrivateKey::from_bytes(bytes).map_err(signature_err)?,
            )),
            ML_DSA_65_NAME => Ok(Self::MLDSA65(
                mldsa::MLDSA65PrivateKey::from_bytes(bytes).map_err(signature_err)?,
            )),
            ML_DSA_87_NAME => Ok(Self::MLDSA87(
                mldsa::MLDSA87PrivateKey::from_bytes(bytes).map_err(signature_err)?,
            )),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{alg_name}\" is not a known Signature"
            ))),
        }
    }

    /// Algorithm name for this key.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MLDSA44(_) => ML_DSA_44_NAME,
            Self::MLDSA65(_) => ML_DSA_65_NAME,
            Self::MLDSA87(_) => ML_DSA_87_NAME,
        }
    }
}

/// Streaming signer engine encapsulating supported signature algorithm state machines.
///
/// Obtained from [`SignatureFactory::sign_init`]. Passes [`Signer::sign_update`] /
/// [`Signer::sign_final`] through to the underlying type.
pub enum SignatureSigner {
    /// ML-DSA-44 streaming signer.
    MLDSA44(MLDSA44),
    /// ML-DSA-65 streaming signer.
    MLDSA65(MLDSA65),
    /// ML-DSA-87 streaming signer.
    MLDSA87(MLDSA87),
}

impl SignatureSigner {
    /// Absorb the next message chunk (pass-through to underlying [`Signer::sign_update`]).
    pub fn sign_update(&mut self, msg_chunk: &[u8]) {
        match self {
            Self::MLDSA44(s) => s.sign_update(msg_chunk),
            Self::MLDSA65(s) => s.sign_update(msg_chunk),
            Self::MLDSA87(s) => s.sign_update(msg_chunk),
        }
    }

    /// Finish signing and return the signature bytes.
    pub fn sign_final(self) -> Result<Vec<u8>, SignatureError> {
        match self {
            Self::MLDSA44(s) => Ok(s.sign_final()?.to_vec()),
            Self::MLDSA65(s) => Ok(s.sign_final()?.to_vec()),
            Self::MLDSA87(s) => Ok(s.sign_final()?.to_vec()),
        }
    }
}

/// Streaming verifier engine encapsulating supported signature algorithm state machines.
///
/// Obtained from [`SignatureFactory::verify_init`].
pub enum SignatureVerifierEngine {
    /// ML-DSA-44 streaming verifier.
    MLDSA44(MLDSA44),
    /// ML-DSA-65 streaming verifier.
    MLDSA65(MLDSA65),
    /// ML-DSA-87 streaming verifier.
    MLDSA87(MLDSA87),
}

impl SignatureVerifierEngine {
    /// Absorb the next message chunk (pass-through to underlying [`SignatureVerifier::verify_update`]).
    pub fn verify_update(&mut self, msg_chunk: &[u8]) {
        match self {
            Self::MLDSA44(s) => s.verify_update(msg_chunk),
            Self::MLDSA65(s) => s.verify_update(msg_chunk),
            Self::MLDSA87(s) => s.verify_update(msg_chunk),
        }
    }

    /// Finish verification against the provided signature.
    pub fn verify_final(self, sig: &[u8]) -> Result<(), SignatureError> {
        match self {
            Self::MLDSA44(s) => s.verify_final(sig),
            Self::MLDSA65(s) => s.verify_final(sig),
            Self::MLDSA87(s) => s.verify_final(sig),
        }
    }
}

/// Factory / algorithm selector for all supported signature algorithms.
///
/// Constructed by name via [`AlgorithmFactory::new`] or the default helpers.
/// Operations pass through to the underlying ML-DSA parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFactory {
    /// ML-DSA-44 (NIST security category 2 / ~128-bit class).
    MLDSA44,
    /// ML-DSA-65 (NIST security category 3 / ~192-bit class).
    MLDSA65,
    /// ML-DSA-87 (NIST security category 5 / ~256-bit class).
    MLDSA87,
}

impl Default for SignatureFactory {
    fn default() -> Self {
        Self::MLDSA65
    }
}

impl AlgorithmFactory for SignatureFactory {
    fn default_128_bit() -> Self {
        Self::MLDSA44
    }

    fn default_256_bit() -> Self {
        Self::MLDSA87
    }

    fn new(alg_name: &str) -> Result<Self, FactoryError> {
        match alg_name {
            DEFAULT => Ok(Self::default()),
            DEFAULT_128_BIT => Ok(Self::default_128_bit()),
            DEFAULT_256_BIT => Ok(Self::default_256_bit()),
            ML_DSA_44_NAME => Ok(Self::MLDSA44),
            ML_DSA_65_NAME => Ok(Self::MLDSA65),
            ML_DSA_87_NAME => Ok(Self::MLDSA87),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{alg_name}\" is not a known Signature"
            ))),
        }
    }
}

impl SignatureFactory {
    /// Algorithm name string for this factory selection.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MLDSA44 => ML_DSA_44_NAME,
            Self::MLDSA65 => ML_DSA_65_NAME,
            Self::MLDSA87 => ML_DSA_87_NAME,
        }
    }

    /// Generate a fresh key pair using the library default OS-backed RNG.
    pub fn keygen(&self) -> Result<(SignaturePublicKey, SignaturePrivateKey), SignatureError> {
        match self {
            Self::MLDSA44 => {
                let (pk, sk) = MLDSA44::keygen()?;
                Ok((SignaturePublicKey::MLDSA44(pk), SignaturePrivateKey::MLDSA44(sk)))
            }
            Self::MLDSA65 => {
                let (pk, sk) = MLDSA65::keygen()?;
                Ok((SignaturePublicKey::MLDSA65(pk), SignaturePrivateKey::MLDSA65(sk)))
            }
            Self::MLDSA87 => {
                let (pk, sk) = MLDSA87::keygen()?;
                Ok((SignaturePublicKey::MLDSA87(pk), SignaturePrivateKey::MLDSA87(sk)))
            }
        }
    }

    /// Generate a key pair using the provided RNG.
    pub fn keygen_from_rng(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<(SignaturePublicKey, SignaturePrivateKey), SignatureError> {
        match self {
            Self::MLDSA44 => {
                let (pk, sk) = MLDSA44::keygen_from_rng(rng)?;
                Ok((SignaturePublicKey::MLDSA44(pk), SignaturePrivateKey::MLDSA44(sk)))
            }
            Self::MLDSA65 => {
                let (pk, sk) = MLDSA65::keygen_from_rng(rng)?;
                Ok((SignaturePublicKey::MLDSA65(pk), SignaturePrivateKey::MLDSA65(sk)))
            }
            Self::MLDSA87 => {
                let (pk, sk) = MLDSA87::keygen_from_rng(rng)?;
                Ok((SignaturePublicKey::MLDSA87(pk), SignaturePrivateKey::MLDSA87(sk)))
            }
        }
    }

    /// Generate a key pair from a 32-byte seed.
    pub fn keygen_from_seed(
        &self,
        seed: &KeyMaterial<32>,
    ) -> Result<(SignaturePublicKey, SignaturePrivateKey), SignatureError> {
        match self {
            Self::MLDSA44 => {
                let (pk, sk) = MLDSA44::keygen_from_seed(seed)?;
                Ok((SignaturePublicKey::MLDSA44(pk), SignaturePrivateKey::MLDSA44(sk)))
            }
            Self::MLDSA65 => {
                let (pk, sk) = MLDSA65::keygen_from_seed(seed)?;
                Ok((SignaturePublicKey::MLDSA65(pk), SignaturePrivateKey::MLDSA65(sk)))
            }
            Self::MLDSA87 => {
                let (pk, sk) = MLDSA87::keygen_from_seed(seed)?;
                Ok((SignaturePublicKey::MLDSA87(pk), SignaturePrivateKey::MLDSA87(sk)))
            }
        }
    }

    /// One-shot sign (pass-through to underlying [`Signer::sign`]).
    pub fn sign(
        &self,
        sk: &SignaturePrivateKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
    ) -> Result<Vec<u8>, SignatureError> {
        match (self, sk) {
            (Self::MLDSA44, SignaturePrivateKey::MLDSA44(sk)) => {
                Ok(MLDSA44::sign(sk, msg, ctx)?.to_vec())
            }
            (Self::MLDSA65, SignaturePrivateKey::MLDSA65(sk)) => {
                Ok(MLDSA65::sign(sk, msg, ctx)?.to_vec())
            }
            (Self::MLDSA87, SignaturePrivateKey::MLDSA87(sk)) => {
                Ok(MLDSA87::sign(sk, msg, ctx)?.to_vec())
            }
            _ => Err(SignatureError::GenericError(
                "Signature private key does not match the selected SignatureFactory algorithm",
            )),
        }
    }

    /// One-shot verify (pass-through to underlying [`SignatureVerifier::verify`]).
    pub fn verify(
        &self,
        pk: &SignaturePublicKey,
        msg: &[u8],
        ctx: Option<&[u8]>,
        sig: &[u8],
    ) -> Result<(), SignatureError> {
        match (self, pk) {
            (Self::MLDSA44, SignaturePublicKey::MLDSA44(pk)) => MLDSA44::verify(pk, msg, ctx, sig),
            (Self::MLDSA65, SignaturePublicKey::MLDSA65(pk)) => MLDSA65::verify(pk, msg, ctx, sig),
            (Self::MLDSA87, SignaturePublicKey::MLDSA87(pk)) => MLDSA87::verify(pk, msg, ctx, sig),
            _ => Err(SignatureError::GenericError(
                "Signature public key does not match the selected SignatureFactory algorithm",
            )),
        }
    }

    /// Begin a streaming sign operation (pass-through to [`Signer::sign_init`]).
    pub fn sign_init(
        &self,
        sk: &SignaturePrivateKey,
        ctx: Option<&[u8]>,
    ) -> Result<SignatureSigner, SignatureError> {
        match (self, sk) {
            (Self::MLDSA44, SignaturePrivateKey::MLDSA44(sk)) => {
                Ok(SignatureSigner::MLDSA44(MLDSA44::sign_init(sk, ctx)?))
            }
            (Self::MLDSA65, SignaturePrivateKey::MLDSA65(sk)) => {
                Ok(SignatureSigner::MLDSA65(MLDSA65::sign_init(sk, ctx)?))
            }
            (Self::MLDSA87, SignaturePrivateKey::MLDSA87(sk)) => {
                Ok(SignatureSigner::MLDSA87(MLDSA87::sign_init(sk, ctx)?))
            }
            _ => Err(SignatureError::GenericError(
                "Signature private key does not match the selected SignatureFactory algorithm",
            )),
        }
    }

    /// Begin a streaming verify operation (pass-through to [`SignatureVerifier::verify_init`]).
    pub fn verify_init(
        &self,
        pk: &SignaturePublicKey,
        ctx: Option<&[u8]>,
    ) -> Result<SignatureVerifierEngine, SignatureError> {
        match (self, pk) {
            (Self::MLDSA44, SignaturePublicKey::MLDSA44(pk)) => {
                Ok(SignatureVerifierEngine::MLDSA44(MLDSA44::verify_init(pk, ctx)?))
            }
            (Self::MLDSA65, SignaturePublicKey::MLDSA65(pk)) => {
                Ok(SignatureVerifierEngine::MLDSA65(MLDSA65::verify_init(pk, ctx)?))
            }
            (Self::MLDSA87, SignaturePublicKey::MLDSA87(pk)) => {
                Ok(SignatureVerifierEngine::MLDSA87(MLDSA87::verify_init(pk, ctx)?))
            }
            _ => Err(SignatureError::GenericError(
                "Signature public key does not match the selected SignatureFactory algorithm",
            )),
        }
    }
}

fn signature_err(e: SignatureError) -> FactoryError {
    FactoryError::UnsupportedAlgorithm(format!("Signature key decode failed: {e:?}"))
}

