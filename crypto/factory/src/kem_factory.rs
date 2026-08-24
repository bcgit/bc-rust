//! KEM factory for creating instances of algorithms that implement KEM traits.
//!
//! As with all Factory objects, this constructs algorithms from strings and defaults.
//! Supported objects are encapsulated in enums that pass operations through to the underlying types.
//!
//! # Design note on traits
//!
//! The core [`KEMEncapsulator`] and [`KEMDecapsulator`] traits are parameterized by const-generic
//! key and ciphertext sizes. A single enum that wraps ML-KEM-512/768/1024 cannot implement those
//! traits with one fixed set of const parameters. This module therefore wraps keys in enums and
//! exposes inherent methods with the same shape as the core traits.
//!
//! Example usage:
//! ```
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_factory::kem_factory::KEMFactory;
//! use bouncycastle_mlkem::ML_KEM_768_NAME;
//!
//! let factory = KEMFactory::new(ML_KEM_768_NAME).unwrap();
//! assert_eq!(factory.algorithm_name(), ML_KEM_768_NAME);
//! // keygen/encaps/decaps pass through to the underlying ML-KEM types;
//! // see the crate tests for full round-trip examples.
//! ```

use crate::{AlgorithmFactory, DEFAULT, DEFAULT_128_BIT, DEFAULT_256_BIT, FactoryError};
use bouncycastle_core::errors::KEMError;
use bouncycastle_core::key_material::KeyMaterial;
use bouncycastle_core::traits::{
    KEMDecapsulator as _, KEMEncapsulator as _, KEMPrivateKey as KEMPrivateKeyTrait,
    KEMPublicKey as KEMPublicKeyTrait, RNG,
};
use bouncycastle_mlkem as mlkem;
use bouncycastle_mlkem::{
    MLKEM512, MLKEM768, MLKEM1024, MLKEMTrait, MLKEM_SS_LEN, ML_KEM_512_NAME, ML_KEM_768_NAME,
    ML_KEM_1024_NAME,
};

/*** Defaults ***/
/// Default KEM algorithm name (192-bit class / ML-KEM-768).
pub const DEFAULT_KEM_NAME: &str = ML_KEM_768_NAME;
/// Default KEM algorithm at the 128-bit security level.
pub const DEFAULT_128BIT_KEM_NAME: &str = ML_KEM_512_NAME;
/// Default KEM algorithm at the 256-bit security level.
pub const DEFAULT_256BIT_KEM_NAME: &str = ML_KEM_1024_NAME;

/// Wrapper for all supported KEM public (encapsulation) keys.
pub enum KEMPublicKey {
    /// ML-KEM-512 public key.
    MLKEM512(mlkem::MLKEM512PublicKey),
    /// ML-KEM-768 public key.
    MLKEM768(mlkem::MLKEM768PublicKey),
    /// ML-KEM-1024 public key.
    MLKEM1024(mlkem::MLKEM1024PublicKey),
}

impl KEMPublicKey {
    /// Encode the public key to its standard byte encoding.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::MLKEM512(pk) => pk.encode().to_vec(),
            Self::MLKEM768(pk) => pk.encode().to_vec(),
            Self::MLKEM1024(pk) => pk.encode().to_vec(),
        }
    }

    /// Decode a public key from bytes for the named algorithm.
    pub fn from_bytes(alg_name: &str, bytes: &[u8]) -> Result<Self, FactoryError> {
        match alg_name {
            ML_KEM_512_NAME => Ok(Self::MLKEM512(
                mlkem::MLKEM512PublicKey::from_bytes(bytes).map_err(kem_err)?,
            )),
            ML_KEM_768_NAME => Ok(Self::MLKEM768(
                mlkem::MLKEM768PublicKey::from_bytes(bytes).map_err(kem_err)?,
            )),
            ML_KEM_1024_NAME => Ok(Self::MLKEM1024(
                mlkem::MLKEM1024PublicKey::from_bytes(bytes).map_err(kem_err)?,
            )),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{alg_name}\" is not a known KEM"
            ))),
        }
    }

    /// Algorithm name for this key.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MLKEM512(_) => ML_KEM_512_NAME,
            Self::MLKEM768(_) => ML_KEM_768_NAME,
            Self::MLKEM1024(_) => ML_KEM_1024_NAME,
        }
    }
}

/// Wrapper for all supported KEM private (decapsulation) keys.
pub enum KEMPrivateKey {
    /// ML-KEM-512 private key.
    MLKEM512(mlkem::MLKEM512PrivateKey),
    /// ML-KEM-768 private key.
    MLKEM768(mlkem::MLKEM768PrivateKey),
    /// ML-KEM-1024 private key.
    MLKEM1024(mlkem::MLKEM1024PrivateKey),
}

impl KEMPrivateKey {
    /// Encode the private key to its standard byte encoding.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::MLKEM512(sk) => sk.encode().to_vec(),
            Self::MLKEM768(sk) => sk.encode().to_vec(),
            Self::MLKEM1024(sk) => sk.encode().to_vec(),
        }
    }

    /// Decode a private key from bytes for the named algorithm.
    pub fn from_bytes(alg_name: &str, bytes: &[u8]) -> Result<Self, FactoryError> {
        match alg_name {
            ML_KEM_512_NAME => Ok(Self::MLKEM512(
                mlkem::MLKEM512PrivateKey::from_bytes(bytes).map_err(kem_err)?,
            )),
            ML_KEM_768_NAME => Ok(Self::MLKEM768(
                mlkem::MLKEM768PrivateKey::from_bytes(bytes).map_err(kem_err)?,
            )),
            ML_KEM_1024_NAME => Ok(Self::MLKEM1024(
                mlkem::MLKEM1024PrivateKey::from_bytes(bytes).map_err(kem_err)?,
            )),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{alg_name}\" is not a known KEM"
            ))),
        }
    }

    /// Algorithm name for this key.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MLKEM512(_) => ML_KEM_512_NAME,
            Self::MLKEM768(_) => ML_KEM_768_NAME,
            Self::MLKEM1024(_) => ML_KEM_1024_NAME,
        }
    }
}

/// Factory / algorithm selector for all supported KEM algorithms.
///
/// Constructed by name via [`AlgorithmFactory::new`] or the default helpers.
/// Operations pass through to the underlying ML-KEM parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KEMFactory {
    /// ML-KEM-512 (NIST security category 1 / ~128-bit class).
    MLKEM512,
    /// ML-KEM-768 (NIST security category 3 / ~192-bit class).
    MLKEM768,
    /// ML-KEM-1024 (NIST security category 5 / ~256-bit class).
    MLKEM1024,
}

impl Default for KEMFactory {
    fn default() -> Self {
        Self::MLKEM768
    }
}

impl AlgorithmFactory for KEMFactory {
    fn default_128_bit() -> Self {
        Self::MLKEM512
    }

    fn default_256_bit() -> Self {
        Self::MLKEM1024
    }

    fn new(alg_name: &str) -> Result<Self, FactoryError> {
        match alg_name {
            DEFAULT => Ok(Self::default()),
            DEFAULT_128_BIT => Ok(Self::default_128_bit()),
            DEFAULT_256_BIT => Ok(Self::default_256_bit()),
            ML_KEM_512_NAME => Ok(Self::MLKEM512),
            ML_KEM_768_NAME => Ok(Self::MLKEM768),
            ML_KEM_1024_NAME => Ok(Self::MLKEM1024),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{alg_name}\" is not a known KEM"
            ))),
        }
    }
}

impl KEMFactory {
    /// Algorithm name string for this factory selection.
    pub fn algorithm_name(&self) -> &'static str {
        match self {
            Self::MLKEM512 => ML_KEM_512_NAME,
            Self::MLKEM768 => ML_KEM_768_NAME,
            Self::MLKEM1024 => ML_KEM_1024_NAME,
        }
    }

    /// Generate a fresh key pair using the library default OS-backed RNG.
    pub fn keygen(&self) -> Result<(KEMPublicKey, KEMPrivateKey), KEMError> {
        match self {
            Self::MLKEM512 => {
                let (pk, sk) = MLKEM512::keygen()?;
                Ok((KEMPublicKey::MLKEM512(pk), KEMPrivateKey::MLKEM512(sk)))
            }
            Self::MLKEM768 => {
                let (pk, sk) = MLKEM768::keygen()?;
                Ok((KEMPublicKey::MLKEM768(pk), KEMPrivateKey::MLKEM768(sk)))
            }
            Self::MLKEM1024 => {
                let (pk, sk) = MLKEM1024::keygen()?;
                Ok((KEMPublicKey::MLKEM1024(pk), KEMPrivateKey::MLKEM1024(sk)))
            }
        }
    }

    /// Generate a key pair using the provided RNG.
    pub fn keygen_from_rng(
        &self,
        rng: &mut dyn RNG,
    ) -> Result<(KEMPublicKey, KEMPrivateKey), KEMError> {
        match self {
            Self::MLKEM512 => {
                let (pk, sk) = MLKEM512::keygen_from_rng(rng)?;
                Ok((KEMPublicKey::MLKEM512(pk), KEMPrivateKey::MLKEM512(sk)))
            }
            Self::MLKEM768 => {
                let (pk, sk) = MLKEM768::keygen_from_rng(rng)?;
                Ok((KEMPublicKey::MLKEM768(pk), KEMPrivateKey::MLKEM768(sk)))
            }
            Self::MLKEM1024 => {
                let (pk, sk) = MLKEM1024::keygen_from_rng(rng)?;
                Ok((KEMPublicKey::MLKEM1024(pk), KEMPrivateKey::MLKEM1024(sk)))
            }
        }
    }

    /// Generate a key pair from a 64-byte seed.
    pub fn keygen_from_seed(
        &self,
        seed: &KeyMaterial<64>,
    ) -> Result<(KEMPublicKey, KEMPrivateKey), KEMError> {
        match self {
            Self::MLKEM512 => {
                let (pk, sk) = MLKEM512::keygen_from_seed(seed)?;
                Ok((KEMPublicKey::MLKEM512(pk), KEMPrivateKey::MLKEM512(sk)))
            }
            Self::MLKEM768 => {
                let (pk, sk) = MLKEM768::keygen_from_seed(seed)?;
                Ok((KEMPublicKey::MLKEM768(pk), KEMPrivateKey::MLKEM768(sk)))
            }
            Self::MLKEM1024 => {
                let (pk, sk) = MLKEM1024::keygen_from_seed(seed)?;
                Ok((KEMPublicKey::MLKEM1024(pk), KEMPrivateKey::MLKEM1024(sk)))
            }
        }
    }

    /// Encapsulate to the given public key (pass-through to [`KEMEncapsulator::encaps`]).
    ///
    /// Returns `(shared_secret, ciphertext)`.
    pub fn encaps(
        &self,
        pk: &KEMPublicKey,
    ) -> Result<(KeyMaterial<MLKEM_SS_LEN>, Vec<u8>), KEMError> {
        match (self, pk) {
            (Self::MLKEM512, KEMPublicKey::MLKEM512(pk)) => {
                let (ss, ct) = MLKEM512::encaps(pk)?;
                Ok((ss, ct.to_vec()))
            }
            (Self::MLKEM768, KEMPublicKey::MLKEM768(pk)) => {
                let (ss, ct) = MLKEM768::encaps(pk)?;
                Ok((ss, ct.to_vec()))
            }
            (Self::MLKEM1024, KEMPublicKey::MLKEM1024(pk)) => {
                let (ss, ct) = MLKEM1024::encaps(pk)?;
                Ok((ss, ct.to_vec()))
            }
            _ => Err(KEMError::GenericError(
                "KEM public key does not match the selected KEMFactory algorithm",
            )),
        }
    }

    /// Encapsulate using a caller-provided RNG (pass-through to [`KEMEncapsulator::encaps_rng`]).
    pub fn encaps_rng(
        &self,
        pk: &KEMPublicKey,
        rng: &mut dyn RNG,
    ) -> Result<(KeyMaterial<MLKEM_SS_LEN>, Vec<u8>), KEMError> {
        match (self, pk) {
            (Self::MLKEM512, KEMPublicKey::MLKEM512(pk)) => {
                let (ss, ct) = MLKEM512::encaps_rng(pk, rng)?;
                Ok((ss, ct.to_vec()))
            }
            (Self::MLKEM768, KEMPublicKey::MLKEM768(pk)) => {
                let (ss, ct) = MLKEM768::encaps_rng(pk, rng)?;
                Ok((ss, ct.to_vec()))
            }
            (Self::MLKEM1024, KEMPublicKey::MLKEM1024(pk)) => {
                let (ss, ct) = MLKEM1024::encaps_rng(pk, rng)?;
                Ok((ss, ct.to_vec()))
            }
            _ => Err(KEMError::GenericError(
                "KEM public key does not match the selected KEMFactory algorithm",
            )),
        }
    }

    /// Decapsulate a ciphertext (pass-through to [`KEMDecapsulator::decaps`]).
    pub fn decaps(
        &self,
        sk: &KEMPrivateKey,
        ct: &[u8],
    ) -> Result<KeyMaterial<MLKEM_SS_LEN>, KEMError> {
        match (self, sk) {
            (Self::MLKEM512, KEMPrivateKey::MLKEM512(sk)) => MLKEM512::decaps(sk, ct),
            (Self::MLKEM768, KEMPrivateKey::MLKEM768(sk)) => MLKEM768::decaps(sk, ct),
            (Self::MLKEM1024, KEMPrivateKey::MLKEM1024(sk)) => MLKEM1024::decaps(sk, ct),
            _ => Err(KEMError::GenericError(
                "KEM private key does not match the selected KEMFactory algorithm",
            )),
        }
    }
}

fn kem_err(e: KEMError) -> FactoryError {
    FactoryError::UnsupportedAlgorithm(format!("KEM key decode failed: {e:?}"))
}


