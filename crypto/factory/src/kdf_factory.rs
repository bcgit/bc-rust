//! KDF factory for creating instances of algorithms that implement the [KDF] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [KDFFactory] object which itself implements the [KDF] trait as a pass-through to the underlying algorithm.
//!
//! Example usage:
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_factory::AlgorithmFactory;
//!
//! // get your key material from a secure place; here we'll use the default RNG, seeded from the OS
//! let seed_key = KeyMaterial256::from_rng(&mut bouncycastle_rng::DefaultRNG::default()).unwrap();
//! let additional_input: &[u8] = b"some additional input";
//!
//! let mut h = bouncycastle_factory::kdf_factory::KDFFactory::new(bouncycastle_hkdf::HKDF_SHA256_NAME).unwrap();
//! let new_key = h.derive_key(&seed_key, additional_input).unwrap();
//! ```
//!
//! You can equivalently invoke this by string instead of using the constant:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_factory::AlgorithmFactory;
//!
//! // get your key material from a secure place; here we'll use the default RNG, seeded from the OS
//! let seed_key = KeyMaterial256::from_rng(&mut bouncycastle_rng::DefaultRNG::default()).unwrap();
//! let additional_input: &[u8] = b"some additional input";
//!
//! let h = bouncycastle_factory::kdf_factory::KDFFactory::new("HKDF-SHA256").unwrap();
//! let new_key = h.derive_key(&seed_key, additional_input).unwrap();
//! ```
//!
//! Or if you don't particularly care which algorithm is used, you can use the built-in default:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_factory::AlgorithmFactory;
//!
//! // get your key material from a secure place; here we'll use the default RNG, seeded from the OS
//! let seed_key = KeyMaterial256::from_rng(&mut bouncycastle_rng::DefaultRNG::default()).unwrap();
//! let additional_input: &[u8] = b"some additional input";
//!
//! let h = bouncycastle_factory::kdf_factory::KDFFactory::default();
//! let new_key = h.derive_key(&seed_key, additional_input).unwrap();
//! ```

use crate::{AlgorithmFactory, DEFAULT, DEFAULT_128_BIT, DEFAULT_256_BIT, FactoryError};
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::traits::{KDF, SecurityStrength};
use bouncycastle_hkdf as hkdf;
use bouncycastle_hkdf::{HKDF_SHA256_NAME, HKDF_SHA512_NAME};
use bouncycastle_sha3 as sha3;
use bouncycastle_sha3::{
    SHA3_224_NAME, SHA3_256_NAME, SHA3_384_NAME, SHA3_512_NAME, SHAKE128_NAME, SHAKE256_NAME,
};

/*** Defaults ***/
pub const DEFAULT_KDF_NAME: &str = HKDF_SHA512_NAME;
pub const DEFAULT_128BIT_KDF_NAME: &str = HKDF_SHA256_NAME;
pub const DEFAULT_256BIT_KDF_NAME: &str = HKDF_SHA512_NAME;

// All members must impl KDF.
pub enum KDFFactory {
    #[allow(non_camel_case_types)]
    HKDF_SHA256(hkdf::HKDF_SHA256),
    #[allow(non_camel_case_types)]
    HKDF_SHA512(hkdf::HKDF_SHA512),
    SHA3_224(sha3::SHA3_224),
    SHA3_256(sha3::SHA3_256),
    SHA3_384(sha3::SHA3_384),
    SHA3_512(sha3::SHA3_512),
    SHAKE128(sha3::SHAKE128),
    SHAKE256(sha3::SHAKE256),
}

impl Default for KDFFactory {
    fn default() -> Self {
        KDFFactory::new(DEFAULT_KDF_NAME).unwrap()
    }
}

impl AlgorithmFactory for KDFFactory {
    fn default_128_bit() -> Self {
        KDFFactory::new(DEFAULT_128BIT_KDF_NAME).unwrap()
    }

    fn default_256_bit() -> Self {
        KDFFactory::new(DEFAULT_256BIT_KDF_NAME).unwrap()
    }

    fn new(alg_name: &str) -> Result<Self, FactoryError> {
        match alg_name {
            DEFAULT => Ok(KDFFactory::default()),
            DEFAULT_128_BIT => Ok(KDFFactory::default_128_bit()),
            DEFAULT_256_BIT => Ok(KDFFactory::default_256_bit()),
            HKDF_SHA256_NAME => Ok(Self::HKDF_SHA256(hkdf::HKDF_SHA256::new())),
            HKDF_SHA512_NAME => Ok(Self::HKDF_SHA512(hkdf::HKDF_SHA512::new())),
            SHA3_224_NAME => Ok(Self::SHA3_224(sha3::SHA3_224::new())),
            SHA3_256_NAME => Ok(Self::SHA3_256(sha3::SHA3_256::new())),
            SHA3_384_NAME => Ok(Self::SHA3_384(sha3::SHA3_384::new())),
            SHA3_512_NAME => Ok(Self::SHA3_512(sha3::SHA3_512::new())),
            SHAKE128_NAME => Ok(Self::SHAKE128(sha3::SHAKE128::new())),
            SHAKE256_NAME => Ok(Self::SHAKE256(sha3::SHAKE256::new())),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{}\" is not a known KDF",
                alg_name
            ))),
        }
    }
}

impl KDF for KDFFactory {
    fn derive_key(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        match self {
            Self::HKDF_SHA256(h) => h.derive_key(key, additional_input),
            Self::HKDF_SHA512(h) => h.derive_key(key, additional_input),
            Self::SHA3_224(h) => h.derive_key(key, additional_input),
            Self::SHA3_256(h) => h.derive_key(key, additional_input),
            Self::SHA3_384(h) => h.derive_key(key, additional_input),
            Self::SHA3_512(h) => h.derive_key(key, additional_input),
            Self::SHAKE128(h) => h.derive_key(key, additional_input),
            Self::SHAKE256(h) => h.derive_key(key, additional_input),
        }
    }

    fn derive_key_out(
        self,
        key: &impl KeyMaterialTrait,
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        match self {
            Self::HKDF_SHA256(h) => h.derive_key_out(key, additional_input, output_key),
            Self::HKDF_SHA512(h) => h.derive_key_out(key, additional_input, output_key),
            Self::SHA3_224(h) => h.derive_key_out(key, additional_input, output_key),
            Self::SHA3_256(h) => h.derive_key_out(key, additional_input, output_key),
            Self::SHA3_384(h) => h.derive_key_out(key, additional_input, output_key),
            Self::SHA3_512(h) => h.derive_key_out(key, additional_input, output_key),
            Self::SHAKE128(h) => h.derive_key_out(key, additional_input, output_key),
            Self::SHAKE256(h) => h.derive_key_out(key, additional_input, output_key),
        }
    }

    fn derive_key_from_multiple(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
    ) -> Result<Box<dyn KeyMaterialTrait>, KDFError> {
        match self {
            Self::HKDF_SHA256(h) => h.derive_key_from_multiple(keys, additional_input),
            Self::HKDF_SHA512(h) => h.derive_key_from_multiple(keys, additional_input),
            Self::SHA3_224(h) => h.derive_key_from_multiple(keys, additional_input),
            Self::SHA3_256(h) => h.derive_key_from_multiple(keys, additional_input),
            Self::SHA3_384(h) => h.derive_key_from_multiple(keys, additional_input),
            Self::SHA3_512(h) => h.derive_key_from_multiple(keys, additional_input),
            Self::SHAKE128(h) => h.derive_key_from_multiple(keys, additional_input),
            Self::SHAKE256(h) => h.derive_key_from_multiple(keys, additional_input),
        }
    }

    fn derive_key_from_multiple_out(
        self,
        keys: &[&impl KeyMaterialTrait],
        additional_input: &[u8],
        output_key: &mut impl KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        match self {
            Self::HKDF_SHA256(h) => {
                h.derive_key_from_multiple_out(keys, additional_input, output_key)
            }
            Self::HKDF_SHA512(h) => {
                h.derive_key_from_multiple_out(keys, additional_input, output_key)
            }
            Self::SHA3_224(h) => h.derive_key_from_multiple_out(keys, additional_input, output_key),
            Self::SHA3_256(h) => h.derive_key_from_multiple_out(keys, additional_input, output_key),
            Self::SHA3_384(h) => h.derive_key_from_multiple_out(keys, additional_input, output_key),
            Self::SHA3_512(h) => h.derive_key_from_multiple_out(keys, additional_input, output_key),
            Self::SHAKE128(h) => h.derive_key_from_multiple_out(keys, additional_input, output_key),
            Self::SHAKE256(h) => h.derive_key_from_multiple_out(keys, additional_input, output_key),
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::HKDF_SHA256(h) => h.max_security_strength(),
            Self::HKDF_SHA512(h) => h.max_security_strength(),
            Self::SHA3_224(h) => h.max_security_strength(),
            Self::SHA3_256(h) => h.max_security_strength(),
            Self::SHA3_384(h) => h.max_security_strength(),
            Self::SHA3_512(h) => h.max_security_strength(),
            Self::SHAKE128(h) => h.max_security_strength(),
            Self::SHAKE256(h) => h.max_security_strength(),
        }
    }
}
