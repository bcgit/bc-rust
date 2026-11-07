//! KDF factory for creating instances of algorithms that implement the [`KDF`] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [`KDFFactory`] object which itself implements the [`KDF`] trait as a pass-through to the underlying algorithm.
//! See [`KDF`] for the full key-derivation API, key-material handling rules, and additional-input semantics.
//! The HKDF variants are `HKDF::new()`, RFC 5869's absent salt; a salted instance is built from
//! the hash crate's alias, `HKDF_SHA256::new_with_salt`, which the factory does not reach.
//!
//! Example usage:
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_factory::AlgorithmFactory;
//!
//! // Obtain key material from a secure place; here the default RNG is used, seeded from the OS is used
//! let seed_key = KeyMaterial256::from_rng(&mut bouncycastle_rng::DefaultRNG::default()).unwrap();
//! let additional_input: &[u8] = b"some additional input";
//!
//! let mut h = bouncycastle_factory::kdf_factory::KDFFactory::new(bouncycastle_sha2::hkdf::HKDF_SHA256_NAME).unwrap();
//! let new_key = h.derive_key(&seed_key, additional_input, 32).unwrap();
//! ```
//!
//! Equivalently, it may be invoked by passing a string instead of using the constant:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_factory::AlgorithmFactory;
//!
//! // Obtain key material from a secure place; here the default RNG is used, seeded from the OS is used
//! let seed_key = KeyMaterial256::from_rng(&mut bouncycastle_rng::DefaultRNG::default()).unwrap();
//! let additional_input: &[u8] = b"some additional input";
//!
//! let h = bouncycastle_factory::kdf_factory::KDFFactory::new("HKDF-SHA256").unwrap();
//! let new_key = h.derive_key(&seed_key, additional_input, 32).unwrap();
//! ```
//!
//! If the algorithm used is not particularly important, the built-in default may be used:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::traits::KDF;
//! use bouncycastle_factory::AlgorithmFactory;
//!
//! // Obtain key material from a secure place; here the default RNG is used, seeded from the OS is used
//! let seed_key = KeyMaterial256::from_rng(&mut bouncycastle_rng::DefaultRNG::default()).unwrap();
//! let additional_input: &[u8] = b"some additional input";
//!
//! let h = bouncycastle_factory::kdf_factory::KDFFactory::default();
//! let new_key = h.derive_key(&seed_key, additional_input, 32).unwrap();
//! ```

use crate::{AlgorithmFactory, DEFAULT, DEFAULT_128_BIT, DEFAULT_256_BIT, FactoryError};
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{AlgorithmInfo, KDF};
use bouncycastle_sha2::hkdf::{
    HKDF_SHA256, HKDF_SHA256_NAME, HKDF_SHA384, HKDF_SHA384_NAME, HKDF_SHA512, HKDF_SHA512_NAME,
};
use bouncycastle_sha3 as sha3;
use bouncycastle_sha3::{
    SHA3_224_NAME, SHA3_256_NAME, SHA3_384_NAME, SHA3_512_NAME, SHAKE128_NAME, SHAKE256_NAME,
};
use bouncycastle_sm3::hkdf::{HKDF_SM3, HKDF_SM3_NAME};

/// Wrapper object for all algorithms that impl [`KDF`].
#[non_exhaustive]
pub enum KDFFactory {
    ///
    #[allow(non_camel_case_types)]
    HKDF_SHA256(HKDF_SHA256),
    ///
    #[allow(non_camel_case_types)]
    HKDF_SHA384(HKDF_SHA384),
    ///
    #[allow(non_camel_case_types)]
    HKDF_SHA512(HKDF_SHA512),
    /// HKDF over SM3.
    #[allow(non_camel_case_types)]
    HKDF_SM3(HKDF_SM3),
    ///
    SHA3_224(sha3::SHA3_224),
    ///
    SHA3_256(sha3::SHA3_256),
    ///
    SHA3_384(sha3::SHA3_384),
    ///
    SHA3_512(sha3::SHA3_512),
    ///
    SHAKE128(sha3::SHAKE128),
    ///
    SHAKE256(sha3::SHAKE256),
}

impl Default for KDFFactory {
    fn default() -> Self {
        Self::HKDF_SHA512(HKDF_SHA512::new())
    }
}

impl AlgorithmFactory for KDFFactory {
    fn default_128_bit() -> Self {
        Self::HKDF_SHA256(HKDF_SHA256::new())
    }

    fn default_256_bit() -> Self {
        Self::HKDF_SHA512(HKDF_SHA512::new())
    }

    fn new(alg_name: &str) -> Result<Self, FactoryError> {
        match alg_name {
            DEFAULT => Ok(KDFFactory::default()),
            DEFAULT_128_BIT => Ok(KDFFactory::default_128_bit()),
            DEFAULT_256_BIT => Ok(KDFFactory::default_256_bit()),
            HKDF_SHA256_NAME => Ok(Self::HKDF_SHA256(HKDF_SHA256::new())),
            HKDF_SHA384_NAME => Ok(Self::HKDF_SHA384(HKDF_SHA384::new())),
            HKDF_SHA512_NAME => Ok(Self::HKDF_SHA512(HKDF_SHA512::new())),
            HKDF_SM3_NAME => Ok(Self::HKDF_SM3(HKDF_SM3::new())),
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
    fn derive_key_out(
        &self,
        ikm: &dyn KeyMaterialTrait,
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        match self {
            Self::HKDF_SHA256(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::HKDF_SHA384(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::HKDF_SHA512(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::HKDF_SM3(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::SHA3_224(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::SHA3_256(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::SHA3_384(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::SHA3_512(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::SHAKE128(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::SHAKE256(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
        }
    }

    fn derive_key_from_multiple_out(
        &self,
        ikms: &[&dyn KeyMaterialTrait],
        fixed_info: &[u8],
        len: usize,
        output_key: &mut dyn KeyMaterialTrait,
    ) -> Result<usize, KDFError> {
        match self {
            Self::HKDF_SHA256(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::HKDF_SHA384(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::HKDF_SHA512(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::HKDF_SM3(h) => h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key),
            Self::SHA3_224(h) => h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key),
            Self::SHA3_256(h) => h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key),
            Self::SHA3_384(h) => h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key),
            Self::SHA3_512(h) => h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key),
            Self::SHAKE128(h) => h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key),
            Self::SHAKE256(h) => h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key),
        }
    }
}

impl AlgorithmInfo for KDFFactory {
    fn alg_name(&self) -> &'static str {
        match self {
            Self::HKDF_SHA256(h) => h.alg_name(),
            Self::HKDF_SHA384(h) => h.alg_name(),
            Self::HKDF_SHA512(h) => h.alg_name(),
            Self::HKDF_SM3(h) => h.alg_name(),
            Self::SHA3_224(h) => h.alg_name(),
            Self::SHA3_256(h) => h.alg_name(),
            Self::SHA3_384(h) => h.alg_name(),
            Self::SHA3_512(h) => h.alg_name(),
            Self::SHAKE128(h) => h.alg_name(),
            Self::SHAKE256(h) => h.alg_name(),
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::HKDF_SHA256(h) => h.max_security_strength(),
            Self::HKDF_SHA384(h) => h.max_security_strength(),
            Self::HKDF_SHA512(h) => h.max_security_strength(),
            Self::HKDF_SM3(h) => h.max_security_strength(),
            Self::SHA3_224(h) => h.max_security_strength(),
            Self::SHA3_256(h) => h.max_security_strength(),
            Self::SHA3_384(h) => h.max_security_strength(),
            Self::SHA3_512(h) => h.max_security_strength(),
            Self::SHAKE128(h) => h.max_security_strength(),
            Self::SHAKE256(h) => h.max_security_strength(),
        }
    }
}
