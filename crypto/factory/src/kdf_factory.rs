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
use bouncycastle_concatkdf::{
    CONCAT_KDF_SHA3_256_NAME, CONCAT_KDF_SHA3_384_NAME, CONCAT_KDF_SHA3_512_NAME,
    CONCAT_KDF_SHA256_NAME, CONCAT_KDF_SHA384_NAME, CONCAT_KDF_SHA512_NAME, ConcatKDF_SHA3_256,
    ConcatKDF_SHA3_384, ConcatKDF_SHA3_512, ConcatKDF_SHA256, ConcatKDF_SHA384, ConcatKDF_SHA512,
};
use bouncycastle_core::errors::KDFError;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{AlgorithmInfo, KDF};
use bouncycastle_sha2::hkdf::{
    HKDF_SHA256, HKDF_SHA256_NAME, HKDF_SHA384, HKDF_SHA384_NAME, HKDF_SHA512, HKDF_SHA512_NAME,
};
use bouncycastle_sm3::hkdf::{HKDF_SM3, HKDF_SM3_NAME};
use bouncycastle_x963kdf::{
    X963KDF_SHA256, X963KDF_SHA256_NAME, X963KDF_SHA384, X963KDF_SHA384_NAME, X963KDF_SHA512,
    X963KDF_SHA512_NAME,
};

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
    /// The ANSI X9.63 KDF over SHA-256 (SEC 1 v2 Section 3.6.1).
    #[allow(non_camel_case_types)]
    X963KDF_SHA256(X963KDF_SHA256),
    /// The ANSI X9.63 KDF over SHA-384.
    #[allow(non_camel_case_types)]
    X963KDF_SHA384(X963KDF_SHA384),
    /// The ANSI X9.63 KDF over SHA-512.
    #[allow(non_camel_case_types)]
    X963KDF_SHA512(X963KDF_SHA512),
    /// The NIST concatenation KDF over SHA-256 (SP 800-56C Rev. 2 Section 4.1, Option 1).
    #[allow(non_camel_case_types)]
    ConcatKDF_SHA256(ConcatKDF_SHA256),
    /// The NIST concatenation KDF over SHA-384.
    #[allow(non_camel_case_types)]
    ConcatKDF_SHA384(ConcatKDF_SHA384),
    /// The NIST concatenation KDF over SHA-512.
    #[allow(non_camel_case_types)]
    ConcatKDF_SHA512(ConcatKDF_SHA512),
    /// The NIST concatenation KDF over SHA3-256.
    #[allow(non_camel_case_types)]
    ConcatKDF_SHA3_256(ConcatKDF_SHA3_256),
    /// The NIST concatenation KDF over SHA3-384.
    #[allow(non_camel_case_types)]
    ConcatKDF_SHA3_384(ConcatKDF_SHA3_384),
    /// The NIST concatenation KDF over SHA3-512.
    #[allow(non_camel_case_types)]
    ConcatKDF_SHA3_512(ConcatKDF_SHA3_512),
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
            X963KDF_SHA256_NAME => Ok(Self::X963KDF_SHA256(X963KDF_SHA256::new())),
            X963KDF_SHA384_NAME => Ok(Self::X963KDF_SHA384(X963KDF_SHA384::new())),
            X963KDF_SHA512_NAME => Ok(Self::X963KDF_SHA512(X963KDF_SHA512::new())),
            CONCAT_KDF_SHA256_NAME => Ok(Self::ConcatKDF_SHA256(ConcatKDF_SHA256::new())),
            CONCAT_KDF_SHA384_NAME => Ok(Self::ConcatKDF_SHA384(ConcatKDF_SHA384::new())),
            CONCAT_KDF_SHA512_NAME => Ok(Self::ConcatKDF_SHA512(ConcatKDF_SHA512::new())),
            CONCAT_KDF_SHA3_256_NAME => Ok(Self::ConcatKDF_SHA3_256(ConcatKDF_SHA3_256::new())),
            CONCAT_KDF_SHA3_384_NAME => Ok(Self::ConcatKDF_SHA3_384(ConcatKDF_SHA3_384::new())),
            CONCAT_KDF_SHA3_512_NAME => Ok(Self::ConcatKDF_SHA3_512(ConcatKDF_SHA3_512::new())),
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
            Self::X963KDF_SHA256(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::X963KDF_SHA384(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::X963KDF_SHA512(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::ConcatKDF_SHA256(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::ConcatKDF_SHA384(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::ConcatKDF_SHA512(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::ConcatKDF_SHA3_256(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::ConcatKDF_SHA3_384(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
            Self::ConcatKDF_SHA3_512(h) => h.derive_key_out(ikm, fixed_info, len, output_key),
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
            Self::X963KDF_SHA256(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::X963KDF_SHA384(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::X963KDF_SHA512(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::ConcatKDF_SHA256(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::ConcatKDF_SHA384(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::ConcatKDF_SHA512(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::ConcatKDF_SHA3_256(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::ConcatKDF_SHA3_384(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
            Self::ConcatKDF_SHA3_512(h) => {
                h.derive_key_from_multiple_out(ikms, fixed_info, len, output_key)
            }
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
            Self::X963KDF_SHA256(h) => h.alg_name(),
            Self::X963KDF_SHA384(h) => h.alg_name(),
            Self::X963KDF_SHA512(h) => h.alg_name(),
            Self::ConcatKDF_SHA256(h) => h.alg_name(),
            Self::ConcatKDF_SHA384(h) => h.alg_name(),
            Self::ConcatKDF_SHA512(h) => h.alg_name(),
            Self::ConcatKDF_SHA3_256(h) => h.alg_name(),
            Self::ConcatKDF_SHA3_384(h) => h.alg_name(),
            Self::ConcatKDF_SHA3_512(h) => h.alg_name(),
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::HKDF_SHA256(h) => h.max_security_strength(),
            Self::HKDF_SHA384(h) => h.max_security_strength(),
            Self::HKDF_SHA512(h) => h.max_security_strength(),
            Self::HKDF_SM3(h) => h.max_security_strength(),
            Self::X963KDF_SHA256(h) => h.max_security_strength(),
            Self::X963KDF_SHA384(h) => h.max_security_strength(),
            Self::X963KDF_SHA512(h) => h.max_security_strength(),
            Self::ConcatKDF_SHA256(h) => h.max_security_strength(),
            Self::ConcatKDF_SHA384(h) => h.max_security_strength(),
            Self::ConcatKDF_SHA512(h) => h.max_security_strength(),
            Self::ConcatKDF_SHA3_256(h) => h.max_security_strength(),
            Self::ConcatKDF_SHA3_384(h) => h.max_security_strength(),
            Self::ConcatKDF_SHA3_512(h) => h.max_security_strength(),
        }
    }
}
