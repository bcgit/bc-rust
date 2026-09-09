//! KDF factory for creating instances of algorithms that implement the [`KDF`] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [`KDFFactory`] object which itself implements the [`KDF`] trait as a pass-through to the underlying algorithm.
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
//! let mut h = bouncycastle_factory::kdf_factory::KDFFactory::new(bouncycastle_hkdf::HKDF_SHA256_NAME).unwrap();
//! let new_key = h.derive_key(&seed_key, additional_input).unwrap();
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
//! let new_key = h.derive_key(&seed_key, additional_input).unwrap();
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
//! let new_key = h.derive_key(&seed_key, additional_input).unwrap();
//! ```

use bouncycastle_factory_macros::{AlgorithmFactory, KDF};
use bouncycastle_hkdf as hkdf;
use bouncycastle_sha3 as sha3;

/// Wrapper object for all algorithms that impl [`KDF`].
#[derive(KDF, AlgorithmFactory)]
#[non_exhaustive]
pub enum KDFFactory {
    ///
    #[allow(non_camel_case_types)]
    #[factory(name = hkdf::HKDF_SHA256_NAME, default_128_bit)]
    HKDF_SHA256(hkdf::HKDF_SHA256),
    ///
    #[factory(name = hkdf::HKDF_SHA512_NAME, default_256_bit)]
    #[allow(non_camel_case_types)]
    HKDF_SHA512(hkdf::HKDF_SHA512),
    ///
    #[factory(name = sha3::SHA3_224_NAME)]
    SHA3_224(sha3::SHA3_224),
    ///
    #[factory(name = sha3::SHA3_256_NAME)]
    SHA3_256(sha3::SHA3_256),
    ///
    #[factory(name = sha3::SHA3_384_NAME)]
    SHA3_384(sha3::SHA3_384),
    ///
    #[factory(name = sha3::SHA3_512_NAME)]
    SHA3_512(sha3::SHA3_512),
    ///
    #[factory(name = sha3::SHAKE128_NAME)]
    SHAKE128(sha3::SHAKE128),
    ///
    #[factory(name = sha3::SHAKE256_NAME)]
    SHAKE256(sha3::SHAKE256),
}
