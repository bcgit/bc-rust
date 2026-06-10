//! RNG factory for creating instances of algorithms that implement the [RNG] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [RNGFactory] object which itself implements the [RNG] trait as a pass-through to the underlying algorithm.
//!
//! A quick note about cryptographic random number generators (RNGs), which are also sometimes
//! cryptographically secure random number generators (CSRNGs) or pseudorandom number generators (PRNGS)).
//! As the last name suggests, they are based on deterministic permutation functions called
//! deterministic random bit generators (DRBGs), which, always produce the same output for the same seed value.
//! Meaning that they are only as cryptographically strong and unique as their seed.
//!
//! All RNGs exposed through the [RNGFactory] are seeded from the underlying operating system's entropy pool,
//! and therefore should be sufficient for most cryptographic use. Additional entropy can be added via the
//! [RNG::add_seed_keymaterial] function.
//!
//! Applications that require direct control over the seed material, for example in order to deterministically
//! re-generate a key stream from a private seed, or in order to use a specific approved entropy source should
//! instead use the objects in the [rng] crate, which expose more instantiation functionality.
//!
//!
//! Example usage:
//! ```
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! let h = bouncycastle_factory::hash_factory::HashFactory::new(sha3::SHA3_256_NAME).unwrap();
//! let mut output = [0u8; 64];
//! let written = h.hash_out(data, &mut output);
//! let digest = &output[..written];
//! ```
//! You can equivalently invoke this by string instead of using the constant:
//!
//! ```
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_core::traits::Hash;
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! let h = bouncycastle_factory::hash_factory::HashFactory::new("SHA3-256").unwrap();
//! let mut output = [0u8; 64];
//! let written = h.hash_out(data, &mut output);
//! let digest = &output[..written];
//! ```

use bouncycastle_core::errors::RNGError;
use bouncycastle_core::traits::{SecurityStrength, RNG};
use bouncycastle_core::key_material::KeyMaterialTrait;
use crate::{AlgorithmFactory, FactoryError};
use crate::{DEFAULT, DEFAULT_128_BIT, DEFAULT_256_BIT};

use bouncycastle_rng as rng;
use bouncycastle_rng::{HASH_DRBG_SHA256_NAME, HASH_DRBG_SHA512_NAME};

/*** Defaults ***/
pub const DEFAULT_DRBG_NAME: &str = HASH_DRBG_SHA512_NAME;
pub const DEFAULT_128BIT_DRBG_NAME: &str = HASH_DRBG_SHA256_NAME;
pub const DEFAULT_256BIT_DRBG_NAME: &str = HASH_DRBG_SHA512_NAME;



/// All members must impl RNG.
pub enum RNGFactory {
    #[allow(non_camel_case_types)]
    HashDRBG_SHA256(rng::HashDRBG_SHA256),
    #[allow(non_camel_case_types)]
    HashDRBG_SHA512(rng::HashDRBG_SHA512),
}

impl Default for RNGFactory {
    fn default() -> Self { Self::new(DEFAULT_DRBG_NAME).unwrap() }
}

impl AlgorithmFactory for RNGFactory {
    fn default_128_bit() -> Self { Self::new(DEFAULT_128BIT_DRBG_NAME).unwrap() }
    fn default_256_bit() -> Self { Self::new(DEFAULT_256BIT_DRBG_NAME).unwrap() }

    fn new(alg_name: &str) -> Result<Self, FactoryError> {
        match alg_name {
            DEFAULT => Ok(Self::default()),
            DEFAULT_128_BIT => Ok(Self::default_128_bit()),
            DEFAULT_256_BIT => Ok(Self::default_256_bit()),
            HASH_DRBG_SHA256_NAME => Ok(Self::HashDRBG_SHA256(rng::HashDRBG_SHA256::new_from_os())),
            HASH_DRBG_SHA512_NAME => Ok(Self::HashDRBG_SHA512(rng::HashDRBG_SHA512::new_from_os())),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!("The algorithm: \"{}\" is not a known RNG", alg_name))),
        }
    }
}

impl RNG for RNGFactory {
    fn add_seed_keymaterial(&mut self, additional_seed: impl KeyMaterialTrait) -> Result<(), RNGError> {
        match self {
            Self::HashDRBG_SHA256(rng) => {rng.add_seed_keymaterial(additional_seed) },
            Self::HashDRBG_SHA512(rng) => { rng.add_seed_keymaterial(additional_seed) },
        }
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        match self {
            Self::HashDRBG_SHA256(rng) => {rng.next_int() },
            Self::HashDRBG_SHA512(rng) => { rng.next_int() },
        }
    }

    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError> {
        match self {
            Self::HashDRBG_SHA256(rng) => {rng.next_bytes(len) },
            Self::HashDRBG_SHA512(rng) => { rng.next_bytes(len) },
        }
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        out.fill(0);

        match self {
            Self::HashDRBG_SHA256(rng) => {rng.next_bytes_out(out) },
            Self::HashDRBG_SHA512(rng) => { rng.next_bytes_out(out) },
        }
    }

    fn fill_keymaterial_out(&mut self, out: &mut impl KeyMaterialTrait) -> Result<usize, RNGError> {
        match self {
            Self::HashDRBG_SHA256(rng) => {rng.fill_keymaterial_out(out) },
            Self::HashDRBG_SHA512(rng) => { rng.fill_keymaterial_out(out) },
        }
    }

    fn security_strength(&self) -> SecurityStrength {
        match self {
            Self::HashDRBG_SHA256(rng) => {rng.security_strength() },
            Self::HashDRBG_SHA512(rng) => { rng.security_strength() },
        }
    }
}
