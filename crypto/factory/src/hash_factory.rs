//! Hash factory for creating instances of algorithms that implement the
//! [`bouncycastle_core::traits::Hash`] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [`HashFactory`] object which itself implements the [`bouncycastle_core::traits::Hash`]
//! trait as a pass-through to the underlying algorithm.
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
//! let output: Vec<u8> = h.hash(data);
//! ```
//! Equivalently, it may be invoked by passing a string instead of using the constant:
//!
//! ```
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_core::traits::Hash;
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! let h = bouncycastle_factory::hash_factory::HashFactory::new("SHA3-256").unwrap();
//! let output: Vec<u8> = h.hash(data);
//! ```

use bouncycastle_core::traits::{Algorithm, SecurityStrength};
use bouncycastle_factory_macros::{AlgorithmFactory, Hash};
use bouncycastle_sha2 as sha2;
use bouncycastle_sha3 as sha3;

/// Wrapper object for all algorithms that impl [`bouncycastle_core::traits::Hash`].
/// Note: no SHAKE because SHAKE is not NIST approved as a hash function. See FIPS 202 section A.2.
#[derive(Hash, AlgorithmFactory)]
#[non_exhaustive]
pub enum HashFactory {
    ///
    #[factory(name = sha2::SHA224_NAME)]
    SHA224(sha2::SHA224),
    ///
    #[factory(name = sha2::SHA256_NAME)]
    SHA256(sha2::SHA256),
    ///
    #[factory(name = sha2::SHA384_NAME)]
    SHA384(sha2::SHA384),
    ///
    #[factory(name = sha2::SHA512_NAME)]
    SHA512(sha2::SHA512),
    ///
    #[factory(name = sha3::SHA3_224_NAME)]
    SHA3_224(sha3::SHA3_224),
    ///
    #[factory(name = sha3::SHA3_256_NAME, default_128_bit)]
    SHA3_256(sha3::SHA3_256),
    ///
    #[factory(name = sha3::SHA3_384_NAME)]
    SHA3_384(sha3::SHA3_384),
    ///
    #[factory(name = sha3::SHA3_512_NAME, default_256_bit)]
    SHA3_512(sha3::SHA3_512),
}

// TODO -- this is broken.
//      The designed behaviour here is that the Factory object pass these through to the underlying algorithm
//      that it's wrapping, but that can't be done with consts, so I think the Algorithm trait needs
//      a rework to be functions instead of consts.
impl Algorithm for HashFactory {
    const ALG_NAME: &'static str = "TODO";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}
