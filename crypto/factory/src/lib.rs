//! Factory crate for creating instances of different types.
//! Factory objects behave like other crypto providers in that they take an algorithm by string name and return an instance of the corresponding type.
//! Generally, there is one factory for each trait in [`bouncycastle_core::traits`].
//!
//! All factories are based on the rust enum factory pattern where, for example, the [`hash_factory::HashFactory`]
//! can hold any Hash type in the library, and [`hash_factory::HashFactory`] itself impls [`bouncycastle_core::traits::Hash`]
//! and so can be called directly as if it is a hash.
//!
//! Example usage:
//! ```
//! use bouncycastle_core::traits::Hash;
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_factory::hash_factory::HashFactory;
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! let h = HashFactory::new("SHA3-256").unwrap();
//! let output: Vec<u8> = h.hash(data);
//! ```
//!
//! All other factory types similarly implement their underlying trait and thus behave the same way.
//!
//! Additionally, all factory types implement [`AlgorithmFactory`] which exposes functions to
//! get the either the default algorithm or the default algorithm at the 128-bit or 256-bit security level.
//! It also exposes [`AlgorithmFactory::new`] which can be used to create an instance of the algorithm
//! by string name according to the string constants associated with the respective factory type.
//!
//! This crate compiles with STD; ie it is explicitly not tagged as `no_std` and it makes use of `Vec` and other
//! dynamically-sized nice things.
//!
//! All enums exported from this crate are tagged `#[non_exhaustive]` to indicate that they
//! are highly likely to gain more branches in the future; therefore, the compiler is to treat it as
//! an error if a caller matches exhaustively against the current set of variants.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use bouncycastle_core::errors::MACError;

pub mod hash_factory;
pub mod kdf_factory;
pub mod mac_factory;
pub mod rng_factory;
pub mod xof_factory;

/*** String constants ***/
///
pub const DEFAULT: &str = "Default";
///
pub const DEFAULT_128_BIT: &str = "Default128Bit";
///
pub const DEFAULT_256_BIT: &str = "Default256Bit";

/// Top-level error type for Factories.
#[derive(Debug)]
#[non_exhaustive]
pub enum FactoryError {
    ///
    MACError(MACError),
    ///
    UnsupportedAlgorithm(String),
}

// todo -- weird that MACError is the only one that we need to promote?
impl From<MACError> for FactoryError {
    fn from(e: MACError) -> FactoryError {
        Self::MACError(e)
    }
}

///
pub trait AlgorithmFactory: Sized + Default {
    /// Get the default configured algorithm at the 128-bit security level.
    fn default_128_bit() -> Self;

    /// Get the default configured algorithm at the 256-bit security level.
    fn default_256_bit() -> Self;

    /// Get an instance of the algorithm by name.
    fn new(alg_name: &str) -> Result<Self, FactoryError>;
}
