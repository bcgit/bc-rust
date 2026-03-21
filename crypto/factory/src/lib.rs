//! Factory crate for creating instances of different types.
//! Factory objects behave like other crypto providers in that they take an algorithm by string name and return an instance of the corresponding type.
//! Generally, there is one factory for each trait in [bouncycastle_core_interface::traits].
//!
//! All factories are based on the rust enum factory pattern where, for example, the [hash_factory::HashFactory]
//! can hold any Hash type in the library, and [hash_factory::HashFactory] itself impls [bouncycastle_core_interface::traits::Hash]
//! and so can be called directly as if it is a hash.
//!
//! Example usage:
//! ```
//! use bouncycastle_core_interface::traits::Hash;
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
//! Additionally, all factory types implement [AlgorithmFactory] which exposes functions to
//! get the either the default algorithm or the default algorithm at the 128-bit or 256-bit security level.
//! It also exposes [AlgorithmFactory::new] which can be used to create an instance of the algorithm
//! by string name according to the string constants associated with the respective factory type.

use bouncycastle_core_interface::errors::{MACError};

pub mod hash_factory;
pub mod kdf_factory;
pub mod mac_factory;
pub mod rng_factory;
pub mod xof_factory;

/*** String constants ***/
pub const DEFAULT: &str = "Default";
pub const DEFAULT_128_BIT: &str = "Default128Bit";
pub const DEFAULT_256_BIT: &str = "Default256Bit";


#[derive(Debug)]
pub enum FactoryError {
    MACError(MACError),
    UnsupportedAlgorithm(String),
}

impl From<MACError> for FactoryError {
    fn from(e: MACError) -> FactoryError {
        Self::MACError(e)
    }
}

pub trait AlgorithmFactory: Sized + Default {

    // Get the default configured algorithm.
    // Not implemented because all factories MUST impl Default.
    // fn default() -> Self;

    /// Get the default configured algorithm at the 128-bit security level.
    fn default_128_bit() -> Self;

    /// Get the default configured algorithm at the 256-bit security level.
    fn default_256_bit() -> Self;

    /// Create an instance of the algorithm by name.
    fn new(alg_name: &str) -> Result<Self, FactoryError>;
}