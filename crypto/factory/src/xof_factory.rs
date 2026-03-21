//! XOF factory for creating instances of algorithms that implement the [XOF] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [XOFFactory] object which itself implements the [XOF] trait as a pass-through to the underlying algorithm.
//!
//! Example usage:
//! ```
//! use core_interface::traits::XOF;
//! use factory::AlgorithmFactory;
//! use factory::xof_factory::XOFFactory;
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! let mut h = XOFFactory::new(sha3::SHAKE128_NAME).unwrap();
//! h.absorb(data).unwrap();
//! let output: Vec<u8> = h.squeeze(16).unwrap();
//! ```
//! You can equivalently invoke this by string instead of using the constant:
//!
//! ```
//! use factory::AlgorithmFactory;
//! use factory::xof_factory::XOFFactory;
//!
//! let mut h = XOFFactory::new("SHAKE128").unwrap();
//! ```
//!
//! Or, if you don't particularly care which algorithm you get, you can use the configured default:
//!
//! ```
//! use factory::AlgorithmFactory;
//! use factory::xof_factory::XOFFactory;
//!
//! let mut h = XOFFactory::default();
//! ```

use bouncycastle_sha3 as sha3;
use bouncycastle_core_interface::errors::HashError;
use bouncycastle_core_interface::traits::{SecurityStrength, KDF, XOF};
use bouncycastle_sha3::{SHAKE128_NAME, SHAKE256_NAME};
use crate::{AlgorithmFactory, FactoryError};


/*** Defaults ***/
pub const DEFAULT_XOF_NAME: &str = SHAKE128_NAME;
pub const DEFAULT_128BIT_XOF_NAME: &str = SHAKE128_NAME;
pub const DEFAULT_256BIT_XOF_NAME: &str = SHAKE256_NAME;


// All members must impl XOF.
pub enum XOFFactory {
    SHAKE128(sha3::SHAKE128),
    SHAKE256(sha3::SHAKE256),
}

impl Default for XOFFactory {
    fn default() -> Self {
        Self::new(DEFAULT_XOF_NAME).unwrap()
    }
}

impl AlgorithmFactory for XOFFactory {
    fn default_128_bit() -> Self {
        Self::new(DEFAULT_128BIT_XOF_NAME).unwrap()
    }

    fn default_256_bit() -> Self { Self::new(DEFAULT_256BIT_XOF_NAME).unwrap() }

    fn new(alg_name: &str) -> Result<Self, FactoryError> {
        match alg_name {
            SHAKE128_NAME => Ok(Self::SHAKE128(sha3::SHAKE128::new())),
            SHAKE256_NAME => Ok(Self::SHAKE256(sha3::SHAKE256::new())),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!("The algorithm: \"{}\" is not a known XOF", alg_name))),
        }
    }
}
impl XOF for XOFFactory {
    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.hash_xof(data, result_len),
            Self::SHAKE256(h) => h.hash_xof(data, result_len),
        }
    }

    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        match self {
            Self::SHAKE128(h) => h.hash_xof_out(data, output),
            Self::SHAKE256(h) => h.hash_xof_out(data, output),
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        match self {
            Self::SHAKE128(h) => h.absorb(data),
            Self::SHAKE256(h) => h.absorb(data),
        }
    }

    fn absorb_last_partial_byte(&mut self, partial_byte: u8, num_partial_bits: usize) -> Result<(), HashError> {
        match self {
            Self::SHAKE128(h) => h.absorb_last_partial_byte(partial_byte, num_partial_bits),
            Self::SHAKE256(h) => h.absorb_last_partial_byte(partial_byte, num_partial_bits),
        }
    }

    fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.squeeze(num_bytes),
            Self::SHAKE256(h) => h.squeeze(num_bytes),
        }
    }

    fn squeeze_out(&mut self, output: &mut [u8]) -> usize {
        match self {
            Self::SHAKE128(h) => h.squeeze_out(output),
            Self::SHAKE256(h) => h.squeeze_out(output),
        }
    }

    fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError> {
        match self {
            Self::SHAKE128(h) => h.squeeze_partial_byte_final(num_bits),
            Self::SHAKE256(h) => h.squeeze_partial_byte_final(num_bits),
        }
    }

    fn squeeze_partial_byte_final_out(self, num_bits: usize, output: &mut u8) -> Result<(), HashError> {
        match self {
            Self::SHAKE128(h) => h.squeeze_partial_byte_final_out(num_bits, output),
            Self::SHAKE256(h) => h.squeeze_partial_byte_final_out(num_bits, output),
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::SHAKE128(h) => KDF::max_security_strength(h),
            Self::SHAKE256(h) => XOF::max_security_strength(h),
        }
    }
}