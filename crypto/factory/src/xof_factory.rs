//! XOF factory for creating instances of algorithms that implement the [`XOF`] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [`XOFFactory`] object which itself implements the [`XOF`] trait as a pass-through to the underlying algorithm.
//!
//! Example usage:
//! ```
//! use bouncycastle_core::traits::{Hash, XOF, XOFOutput};
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_factory::xof_factory::XOFFactory;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! let mut h = XOFFactory::new(sha3::SHAKE128_NAME).unwrap();
//! h.do_update(data);
//! let output: Vec<u8> = h.into_output().do_output(16);
//! ```
//! `XOFFactory` implements [`Hash`] too, so it can be used wherever a hash is wanted; `do_final`
//! then produces the nominal 32 or 64 bytes.
//! Equivalently, it may be invoked by passing a string instead of using the constant:
//!
//! ```
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_factory::xof_factory::XOFFactory;
//!
//! let mut h = XOFFactory::new("SHAKE128");
//! ```
//! If the algorithm used is not particularly important, the configured default may be used:
//!
//! ```
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_factory::xof_factory::XOFFactory;
//!
//! let mut h = XOFFactory::default();
//! ```

use crate::{AlgorithmFactory, FactoryError};
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, XOF, XOFOutput};
use bouncycastle_sha3 as sha3;
use bouncycastle_sha3::{SHAKE128_NAME, SHAKE256_NAME};

/*** Defaults ***/
///
pub const DEFAULT_XOF_NAME: &str = SHAKE128_NAME;
///
pub const DEFAULT_128BIT_XOF_NAME: &str = SHAKE128_NAME;
///
pub const DEFAULT_256BIT_XOF_NAME: &str = SHAKE256_NAME;

/// Wrapper object for all algorithms that impl [`XOF`].
#[non_exhaustive]
#[derive(Clone)]
pub enum XOFFactory {
    ///
    SHAKE128(sha3::SHAKE128),
    ///
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

    fn default_256_bit() -> Self {
        Self::new(DEFAULT_256BIT_XOF_NAME).unwrap()
    }

    fn new(alg_name: &str) -> Result<Self, FactoryError> {
        match alg_name {
            SHAKE128_NAME => Ok(Self::SHAKE128(sha3::SHAKE128::new())),
            SHAKE256_NAME => Ok(Self::SHAKE256(sha3::SHAKE256::new())),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{}\" is not a known XOF",
                alg_name
            ))),
        }
    }
}
/// `Hash` requires it, and the factory does not know which algorithm it holds until it is
/// constructed, so the constants are placeholders -- the same stance `HashFactory` takes. The
/// per-value answers come from [`Hash::output_len`] and [`Hash::max_security_strength`], which
/// dispatch on the variant.
impl Algorithm for XOFFactory {
    const ALG_NAME: &'static str = "TODO";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}

/// The squeezing phase of whichever XOF the factory selected.
///
/// [`XOF::into_output`] consumes the factory value, so this enum is what remains; like
/// [`XOFFactory`] itself it dispatches on the variant.
pub enum XOFFactoryOutput {
    /// SHAKE128 output.
    SHAKE128(<sha3::SHAKE128 as XOF>::Output),
    /// SHAKE256 output.
    SHAKE256(<sha3::SHAKE256 as XOF>::Output),
}

impl XOFOutput for XOFFactoryOutput {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        match self {
            Self::SHAKE128(o) => o.do_output(num_bytes),
            Self::SHAKE256(o) => o.do_output(num_bytes),
        }
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        match self {
            Self::SHAKE128(o) => o.do_output_out(output),
            Self::SHAKE256(o) => o.do_output_out(output),
        }
    }
}

impl Hash for XOFFactory {
    fn block_bitlen(&self) -> usize {
        match self {
            Self::SHAKE128(h) => h.block_bitlen(),
            Self::SHAKE256(h) => h.block_bitlen(),
        }
    }

    fn output_len(&self) -> usize {
        match self {
            Self::SHAKE128(h) => h.output_len(),
            Self::SHAKE256(h) => h.output_len(),
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.hash(data),
            Self::SHAKE256(h) => h.hash(data),
        }
    }

    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize {
        match self {
            Self::SHAKE128(h) => h.hash_out(data, output),
            Self::SHAKE256(h) => h.hash_out(data, output),
        }
    }

    fn do_update(&mut self, data: &[u8]) {
        match self {
            Self::SHAKE128(h) => h.do_update(data),
            Self::SHAKE256(h) => h.do_update(data),
        }
    }

    fn do_final(self) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.do_final(),
            Self::SHAKE256(h) => h.do_final(),
        }
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        match self {
            Self::SHAKE128(h) => h.do_final_out(output),
            Self::SHAKE256(h) => h.do_final_out(output),
        }
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        match self {
            Self::SHAKE128(h) => h.do_final_partial_bits(partial_byte, num_bits),
            Self::SHAKE256(h) => h.do_final_partial_bits(partial_byte, num_bits),
        }
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        match self {
            Self::SHAKE128(h) => h.do_final_partial_bits_out(partial_byte, num_bits, output),
            Self::SHAKE256(h) => h.do_final_partial_bits_out(partial_byte, num_bits, output),
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::SHAKE128(h) => Hash::max_security_strength(h),
            Self::SHAKE256(h) => Hash::max_security_strength(h),
        }
    }
}

impl XOF for XOFFactory {
    type Output = XOFFactoryOutput;

    fn into_output(self) -> Self::Output {
        match self {
            Self::SHAKE128(h) => XOFFactoryOutput::SHAKE128(h.into_output()),
            Self::SHAKE256(h) => XOFFactoryOutput::SHAKE256(h.into_output()),
        }
    }

    fn into_output_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Output, HashError> {
        Ok(match self {
            Self::SHAKE128(h) => {
                XOFFactoryOutput::SHAKE128(h.into_output_partial_bits(partial_byte, num_bits)?)
            }
            Self::SHAKE256(h) => {
                XOFFactoryOutput::SHAKE256(h.into_output_partial_bits(partial_byte, num_bits)?)
            }
        })
    }

    fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.hash_xof(data, result_len),
            Self::SHAKE256(h) => h.hash_xof(data, result_len),
        }
    }

    fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        match self {
            Self::SHAKE128(h) => h.hash_xof_out(data, output),
            Self::SHAKE256(h) => h.hash_xof_out(data, output),
        }
    }
}
