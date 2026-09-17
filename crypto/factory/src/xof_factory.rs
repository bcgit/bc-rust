//! XOF factory for creating instances of algorithms that implement the [`XOF`] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [`XOFFactory`] object which itself implements the [`XOF`] trait as a pass-through to the underlying algorithm.
//!
//! Example usage:
//! ```
//! use bouncycastle_core::traits::XOF;
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_factory::xof_factory::XOFFactory;
//! use bouncycastle_sha3 as sha3;
//!
//! let data: &[u8] = b"Hello, world!";
//!
//! let mut h = XOFFactory::new(sha3::SHAKE128_NAME).unwrap();
//! h.absorb(data);
//! let output: Vec<u8> = h.squeeze(16);
//! ```
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
use bouncycastle_ascon::ASCON_XOF128_NAME;
use bouncycastle_ascon::ascon_xof128::AsconXof128;
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Algorithm, Hash, SecurityStrength, XOF, XOFSqueezer};
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
    ///
    AsconXof128(AsconXof128),
}

/// Wrapper object for XOF squeezing states.
pub enum XOFFactorySqueezer {
    ///
    SHAKE128(<sha3::SHAKE128 as XOF>::Squeezer),
    ///
    SHAKE256(<sha3::SHAKE256 as XOF>::Squeezer),
    ///
    AsconXof128(<AsconXof128 as XOF>::Squeezer),
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
            ASCON_XOF128_NAME => Ok(Self::AsconXof128(AsconXof128::new())),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{}\" is not a known XOF",
                alg_name
            ))),
        }
    }
}

impl XOFFactory {
    /// Compatibility helper for the old one-shot XOF API.
    pub fn hash_xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.hash_xof(data, result_len),
            Self::SHAKE256(h) => h.hash_xof(data, result_len),
            Self::AsconXof128(h) => h.hash_xof(data, result_len),
        }
    }

    /// Compatibility helper for the old one-shot XOF API.
    pub fn hash_xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        match self {
            Self::SHAKE128(h) => h.hash_xof_out(data, output),
            Self::SHAKE256(h) => h.hash_xof_out(data, output),
            Self::AsconXof128(h) => h.hash_xof_out(data, output),
        }
    }

    /// Compatibility helper for the old streaming API: absorb bytes while still in the input phase.
    pub fn absorb(&mut self, data: &[u8]) -> Result<(), HashError> {
        match self {
            Self::SHAKE128(h) => h.absorb(data),
            Self::SHAKE256(h) => h.absorb(data),
            Self::AsconXof128(h) => h.absorb(data),
        }
    }

    /// Compatibility helper for the old streaming API: switch to squeezing with a final partial byte.
    pub fn absorb_last_partial_byte(
        &mut self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<(), HashError> {
        match self {
            Self::SHAKE128(h) => h.absorb_last_partial_byte(partial_byte, num_partial_bits),
            Self::SHAKE256(h) => h.absorb_last_partial_byte(partial_byte, num_partial_bits),
            Self::AsconXof128(h) => h.absorb_last_partial_byte(partial_byte, num_partial_bits),
        }
    }

    /// Compatibility helper for the old streaming API: produce `num_bytes` bytes.
    pub fn squeeze(&mut self, num_bytes: usize) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.squeeze(num_bytes),
            Self::SHAKE256(h) => h.squeeze(num_bytes),
            Self::AsconXof128(h) => h.squeeze(num_bytes),
        }
    }

    /// Compatibility helper for the old streaming API: fill `output` from the XOF stream.
    pub fn squeeze_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);

        match self {
            Self::SHAKE128(h) => h.squeeze_out(output),
            Self::SHAKE256(h) => h.squeeze_out(output),
            Self::AsconXof128(h) => h.squeeze_out(output),
        }
    }

    /// Compatibility helper for the old streaming API: finish with a partial output byte.
    pub fn squeeze_partial_byte_final(self, num_bits: usize) -> Result<u8, HashError> {
        match self {
            Self::SHAKE128(h) => h.squeeze_partial_byte_final(num_bits),
            Self::SHAKE256(h) => h.squeeze_partial_byte_final(num_bits),
            Self::AsconXof128(h) => h.squeeze_partial_byte_final(num_bits),
        }
    }

    /// Compatibility helper for the old streaming API: finish with a partial output byte.
    pub fn squeeze_partial_byte_final_out(
        self,
        num_bits: usize,
        output: &mut u8,
    ) -> Result<(), HashError> {
        *output = 0;

        match self {
            Self::SHAKE128(h) => h.squeeze_partial_byte_final_out(num_bits, output),
            Self::SHAKE256(h) => h.squeeze_partial_byte_final_out(num_bits, output),
            Self::AsconXof128(h) => h.squeeze_partial_byte_final_out(num_bits, output),
        }
    }
}

impl Algorithm for XOFFactory {
    const ALG_NAME: &'static str = "TODO";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}

impl Hash for XOFFactory {
    fn block_bitlen(&self) -> usize {
        match self {
            Self::SHAKE128(h) => h.block_bitlen(),
            Self::SHAKE256(h) => h.block_bitlen(),
            Self::AsconXof128(h) => h.block_bitlen(),
        }
    }

    fn output_len(&self) -> usize {
        match self {
            Self::SHAKE128(h) => h.output_len(),
            Self::SHAKE256(h) => h.output_len(),
            Self::AsconXof128(h) => h.output_len(),
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.hash(data),
            Self::SHAKE256(h) => h.hash(data),
            Self::AsconXof128(h) => h.hash(data),
        }
    }

    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        match self {
            Self::SHAKE128(h) => h.hash_out(data, output),
            Self::SHAKE256(h) => h.hash_out(data, output),
            Self::AsconXof128(h) => h.hash_out(data, output),
        }
    }

    fn do_update(&mut self, data: &[u8]) {
        match self {
            Self::SHAKE128(h) => h.do_update(data),
            Self::SHAKE256(h) => h.do_update(data),
            Self::AsconXof128(h) => h.do_update(data),
        }
    }

    fn do_final(self) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.do_final(),
            Self::SHAKE256(h) => h.do_final(),
            Self::AsconXof128(h) => h.do_final(),
        }
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        output.fill(0);

        match self {
            Self::SHAKE128(h) => h.do_final_out(output),
            Self::SHAKE256(h) => h.do_final_out(output),
            Self::AsconXof128(h) => h.do_final_out(output),
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
            Self::AsconXof128(h) => h.do_final_partial_bits(partial_byte, num_bits),
        }
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        output.fill(0);

        match self {
            Self::SHAKE128(h) => h.do_final_partial_bits_out(partial_byte, num_bits, output),
            Self::SHAKE256(h) => h.do_final_partial_bits_out(partial_byte, num_bits, output),
            Self::AsconXof128(h) => h.do_final_partial_bits_out(partial_byte, num_bits, output),
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::SHAKE128(h) => h.max_security_strength(),
            Self::SHAKE256(h) => h.max_security_strength(),
            Self::AsconXof128(h) => h.max_security_strength(),
        }
    }
}

impl XOF for XOFFactory {
    type Squeezer = XOFFactorySqueezer;

    fn into_squeezer(self) -> Self::Squeezer {
        match self {
            Self::SHAKE128(h) => XOFFactorySqueezer::SHAKE128(h.into_squeezer()),
            Self::SHAKE256(h) => XOFFactorySqueezer::SHAKE256(h.into_squeezer()),
            Self::AsconXof128(h) => XOFFactorySqueezer::AsconXof128(h.into_squeezer()),
        }
    }

    fn into_squeezer_partial_bits(
        self,
        partial_byte: u8,
        num_bits: usize,
    ) -> Result<Self::Squeezer, HashError> {
        match self {
            Self::SHAKE128(h) => Ok(XOFFactorySqueezer::SHAKE128(
                h.into_squeezer_partial_bits(partial_byte, num_bits)?,
            )),
            Self::SHAKE256(h) => Ok(XOFFactorySqueezer::SHAKE256(
                h.into_squeezer_partial_bits(partial_byte, num_bits)?,
            )),
            Self::AsconXof128(h) => Ok(XOFFactorySqueezer::AsconXof128(
                h.into_squeezer_partial_bits(partial_byte, num_bits)?,
            )),
        }
    }

    fn xof(self, data: &[u8], result_len: usize) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.xof(data, result_len),
            Self::SHAKE256(h) => h.xof(data, result_len),
            Self::AsconXof128(h) => h.xof(data, result_len),
        }
    }

    fn xof_out(self, data: &[u8], output: &mut [u8]) -> usize {
        output.fill(0);

        match self {
            Self::SHAKE128(h) => h.xof_out(data, output),
            Self::SHAKE256(h) => h.xof_out(data, output),
            Self::AsconXof128(h) => h.xof_out(data, output),
        }
    }
}

impl XOFSqueezer for XOFFactorySqueezer {
    fn do_output(&mut self, num_bytes: usize) -> Vec<u8> {
        match self {
            Self::SHAKE128(h) => h.do_output(num_bytes),
            Self::SHAKE256(h) => h.do_output(num_bytes),
            Self::AsconXof128(h) => h.do_output(num_bytes),
        }
    }

    fn do_output_out(&mut self, output: &mut [u8]) -> usize {
        output.fill(0);

        match self {
            Self::SHAKE128(h) => h.do_output_out(output),
            Self::SHAKE256(h) => h.do_output_out(output),
            Self::AsconXof128(h) => h.do_output_out(output),
        }
    }
}
