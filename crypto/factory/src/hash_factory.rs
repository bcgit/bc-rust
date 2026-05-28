//! Hash factory for creating instances of algorithms that implement the [Hash] trait.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [HashFactory] object which itself implements the [Hash] trait as a pass-through to the underlying algorithm.
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
//! You can equivalently invoke this by string instead of using the constant:
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

use crate::{AlgorithmFactory, FactoryError};
use crate::{DEFAULT, DEFAULT_128_BIT, DEFAULT_256_BIT};
use bouncycastle_core::errors::HashError;
use bouncycastle_core::traits::{Hash, SecurityStrength};
use bouncycastle_sha2 as sha2;
use bouncycastle_sha2::{SHA224_NAME, SHA256_NAME, SHA384_NAME, SHA512_NAME};
use bouncycastle_sha3 as sha3;
use bouncycastle_sha3::{SHA3_224_NAME, SHA3_256_NAME, SHA3_384_NAME, SHA3_512_NAME};

/*** Defaults ***/
pub const DEFAULT_HASH_NAME: &str = SHA3_256_NAME;
pub const DEFAULT_128BIT_HASH_NAME: &str = SHA3_256_NAME;
pub const DEFAULT_256BIT_HASH_NAME: &str = SHA3_512_NAME;

/// All members must impl Hash.
/// Note: no SHAKE because SHAKE is not NIST approved as a hash function. See FIPS 202 section A.2.
pub enum HashFactory {
    SHA224(sha2::SHA224),
    SHA256(sha2::SHA256),
    SHA384(sha2::SHA384),
    SHA512(sha2::SHA512),
    SHA3_224(sha3::SHA3_224),
    SHA3_256(sha3::SHA3_256),
    SHA3_384(sha3::SHA3_384),
    SHA3_512(sha3::SHA3_512),
}

impl Default for HashFactory {
    fn default() -> HashFactory {
        Self::new(DEFAULT_HASH_NAME).unwrap()
    }
}

impl AlgorithmFactory for HashFactory {
    fn default_128_bit() -> HashFactory {
        Self::new(DEFAULT_128BIT_HASH_NAME).unwrap()
    }
    fn default_256_bit() -> HashFactory {
        Self::new(DEFAULT_256BIT_HASH_NAME).unwrap()
    }

    fn new(alg_name: &str) -> Result<Self, FactoryError> {
        match alg_name {
            DEFAULT => Ok(Self::default()),
            DEFAULT_128_BIT => Ok(Self::default_128_bit()),
            DEFAULT_256_BIT => Ok(Self::default_256_bit()),
            SHA224_NAME => Ok(Self::SHA224(sha2::SHA224::new())),
            SHA256_NAME => Ok(Self::SHA256(sha2::SHA256::new())),
            SHA384_NAME => Ok(Self::SHA384(sha2::SHA384::new())),
            SHA512_NAME => Ok(Self::SHA512(sha2::SHA512::new())),
            SHA3_224_NAME => Ok(Self::SHA3_224(sha3::SHA3_224::new())),
            SHA3_256_NAME => Ok(Self::SHA3_256(sha3::SHA3_256::new())),
            SHA3_384_NAME => Ok(Self::SHA3_384(sha3::SHA3_384::new())),
            SHA3_512_NAME => Ok(Self::SHA3_512(sha3::SHA3_512::new())),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{}\" is not a known Hash",
                alg_name
            ))),
        }
    }
}

impl Hash for HashFactory {
    fn block_bitlen(&self) -> usize {
        match self {
            Self::SHA224(h) => h.block_bitlen(),
            Self::SHA256(h) => h.block_bitlen(),
            Self::SHA384(h) => h.block_bitlen(),
            Self::SHA512(h) => h.block_bitlen(),
            Self::SHA3_224(h) => h.block_bitlen(),
            Self::SHA3_256(h) => h.block_bitlen(),
            Self::SHA3_384(h) => h.block_bitlen(),
            Self::SHA3_512(h) => h.block_bitlen(),
        }
    }

    fn output_len(&self) -> usize {
        match self {
            Self::SHA224(h) => h.output_len(),
            Self::SHA256(h) => h.output_len(),
            Self::SHA384(h) => h.output_len(),
            Self::SHA512(h) => h.output_len(),
            Self::SHA3_224(h) => h.output_len(),
            Self::SHA3_256(h) => h.output_len(),
            Self::SHA3_384(h) => h.output_len(),
            Self::SHA3_512(h) => h.output_len(),
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::SHA224(h) => h.hash(data),
            Self::SHA256(h) => h.hash(data),
            Self::SHA384(h) => h.hash(data),
            Self::SHA512(h) => h.hash(data),
            Self::SHA3_224(h) => h.hash(data),
            Self::SHA3_256(h) => h.hash(data),
            Self::SHA3_384(h) => h.hash(data),
            Self::SHA3_512(h) => h.hash(data),
        }
    }

    fn hash_out(self, data: &[u8], output: &mut [u8]) -> usize {
        match self {
            Self::SHA224(h) => h.hash_out(data, output),
            Self::SHA256(h) => h.hash_out(data, output),
            Self::SHA384(h) => h.hash_out(data, output),
            Self::SHA512(h) => h.hash_out(data, output),
            Self::SHA3_224(h) => h.hash_out(data, output),
            Self::SHA3_256(h) => h.hash_out(data, output),
            Self::SHA3_384(h) => h.hash_out(data, output),
            Self::SHA3_512(h) => h.hash_out(data, output),
        }
    }

    fn do_update(&mut self, data: &[u8]) {
        match self {
            Self::SHA224(h) => h.do_update(data),
            Self::SHA256(h) => h.do_update(data),
            Self::SHA384(h) => h.do_update(data),
            Self::SHA512(h) => h.do_update(data),
            Self::SHA3_224(h) => h.do_update(data),
            Self::SHA3_256(h) => h.do_update(data),
            Self::SHA3_384(h) => h.do_update(data),
            Self::SHA3_512(h) => h.do_update(data),
        }
    }

    fn do_final(self) -> Vec<u8> {
        match self {
            Self::SHA224(h) => h.do_final(),
            Self::SHA256(h) => h.do_final(),
            Self::SHA384(h) => h.do_final(),
            Self::SHA512(h) => h.do_final(),
            Self::SHA3_224(h) => h.do_final(),
            Self::SHA3_256(h) => h.do_final(),
            Self::SHA3_384(h) => h.do_final(),
            Self::SHA3_512(h) => h.do_final(),
        }
    }

    fn do_final_out(self, output: &mut [u8]) -> usize {
        match self {
            Self::SHA224(h) => h.do_final_out(output),
            Self::SHA256(h) => h.do_final_out(output),
            Self::SHA384(h) => h.do_final_out(output),
            Self::SHA512(h) => h.do_final_out(output),
            Self::SHA3_224(h) => h.do_final_out(output),
            Self::SHA3_256(h) => h.do_final_out(output),
            Self::SHA3_384(h) => h.do_final_out(output),
            Self::SHA3_512(h) => h.do_final_out(output),
        }
    }

    fn do_final_partial_bits(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
    ) -> Result<Vec<u8>, HashError> {
        match self {
            Self::SHA224(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),
            Self::SHA256(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),
            Self::SHA384(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),
            Self::SHA512(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),
            Self::SHA3_224(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),
            Self::SHA3_256(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),
            Self::SHA3_384(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),
            Self::SHA3_512(h) => h.do_final_partial_bits(partial_byte, num_partial_bits),
        }
    }

    fn do_final_partial_bits_out(
        self,
        partial_byte: u8,
        num_partial_bits: usize,
        output: &mut [u8],
    ) -> Result<usize, HashError> {
        match self {
            Self::SHA224(h) => h.do_final_partial_bits_out(partial_byte, num_partial_bits, output),
            Self::SHA256(h) => h.do_final_partial_bits_out(partial_byte, num_partial_bits, output),
            Self::SHA384(h) => h.do_final_partial_bits_out(partial_byte, num_partial_bits, output),
            Self::SHA512(h) => h.do_final_partial_bits_out(partial_byte, num_partial_bits, output),
            Self::SHA3_224(h) => {
                h.do_final_partial_bits_out(partial_byte, num_partial_bits, output)
            }
            Self::SHA3_256(h) => {
                h.do_final_partial_bits_out(partial_byte, num_partial_bits, output)
            }
            Self::SHA3_384(h) => {
                h.do_final_partial_bits_out(partial_byte, num_partial_bits, output)
            }
            Self::SHA3_512(h) => {
                h.do_final_partial_bits_out(partial_byte, num_partial_bits, output)
            }
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::SHA224(h) => h.max_security_strength(),
            Self::SHA256(h) => h.max_security_strength(),
            Self::SHA384(h) => h.max_security_strength(),
            Self::SHA512(h) => h.max_security_strength(),
            Self::SHA3_224(h) => h.max_security_strength(),
            Self::SHA3_256(h) => h.max_security_strength(),
            Self::SHA3_384(h) => h.max_security_strength(),
            Self::SHA3_512(h) => h.max_security_strength(),
        }
    }
}
