//! MAC factory for creating MAC keys by algorithm name.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [`MACFactory`] object: a key, which implements [`MacGenerationKey`] and
//! [`MacVerificationKey`] as a pass-through to the underlying key type, and whose workers,
//! [`MACFactoryWorker`], implement [`MAC`] the same way.
//!
//! Example usage:
//! Generating and verifying a MAC value for a given piece of data:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_core::symmetric_key::{MacGenerationKey, MacVerificationKey};
//! use bouncycastle_hex as hex;
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_factory::mac_factory::MACFactory;
//!
//! let data = b"Hi There!";
//! let key = KeyMaterial256::from_bytes_as_type(
//!         // Note: This would be a bad key to use in a production application!
//!         // But we'll hard-code a silly key for demonstration purposes.
//!         &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
//!         KeyType::MACKey,
//!     ).unwrap();
//! let hmac = MACFactory::new(bouncycastle_sha3::hmac::HMAC_SHA3_256_NAME, &key).unwrap();
//!
//! // Generate the MAC value
//! let mac_value: Vec<u8> = hmac.mac(data);
//!
//! // Verify the MAC value; the key is used for any number of messages
//! if hmac.verify(data, &mac_value,) {
//!     println!("MAC verified successfully!")
//! } else {
//!     println!("MAC verification failed")
//! }
//! ```
//!
//! Equivalently, an instance of [`MACFactory`] may be constructed by string instead of using the constant:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_hex as hex;
//! use bouncycastle_factory::mac_factory::MACFactory;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!         // Note: This would be a bad key to use in a production application!
//!         // But we'll hard-code a silly key for demonstration purposes.
//!         &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
//!         KeyType::MACKey,
//!     ).unwrap();
//!
//! let hmac = MACFactory::new("HMAC-SHA256", &key).unwrap();
//! ```
//!
//! If the algorithm used is not particularly important, the built-in default may be used:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
//! use bouncycastle_factory::AlgorithmFactory;
//! use bouncycastle_hex as hex;
//! use bouncycastle_factory::mac_factory::MACFactory;
//!
//! let key = KeyMaterial256::from_bytes_as_type(
//!         // Note: This would be a bad key to use in a production application!
//!         // But we'll hard-code a silly key for demonstration purposes.
//!         &hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap(),
//!         KeyType::MACKey,
//!     ).unwrap();
//!
//! let hmac = MACFactory::default(&key);
//! ```

use crate::{DEFAULT, DEFAULT_128_BIT, DEFAULT_256_BIT, FactoryError};
use bouncycastle_core::errors::MACError;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::MAC;
use bouncycastle_hmac::{HMAC, HmacKey};
use bouncycastle_sha2 as sha2;
use bouncycastle_sha2::hmac::{
    HMAC_SHA224_NAME, HMAC_SHA256_NAME, HMAC_SHA384_NAME, HMAC_SHA512_224_NAME,
    HMAC_SHA512_256_NAME, HMAC_SHA512_NAME,
};
use bouncycastle_sha3 as sha3;
use bouncycastle_sha3::hmac::{
    HMAC_SHA3_224_NAME, HMAC_SHA3_256_NAME, HMAC_SHA3_384_NAME, HMAC_SHA3_512_NAME,
};
use bouncycastle_sha3::kmac::{
    KMAC128, KMAC128_NAME, KMAC128Key, KMAC256, KMAC256_NAME, KMAC256Key,
};
use bouncycastle_sm3 as sm3;
use bouncycastle_sm3::hmac::HMAC_SM3_NAME;

/*** Defaults ***/
///
pub const DEFAULT_MAC_NAME: &str = HMAC_SHA256_NAME;
///
pub const DEFAULT_128BIT_MAC_NAME: &str = HMAC_SHA256_NAME;
///
pub const DEFAULT_256BIT_MAC_NAME: &str = HMAC_SHA256_NAME;

/// A MAC key selected by name: the key object of whichever algorithm was named, which hands out
/// [`MACFactoryWorker`]s through [`MacGenerationKey`] and [`MacVerificationKey`].
/// MACFactory deviates from the usual AlgorithmFactory trait because MAC keys do not have a no-arg
/// constructor; instead they have a constructor that takes a [`KeyMaterialTrait`] and can return
/// an error.
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum MACFactory {
    /// KMAC128 with no customization string and a 32-byte tag (NIST SP 800-185 Sec 4).
    /// For a customization string or a different output length, construct
    /// `bouncycastle_sha3::KMAC128Key` directly -- the factory selects by name alone and has no
    /// channel for those parameters.
    KMAC128(KMAC128Key),
    /// KMAC256 with no customization string and a 64-byte tag. See [`MACFactory::KMAC128`].
    KMAC256(KMAC256Key),
    ///
    HMAC_SHA224(HmacKey<sha2::SHA224>),
    ///
    HMAC_SHA256(HmacKey<sha2::SHA256>),
    ///
    HMAC_SHA384(HmacKey<sha2::SHA384>),
    ///
    HMAC_SHA512(HmacKey<sha2::SHA512>),
    ///
    HMAC_SHA512_224(HmacKey<sha2::SHA512_224>),
    ///
    HMAC_SHA512_256(HmacKey<sha2::SHA512_256>),
    ///
    HMAC_SHA3_224(HmacKey<sha3::SHA3_224>),
    ///
    HMAC_SHA3_256(HmacKey<sha3::SHA3_256>),
    ///
    HMAC_SHA3_384(HmacKey<sha3::SHA3_384>),
    ///
    HMAC_SHA3_512(HmacKey<sha3::SHA3_512>),
    ///
    HMAC_SM3(HmacKey<sm3::SM3>),
}

/// The worker a [`MACFactory`] key hands out: the named algorithm's own worker, borrowing the key
/// for `'k`, behind one [`MAC`] impl.
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum MACFactoryWorker<'k> {
    ///
    KMAC128(KMAC128),
    ///
    KMAC256(KMAC256),
    ///
    HMAC_SHA224(HMAC<'k, sha2::SHA224>),
    ///
    HMAC_SHA256(HMAC<'k, sha2::SHA256>),
    ///
    HMAC_SHA384(HMAC<'k, sha2::SHA384>),
    ///
    HMAC_SHA512(HMAC<'k, sha2::SHA512>),
    ///
    HMAC_SHA512_224(HMAC<'k, sha2::SHA512_224>),
    ///
    HMAC_SHA512_256(HMAC<'k, sha2::SHA512_256>),
    ///
    HMAC_SHA3_224(HMAC<'k, sha3::SHA3_224>),
    ///
    HMAC_SHA3_256(HMAC<'k, sha3::SHA3_256>),
    ///
    HMAC_SHA3_384(HMAC<'k, sha3::SHA3_384>),
    ///
    HMAC_SHA3_512(HMAC<'k, sha3::SHA3_512>),
    ///
    HMAC_SM3(HMAC<'k, sm3::SM3>),
}

impl MACFactory {
    /// Get the default MAC algorithm.
    pub fn default(key: &impl KeyMaterialTrait) -> Result<Self, FactoryError> {
        Self::new(DEFAULT_MAC_NAME, key)
    }
    /// Get the default 128-bit MAC algorithm.
    pub fn default_128_bit(key: &impl KeyMaterialTrait) -> Result<Self, FactoryError> {
        Self::new(DEFAULT_128BIT_MAC_NAME, key)
    }
    /// Get the default 256-bit MAC algorithm.
    pub fn default_256_bit(key: &impl KeyMaterialTrait) -> Result<Self, FactoryError> {
        Self::new(DEFAULT_256BIT_MAC_NAME, key)
    }
    /// Get an instance of the algorithm by name.
    pub fn new(alg_name: &str, key: &impl KeyMaterialTrait) -> Result<Self, FactoryError> {
        match alg_name {
            DEFAULT => Self::default(key),
            DEFAULT_128_BIT => Self::default_128_bit(key),
            DEFAULT_256_BIT => Self::default_256_bit(key),
            KMAC128_NAME => Ok(Self::KMAC128(KMAC128Key::from_key_material(key)?)),
            KMAC256_NAME => Ok(Self::KMAC256(KMAC256Key::from_key_material(key)?)),
            HMAC_SHA224_NAME => Ok(Self::HMAC_SHA224(HmacKey::from_key_material(key)?)),
            HMAC_SHA256_NAME => Ok(Self::HMAC_SHA256(HmacKey::from_key_material(key)?)),
            HMAC_SHA384_NAME => Ok(Self::HMAC_SHA384(HmacKey::from_key_material(key)?)),
            HMAC_SHA512_NAME => Ok(Self::HMAC_SHA512(HmacKey::from_key_material(key)?)),
            HMAC_SHA512_224_NAME => Ok(Self::HMAC_SHA512_224(HmacKey::from_key_material(key)?)),
            HMAC_SHA512_256_NAME => Ok(Self::HMAC_SHA512_256(HmacKey::from_key_material(key)?)),
            HMAC_SHA3_224_NAME => Ok(Self::HMAC_SHA3_224(HmacKey::from_key_material(key)?)),
            HMAC_SHA3_256_NAME => Ok(Self::HMAC_SHA3_256(HmacKey::from_key_material(key)?)),
            HMAC_SHA3_384_NAME => Ok(Self::HMAC_SHA3_384(HmacKey::from_key_material(key)?)),
            HMAC_SHA3_512_NAME => Ok(Self::HMAC_SHA3_512(HmacKey::from_key_material(key)?)),
            HMAC_SM3_NAME => Ok(Self::HMAC_SM3(HmacKey::from_key_material(key)?)),
            _ => Err(FactoryError::UnsupportedAlgorithm(format!(
                "The algorithm: \"{}\" is not a known MAC",
                alg_name
            ))),
        }
    }

    /// The worker for one message, from whichever key this is.
    fn worker(&self) -> MACFactoryWorker<'_> {
        match self {
            Self::KMAC128(k) => MACFactoryWorker::KMAC128(k.create_generator()),
            Self::KMAC256(k) => MACFactoryWorker::KMAC256(k.create_generator()),
            Self::HMAC_SHA224(k) => MACFactoryWorker::HMAC_SHA224(k.create_generator()),
            Self::HMAC_SHA256(k) => MACFactoryWorker::HMAC_SHA256(k.create_generator()),
            Self::HMAC_SHA384(k) => MACFactoryWorker::HMAC_SHA384(k.create_generator()),
            Self::HMAC_SHA512(k) => MACFactoryWorker::HMAC_SHA512(k.create_generator()),
            Self::HMAC_SHA512_224(k) => MACFactoryWorker::HMAC_SHA512_224(k.create_generator()),
            Self::HMAC_SHA512_256(k) => MACFactoryWorker::HMAC_SHA512_256(k.create_generator()),
            Self::HMAC_SHA3_224(k) => MACFactoryWorker::HMAC_SHA3_224(k.create_generator()),
            Self::HMAC_SHA3_256(k) => MACFactoryWorker::HMAC_SHA3_256(k.create_generator()),
            Self::HMAC_SHA3_384(k) => MACFactoryWorker::HMAC_SHA3_384(k.create_generator()),
            Self::HMAC_SHA3_512(k) => MACFactoryWorker::HMAC_SHA3_512(k.create_generator()),
            Self::HMAC_SM3(k) => MACFactoryWorker::HMAC_SM3(k.create_generator()),
        }
    }
}

impl MacGenerationKey for MACFactory {
    type Generator<'k>
        = MACFactoryWorker<'k>
    where
        Self: 'k;

    fn create_generator<'k>(&'k self) -> Self::Generator<'k> {
        self.worker()
    }
}

impl MacVerificationKey for MACFactory {
    type Verifier<'k>
        = MACFactoryWorker<'k>
    where
        Self: 'k;

    fn create_verifier<'k>(&'k self) -> Self::Verifier<'k> {
        self.worker()
    }
}

/// Every method is the named worker's own.
macro_rules! forward {
    ($self:expr, $w:ident => $e:expr) => {
        match $self {
            MACFactoryWorker::KMAC128($w) => $e,
            MACFactoryWorker::KMAC256($w) => $e,
            MACFactoryWorker::HMAC_SHA224($w) => $e,
            MACFactoryWorker::HMAC_SHA256($w) => $e,
            MACFactoryWorker::HMAC_SHA384($w) => $e,
            MACFactoryWorker::HMAC_SHA512($w) => $e,
            MACFactoryWorker::HMAC_SHA512_224($w) => $e,
            MACFactoryWorker::HMAC_SHA512_256($w) => $e,
            MACFactoryWorker::HMAC_SHA3_224($w) => $e,
            MACFactoryWorker::HMAC_SHA3_256($w) => $e,
            MACFactoryWorker::HMAC_SHA3_384($w) => $e,
            MACFactoryWorker::HMAC_SHA3_512($w) => $e,
            MACFactoryWorker::HMAC_SM3($w) => $e,
        }
    };
}

impl MAC for MACFactoryWorker<'_> {
    fn output_len(&self) -> usize {
        forward!(self, h => h.output_len())
    }

    fn mac(self, data: &[u8]) -> Vec<u8> {
        forward!(self, h => h.mac(data))
    }

    fn mac_out(self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        forward!(self, h => h.mac_out(data, out))
    }

    fn verify(self, data: &[u8], mac: &[u8]) -> bool {
        forward!(self, h => h.verify(data, mac))
    }

    fn do_update(&mut self, data: &[u8]) {
        forward!(self, h => h.do_update(data))
    }

    fn do_final(self) -> Vec<u8> {
        forward!(self, h => h.do_final())
    }

    fn do_final_out(self, out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        forward!(self, h => h.do_final_out(out))
    }

    fn do_verify_final(self, mac: &[u8]) -> bool {
        forward!(self, h => h.do_verify_final(mac))
    }

    fn max_security_strength(&self) -> SecurityStrength {
        forward!(self, h => h.max_security_strength())
    }
}
