//! MAC factory for creating MAC keys by algorithm name.
//!
//! As with all Factory objects, this implements constructions from strings and defaults, and
//! returns a [`MACFactory`] object: a key, the named algorithm's own key object behind one enum,
//! whose workers, [`MACFactoryWorker`], are the named algorithm's own workers behind another.
//!
//! The factory is the run-time form of the MAC roles: the algorithm is chosen by a string, so the
//! tag length is a run-time value ([`MACFactory::output_len`]) rather than the const parameter
//! the role traits in `bouncycastle_core::symmetric_key` carry, and the one-shots and finals here
//! take and return slices and `Vec`s where the roles take arrays. A caller that knows its
//! algorithm at compile time uses the key type directly.
//!
//! Example usage:
//! Generating and verifying a MAC value for a given piece of data:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
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
//! if hmac.verify(data, &mac_value).is_ok() {
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
use bouncycastle_core::direction::{Decrypting, Encrypting};
use bouncycastle_core::errors::MACError;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{AlgorithmInfo, HashAlgParams, MACGenerator, MACVerifier};
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
/// The default MAC: HMAC-SHA256, a 128-bit MAC.
pub const DEFAULT_MAC_NAME: &str = HMAC_SHA256_NAME;
/// The default 128-bit MAC: HMAC-SHA256.
pub const DEFAULT_128BIT_MAC_NAME: &str = HMAC_SHA256_NAME;
/// The default 256-bit MAC: HMAC-SHA512, as the 256-bit KDF default is HKDF-SHA512.
pub const DEFAULT_256BIT_MAC_NAME: &str = HMAC_SHA512_NAME;

/// A MAC key selected by name: the key object of whichever algorithm was named, which hands out
/// [`MACFactoryWorker`]s through [`create_generator`](Self::create_generator) and
/// [`create_verifier`](Self::create_verifier), with the one-shots [`mac`](Self::mac),
/// [`mac_out`](Self::mac_out) and [`verify`](Self::verify) over them.
/// MACFactory deviates from the usual AlgorithmFactory trait because MAC keys do not have a no-arg
/// constructor; instead they have a constructor that takes a [`KeyMaterialTrait`] and can return
/// an error.
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum MACFactory {
    /// KMAC128 with no customization string and a 32-byte tag (NIST SP 800-185 Sec 4).
    /// For a customization string or a different output length, construct
    /// `bouncycastle_sha3::kmac::KMAC128Key` directly -- the factory selects by name alone and has
    /// no channel for those parameters.
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
/// for `'k`, generating a tag (`Dir = Encrypting`, from [`MACFactory::create_generator`]) or
/// verifying one (`Dir = Decrypting`, from [`MACFactory::create_verifier`]). Its finals take
/// run-time-length buffers, since the algorithm is chosen at run time.
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum MACFactoryWorker<'k, Dir> {
    ///
    KMAC128(KMAC128<Dir>),
    ///
    KMAC256(KMAC256<Dir>),
    ///
    HMAC_SHA224(HMAC<'k, sha2::SHA224, Dir>),
    ///
    HMAC_SHA256(HMAC<'k, sha2::SHA256, Dir>),
    ///
    HMAC_SHA384(HMAC<'k, sha2::SHA384, Dir>),
    ///
    HMAC_SHA512(HMAC<'k, sha2::SHA512, Dir>),
    ///
    HMAC_SHA512_224(HMAC<'k, sha2::SHA512_224, Dir>),
    ///
    HMAC_SHA512_256(HMAC<'k, sha2::SHA512_256, Dir>),
    ///
    HMAC_SHA3_224(HMAC<'k, sha3::SHA3_224, Dir>),
    ///
    HMAC_SHA3_256(HMAC<'k, sha3::SHA3_256, Dir>),
    ///
    HMAC_SHA3_384(HMAC<'k, sha3::SHA3_384, Dir>),
    ///
    HMAC_SHA3_512(HMAC<'k, sha3::SHA3_512, Dir>),
    ///
    HMAC_SM3(HMAC<'k, sm3::SM3, Dir>),
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

    /// The tag length of the selected algorithm, in bytes: the hash's output length for an HMAC,
    /// 32 for KMAC128 and 64 for KMAC256.
    pub fn output_len(&self) -> usize {
        match self {
            Self::KMAC128(_) => 32,
            Self::KMAC256(_) => 64,
            Self::HMAC_SHA224(_) => <sha2::SHA224 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA256(_) => <sha2::SHA256 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA384(_) => <sha2::SHA384 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA512(_) => <sha2::SHA512 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA512_224(_) => <sha2::SHA512_224 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA512_256(_) => <sha2::SHA512_256 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA3_224(_) => <sha3::SHA3_224 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA3_256(_) => <sha3::SHA3_256 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA3_384(_) => <sha3::SHA3_384 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA3_512(_) => <sha3::SHA3_512 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SM3(_) => <sm3::SM3 as HashAlgParams>::OUTPUT_LEN,
        }
    }

    /// Begins a tag over a new message: the named algorithm's generator. Infallible, and any
    /// number can be in flight from one key.
    pub fn create_generator(&self) -> MACFactoryWorker<'_, Encrypting> {
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

    /// Begins the verification of a tag over a new message: the named algorithm's verifier.
    pub fn create_verifier(&self) -> MACFactoryWorker<'_, Decrypting> {
        match self {
            Self::KMAC128(k) => MACFactoryWorker::KMAC128(k.create_verifier()),
            Self::KMAC256(k) => MACFactoryWorker::KMAC256(k.create_verifier()),
            Self::HMAC_SHA224(k) => MACFactoryWorker::HMAC_SHA224(k.create_verifier()),
            Self::HMAC_SHA256(k) => MACFactoryWorker::HMAC_SHA256(k.create_verifier()),
            Self::HMAC_SHA384(k) => MACFactoryWorker::HMAC_SHA384(k.create_verifier()),
            Self::HMAC_SHA512(k) => MACFactoryWorker::HMAC_SHA512(k.create_verifier()),
            Self::HMAC_SHA512_224(k) => MACFactoryWorker::HMAC_SHA512_224(k.create_verifier()),
            Self::HMAC_SHA512_256(k) => MACFactoryWorker::HMAC_SHA512_256(k.create_verifier()),
            Self::HMAC_SHA3_224(k) => MACFactoryWorker::HMAC_SHA3_224(k.create_verifier()),
            Self::HMAC_SHA3_256(k) => MACFactoryWorker::HMAC_SHA3_256(k.create_verifier()),
            Self::HMAC_SHA3_384(k) => MACFactoryWorker::HMAC_SHA3_384(k.create_verifier()),
            Self::HMAC_SHA3_512(k) => MACFactoryWorker::HMAC_SHA3_512(k.create_verifier()),
            Self::HMAC_SM3(k) => MACFactoryWorker::HMAC_SM3(k.create_verifier()),
        }
    }

    /// One-shot: the tag of `data`, [`output_len`](Self::output_len) bytes.
    pub fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut generator = self.create_generator();
        generator.do_update(data);
        generator.do_final()
    }

    /// One-shot: the tag of `data` into `out`, which is zeroized first; returns the number of
    /// bytes written, [`output_len`](Self::output_len).
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `out` is shorter than the tag.
    pub fn mac_out(&self, data: &[u8], out: &mut [u8]) -> Result<usize, MACError> {
        let mut generator = self.create_generator();
        generator.do_update(data);
        generator.do_final_out(out)
    }

    /// One-shot: checks `mac` against `data`, in constant time.
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `mac` is not [`output_len`](Self::output_len) bytes;
    /// [`MACError::VerificationFailed`] if it is not the tag of `data` under this key.
    pub fn verify(&self, data: &[u8], mac: &[u8]) -> Result<(), MACError> {
        let mut verifier = self.create_verifier();
        verifier.do_update(data);
        verifier.do_verify_final(mac)
    }
}

/// `tag` into the front of `out`, for the run-time-length finals: the length check is the
/// caller's.
fn write_tag<const N: usize>(tag: [u8; N], out: &mut [u8]) -> usize {
    out[..N].copy_from_slice(&tag);
    N
}

/// `mac` as the fixed-length tag `verifier` takes, or `InvalidLength`.
fn verify_tag<const N: usize, V: MACVerifier<N>>(verifier: V, mac: &[u8]) -> Result<(), MACError> {
    let Ok(mac) = <&[u8; N]>::try_from(mac) else {
        return Err(MACError::InvalidLength("the tag is not the algorithm's output length"));
    };
    verifier.do_verify_final(mac)
}

impl MACFactoryWorker<'_, Encrypting> {
    /// Absorbs the next chunk of the message; see
    /// [`MACGenerator::do_update`](bouncycastle_core::traits::MACGenerator::do_update).
    pub fn do_update(&mut self, data: &[u8]) {
        match self {
            Self::KMAC128(h) => h.do_update(data),
            Self::KMAC256(h) => h.do_update(data),
            Self::HMAC_SHA224(h) => h.do_update(data),
            Self::HMAC_SHA256(h) => h.do_update(data),
            Self::HMAC_SHA384(h) => h.do_update(data),
            Self::HMAC_SHA512(h) => h.do_update(data),
            Self::HMAC_SHA512_224(h) => h.do_update(data),
            Self::HMAC_SHA512_256(h) => h.do_update(data),
            Self::HMAC_SHA3_224(h) => h.do_update(data),
            Self::HMAC_SHA3_256(h) => h.do_update(data),
            Self::HMAC_SHA3_384(h) => h.do_update(data),
            Self::HMAC_SHA3_512(h) => h.do_update(data),
            Self::HMAC_SM3(h) => h.do_update(data),
        }
    }

    /// Produces the tag, the algorithm's output length. Consumes the worker.
    pub fn do_final(self) -> Vec<u8> {
        match self {
            Self::KMAC128(h) => h.do_final().to_vec(),
            Self::KMAC256(h) => h.do_final().to_vec(),
            Self::HMAC_SHA224(h) => h.do_final().to_vec(),
            Self::HMAC_SHA256(h) => h.do_final().to_vec(),
            Self::HMAC_SHA384(h) => h.do_final().to_vec(),
            Self::HMAC_SHA512(h) => h.do_final().to_vec(),
            Self::HMAC_SHA512_224(h) => h.do_final().to_vec(),
            Self::HMAC_SHA512_256(h) => h.do_final().to_vec(),
            Self::HMAC_SHA3_224(h) => h.do_final().to_vec(),
            Self::HMAC_SHA3_256(h) => h.do_final().to_vec(),
            Self::HMAC_SHA3_384(h) => h.do_final().to_vec(),
            Self::HMAC_SHA3_512(h) => h.do_final().to_vec(),
            Self::HMAC_SM3(h) => h.do_final().to_vec(),
        }
    }

    /// Produces the tag into `out`, which is zeroized first; returns the number of bytes
    /// written, the algorithm's output length. Consumes the worker.
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `out` is shorter than the tag; it is left zeroized.
    pub fn do_final_out(self, out: &mut [u8]) -> Result<usize, MACError> {
        out.fill(0);
        if out.len() < self.output_len() {
            return Err(MACError::InvalidLength("output buffer is smaller than the tag"));
        }
        Ok(match self {
            Self::KMAC128(h) => write_tag(h.do_final(), out),
            Self::KMAC256(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA224(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA256(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA384(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA512(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA512_224(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA512_256(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA3_224(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA3_256(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA3_384(h) => write_tag(h.do_final(), out),
            Self::HMAC_SHA3_512(h) => write_tag(h.do_final(), out),
            Self::HMAC_SM3(h) => write_tag(h.do_final(), out),
        })
    }
}

impl MACFactoryWorker<'_, Decrypting> {
    /// Absorbs the next chunk of the message; see
    /// [`MACVerifier::do_update`](bouncycastle_core::traits::MACVerifier::do_update).
    pub fn do_update(&mut self, data: &[u8]) {
        match self {
            Self::KMAC128(h) => h.do_update(data),
            Self::KMAC256(h) => h.do_update(data),
            Self::HMAC_SHA224(h) => h.do_update(data),
            Self::HMAC_SHA256(h) => h.do_update(data),
            Self::HMAC_SHA384(h) => h.do_update(data),
            Self::HMAC_SHA512(h) => h.do_update(data),
            Self::HMAC_SHA512_224(h) => h.do_update(data),
            Self::HMAC_SHA512_256(h) => h.do_update(data),
            Self::HMAC_SHA3_224(h) => h.do_update(data),
            Self::HMAC_SHA3_256(h) => h.do_update(data),
            Self::HMAC_SHA3_384(h) => h.do_update(data),
            Self::HMAC_SHA3_512(h) => h.do_update(data),
            Self::HMAC_SM3(h) => h.do_update(data),
        }
    }

    /// Checks `mac` against the message absorbed so far, in constant time. Consumes the worker.
    ///
    /// # Errors
    /// [`MACError::InvalidLength`] if `mac` is not the algorithm's output length;
    /// [`MACError::VerificationFailed`] if it is not the tag of the message under the key.
    pub fn do_verify_final(self, mac: &[u8]) -> Result<(), MACError> {
        match self {
            Self::KMAC128(h) => verify_tag(h, mac),
            Self::KMAC256(h) => verify_tag(h, mac),
            Self::HMAC_SHA224(h) => verify_tag(h, mac),
            Self::HMAC_SHA256(h) => verify_tag(h, mac),
            Self::HMAC_SHA384(h) => verify_tag(h, mac),
            Self::HMAC_SHA512(h) => verify_tag(h, mac),
            Self::HMAC_SHA512_224(h) => verify_tag(h, mac),
            Self::HMAC_SHA512_256(h) => verify_tag(h, mac),
            Self::HMAC_SHA3_224(h) => verify_tag(h, mac),
            Self::HMAC_SHA3_256(h) => verify_tag(h, mac),
            Self::HMAC_SHA3_384(h) => verify_tag(h, mac),
            Self::HMAC_SHA3_512(h) => verify_tag(h, mac),
            Self::HMAC_SM3(h) => verify_tag(h, mac),
        }
    }
}

impl<Dir> MACFactoryWorker<'_, Dir> {
    /// The tag length of the selected algorithm, in bytes: [`MACFactory::output_len`].
    pub fn output_len(&self) -> usize {
        match self {
            Self::KMAC128(_) => 32,
            Self::KMAC256(_) => 64,
            Self::HMAC_SHA224(_) => <sha2::SHA224 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA256(_) => <sha2::SHA256 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA384(_) => <sha2::SHA384 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA512(_) => <sha2::SHA512 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA512_224(_) => <sha2::SHA512_224 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA512_256(_) => <sha2::SHA512_256 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA3_224(_) => <sha3::SHA3_224 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA3_256(_) => <sha3::SHA3_256 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA3_384(_) => <sha3::SHA3_384 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SHA3_512(_) => <sha3::SHA3_512 as HashAlgParams>::OUTPUT_LEN,
            Self::HMAC_SM3(_) => <sm3::SM3 as HashAlgParams>::OUTPUT_LEN,
        }
    }
}

impl<Dir> AlgorithmInfo for MACFactoryWorker<'_, Dir> {
    fn alg_name(&self) -> &'static str {
        match self {
            Self::KMAC128(h) => h.alg_name(),
            Self::KMAC256(h) => h.alg_name(),
            Self::HMAC_SHA224(h) => h.alg_name(),
            Self::HMAC_SHA256(h) => h.alg_name(),
            Self::HMAC_SHA384(h) => h.alg_name(),
            Self::HMAC_SHA512(h) => h.alg_name(),
            Self::HMAC_SHA512_224(h) => h.alg_name(),
            Self::HMAC_SHA512_256(h) => h.alg_name(),
            Self::HMAC_SHA3_224(h) => h.alg_name(),
            Self::HMAC_SHA3_256(h) => h.alg_name(),
            Self::HMAC_SHA3_384(h) => h.alg_name(),
            Self::HMAC_SHA3_512(h) => h.alg_name(),
            Self::HMAC_SM3(h) => h.alg_name(),
        }
    }

    fn max_security_strength(&self) -> SecurityStrength {
        match self {
            Self::KMAC128(h) => h.max_security_strength(),
            Self::KMAC256(h) => h.max_security_strength(),
            Self::HMAC_SHA224(h) => h.max_security_strength(),
            Self::HMAC_SHA256(h) => h.max_security_strength(),
            Self::HMAC_SHA384(h) => h.max_security_strength(),
            Self::HMAC_SHA512(h) => h.max_security_strength(),
            Self::HMAC_SHA512_224(h) => h.max_security_strength(),
            Self::HMAC_SHA512_256(h) => h.max_security_strength(),
            Self::HMAC_SHA3_224(h) => h.max_security_strength(),
            Self::HMAC_SHA3_256(h) => h.max_security_strength(),
            Self::HMAC_SHA3_384(h) => h.max_security_strength(),
            Self::HMAC_SHA3_512(h) => h.max_security_strength(),
            Self::HMAC_SM3(h) => h.max_security_strength(),
        }
    }
}
