//! RNG objects for cryptographically secure random number generation.
//!
//! This crate provides the implementations of the deterministic random bit generator (DRBG) algorithms
//! which, together with a strong entropy source, form the basis of cryptographic random number generation.
//!
//! # Usage Examples
//!
//! Here is the basic way to get some random bytes:
//!
#![cfg_attr(feature = "std", doc = "```")]
#![cfg_attr(not(feature = "std"), doc = "```ignore")]
//! use bouncycastle_core::traits::RNG;
//! use bouncycastle_rng as rng;
//!
//! let mut random_bytes = [0u8; 32];
//! rng::DefaultRNG::default().next_bytes_out(&mut random_bytes).unwrap();
//! ```
//! This is secure because `::default()` seeds the RNG from the OS, configured for general use.
//! It needs the `std` feature.
//!
//! **WARNING: most people should stop reading here and should not attempt to modify the internals of RNGs.
//! This crate contains dragons and other horrible things. 🐉🐍🐜**
//!
//! Where there is no operating system to seed from, the caller supplies the seed material: the
//! entropy input, as [`KeyMaterial`](bouncycastle_core::key_material::KeyMaterial) of type
//! [`KeyType::Seed`]; the nonce, also a `KeyMaterial`, whose type is not checked (Section 8.6.7:
//! it "need not be secret"); and a personalization string. This is all the crate offers without
//! `std`, and it allocates nothing:
//!
//! ```
//! use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyType};
//! use bouncycastle_core::security_strength::SecurityStrength;
//! use bouncycastle_rng::HashDRBG_SHA256;
//! use bouncycastle_rng::hazmat::NewUninitialized;
//! use bouncycastle_rng::prelude::*;
//!
//! # fn read_entropy_source() -> [u8; 32] { [0x5a; 32] }
//! # fn instantiation_counter() -> u64 { 7 }
//! # fn main() -> Result<(), bouncycastle_core::errors::RNGError> {
//! // 256 bits from the device's entropy source, and a nonce that does not repeat: a persistent
//! // count of the instantiations made on this device.
//! let entropy_input = KeyMaterial256::from_bytes_as_type(&read_entropy_source(), KeyType::Seed)?;
//! let nonce =
//!     KeyMaterial::<8>::from_bytes_as_type(&instantiation_counter().to_be_bytes(), KeyType::Seed)?;
//!
//! let mut drbg = HashDRBG_SHA256::new_uninitialized();
//! drbg.instantiate(false, entropy_input, &nonce, b"device serial 0042", SecurityStrength::_128bit)?;
//!
//! let mut random_bytes = [0u8; 32];
//! drbg.next_bytes_out(&mut random_bytes)?;
//!
//! // Later, with fresh entropy.
//! let fresh = KeyMaterial256::from_bytes_as_type(&read_entropy_source(), KeyType::Seed)?;
//! drbg.reseed(&fresh, &[])?;
//! # Ok(())
//! # }
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! Misuse of the objects in this crate can lead to output which may appear random, but
//! is in fact completely deterministic (ie multiple runs of your application will give the same outputs)
//! and will therefore compromise any cryptographic operation built on top of those outputs.
//! You should only be here if your application requires direct control over configuring the internals of the DRBG.
//!
//! This crate contains the [`Sp80090ADrbg`] trait, which is intentionally defined here and not in [`bouncycastle_core::traits`]
//! since misuse of [`Sp80090ADrbg::instantiate`] can completely undermine the security of your entire
//! cryptographic application. A DRBG with no seed at all comes only from
//! [`hazmat::NewUninitialized`].
//!
//! A caller that seeds the DRBG itself owes what the OS-seeded constructors otherwise supply,
//! and the crate can check only lengths and the key type (SP 800-90A Rev. 1):
//!
//! * **The entropy input** carries at least the instantiation's security strength in entropy
//!   (Section 8.6.3: "having less entropy than the assessed amount could be fatal to security"),
//!   comes from an approved randomness source (Section 8.6.5) and stays secret (Section 8.6.6),
//!   as does every seed given to [`Sp80090ADrbg::reseed`]. A constant, a serial number or a
//!   clock reading is not an entropy input.
//! * **The nonce** is Section 8.6.7's, quoted on [`Sp80090ADrbg::instantiate`]: it does not
//!   repeat across instantiations, and need not be secret. With an empty nonce the entropy
//!   input carries 3/2 of the security strength instead.
//! * **The personalization string** (Section 8.7.1) is "optional (but recommended)" and tells
//!   this instantiation from every other; a DRBG "does not rely on a personalization string to
//!   provide entropy".
//!
//! Two instances given the same three inputs produce the same output.
//!
//! # Features
//!
//! * `std`, on by default, adds the constructors that seed from the operating system
//!   (`new_from_os`, `new` and `Default`) and with them the dependency on `getrandom`. It
//!   implies `alloc`.
//! * `alloc` adds `Sp80090ADrbg::generate`, which returns a `Vec`.
//!
//! With neither (`default-features = false`) the crate links no allocator and draws from no
//! operating system: a DRBG is made by [`hazmat::NewUninitialized`] and seeded by
//! [`Sp80090ADrbg::instantiate`], and there is no fallback seed. Neither feature turns on a
//! feature of `bouncycastle-core` or `bouncycastle-digest`.

#![no_std]
#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use crate::hash_drbg80090a::{
    HashDRBG80090A, HashDRBG80090AParams_SHA256, HashDRBG80090AParams_SHA512,
};
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;

// needed for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyType;
// end doc-only imports

#[cfg(feature = "alloc")]
extern crate alloc;
// The unit tests use `format!`, `Vec` and `catch_unwind`.
#[cfg(test)]
extern crate std;

pub mod hash_drbg80090a;
pub mod hazmat;
pub mod prelude;

/*** pub types ***/
/// Public type for HashDRBG using SHA256.
#[allow(non_camel_case_types)]
pub type HashDRBG_SHA256 = HashDRBG80090A<HashDRBG80090AParams_SHA256>;
/// Public type for HashDRBG using SHA512.
#[allow(non_camel_case_types)]
pub type HashDRBG_SHA512 = HashDRBG80090A<HashDRBG80090AParams_SHA512>;

/*** Defaults ***/
/// The library's default RNG.
pub type DefaultRNG = HashDRBG_SHA512;
/// The library's default RNG at the 128-bit security level.
pub type Default128BitRNG = HashDRBG_SHA256;
/// The library's default RNG at the 256-bit security level.
pub type Default256BitRNG = HashDRBG_SHA512;

/// The shortest non-empty nonce [`Sp80090ADrbg::instantiate`] accepts, in bytes: a 64-bit
/// timestamp, which can meet SP 800-90A Rev. 1 Section 8.6.7 b.
pub const MIN_NONCE_LEN: usize = 8;

/// The DRBG mechanism functions of SP 800-90A Rev. 1 Section 7.4: instantiate, generate and
/// reseed are the methods below; uninstantiate is Rust's `Drop` on the sensitive working state;
/// the health test is not implemented yet. `prediction_resistance` is not supported: only
/// `false` is accepted. A constructor that seeds from the OS (`new`, `new_from_os`, `Default`,
/// all behind the `std` feature) panics if the OS entropy source fails, since it cannot return
/// an error.
///
/// Reseeding is the caller's: after `reseed_interval` (2^48) requests every generating method,
/// the [`bouncycastle_core::traits::RNG`] ones included, returns [`RNGError::ReseedRequired`] until [`Self::reseed`] or
/// [`bouncycastle_core::traits::RNG::add_seed_keymaterial`] has run (Section 9.3.1 steps 7-8, with the "go back" loop left
/// to the application). Both are the full reseed of Section 10.1.1.3, so the seed they take must
/// carry at least the instance's security strength, as at instantiation; there is no automatic
/// reseed from the OS.
pub trait Sp80090ADrbg {
    /// The input KeyMaterial must be of type [`KeyType::Seed`].
    ///
    /// """
    /// 8.6.3 Entropy Requirements for the Entropy Input
    /// The entropy input shall have entropy that is equal to or greater than the security strength of the
    /// instantiation. Additional entropy may be provided in the nonce or the optional personalization
    /// string during instantiation, or in the additional input during reseeding and generation, but this is
    /// not required and does not increase the “official” security strength of the DRBG instantiation that
    /// is recorded in the internal state.
    ///
    /// 8.6.4 Seed Length
    /// The minimum length of the seed depends on the DRBG mechanism and the security strength
    /// required by the consuming application, but shall be at least the number of bits of entropy
    /// required.
    /// """
    ///
    /// This function takes ownership of the seed KeyMaterial object,
    /// to reduce the likelihood of its reuse in a second function call.
    ///
    /// The nonce is Section 8.6.7's: "either: a. A value with at least (security_strength/2) bits
    /// of entropy, or b. A value that is expected to repeat no more often than a
    /// (security_strength/2)-bit random string would be expected to repeat", unique to the module
    /// and "considered to be a critical security parameter" though it "need not be secret", which
    /// is why it is a KeyMaterial. Only its length can be checked: a non-empty nonce shorter than
    /// [`MIN_NONCE_LEN`] bytes is refused. An empty nonce is Section 9.1's alternative of drawing
    /// the nonce's entropy with the entropy input, so the seed must then be at least
    /// `3 * security_strength / 2` bits long; `new_from_os` takes this route with a seed of twice
    /// the strength.
    ///
    /// A `security_strength` below 112 bits, [`SecurityStrength::None`] included, is taken as
    /// 112 bits (Section 9.1, Instantiate Process step 4), and the seed and nonce are checked
    /// against that.
    ///
    /// # Errors
    /// [`RNGError::GenericError`] if the instance is already instantiated, if
    /// `prediction_resistance` is `true` (it is not supported), or if the personalization string
    /// is longer than 2^35 bits; [`RNGError::KeyMaterialError`] if the seed is not
    /// [`KeyType::Seed`], if the seed is too short or longer than 2^35 bits, if the nonce is too
    /// short, or if `security_strength` exceeds what the DRBG supports.
    fn instantiate(
        &mut self,
        prediction_resistance: bool,
        seed: impl KeyMaterialTrait,
        nonce: &impl KeyMaterialTrait,
        personalization_string: &[u8],
        security_strength: SecurityStrength,
    ) -> Result<(), RNGError>;

    /// Reseeds the DRBG with the provided seed.
    /// TODO: this needs to be redesigned to take some sort of EntropySource object that will work well
    // with DRBGs that require frequent reseeding.
    fn reseed<K: KeyMaterialTrait + ?Sized>(
        &mut self,
        seed: &K,
        additional_input: &[u8],
    ) -> Result<(), RNGError>;

    /// Fills `out` with pseudorandom bytes, first zeroizing it, and returns the number of bytes
    /// written, the slice's length.
    ///
    /// Note that for a calling application to be in compliance with SP 800-90A, this requirement
    /// from section 8.4 must be met:
    ///    "The pseudorandom bits returned from a DRBG shall not be used for any
    /// application that requires a higher security strength than the DRBG is instantiated to support. The
    /// security strength provided in these returned bits is the minimum of the security strength
    /// supported by the DRBG and the length of the bit string returned"
    ///
    /// Section 8.4 does not limit the output length: "Security_strength_of_output =
    /// min(output_length, DRBG_security_strength)", so a longer output is allowed and carries no
    /// more strength than the instance has, and neither does a concatenation of outputs.
    /// Extracting two 128-bit values from an instance instantiated at
    /// [`SecurityStrength::_128bit`] and combining them into an AES-256 key gives a 128-bit key.
    /// What is limited is one request: an `out` longer than `max_number_of_bits_per_request`
    /// (2^19 bits, Table 2) is refused, and so is an `additional_input` over 2^35 bits.
    ///
    /// # Errors
    /// [`RNGError::Uninitialized`] before [`Self::instantiate`]; [`RNGError::ReseedRequired`] after
    /// `reseed_interval` requests; [`RNGError::GenericError`] for the length limits. On any error
    /// `out` is left zeroized: Section 9.3.1 has "a Null string" returned as the pseudorandom bits
    /// with any status other than SUCCESS.
    fn generate_out(&mut self, additional_input: &[u8], out: &mut [u8]) -> Result<usize, RNGError>;

    /// [`Sp80090ADrbg::generate_out`] into a new `Vec` of `len` bytes, with its limits and
    /// errors. Only available with the `alloc` feature.
    #[cfg(feature = "alloc")]
    fn generate(
        &mut self,
        additional_input: &[u8],
        len: usize,
    ) -> Result<alloc::vec::Vec<u8>, RNGError> {
        let mut out = alloc::vec![0u8; len];
        self.generate_out(additional_input, &mut out)?;
        Ok(out)
    }

    /// As per [`Sp80090ADrbg::generate_out`], but writes to the provided KeyMaterial, which is
    /// filled to capacity and tagged [`KeyType::CryptographicRandom`] at Section 8.4's
    /// `min(output_length, DRBG_security_strength)`. Returns the number of bytes written.
    fn generate_keymaterial_out<K: KeyMaterialTrait + ?Sized>(
        &mut self,
        additional_input: &[u8],
        out: &mut K,
    ) -> Result<usize, RNGError>;

    // TODO -- implement FIPS health tests
    // fn health_test(&mut self) -> Result<bool, RNGError>;
}
