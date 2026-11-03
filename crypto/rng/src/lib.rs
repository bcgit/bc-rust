//! RNG objects for cryptographically secure random number generation.
//!
//! This crate provides the implementations of the deterministic random bit generator (DRBG) algorithms
//! which, together with a strong entropy source, form the basis of cryptographic random number generation.
//!
//! Here is the basic way to get some random bytes:
//!
//! ```
//! use bouncycastle_core::traits::RNG;
//! use bouncycastle_rng as rng;
//!
//! let random_bytes = rng::DefaultRNG::default().next_bytes(32);
//! ```
//! This is secure because `::default()` seeds the RNG from the OS, configured for general use.
//!
//! **WARNING: most people should stop reading here and should not attempt to modify the internals of RNGs.
//! This crate contains dragons and other horrible things. 🐉🐍🐜**
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

pub mod fixed_seed_rng;
pub mod hash_drbg80090a;
pub mod hazmat;

pub use fixed_seed_rng::FixedSeedRNG;

/*** String constants ***/
///
pub const HASH_DRBG_SHA256_NAME: &str = "HashDRBG-SHA256";
///
pub const HASH_DRBG_SHA512_NAME: &str = "HashDRBG-SHA512";

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

/// The DRBG mechanism functions of SP 800-90A Rev. 1 Section 7.4: instantiate, generate and
/// reseed are the methods below; uninstantiate is Rust's `Drop` on the sensitive working state;
/// the health test is not implemented yet. `prediction_resistance` is not supported: only
/// `false` is accepted. A constructor that seeds from the OS (`new`, `new_from_os`, `Default`)
/// panics if the OS entropy source fails, since it cannot return an error.
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
    /// and "considered to be a critical security parameter" though it "need not be secret". It is
    /// not checked here, which is why it is a KeyMaterial: so that it gets the erasure and logging
    /// protections of one. An empty nonce is accepted and the seed then has to carry the whole
    /// requirement on its own (`new_from_os` passes one, with a seed of the full strength).
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

    /// Note that for a calling application to be in compliance with SP 800-90A, this requirement
    /// from section 8.4 must be met:
    ///    "The pseudorandom bits returned from a DRBG shall not be used for any
    /// application that requires a higher security strength than the DRBG is instantiated to support. The
    /// security strength provided in these returned bits is the minimum of the security strength
    /// supported by the DRBG and the length of the bit string returned"
    ///
    /// Section 8.4 does not limit `len`: "Security_strength_of_output = min(output_length,
    /// DRBG_security_strength)", so a longer output is allowed and carries no more strength than
    /// the instance has, and neither does a concatenation of outputs. Extracting two 128-bit
    /// values from an instance instantiated at [`SecurityStrength::_128bit`] and combining them
    /// into an AES-256 key gives a 128-bit key. What is limited is one request: `len` is bytes,
    /// and more than `max_number_of_bits_per_request` (2^19 bits, Table 2) is refused as
    /// [`RNGError::GenericError`]; so is an `additional_input` over 2^35 bits.
    ///
    /// # Errors
    /// [`RNGError::Uninitialized`] before [`Self::instantiate`]; [`RNGError::ReseedRequired`] after
    /// `reseed_interval` requests; [`RNGError::GenericError`] for the length limits.
    fn generate(&mut self, additional_input: &[u8], len: usize) -> Result<Vec<u8>, RNGError>;

    /// As per [`Sp80090ADrbg::generate`], but writes to the provided output slice, which is
    /// filled (and zeroized first). Returns the number of bytes written, the slice's length.
    fn generate_out(&mut self, additional_input: &[u8], out: &mut [u8]) -> Result<usize, RNGError>;

    /// As per [`Sp80090ADrbg::generate`], but writes to the provided KeyMaterial, which is filled
    /// to capacity and tagged [`KeyType::CryptographicRandom`] at Section 8.4's
    /// `min(output_length, DRBG_security_strength)`. Returns the number of bytes written.
    fn generate_keymaterial_out<K: KeyMaterialTrait + ?Sized>(
        &mut self,
        additional_input: &[u8],
        out: &mut K,
    ) -> Result<usize, RNGError>;

    // TODO -- implement FIPS health tests
    // fn health_test(&mut self) -> Result<bool, RNGError>;
}
