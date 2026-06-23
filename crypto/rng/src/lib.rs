//! RNG objects for cryptographically secure random number generation.
//!
//! This crate provides the implementations of the deterministic random bit generator (DRBG) algorithms
//! which, together with a strong entropy source, form the basis of cryptographic random number generation.
//!
//! Here's the basic way to get some random bytes:
//!
//! ```
//! use bouncycastle_core::traits::RNG;
//! use bouncycastle_rng as rng;
//!
//! let random_bytes = rng::DefaultRNG::default().next_bytes(32);
//! ```
//! This is secure because `::default()` seeds the RNG from the OS, configured for general use.
//!
//! **WARNING: most people should stop reading here and should not be mucking around with the internals of RNGs.
//! This crate contains dragons and other horrible things. 🐉🐍🐜**
//!
//! # 🚨🚨🚨Security Warning 🚨🚨🚨
//!
//! Misuse of the objects in this crate can lead to output which may appear random, but
//! is in fact completely deterministic (ie multiple runs of your application will give the same outputs)
//! and will therefore compromise any cryptographic operation built on top of those outputs.
//! You should only be here if your application requires direct control over configuring the internals of the DRBG.
//!
//! This crate contains the [Sp80090ADrbg] trait, which is intentionally defined here and not in [bouncycastle_core::traits]
//! since misuse of [Sp80090ADrbg::instantiate] can completely undermine the security of your entire
//! cryptographic application.

#![forbid(unsafe_code)]

use crate::hash_drbg80090a::{
    HashDRBG80090A, HashDRBG80090AParams_SHA256, HashDRBG80090AParams_SHA512,
};
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::traits::SecurityStrength;

// needed for docs
#[allow(unused_imports)]
use bouncycastle_core::key_material::KeyType;
// end doc-only imports

pub mod hash_drbg80090a;

/*** String constants ***/
pub const HASH_DRBG_SHA256_NAME: &str = "HashDRBG-SHA256";
pub const HASH_DRBG_SHA512_NAME: &str = "HashDRBG-SHA512";

/*** pub types ***/
#[allow(non_camel_case_types)]
pub type HashDRBG_SHA256 = HashDRBG80090A<HashDRBG80090AParams_SHA256>;
#[allow(non_camel_case_types)]
pub type HashDRBG_SHA512 = HashDRBG80090A<HashDRBG80090AParams_SHA512>;

/*** Defaults ***/
pub type DefaultRNG = HashDRBG_SHA512;
pub type Default128BitRNG = HashDRBG_SHA256;
pub type Default256BitRNG = HashDRBG_SHA512;

/// Implements the five functions specified in SP 800-90A section 7.4 are instantate, generate, reseed, uninstantiate, and health_test.
/// Note: this function implements Rust's Drop on the sensitive working state in place of the explicit Uninstantiate function listed in SP 800-90Ar1.
pub trait Sp80090ADrbg {
    /// The input KeyMaterial must be of type [KeyType::Seed].
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
    /// This function takes ownership of the seed KeyMaterial object, to reduce the likelihood of its reuse in a second function call.
    ///
    /// There is no entropy requirement on the nonce, but it is expected as a KeyMaterial so that it
    /// benefits from the secure erasure and logging protections in the KeyMaterial object.
    fn instantiate(
        &mut self,
        prediction_resistance: bool,
        seed: impl KeyMaterialTrait,
        nonce: &impl KeyMaterialTrait,
        personalization_string: &[u8],
        security_strength: SecurityStrength,
    ) -> Result<(), RNGError>;

    /// Reseeds the DRBG with the provided seed.
    /// TODO: this needs to be thought out to take some sort of EntropySource object that'll work well with DRBGs that require frequent reseeding.
    fn reseed(
        &mut self,
        seed: &impl KeyMaterialTrait,
        additional_input: &[u8],
    ) -> Result<(), RNGError>;

    /// Note that for a calling application to be in compliance with SP 800-90A, this requirement
    /// from section 8.4 must be met:
    ///    "The pseudorandom bits returned from a DRBG shall not be used for any
    /// application that requires a higher security strength than the DRBG is instantiated to support. The
    /// security strength provided in these returned bits is the minimum of the security strength
    /// supported by the DRBG and the length of the bit string returned"
    ///
    /// As required by SP 800-90A section 8.4, `len` cannot exceed the initialized [SecurityStrength]
    /// of this instance, although multiple calls to this function can be made, in which case it is the
    /// application's responsibility to track that it is not expecting more entropy than the [SecurityStrength]
    /// to which this instance was instantiated. For example, extracting two 128-bit values from an instance
    /// instantiated to [SecurityStrength::_128bit] and then combining tem to form an AES-256 key would likely
    /// not pass FIPS certification.
    ///
    /// Throws a [RNGError::InsufficientSeedEntropy] if `len` exceeds [SecurityStrength].
    fn generate(&mut self, additional_input: &[u8], len: usize) -> Result<Vec<u8>, RNGError>;

    /// As per [Sp80090ADrbg::generate], but writes to the provided output slice.
    /// The output slice is filled.
    /// Throws a [RNGError::InsufficientSeedEntropy] if the length of the output slice exceeds [SecurityStrength].
    /// Retruns the number of bits output.
    fn generate_out(&mut self, additional_input: &[u8], out: &mut [u8]) -> Result<usize, RNGError>;

    /// As per [Sp80090ADrbg::generate], but writes to the provided KeyMaterial.
    /// The output [KeyMaterialTrait] is filled to capacity.
    /// Throws a [RNGError::InsufficientSeedEntropy] if the capacity of the output KeyMaterial exceeds [SecurityStrength].
    /// Retruns the number of bits output.
    fn generate_keymaterial_out(
        &mut self,
        additional_input: &[u8],
        out: &mut impl KeyMaterialTrait,
    ) -> Result<usize, RNGError>;

    // TODO -- implement FIPS health tests
    // fn health_test(&mut self) -> Result<bool, RNGError>;
}
