//! Generic behaviour tests for `bouncycastle_core::traits::KeyPairGenerator`.

use crate::FailingRNG;
use bouncycastle_core::errors::{KeyMaterialError, RNGError};
use bouncycastle_core::key_material::KeyMaterialTrait;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::{KeyPairGenerator, RNG};
use core::fmt::Debug;

/// Instance of the test framework.
pub struct TestFrameworkKeyPairGenerator {}

impl Default for TestFrameworkKeyPairGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// An RNG that claims full strength and fails every draw, so that generation gets past its
/// strength check and fails on the draw. (The crate's `FailingRNG` claims no strength.)
struct FullStrengthFailingRng;

impl RNG for FullStrengthFailingRng {
    fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn next_int(&mut self) -> Result<u32, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn next_bytes_out(&mut self, _: &mut [u8]) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn fill_keymaterial_out(&mut self, _: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        Err(RNGError::GenericError("failing RNG"))
    }
    fn security_strength(&self) -> SecurityStrength {
        SecurityStrength::_256bit
    }
}

impl TestFrameworkKeyPairGenerator {
    /// A framework instance; it holds no configuration.
    pub fn new() -> Self {
        Self {}
    }

    /// Every member of [`KeyPairGenerator`] for `SK`: a generated pair belongs together, two
    /// generations differ, an unfilled key has no public key, and a failed generation leaves a
    /// key that held one unfilled, whether the RNG fails to deliver or is too weak. `rng` must be
    /// strong enough for the algorithm.
    pub fn test<SK>(&self, rng: &mut dyn RNG)
    where
        SK: KeyPairGenerator,
        SK::PublicKey: PartialEq + Debug,
        SK::Error: PartialEq + Debug,
    {
        let zeroized = SK::Error::from(KeyMaterialError::ActingOnZeroizedKey);

        let (pk, sk) = SK::generate(rng).unwrap();
        assert_eq!(sk.pub_key().unwrap(), pk);

        let mut other = SK::zeroized();
        assert_eq!(other.pub_key().unwrap_err(), zeroized);
        SK::generate_out(rng, &mut other).unwrap();
        assert_ne!(other.pub_key().unwrap(), pk, "two generations gave the same key");

        assert!(SK::generate_out(&mut FullStrengthFailingRng, &mut other).is_err());
        assert_eq!(other.pub_key().unwrap_err(), zeroized);

        // An RNG weaker than the algorithm is refused before any draw; the key is zeroized
        // first all the same.
        SK::generate_out(rng, &mut other).unwrap();
        assert!(SK::generate_out(&mut FailingRNG, &mut other).is_err());
        assert_eq!(other.pub_key().unwrap_err(), zeroized);
        assert!(SK::generate(&mut FullStrengthFailingRng).is_err());
    }
}
