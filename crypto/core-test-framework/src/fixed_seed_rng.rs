//! A deterministic fake [RNG] for reproducible tests.

use bouncycastle_core::errors::{KeyMaterialError, RNGError};
use bouncycastle_core::key_material;
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{RNG, SecurityStrength};

/// A test-only fake [RNG] that produces a fixed, fully deterministic byte stream.
///
/// The stream is the `SEED_LEN`-byte seed repeated indefinitely. A single internal counter is
/// shared across every [RNG] method, so each byte handed out — whether through
/// [RNG::next_bytes_out], [RNG::next_bytes], [RNG::next_int], or [RNG::fill_keymaterial_out] —
/// advances the same stream. Two instances built from the same seed therefore emit identical
/// streams, which is what makes RNG-driven operations reproducible (and comparable against their
/// seed/`m`-driven internal counterparts) in tests.
///
/// This is a deterministic stub for tests only; it is in no way a secure RNG.
pub struct FixedSeedRNG<const SEED_LEN: usize> {
    seed: [u8; SEED_LEN],
    counter: usize,
    security_strength: SecurityStrength,
}

impl<const SEED_LEN: usize> FixedSeedRNG<SEED_LEN> {
    /// Create an instance that emits `seed` repeated indefinitely, starting from its first byte.
    pub fn new(seed: [u8; SEED_LEN]) -> Self {
        Self { seed, counter: 0, security_strength: SecurityStrength::_256bit }
    }

    /// Pull the next byte from the deterministic stream and advance the counter.
    fn next_byte(&mut self) -> u8 {
        let b = self.seed[self.counter % SEED_LEN];
        self.counter += 1;
        b
    }

    /// For testing purposes, set the security strength that this RNG will report
    pub fn set_security_strength(&mut self, security_strength: SecurityStrength) {
        self.security_strength = security_strength;
    }
}

impl<const SEED_LEN: usize> RNG for FixedSeedRNG<SEED_LEN> {
    /// No-op: this fake RNG ignores reseeding, since its stream is fixed by construction.
    fn add_seed_keymaterial(
        &mut self,
        _additional_seed: &dyn KeyMaterialTrait,
    ) -> Result<(), RNGError> {
        Ok(())
    }

    fn next_int(&mut self) -> Result<u32, RNGError> {
        let mut buf = [0u8; 4];
        for slot in buf.iter_mut() {
            *slot = self.next_byte();
        }
        Ok(u32::from_le_bytes(buf))
    }

    fn next_bytes(&mut self, len: usize) -> Result<Vec<u8>, RNGError> {
        let mut out = vec![0u8; len];
        for slot in out.iter_mut() {
            *slot = self.next_byte();
        }
        Ok(out)
    }

    fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
        for slot in out.iter_mut() {
            *slot = self.next_byte();
        }
        Ok(out.len())
    }

    /// Fill `out` to capacity from the stream and mark it as a full-entropy 256-bit seed,
    /// mirroring what a real DRBG's `generate_keymaterial_out` produces. A 256-bit security
    /// strength is enough for every ML-KEM / ML-DSA parameter set.
    fn fill_keymaterial_out(&mut self, out: &mut dyn KeyMaterialTrait) -> Result<usize, RNGError> {
        let mut len = 0;
        key_material::do_hazardous_operations(out, |out| {
            len = self
                .next_bytes_out(out.ref_to_bytes_mut()?)
                .map_err(|_| KeyMaterialError::GenericError("RNG failed to acquire next bytes."))?;
            out.set_key_len(len)?;
            out.set_key_type(KeyType::Seed)?;
            out.set_security_strength(SecurityStrength::_256bit)
        })?;

        Ok(len)
    }

    fn security_strength(&self) -> SecurityStrength {
        self.security_strength.clone()
    }
}
