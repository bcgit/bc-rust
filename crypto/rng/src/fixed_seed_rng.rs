//! A deterministic [`RNG`] that hands back the bytes it was given, for known-answer and other
//! reproducible tests.

use bouncycastle_core::errors::{KeyMaterialError, RNGError};
use bouncycastle_core::hazmat::do_hazardous_operations;
use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;

/// A fake [`RNG`] that produces a fixed, fully deterministic byte stream: the bytes a test
/// supplies come back out, so a known-answer vector's nonce, `rnd` or seed can be fed through an
/// algorithm's ordinary `rng`-taking entry point.
///
/// The stream is the given bytes repeated indefinitely. A single internal cursor is shared across
/// every [`RNG`] method, so each byte handed out — whether through [`RNG::next_bytes_out`],
/// [`RNG::next_bytes`], [`RNG::next_int`], or [`RNG::fill_keymaterial_out`] — advances the same
/// stream. Two instances built from the same bytes therefore emit identical streams, which is
/// what makes RNG-driven operations reproducible (and comparable against their seed/`m`-driven
/// internal counterparts) in tests.
///
/// `B` is whatever holds the bytes: borrow them (`FixedSeedRNG::new(&vector.rnd)`), and the RNG
/// is a slice and a cursor whatever their length; or hand it an array when the value has to be
/// owned. Drawing from an empty `B` panics.
///
/// This is a deterministic stub for tests only; it is in no way a secure RNG, and nothing outside
/// a test should construct one.
pub struct FixedSeedRNG<B: AsRef<[u8]>> {
    bytes: B,
    pos: usize,
    security_strength: SecurityStrength,
}

impl<B: AsRef<[u8]>> FixedSeedRNG<B> {
    /// Create an instance that emits `bytes` repeated indefinitely, starting from the first.
    pub fn new(bytes: B) -> Self {
        Self { bytes, pos: 0, security_strength: SecurityStrength::_256bit }
    }

    /// Pull the next byte from the deterministic stream and advance the cursor.
    fn next_byte(&mut self) -> u8 {
        let bytes = self.bytes.as_ref();
        let b = bytes[self.pos % bytes.len()];
        self.pos += 1;
        b
    }

    /// For testing purposes, set the security strength that this RNG will report
    pub fn set_security_strength(&mut self, security_strength: SecurityStrength) {
        self.security_strength = security_strength;
    }
}

impl<B: AsRef<[u8]>> RNG for FixedSeedRNG<B> {
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
        do_hazardous_operations(out, |out| {
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
        self.security_strength
    }
}
