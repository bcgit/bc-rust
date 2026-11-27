//! [`KdfCredit`] and [`label_kdf_output`] over it, the one place the [`KDF`](crate::traits::KDF)
//! trait's rule for typing derived keying material is written down as code.

use crate::errors::KeyMaterialError;
use crate::hazmat::do_hazardous_operations;
use crate::key_material::{KeyMaterialTrait, KeyType};
use crate::security_strength::SecurityStrength;
use bouncycastle_utils::{max, min};

/// The [`KDF`](crate::traits::KDF) trait's rule for typing derived keying material, as a
/// running account of the keys a derivation has consumed: [`credit`](Self::credit) for each
/// key, then [`label_output`](Self::label_output) once the output is in place. For a KDF that
/// takes its keys one at a time (HKDF's streaming extract); one that has them all at hand calls
/// [`label_kdf_output`].
#[derive(Clone, Copy)]
pub struct KdfCredit {
    credited: usize,
    strength: SecurityStrength,
}

impl KdfCredit {
    /// An account with nothing credited.
    pub const fn new() -> Self {
        Self { credited: 0, strength: SecurityStrength::None }
    }

    /// Counts `key` as an input of the derivation, and returns the bytes it credits: its length
    /// when it is full-entropy with a strength, which then also lends that strength, and
    /// nothing otherwise.
    pub fn credit(&mut self, key: &(impl KeyMaterialTrait + ?Sized)) -> usize {
        if !key.is_full_entropy() || key.security_strength() == SecurityStrength::None {
            return 0;
        }
        // Saturating: the counter is bookkeeping.
        self.credited = self.credited.saturating_add(key.key_len());
        self.strength = *max(&self.strength, &key.security_strength());
        key.key_len()
    }

    /// The bytes credited so far.
    pub fn credited(&self) -> usize {
        self.credited
    }

    /// Types the derived keying material in `dkm`, `len` bytes of it already written:
    /// [`KeyType::CryptographicRandom`] when the keys credited carry at least `seed_len` bytes
    /// between them, at the least of the strongest such key's strength, `max_strength` and the
    /// strength `len` bytes can hold; and otherwise [`KeyType::Unknown`] with no strength.
    ///
    /// `seed_len` is the function's own strength bound in bytes (half a hash output for a
    /// hash-based KDF), and `max_strength` the ceiling of the function underneath. The
    /// arguments are trusted: a `seed_len` of zero would call output seeded that no key seeded,
    /// so the caller passes a non-zero bound and refuses a zero-length derivation itself.
    ///
    /// # Errors
    /// What the setters of `dkm` return; none on a buffer that holds `len` bytes.
    pub fn label_output(
        &self,
        len: usize,
        seed_len: usize,
        max_strength: SecurityStrength,
        dkm: &mut (impl KeyMaterialTrait + ?Sized),
    ) -> Result<(), KeyMaterialError> {
        do_hazardous_operations(dkm, |dkm| {
            dkm.set_key_len(len)?;
            if self.credited >= seed_len {
                dkm.set_key_type(KeyType::CryptographicRandom)?;
                let by_len = SecurityStrength::from_bytes(len);
                dkm.set_security_strength(*min(min(&self.strength, &max_strength), &by_len))
            } else {
                dkm.set_key_type(KeyType::Unknown)?;
                dkm.set_security_strength(SecurityStrength::None)
            }
        })
    }
}

impl Default for KdfCredit {
    fn default() -> Self {
        Self::new()
    }
}

/// Types the derived keying material in `dkm`, `len` bytes of it already written, by the
/// [`KDF`](crate::traits::KDF) trait's rule, from all of the input keys the function consumed:
/// each of `keys` through [`KdfCredit::credit`], then [`KdfCredit::label_output`], which
/// documents `seed_len` and `max_strength`. For a KDF implementation to call once its output is
/// in place.
///
/// # Errors
/// What the setters of `dkm` return; none on a buffer that holds `len` bytes.
pub fn label_kdf_output<K: KeyMaterialTrait + ?Sized>(
    keys: &[&K],
    len: usize,
    seed_len: usize,
    max_strength: SecurityStrength,
    dkm: &mut (impl KeyMaterialTrait + ?Sized),
) -> Result<(), KeyMaterialError> {
    let mut credit = KdfCredit::new();
    for key in keys {
        credit.credit(*key);
    }
    credit.label_output(len, seed_len, max_strength, dkm)
}
