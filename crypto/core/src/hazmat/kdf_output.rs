//! [`label_kdf_output`], the one place the [`KDF`](crate::traits::KDF) trait's rule for typing
//! derived keying material is written down as code.

use crate::errors::KeyMaterialError;
use crate::hazmat::do_hazardous_operations;
use crate::key_material::{KeyMaterialTrait, KeyType};
use crate::security_strength::SecurityStrength;
use bouncycastle_utils::{max, min};

/// Types the derived keying material in `dkm`, `len` bytes of it already written, by the
/// [`KDF`](crate::traits::KDF) trait's rule: [`KeyType::CryptographicRandom`] when the
/// full-entropy `keys` with a strength carry at least `seed_len` bytes between them, at the
/// least of the strongest such key's strength, `max_strength` and the strength `len` bytes can
/// hold; and otherwise [`KeyType::Unknown`] with no strength.
///
/// `keys` are the input keys the function consumed, `seed_len` its own strength bound in
/// bytes (half a hash output for a hash-based KDF), and `max_strength` the ceiling of the
/// function underneath. For a KDF implementation to call once its output is in place. The
/// arguments are trusted: a `seed_len` of zero would call output seeded that no key seeded, so
/// the caller passes a non-zero bound and refuses a zero-length derivation itself.
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
    let mut credited = 0usize;
    let mut strength = SecurityStrength::None;
    for key in keys {
        if key.is_full_entropy() && key.security_strength() != SecurityStrength::None {
            credited = credited.saturating_add(key.key_len());
            strength = *max(&strength, &key.security_strength());
        }
    }
    do_hazardous_operations(dkm, |dkm| {
        dkm.set_key_len(len)?;
        if credited >= seed_len {
            dkm.set_key_type(KeyType::CryptographicRandom)?;
            let by_len = SecurityStrength::from_bytes(len);
            dkm.set_security_strength(*min(min(&strength, &max_strength), &by_len))
        } else {
            dkm.set_key_type(KeyType::Unknown)?;
            dkm.set_security_strength(SecurityStrength::None)
        }
    })
}
