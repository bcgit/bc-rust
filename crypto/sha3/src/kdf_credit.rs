//! The entropy accounting of a hash or XOF used as a KDF: the rule of
//! [`KDF`](bouncycastle_core::traits::KDF)'s docs, kept beside the derivation rather than in the
//! sponge, since the derivation starts from a fresh state and the instance holds nothing.

use bouncycastle_core::key_material::{KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_utils::{max, min};

/// What the input keys of one derivation are worth: the bytes of full-entropy material with a
/// strength, and the strongest such key's strength, capped at what the function can claim.
pub(crate) struct KdfCredit {
    bytes: usize,
    strength: SecurityStrength,
    cap: SecurityStrength,
}

impl KdfCredit {
    /// `cap` is the most the output's label can say: the function's own strength bound.
    pub(crate) fn new(cap: SecurityStrength) -> Self {
        Self { bytes: 0, strength: SecurityStrength::None, cap }
    }

    /// Credits `key`: its bytes when it is full-entropy material with a strength, nothing
    /// otherwise. The same key credited twice counts twice.
    pub(crate) fn credit(&mut self, key: &dyn KeyMaterialTrait) {
        if !key.is_full_entropy() || key.security_strength() == SecurityStrength::None {
            return;
        }
        self.bytes = self.bytes.saturating_add(key.key_len());
        self.strength = *min(&*max(&self.strength, &key.security_strength()), &self.cap);
    }

    /// The output's type and strength: [`KeyType::CryptographicRandom`] once at least
    /// `threshold` bytes were credited, at the least of the credited strength and what `len`
    /// bytes carry; else [`KeyType::Unknown`] with no strength.
    pub(crate) fn output(&self, threshold: usize, len: usize) -> (KeyType, SecurityStrength) {
        if self.bytes >= threshold {
            (
                KeyType::CryptographicRandom,
                *min(&self.strength, &SecurityStrength::from_bits(len * 8)),
            )
        } else {
            (KeyType::Unknown, SecurityStrength::None)
        }
    }
}

/// The 4-byte big-endian length that prefixes each input key in the derivation's input, so
/// that the keys and the fixed info are bound unambiguously.
///
/// # Errors
/// A key longer than `u32::MAX` bytes has no prefix.
pub(crate) fn len_prefix(key: &dyn KeyMaterialTrait) -> Result<[u8; 4], ()> {
    u32::try_from(key.key_len()).map(u32::to_be_bytes).map_err(|_| ())
}
