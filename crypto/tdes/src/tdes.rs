//! The TDEA forward and inverse cipher operations (SP 800-67r2 Sec 3.1), the key-bundle checks of
//! Sec 3.1 and Sec 3.3.2, and the three-key engine type. The two-key engine is in
//! [`crate::tdes2`] and shares the checks defined here.

use crate::des::{Subkeys, inverse_ip, ip, rounds};
use crate::schedule::{PARITY_MASK, expand, is_weak};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, ElectronicCodeBook, SecurityStrength};
use bouncycastle_utils::ct::ct_eq_zero_bytes;
use bouncycastle_utils::secret::Secret;

/// The DEA block length in bytes: 64 bits (SP 800-67r2 Sec 2).
pub const BLOCK_LEN: usize = 8;

/// The length of a three-key TDEA key bundle in bytes: three 64-bit DEA keys,
/// `Key1 || Key2 || Key3` (SP 800-67r2 Sec 3.1).
pub const KEY_LEN: usize = 24;

pub(crate) type Block = [u8; BLOCK_LEN];

/// The three-key TDEA keyed permutation (SP 800-67r2 Sec 3.1), "3TDEA".
///
/// The only state is the three expanded DEA keys, held in a [`Secret`] so that they are zeroized
/// on drop and redacted from `Debug`. There is no direction flag: the inverse transformation reads
/// the same round keys backwards (Sec 2.2), so one value serves both directions, and a
/// constructed value is always ready to use, so there is no `init()` or `reset()`.
///
/// Only bundles of three distinct keys are accepted. See `TDES::new` for what is rejected and
/// why; for two-key TDEA, which is decryption-only, see [`crate::TDES2Key`]. See the crate docs
/// for the standing of TDEA today.
pub struct TDES {
    schedule: Secret<[Subkeys; 3]>,
}

/// Checks the [`KeyMaterial`] wrapper before the key bytes are looked at.
///
/// The key must be tagged [`KeyType::SymmetricCipherKey`], must be exactly `key_len` bytes, and
/// must carry a [`SecurityStrength`] of at least `min_strength` -- the engine's
/// [`Algorithm::MAX_SECURITY_STRENGTH`]. A key from a correctly-instantiated RNG or KDF will carry
/// more than that; the check catches material that arrived from somewhere it should not have.
pub(crate) fn validate_wrapper(
    key: &dyn KeyMaterialTrait,
    key_len: usize,
    min_strength: SecurityStrength,
) -> Result<(), SymmetricCipherError> {
    if key.key_type() != KeyType::SymmetricCipherKey {
        return Err(KeyMaterialError::InvalidKeyType(
            "TDES requires a key of type KeyType::SymmetricCipherKey.",
        )
        .into());
    }
    if key.key_len() != key_len {
        return Err(KeyMaterialError::InvalidLength.into());
    }
    if key.security_strength() < min_strength {
        return Err(KeyMaterialError::SecurityStrength(
            "The provided key has a lower security strength than this TDES engine provides.",
        )
        .into());
    }
    Ok(())
}

/// Whether two DEA keys are the same key to the engine: equal once the parity bits, which the
/// algorithm ignores (Appendix A), are cleared. Constant time.
pub(crate) fn same_key(a: u64, b: u64) -> bool {
    ct_eq_zero_bytes(&((a ^ b) & PARITY_MASK).to_be_bytes())
}

/// Sec 3.1's requirement that the component keys of a bundle be distinct, as an error.
pub(crate) const REPEATED_KEY: KeyMaterialError = KeyMaterialError::WeakKey(
    "TDES requires distinct component keys (SP 800-67r2 Sec 3.1); a bundle with a repeated key \
     collapses to single DES.",
);

/// Sec 3.3.2: "weak, semi-weak and possibly weak keys ... should be avoided". Every component is
/// checked, so that timing does not say which one was weak.
pub(crate) fn any_weak(keys: &[u64]) -> Result<(), SymmetricCipherError> {
    let mut weak = false;
    for &k in keys {
        weak |= is_weak(k);
    }
    if weak {
        return Err(KeyMaterialError::WeakKey(
            "TDES component key is a weak, semi-weak or possibly weak DES key (SP 800-67r2 Sec \
             3.3.2).",
        )
        .into());
    }
    Ok(())
}

impl TDES {
    /// Expands a 24-byte key bundle `Key1 || Key2 || Key3` into the three DEA key schedules.
    ///
    /// The parity bits (the last bit of each key byte, Appendix A) are ignored, as the algorithm
    /// ignores them; a key with wrong parity is not rejected, and two keys differing only in
    /// parity are the same key for every check below.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not [`KeyType::SymmetricCipherKey`].
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 24 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 112 bits, the
    ///   strength SP 800-57 Part 1 Rev 5, Sec 5.6.1 Table 2 assigns to 3TDEA.
    /// * [`KeyMaterialError::WeakKey`] if the three component keys are not pairwise distinct. Sec
    ///   3.1 defines three-key TDEA only for `Key1 != Key2`, `Key2 != Key3`, `Key3 != Key1`:
    ///   `Key1 = Key2` or `Key2 = Key3` makes two of the three DEA transformations cancel, leaving
    ///   single DES, and `Key1 = Key3` is two-key TDEA, which has its own decryption-only type,
    ///   [`crate::TDES2Key`], taking the 16-byte `Key1 || Key2`.
    /// * [`KeyMaterialError::WeakKey`] if any component is one of the 64 weak, semi-weak or
    ///   possibly weak DEA keys of Sec 3.3.2.
    pub(crate) fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        validate_wrapper(key, KEY_LEN, Self::MAX_SECURITY_STRENGTH)?;
        // `validate_wrapper` has established the length; this is a type change, not a check.
        let bytes: &[u8; KEY_LEN] =
            key.ref_to_bytes().try_into().map_err(|_| KeyMaterialError::InvalidLength)?;
        let (keys, _) = bytes.as_chunks::<8>();
        let k: [u64; 3] = core::array::from_fn(|i| u64::from_be_bytes(keys[i]));

        // Sec 3.1: three distinct keys. Every comparison is evaluated so that timing does not say
        // which pair matched.
        if same_key(k[0], k[1]) | same_key(k[1], k[2]) | same_key(k[0], k[2]) {
            return Err(REPEATED_KEY.into());
        }
        any_weak(&k)?;

        let mut schedule = Secret::<[Subkeys; 3]>::new();
        for (i, sk) in schedule.iter_mut().enumerate() {
            expand(k[i], sk);
        }
        Ok(Self { schedule })
    }

    /// The TDEA forward cipher operation, `O = F_Key3(I_Key2(F_Key1(d)))` (Sec 3.1), in place.
    ///
    /// Each DEA transformation is `IP`, sixteen iterations, `IP^-1` (Sec 2.1). The `IP^-1` ending
    /// one and the `IP` beginning the next cancel, so `IP` is applied once before the forty-eight
    /// iterations and `IP^-1` once after; see [`rounds`].
    pub(crate) fn encrypt_block(&self, block: &mut Block) {
        let [k1, k2, k3] = &*self.schedule;
        forward(block, k1, k2, k3);
    }

    /// The TDEA inverse cipher operation, `O = I_Key1(F_Key2(I_Key3(d)))` (Sec 3.1), in place.
    pub(crate) fn decrypt_block(&self, block: &mut Block) {
        let [k1, k2, k3] = &*self.schedule;
        inverse(block, k1, k2, k3);
    }
}

/// `F_Key3(I_Key2(F_Key1(d)))` on one block, with `IP` and `IP^-1` applied once around all
/// forty-eight iterations. Shared by the three-key and two-key engines.
#[inline(always)]
pub(crate) fn forward(block: &mut Block, k1: &Subkeys, k2: &Subkeys, k3: &Subkeys) {
    let (l, r) = split(block);
    let (l, r) = ip(l, r);
    let (l, r) = rounds(l, r, k1, false); // F_Key1
    let (l, r) = rounds(l, r, k2, true); // I_Key2
    let (l, r) = rounds(l, r, k3, false); // F_Key3
    join(block, inverse_ip(l, r));
}

/// `I_Key1(F_Key2(I_Key3(d)))` on one block. See [`forward`].
#[inline(always)]
pub(crate) fn inverse(block: &mut Block, k1: &Subkeys, k2: &Subkeys, k3: &Subkeys) {
    let (l, r) = split(block);
    let (l, r) = ip(l, r);
    let (l, r) = rounds(l, r, k3, true); // I_Key3
    let (l, r) = rounds(l, r, k2, false); // F_Key2
    let (l, r) = rounds(l, r, k1, true); // I_Key1
    join(block, inverse_ip(l, r));
}

/// The block as `L R`: the first four bytes and the last four, big-endian, so that spec bit 1 is
/// the most significant bit of `L`.
#[inline(always)]
fn split(block: &Block) -> (u32, u32) {
    (
        u32::from_be_bytes([block[0], block[1], block[2], block[3]]),
        u32::from_be_bytes([block[4], block[5], block[6], block[7]]),
    )
}

#[inline(always)]
fn join(block: &mut Block, (l, r): (u32, u32)) {
    block[..4].copy_from_slice(&l.to_be_bytes());
    block[4..].copy_from_slice(&r.to_be_bytes());
}

impl Algorithm for TDES {
    const ALG_NAME: &'static str = "TDES";
    /// SP 800-57 Part 1 Rev 5, Sec 5.6.1 Table 2: 3TDEA provides 112 bits of security strength.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_112bit;
}

impl ElectronicCodeBook<KEY_LEN, BLOCK_LEN> for TDES {
    fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        TDES::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        TDES::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        TDES::decrypt_block(self, block)
    }
    // The pair and four-block methods keep their defaults: the engine has no natural unit larger
    // than one block, so there is nothing to gain from overriding them.
}

impl core::fmt::Debug for TDES {
    /// Prints the algorithm name only. The key schedule is secret and is never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(Self::ALG_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_size_is_exactly_the_three_schedules() {
        // The "Memory Usage" table in the crate docs quotes this. No direction flag, no counters:
        // three DEA keys of sixteen two-word round keys.
        assert_eq!(size_of::<TDES>(), 3 * 16 * 2 * 4);
        assert_eq!(size_of::<TDES>(), 384);
    }

    #[test]
    fn test_alg_name_and_strength() {
        assert_eq!(<TDES as Algorithm>::ALG_NAME, "TDES");
        assert_eq!(<TDES as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::_112bit);
        assert!(<TDES as ElectronicCodeBook<KEY_LEN, BLOCK_LEN>>::ENCRYPTION_APPROVED);
    }

    #[test]
    fn test_split_and_join_round_trip_big_endian() {
        let block: Block = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let (l, r) = split(&block);
        assert_eq!((l, r), (0x0123_4567, 0x89AB_CDEF));
        let mut out = [0u8; BLOCK_LEN];
        join(&mut out, (l, r));
        assert_eq!(out, block);
    }

    #[test]
    fn test_same_key_ignores_parity_only() {
        assert!(same_key(0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF ^ !PARITY_MASK));
        assert!(!same_key(0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF ^ 2));
    }
}
