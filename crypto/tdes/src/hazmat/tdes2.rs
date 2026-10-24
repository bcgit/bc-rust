//! Two-key TDEA (SP 800-67r2 Sec 3.1, "2TDEA"), for decryption of legacy data only.

use crate::BLOCK_LEN;
use crate::KEY_LEN_2KEY;
use crate::des::Subkeys;
use crate::hazmat::tdes::{
    Block, REPEATED_KEY, any_weak, forward, inverse, same_key, validate_wrapper,
};
use crate::schedule::expand;
use bouncycastle_cipher::modes::ModeNames;
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{BlockPermutation, ElectronicCodeBook};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::Algorithm;
use bouncycastle_utils::secret::Secret;

/// The two-key TDEA keyed permutation (SP 800-67r2 Sec 3.1, "2TDEA"): `Key3 = Key1`, so the bundle
/// is the 16 bytes `Key1 || Key2`. The engine under [`TDES2Key`](crate::TDES2Key).
///
/// **Decryption only.** SP 800-67r2 Sec 3.1 allows two-key TDEA "for legacy use only, as defined
/// in SP 800-131A", and SP 800-131A Rev 2 Table 1 has it as "Disallowed" for encryption and
/// "Legacy use" for decryption. This type therefore sets
/// [`ElectronicCodeBook::ENCRYPTION_APPROVED`] to `false`, and every mode in
/// `bouncycastle_cipher::modes` refuses to make an encrypting worker over it **at compile time**,
/// so a two-key key's `create_encryptor` does not compile:
///
/// ```compile_fail
/// use bouncycastle_tdes::TDES2Key;
/// use bouncycastle_cipher::modes::CBC;
/// use bouncycastle_cipher::padding::PKCS7;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
/// let key = TDES2Key::<CBC<PKCS7>>::from_key_material(&material).unwrap();
///
/// // Two-key TDEA may not apply protection: this does not compile.
/// let _ = key.create_encryptor(&mut HashDRBG_SHA512::new_from_os());
/// ```
///
/// The stream modes check the same constant when they make their keystream, so the refusal holds
/// for CTR, CFB and CFB8 too:
///
/// ```compile_fail
/// use bouncycastle_tdes::{BLOCK_LEN, CTR_NONCE_LEN, TDES2Key};
/// use bouncycastle_cipher::modes::CTR;
/// use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// use bouncycastle_core::symmetric_key::{FromKeyMaterial, SymmetricEncryptionKey};
/// use bouncycastle_rng::HashDRBG_SHA512;
///
/// let bytes: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
/// let material = KeyMaterial::<16>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey).unwrap();
/// let key = TDES2Key::<CTR<CTR_NONCE_LEN, BLOCK_LEN>>::from_key_material(&material).unwrap();
///
/// // Two-key TDEA may not apply protection through CTR either: this does not compile.
/// let _ = key.create_encryptor(&mut HashDRBG_SHA512::new_from_os());
/// ```
///
/// `create_decryptor` on every mode works, and this crate names those decryptors
/// [`TDES2_CBC`](crate::TDES2_CBC), [`TDES2_CFB`](crate::TDES2_CFB), [`TDES2_CFB8`](crate::TDES2_CFB8),
/// [`TDES2_CTR`](crate::TDES2_CTR) and [`TDES2_ECB`](crate::TDES2_ECB). The raw
/// [`BlockPermutation::encrypt_block`] is still present, because CFB and CTR decryption are
/// built on the forward cipher function; a raw permutation is not something to encrypt data with
/// anyway (see the crate docs).
///
/// # Security strength
///
/// SP 800-57 Part 1 Rev 5, Sec 5.6.1 Table 2 rates 2TDEA at "<= 80" bits. That is below the lowest
/// level [`SecurityStrength`] models (112), so [`Algorithm::MAX_SECURITY_STRENGTH`] is
/// [`SecurityStrength::None`] and the key-strength check in `new` never rejects a key -- there is
/// no honest higher value to demand.
///
/// The persistent state is the two expanded DEA keys, 256 bytes, in a [`Secret`].
#[derive(Clone)]
pub struct TDES2Internal {
    schedule: Secret<[Subkeys; 2]>,
}

impl Algorithm for TDES2Internal {
    const ALG_NAME: &'static str = "TDES-2KEY";
    /// SP 800-57 Part 1 Rev 5, Sec 5.6.1 Table 2: 2TDEA provides at most 80 bits, below the lowest
    /// modelled level. See the type docs.
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::None;
}

impl ElectronicCodeBook<KEY_LEN_2KEY, BLOCK_LEN> for TDES2Internal {
    /// Expands a 16-byte key bundle `Key1 || Key2` into the two DEA key schedules.
    ///
    /// Parity bits are ignored, as for [`TDESInternal`](super::TDESInternal).
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not `KeyType::SymmetricCipherKey`.
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::WeakKey`] if `Key1 = Key2` (with parity ignored), which collapses the
    ///   three DEA transformations to single DES -- Sec 3.1 requires `Key1 != Key2` for two-key TDEA
    ///   as well.
    /// * [`KeyMaterialError::WeakKey`] if either component is one of the 64 weak, semi-weak or
    ///   possibly weak DEA keys of Sec 3.3.2.
    fn new(key: &KeyMaterial<KEY_LEN_2KEY>) -> Result<Self, SymmetricCipherError> {
        validate_wrapper(key, KEY_LEN_2KEY, Self::MAX_SECURITY_STRENGTH)?;
        let bytes: &[u8; KEY_LEN_2KEY] =
            key.ref_to_bytes().try_into().map_err(|_| KeyMaterialError::InvalidLength)?;
        let (keys, _) = bytes.as_chunks::<8>();
        let k: [u64; 2] = core::array::from_fn(|i| u64::from_be_bytes(keys[i]));

        if same_key(k[0], k[1]) {
            return Err(REPEATED_KEY.into());
        }
        any_weak(&k)?;

        let mut schedule = Secret::<[Subkeys; 2]>::new();
        for (i, sk) in schedule.iter_mut().enumerate() {
            expand(k[i], sk);
        }
        Ok(Self { schedule })
    }

    /// SP 800-131A Rev 2 Table 1: two-key TDEA encryption is disallowed.
    const ENCRYPTION_APPROVED: bool = false;
}

impl BlockPermutation<BLOCK_LEN> for TDES2Internal {
    /// The forward cipher operation with `Key3 = Key1`: `O = F_Key1(I_Key2(F_Key1(d)))`.
    ///
    /// Present because CFB and CTR decryption need it, and because the trait requires it; the
    /// encrypting modes will not compile over this type. See the type docs.
    fn encrypt_block(&self, block: &mut Block) {
        let [k1, k2] = &*self.schedule;
        forward(block, k1, k2, k1);
    }
    /// The inverse cipher operation with `Key3 = Key1`: `O = I_Key1(F_Key2(I_Key1(d)))`.
    fn decrypt_block(&self, block: &mut Block) {
        let [k1, k2] = &*self.schedule;
        inverse(block, k1, k2, k1);
    }
    // As for `TDESInternal`: no unit larger than one block, so the batch methods are single-block
    // loops.
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block)
        }
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block)
        }
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        for block in blocks.iter_mut() {
            self.encrypt_block(block)
        }
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        for block in blocks.iter_mut() {
            self.decrypt_block(block)
        }
    }
}

/// The same modes as the three-key engine, under their own names.
impl ModeNames for TDES2Internal {
    const CBC_ALG_NAME: &'static str = "TDES2_CBC";
    const CCM_ALG_NAME: &'static str = "";
    const CFB_ALG_NAME: &'static str = "TDES2_CFB";
    const CFB8_ALG_NAME: &'static str = "TDES2_CFB8";
    const CMAC_ALG_NAME: &'static str = "";
    const CTR_ALG_NAME: &'static str = "TDES2_CTR";
    const ECB_ALG_NAME: &'static str = "TDES2_ECB";
    const GCM_ALG_NAME: &'static str = "";
    const GMAC_ALG_NAME: &'static str = "";
}

impl core::fmt::Debug for TDES2Internal {
    /// Prints the algorithm name only. The key schedule is secret and is never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(Self::ALG_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_size_is_exactly_the_two_schedules() {
        assert_eq!(size_of::<TDES2Internal>(), 2 * 16 * 2 * 4);
        assert_eq!(size_of::<TDES2Internal>(), 256);
    }

    #[test]
    fn test_alg_name_strength_and_gate() {
        assert_eq!(<TDES2Internal as Algorithm>::ALG_NAME, "TDES-2KEY");
        assert_eq!(<TDES2Internal as Algorithm>::MAX_SECURITY_STRENGTH, SecurityStrength::None);
        assert!(
            !<TDES2Internal as ElectronicCodeBook<KEY_LEN_2KEY, BLOCK_LEN>>::ENCRYPTION_APPROVED
        );
    }
}
