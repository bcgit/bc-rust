//! CIPHER() and INVCIPHER() (FIPS 197 §5.1 and §5.3), and the public types.

use crate::bitslice::{Planes, pack, unpack};
use crate::round::{add_round_key, inv_mix_columns, inv_shift_rows, mix_columns, shift_rows};
use crate::sbox::{inv_sbox, sbox};
use crate::schedule::{AES128Params, AES192Params, AES256Params, AESParams, expand, round_key};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, SecurityStrength};
use bouncycastle_utils::secret::Secret;

/// The AES block length in bytes: 16 (FIPS 197 §5, Table 3, `Nb` = 4 words).
/// AES-128, AES-192, and AES-256 all use a block length of 16 bytes.
pub const BLOCK_LEN: usize = 16;

/// One 16-byte AES block, in the order of FIPS 197 Eq (3.6): `block[r + 4c] == s[r,c]`.
pub type Block = [u8; BLOCK_LEN];

/// The AES keyed permutation, parameterised by key length.
///
/// The core internal implementation of the ML-KEM algorithm.
/// This needs to be public for the compiler to be able to find it,
/// but is shouldn't ever need to be used directly.
/// Please use the named public types.
pub struct AES<P: AESParams> {
    schedule: Secret<P::Schedule>,
}

/// AES-128: 16-byte key, 10 rounds (FIPS 197 §5, Table 3).
pub type AES_128 = AES<AES128Params>;
/// AES-192: 24-byte key, 12 rounds (FIPS 197 §5, Table 3).
pub type AES_192 = AES<AES192Params>;
/// AES-256: 32-byte key, 14 rounds (FIPS 197 §5, Table 3).
pub type AES_256 = AES<AES256Params>;

impl<P: AESParams> AES<P> {
    /// Checks a key is fit to use before it is expanded:
    ///
    /// It must be:
    /// * tagged [`KeyType::SymmetricCipherKey`],
    /// * exactly `P::KEY_LEN` bytes,
    /// * must carry a [`SecurityStrength`] at least equal to its own length.
    ///
    /// Takes `&dyn KeyMaterialTrait` so the three constructors, whose `KeyMaterial<N>` capacities
    /// differ, can share one implementation.
    fn validate(key: &dyn KeyMaterialTrait) -> Result<(), SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "AES requires a key of type KeyType::SymmetricCipherKey.",
            )
            .into());
        }
        if key.key_len() != P::KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        if key.security_strength() < SecurityStrength::from_bytes(P::KEY_LEN) {
            return Err(KeyMaterialError::SecurityStrength(
                "The provided key has a lower security strength than the AES key length implies.",
            )
            .into());
        }
        Ok(())
    }

    /// CIPHER() (FIPS 197 Sec 5.1, Algorithm 1) acting on two blocks at once.
    fn cipher2(&self, q: &mut Planes) {
        // line 3: state = state XOR w[0..3]
        add_round_key(q, &round_key::<P>(&self.schedule, 0));

        // lines 4-9: for round from 1 to Nr - 1
        for round in 1..P::NR {
            sbox(q); // line 5, SUBBYTES()
            shift_rows(q); // line 6, SHIFTROWS()
            mix_columns(q); // line 7, MIXCOLUMNS()
            add_round_key(q, &round_key::<P>(&self.schedule, round)); // line 8
        }

        // lines 10-12: the final round has no MIXCOLUMNS()
        sbox(q);
        shift_rows(q);
        add_round_key(q, &round_key::<P>(&self.schedule, P::NR));
    }

    /// INVCIPHER() (FIPS 197 Sec 5.3, Algorithm 3) acting on two blocks at once.
    fn inv_cipher2(&self, q: &mut Planes) {
        // line 3: state = state XOR w[4*Nr .. 4*Nr+3]
        add_round_key(q, &round_key::<P>(&self.schedule, P::NR));

        // lines 4-9: for round from Nr - 1 down to 1
        for round in (1..P::NR).rev() {
            inv_shift_rows(q); // line 5, INVSHIFTROWS()
            inv_sbox(q); // line 6, INVSUBBYTES()
            add_round_key(q, &round_key::<P>(&self.schedule, round)); // line 7
            inv_mix_columns(q); // line 8, INVMIXCOLUMNS()
        }

        // lines 10-12: the final inverse round has no INVMIXCOLUMNS()
        inv_shift_rows(q);
        inv_sbox(q);
        add_round_key(q, &round_key::<P>(&self.schedule, 0));
    }

    /// Encrypts one block in place.
    ///
    /// The bit-sliced state always acts on two blocks, so this encrypts the provided block and a
    /// dummy block. Use [`AES::encrypt_2blocks`] where two blocks are available.
    // Dev note: This is acting on two copies of the provided block, which costs exactly what filling
    // the unused half with zeros would, and it buys a free self-check: the two halves must come out
    // equal, which `debug_assert` verifies.
    pub fn encrypt_block(&self, block: &mut Block) {
        let mut q = pack(block, block);
        self.cipher2(&mut q);
        let mut discard = [0u8; BLOCK_LEN];
        unpack(&q, block, &mut discard);
        debug_assert_eq!(*block, discard, "the two interleaved halves must agree");
    }

    /// Encrypts two blocks in place.
    ///
    /// The internal bit-sliced state is constructed to act on two blocks simultaneously, so two
    /// blocks cost almost exactly the same as one.
    /// Prefer this over two [`AES::encrypt_block`] calls whenever two blocks are available and
    /// independent -- which, for a mode of operation, means CTR, or the decryption direction of CBC
    /// and CFB, but *not* CBC encryption, whose blocks are serially dependent.
    pub fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        let mut q = pack(&blocks[0], &blocks[1]);
        self.cipher2(&mut q);
        let (a, b) = blocks.split_at_mut(1);
        unpack(&q, &mut a[0], &mut b[0]);
    }

    /// Decrypts one block in place. See [`AES::encrypt_block`].
    pub fn decrypt_block(&self, block: &mut Block) {
        let mut q = pack(block, block);
        self.inv_cipher2(&mut q);
        let mut discard = [0u8; BLOCK_LEN];
        unpack(&q, block, &mut discard);
        debug_assert_eq!(*block, discard, "the two interleaved halves must agree");
    }

    /// Decrypts two blocks in place. See [`AES::encrypt_2blocks`].
    pub fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        let mut q = pack(&blocks[0], &blocks[1]);
        self.inv_cipher2(&mut q);
        let (a, b) = blocks.split_at_mut(1);
        unpack(&q, &mut a[0], &mut b[0]);
    }
}

impl AES_128 {
    /// Expands a 16-byte key into an AES-128 schedule.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not [`KeyType::SymmetricCipherKey`].
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    pub fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<AES128Params>(key.ref_to_bytes()) })
    }
}

impl AES_192 {
    /// Expands a 24-byte key into an AES-192 schedule. See [`AES_128::new`] for the error cases.
    pub fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<AES192Params>(key.ref_to_bytes()) })
    }
}

impl AES_256 {
    /// Expands a 32-byte key into an AES-256 schedule. See [`AES_128::new`] for the error cases.
    pub fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<AES256Params>(key.ref_to_bytes()) })
    }
}

impl Algorithm for AES_128 {
    const ALG_NAME: &'static str = AES128Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Algorithm for AES_192 {
    const ALG_NAME: &'static str = AES192Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl Algorithm for AES_256 {
    const ALG_NAME: &'static str = AES256Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

impl<P: AESParams> core::fmt::Debug for AES<P> {
    /// Prints the algorithm name only. The key schedule is secret and is never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(P::ALG_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_constants_match_the_documented_memory_table() {
        // The "Memory Usage" table in the crate docs quotes these, and the whole point of the
        // crate is that they are this small: 4 * (Nr + 1) words of schedule, nothing else, and no
        // tables anywhere. If the representation grows, the docs are wrong -- fix both.
        assert_eq!(size_of::<AES_128>(), 176, "AES-128: 4 * (10 + 1) words");
        assert_eq!(size_of::<AES_192>(), 208, "AES-192: 4 * (12 + 1) words");
        assert_eq!(size_of::<AES_256>(), 240, "AES-256: 4 * (14 + 1) words");
    }

    #[test]
    fn test_engine_size_is_exactly_the_schedule() {
        // No round counter, no direction flag, no initialised marker: the schedule is all there
        // is, which is what makes both directions available from one value at no extra cost.
        assert_eq!(size_of::<AES_128>(), size_of::<<AES128Params as AESParams>::Schedule>());
        assert_eq!(size_of::<AES_192>(), size_of::<<AES192Params as AESParams>::Schedule>());
        assert_eq!(size_of::<AES_256>(), size_of::<<AES256Params as AESParams>::Schedule>());
    }

    #[test]
    fn test_alg_names() {
        assert_eq!(<AES_128 as Algorithm>::ALG_NAME, "AES-128");
        assert_eq!(<AES_192 as Algorithm>::ALG_NAME, "AES-192");
        assert_eq!(<AES_256 as Algorithm>::ALG_NAME, "AES-256");
    }

    #[test]
    fn test_max_security_strength_matches_the_key_length() {
        assert_eq!(
            <AES_128 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(AES128Params::KEY_LEN)
        );
        assert_eq!(
            <AES_192 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(AES192Params::KEY_LEN)
        );
        assert_eq!(
            <AES_256 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(AES256Params::KEY_LEN)
        );
    }
}
