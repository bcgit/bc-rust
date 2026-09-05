//! The public engine types, and the encryption and decryption entry points (RFC 3713 Sec 2.3).

use crate::round::rounds;
use crate::schedule::{
    Camellia128Params, Camellia192Params, Camellia256Params, CamelliaParams, expand, k, ke, kw,
};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, ElectronicCodeBook, SecurityStrength};
use bouncycastle_utils::secret::Secret;

/// The Camellia block length in bytes: 16 (RFC 3713 Sec 1.1, "128-bit block size").
pub const BLOCK_LEN: usize = 16;

/// One Camellia block.
pub type Block = [u8; BLOCK_LEN];

/// The number of blocks the bit-sliced S-box layer substitutes at once. See
/// [`Camellia::encrypt_4blocks`].
pub const LANES: usize = 4;

/// The Camellia keyed permutation, parameterised by key length, constant-time.
///
/// Use the aliases [`Camellia_128`], [`Camellia_192`] and [`Camellia_256`] rather than naming this
/// directly. `P` is sealed to the three parameter sets of RFC 3713, so no fourth instantiation
/// exists.
///
/// The only state is the subkeys, held in a [`Secret`] so that they are zeroized on drop and
/// redacted from `Debug`. There is no direction flag and no initialisation state: decryption is
/// encryption with the subkeys read in the swapped order of Sec 2.3.3, so both directions work
/// from the same stored schedule, and a constructed value is always ready to use -- there is no
/// `init()` or `reset()`. This is the one structural departure from BC Java's `CamelliaEngine`,
/// which lays the subkeys out for the direction its `init(forEncryption, ..)` call asks for.
pub struct Camellia<P: CamelliaParams> {
    schedule: Secret<P::Schedule>,
}

/// Camellia-128: 16-byte key, 18 rounds (RFC 3713 Sec 2.3.1).
#[allow(non_camel_case_types)]
pub type Camellia_128 = Camellia<Camellia128Params>;
/// Camellia-192: 24-byte key, 24 rounds (RFC 3713 Sec 2.3.2).
#[allow(non_camel_case_types)]
pub type Camellia_192 = Camellia<Camellia192Params>;
/// Camellia-256: 32-byte key, 24 rounds (RFC 3713 Sec 2.3.2).
#[allow(non_camel_case_types)]
pub type Camellia_256 = Camellia<Camellia256Params>;

impl<P: CamelliaParams> Camellia<P> {
    /// Checks a key is fit to use before it is expanded.
    ///
    /// The key must be tagged [`KeyType::SymmetricCipherKey`], must be exactly `P::KEY_LEN` bytes
    /// of the buffer, and must carry a [`SecurityStrength`] at least equal to its own length --
    /// which is what a key of this length from a correctly-instantiated RNG or KDF will have.
    /// The checks exist to catch a key that arrived from somewhere it should not have: a seed
    /// reused as a cipher key, or a 32-byte buffer holding material only derived at the 128-bit
    /// strength.
    ///
    /// Takes `&dyn KeyMaterialTrait` so the three constructors, whose `KeyMaterial<N>` capacities
    /// differ, can share one implementation.
    fn validate(key: &dyn KeyMaterialTrait) -> Result<(), SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "Camellia requires a key of type KeyType::SymmetricCipherKey.",
            )
            .into());
        }
        if key.key_len() != P::KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        if key.security_strength() < SecurityStrength::from_bytes(P::KEY_LEN) {
            return Err(KeyMaterialError::SecurityStrength(
                "The provided key has a lower security strength than the Camellia key length implies.",
            )
            .into());
        }
        Ok(())
    }

    /// Encrypts four independent blocks in place (Sec 2.3.1 / Sec 2.3.2): the subkeys in the
    /// order the schedule lists them.
    ///
    /// This is the natural unit of work. The S-box circuit substitutes 32 bytes per pass and a
    /// round substitutes eight bytes per block, so four blocks fill it exactly; fewer blocks cost
    /// the same. Modes whose blocks are independent -- CTR, and the decryption direction of CBC
    /// and CFB -- reach it as the `ElectronicCodeBook` four-block batch; CBC
    /// encryption cannot, since its blocks are serially dependent.
    ///
    /// Infallible: a constructed [`Camellia`] is always usable and every input length is fixed.
    pub fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        let s = self.schedule.as_ref();
        rounds(blocks, P::ROUNDS, |i| kw(s, i), |i| k(s, i), |i| ke::<P>(s, i));
    }

    /// Decrypts four independent blocks in place (Sec 2.3.3): "the same way as the encryption
    /// procedure by reversing the order of the subkeys", namely `kw1 <-> kw3`, `kw2 <-> kw4`,
    /// `k_i <-> k_{n+1-i}` for `n` rounds, and `ke_i <-> ke_{m+1-i}` for `m` FL keys. See
    /// [`Camellia::encrypt_4blocks`].
    pub fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        let s = self.schedule.as_ref();
        rounds(
            blocks,
            P::ROUNDS,
            |i| kw(s, [3, 4, 1, 2][i - 1]),
            |i| k(s, P::ROUNDS + 1 - i),
            |i| ke::<P>(s, P::FL_KEYS + 1 - i),
        );
    }

    /// Encrypts one block in place.
    ///
    /// The circuit always processes four lanes, so a single-block call puts the block in every
    /// lane and discards three results: it does four blocks' worth of work. Use
    /// [`Camellia::encrypt_4blocks`] where independent blocks
    /// are available.
    ///
    /// Filling the spare lanes with copies costs exactly what zeros would, and buys a free
    /// self-check: all four lanes must agree, which `debug_assert` verifies. It is not a security
    /// property; the spare lanes are never returned either way.
    pub fn encrypt_block(&self, block: &mut Block) {
        let mut lanes = [*block; LANES];
        self.encrypt_4blocks(&mut lanes);
        debug_assert!(lanes.iter().all(|b| *b == lanes[0]), "all lanes must agree");
        *block = lanes[0];
    }

    /// Decrypts one block in place. See [`Camellia::encrypt_block`] for the four-lane caveat.
    pub fn decrypt_block(&self, block: &mut Block) {
        let mut lanes = [*block; LANES];
        self.decrypt_4blocks(&mut lanes);
        debug_assert!(lanes.iter().all(|b| *b == lanes[0]), "all lanes must agree");
        *block = lanes[0];
    }

    /// Encrypts two blocks in place, in lanes 0 and 1; the other two lanes carry copies of the
    /// first and are discarded. Two blocks for the price of four, but twice as good as two
    /// [`Camellia::encrypt_block`] calls, which is why the trait method is overridden.
    pub fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        let mut lanes = [blocks[0]; LANES];
        lanes[1] = blocks[1];
        self.encrypt_4blocks(&mut lanes);
        *blocks = [lanes[0], lanes[1]];
    }

    /// Decrypts two blocks in place. See [`Camellia::encrypt_2blocks`].
    pub fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        let mut lanes = [blocks[0]; LANES];
        lanes[1] = blocks[1];
        self.decrypt_4blocks(&mut lanes);
        *blocks = [lanes[0], lanes[1]];
    }
}

impl Camellia_128 {
    /// Expands a 16-byte key into the Camellia-128 subkeys (Sec 2.2).
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not [`KeyType::SymmetricCipherKey`].
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    pub fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<Camellia128Params>(key.ref_to_bytes()) })
    }
}

impl Camellia_192 {
    /// Expands a 24-byte key into the Camellia-192 subkeys. See [`Camellia_128::new`] for the
    /// error cases.
    pub fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<Camellia192Params>(key.ref_to_bytes()) })
    }
}

impl Camellia_256 {
    /// Expands a 32-byte key into the Camellia-256 subkeys. See [`Camellia_128::new`] for the
    /// error cases.
    pub fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<Camellia256Params>(key.ref_to_bytes()) })
    }
}

impl Algorithm for Camellia_128 {
    const ALG_NAME: &'static str = Camellia128Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Algorithm for Camellia_192 {
    const ALG_NAME: &'static str = Camellia192Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl Algorithm for Camellia_256 {
    const ALG_NAME: &'static str = Camellia256Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

// The three `ElectronicCodeBook` impls are one-line delegations to the inherent methods above,
// written out longhand rather than generated because `cargo mutants` cannot see into macro bodies.
//
// Each overrides the pair and four-block methods: two blocks in two of the four lanes cost one
// circuit pass per round where the default would cost two, and four blocks are one full pass
// where the default (two pair calls) would be two.

impl ElectronicCodeBook<16, BLOCK_LEN> for Camellia_128 {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Camellia_128::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Camellia::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Camellia::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Camellia::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Camellia::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        Camellia::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        Camellia::decrypt_4blocks(self, blocks)
    }
}

impl ElectronicCodeBook<24, BLOCK_LEN> for Camellia_192 {
    fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Camellia_192::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Camellia::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Camellia::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Camellia::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Camellia::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        Camellia::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        Camellia::decrypt_4blocks(self, blocks)
    }
}

impl ElectronicCodeBook<32, BLOCK_LEN> for Camellia_256 {
    fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Camellia_256::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Camellia::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Camellia::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Camellia::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        Camellia::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        Camellia::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        Camellia::decrypt_4blocks(self, blocks)
    }
}

impl<P: CamelliaParams> core::fmt::Debug for Camellia<P> {
    /// Prints the algorithm name only. The subkeys are secret and are never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(P::ALG_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_sizes_are_exactly_the_subkeys() {
        // The "Memory Usage" table in the crate docs quotes these: 26 or 34 subkeys of 64 bits and
        // nothing else -- no direction flag, no round counter, no initialised marker.
        assert_eq!(size_of::<Camellia_128>(), 208);
        assert_eq!(size_of::<Camellia_192>(), 272);
        assert_eq!(size_of::<Camellia_256>(), 272);
        assert_eq!(size_of::<Camellia_128>(), size_of::<[u64; 4 + 18 + 4]>());
        assert_eq!(size_of::<Camellia_256>(), size_of::<[u64; 4 + 24 + 6]>());
    }

    #[test]
    fn test_alg_names_and_strengths() {
        assert_eq!(<Camellia_128 as Algorithm>::ALG_NAME, "Camellia-128");
        assert_eq!(<Camellia_192 as Algorithm>::ALG_NAME, "Camellia-192");
        assert_eq!(<Camellia_256 as Algorithm>::ALG_NAME, "Camellia-256");
        assert_eq!(
            <Camellia_128 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(Camellia128Params::KEY_LEN)
        );
        assert_eq!(
            <Camellia_192 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(Camellia192Params::KEY_LEN)
        );
        assert_eq!(
            <Camellia_256 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(Camellia256Params::KEY_LEN)
        );
    }

    #[test]
    fn test_lanes_constant() {
        // The docs and the two-block override both assume four lanes: four 8-byte F-function
        // inputs fill the 32 byte positions of the eight u32 planes.
        assert_eq!(LANES, 4);
        assert_eq!(LANES * 8, 32);
    }

    #[test]
    fn test_decryption_subkey_swap_is_section_2_3_3() {
        // kw1 <-> kw3, kw2 <-> kw4; k_i <-> k_{n+1-i}; ke_i <-> ke_{m+1-i}. The table below is
        // the RFC's, and the closures in decrypt_4blocks must implement exactly it.
        let swap_kw = |i: usize| [3, 4, 1, 2][i - 1];
        assert_eq!([swap_kw(1), swap_kw(2), swap_kw(3), swap_kw(4)], [3, 4, 1, 2]);
        // 128-bit key: k1 <-> k18 ... k9 <-> k10; ke1 <-> ke4, ke2 <-> ke3.
        let n = Camellia128Params::ROUNDS;
        let swapped: [usize; 18] = core::array::from_fn(|i| n + 1 - (i + 1));
        let expected: [usize; 18] = core::array::from_fn(|i| 18 - i);
        assert_eq!(swapped, expected);
        let m = Camellia128Params::FL_KEYS;
        let swapped: [usize; 4] = core::array::from_fn(|i| m + 1 - (i + 1));
        assert_eq!(swapped, [4, 3, 2, 1]);
        // 192- or 256-bit key: k1 <-> k24 ... k12 <-> k13; ke1 <-> ke6, ke2 <-> ke5, ke3 <-> ke4.
        let n = Camellia256Params::ROUNDS;
        assert_eq!(n + 1 - 1, 24);
        assert_eq!(n + 1 - 12, 13);
        let m = Camellia256Params::FL_KEYS;
        let swapped: [usize; 6] = core::array::from_fn(|i| m + 1 - (i + 1));
        assert_eq!(swapped, [6, 5, 4, 3, 2, 1]);
    }
}
