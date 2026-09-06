//! CIPHER() and INVCIPHER() (FIPS 197 Sec 5.1 and Sec 5.3), and the public engine types.

use crate::bitslice::{Block, Planes, pack, unpack};
use crate::round::{add_round_key, inv_mix_columns, inv_shift_rows, mix_columns, shift_rows};
use crate::sbox::{inv_sbox, sbox};
use crate::schedule::{Aes128Params, Aes192Params, Aes256Params, AesParams, expand, round_key};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, BlockPermutation, SecurityStrength};
use bouncycastle_utils::secret::Secret;

/// The AES block length in bytes: 16 (FIPS 197 Sec 3.4, `Nb` = 4 words).
pub const BLOCK_LEN: usize = 16;

/// The AES keyed permutation, parameterised by key length.
///
/// Use the aliases [`Aes128`], [`Aes192`] and [`Aes256`] rather than naming this directly.
/// `P` is sealed to the three parameter sets of FIPS 197 Sec 6.1, so no fourth instantiation
/// exists.
///
/// The only state is the key schedule, held in a [`Secret`] so that it is zeroized on drop and
/// redacted from `Debug`. There is no direction flag and no initialisation state: both directions
/// work from the same schedule (see [`Aes::decrypt_blocks2`]), and a constructed value is always
/// ready to use, so there is no `init()` or `reset()`.
pub struct Aes<P: AesParams> {
    schedule: Secret<P::Schedule>,
}

/// AES-128: 16-byte key, 10 rounds (FIPS 197 Sec 6.1).
pub type Aes128 = Aes<Aes128Params>;
/// AES-192: 24-byte key, 12 rounds (FIPS 197 Sec 6.1).
pub type Aes192 = Aes<Aes192Params>;
/// AES-256: 32-byte key, 14 rounds (FIPS 197 Sec 6.1).
pub type Aes256 = Aes<Aes256Params>;

impl<P: AesParams> Aes<P> {
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

    /// CIPHER() on two blocks at once (FIPS 197 Sec 5.1, Algorithm 1).
    ///
    /// Algorithm 1 line by line: line 3 is the initial ADDROUNDKEY() with `w[0..3]`; lines 4-9 are
    /// the `Nr - 1` full rounds; lines 10-13 are the final round, which omits MIXCOLUMNS().
    fn encrypt2(&self, q: &mut Planes) {
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

    /// INVCIPHER() on two blocks at once (FIPS 197 Sec 5.3, Algorithm 3).
    ///
    /// This is the **straight** inverse cipher of Algorithm 3, not the equivalent inverse cipher
    /// of Sec 5.3.5. That matters: Algorithm 3 applies INVMIXCOLUMNS() *after* ADDROUNDKEY(),
    /// which lets it use the ordinary key schedule, whereas Sec 5.3.5 reorders the round to put
    /// the two the other way round and needs a separate schedule with INVMIXCOLUMNS() applied to
    /// each round key (Algorithm 5, KEYEXPANSIONEIC()).
    ///
    /// Following Algorithm 3 is therefore what allows one [`Aes`] value to encrypt *and* decrypt
    /// from a single stored schedule, with no second copy and no transformation at construction
    /// time -- which is the whole reason this crate can offer both directions at 176-240 bytes of
    /// state.
    ///
    /// Line by line: line 3 is ADDROUNDKEY() with the last round key; lines 4-9 are the
    /// `Nr - 1` full inverse rounds; lines 10-13 are the final one, which omits INVMIXCOLUMNS().
    fn decrypt2(&self, q: &mut Planes) {
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

    /// Encrypts two blocks in place.
    ///
    /// This is the natural unit of work: the bit-sliced state holds two blocks, so two blocks cost
    /// almost exactly what one does. Prefer this over two [`Aes::encrypt_block`] calls whenever
    /// two blocks are available and independent -- which, for a mode of operation, means CTR, or
    /// the decryption direction of CBC and CFB, but *not* CBC encryption, whose blocks are
    /// serially dependent.
    ///
    /// Infallible: a constructed [`Aes`] is always usable and every input length is fixed.
    pub fn encrypt_blocks2(&self, blocks: &mut [Block; 2]) {
        let mut q = pack(&blocks[0], &blocks[1]);
        self.encrypt2(&mut q);
        let (a, b) = blocks.split_at_mut(1);
        unpack(&q, &mut a[0], &mut b[0]);
    }

    /// Decrypts two blocks in place. See [`Aes::encrypt_blocks2`].
    pub fn decrypt_blocks2(&self, blocks: &mut [Block; 2]) {
        let mut q = pack(&blocks[0], &blocks[1]);
        self.decrypt2(&mut q);
        let (a, b) = blocks.split_at_mut(1);
        unpack(&q, &mut a[0], &mut b[0]);
    }

    /// Encrypts one block in place.
    ///
    /// The bit-sliced state always holds two blocks, so a single-block call duplicates the block
    /// into both halves and discards one result: it does twice the necessary work. Use
    /// [`Aes::encrypt_blocks2`] where two blocks are available.
    ///
    /// Duplicating the block costs exactly what filling the unused half with zeros would, and it
    /// buys a free self-check: the two halves must come out equal, which `debug_assert` verifies.
    /// That is the whole reason for the choice -- it is not a security property, since the unused
    /// half is never returned either way.
    pub fn encrypt_block(&self, block: &mut Block) {
        let mut q = pack(block, block);
        self.encrypt2(&mut q);
        let mut discard = [0u8; BLOCK_LEN];
        unpack(&q, block, &mut discard);
        debug_assert_eq!(*block, discard, "the two interleaved halves must agree");
    }

    /// Decrypts one block in place. See [`Aes::encrypt_block`] for the two-blocks-at-once caveat.
    pub fn decrypt_block(&self, block: &mut Block) {
        let mut q = pack(block, block);
        self.decrypt2(&mut q);
        let mut discard = [0u8; BLOCK_LEN];
        unpack(&q, block, &mut discard);
        debug_assert_eq!(*block, discard, "the two interleaved halves must agree");
    }
}

// The three constructors and `Algorithm` impls below are written out longhand rather than
// generated with `macro_rules!`: `cargo mutants` cannot see into macro bodies, so a macro would
// hide the key checks and the security-strength constants from mutation testing (see CLAUDE.md).
// Each `new` differs only in the `KeyMaterial<N>` capacity it accepts, which is what makes a
// wrong-length key a compile error at the call site rather than a runtime error.

impl Aes128 {
    /// Expands a 16-byte key into an AES-128 schedule.
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not [`KeyType::SymmetricCipherKey`].
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    pub fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<Aes128Params>(key.ref_to_bytes()) })
    }
}

impl Aes192 {
    /// Expands a 24-byte key into an AES-192 schedule. See [`Aes128::new`] for the error cases.
    pub fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<Aes192Params>(key.ref_to_bytes()) })
    }
}

impl Aes256 {
    /// Expands a 32-byte key into an AES-256 schedule. See [`Aes128::new`] for the error cases.
    pub fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<Aes256Params>(key.ref_to_bytes()) })
    }
}

impl Algorithm for Aes128 {
    const ALG_NAME: &'static str = Aes128Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Algorithm for Aes192 {
    const ALG_NAME: &'static str = Aes192Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl Algorithm for Aes256 {
    const ALG_NAME: &'static str = Aes256Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

// The three `BlockPermutation` impls are one-line delegations to the inherent methods above. They
// are written out longhand rather than generated, for the `cargo mutants` reason given above.
//
// Each overrides `encrypt_blocks2` / `decrypt_blocks2`, because a pair of blocks is exactly what
// the bit-sliced state holds: the pair form costs barely more than one block, where the default
// (two single-block calls) would do four blocks' worth of work.

impl BlockPermutation<16, BLOCK_LEN> for Aes128 {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Aes128::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Aes::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Aes::decrypt_block(self, block)
    }
    fn encrypt_blocks2(&self, blocks: &mut [Block; 2]) {
        Aes::encrypt_blocks2(self, blocks)
    }
    fn decrypt_blocks2(&self, blocks: &mut [Block; 2]) {
        Aes::decrypt_blocks2(self, blocks)
    }
}

impl BlockPermutation<24, BLOCK_LEN> for Aes192 {
    fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Aes192::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Aes::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Aes::decrypt_block(self, block)
    }
    fn encrypt_blocks2(&self, blocks: &mut [Block; 2]) {
        Aes::encrypt_blocks2(self, blocks)
    }
    fn decrypt_blocks2(&self, blocks: &mut [Block; 2]) {
        Aes::decrypt_blocks2(self, blocks)
    }
}

impl BlockPermutation<32, BLOCK_LEN> for Aes256 {
    fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Aes256::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        Aes::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        Aes::decrypt_block(self, block)
    }
    fn encrypt_blocks2(&self, blocks: &mut [Block; 2]) {
        Aes::encrypt_blocks2(self, blocks)
    }
    fn decrypt_blocks2(&self, blocks: &mut [Block; 2]) {
        Aes::decrypt_blocks2(self, blocks)
    }
}

impl<P: AesParams> core::fmt::Debug for Aes<P> {
    /// Prints the algorithm name only. The key schedule is secret and is never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(P::ALG_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_sizes_match_the_documented_memory_table() {
        // The "Memory Usage" table in the crate docs quotes these, and the whole point of the
        // crate is that they are this small: 4 * (Nr + 1) words of schedule, nothing else, and no
        // tables anywhere. If the representation grows, the docs are wrong -- fix both.
        assert_eq!(size_of::<Aes128>(), 176, "AES-128: 4 * (10 + 1) words");
        assert_eq!(size_of::<Aes192>(), 208, "AES-192: 4 * (12 + 1) words");
        assert_eq!(size_of::<Aes256>(), 240, "AES-256: 4 * (14 + 1) words");
    }

    #[test]
    fn test_engine_size_is_exactly_the_schedule() {
        // No round counter, no direction flag, no initialised marker: the schedule is all there
        // is, which is what makes both directions available from one value at no extra cost.
        assert_eq!(size_of::<Aes128>(), size_of::<<Aes128Params as AesParams>::Schedule>());
        assert_eq!(size_of::<Aes192>(), size_of::<<Aes192Params as AesParams>::Schedule>());
        assert_eq!(size_of::<Aes256>(), size_of::<<Aes256Params as AesParams>::Schedule>());
    }

    #[test]
    fn test_alg_names() {
        assert_eq!(<Aes128 as Algorithm>::ALG_NAME, "AES-128");
        assert_eq!(<Aes192 as Algorithm>::ALG_NAME, "AES-192");
        assert_eq!(<Aes256 as Algorithm>::ALG_NAME, "AES-256");
    }

    #[test]
    fn test_max_security_strength_matches_the_key_length() {
        assert_eq!(
            <Aes128 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(Aes128Params::KEY_LEN)
        );
        assert_eq!(
            <Aes192 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(Aes192Params::KEY_LEN)
        );
        assert_eq!(
            <Aes256 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(Aes256Params::KEY_LEN)
        );
    }
}
