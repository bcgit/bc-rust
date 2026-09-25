//! The public engine types, and the encryption and decryption entry points (RFC 5794 Sec 2.3).

use crate::round::{RoundKey, diffuse, rounds};
use crate::schedule::{ARIA128Params, ARIA192Params, ARIA256Params, ARIAParams, ek, expand};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, ElectronicCodeBook, SecurityStrength};
use bouncycastle_utils::secret::Secret;

/// The ARIA block length in bytes: 16 (RFC 5794 Sec 1.1, "encrypts 128-bit blocks").
pub const BLOCK_LEN: usize = 16;

/// One ARIA block.
pub type Block = [u8; BLOCK_LEN];

/// The number of blocks the bit-sliced S-box circuits substitute at once. See
/// [`ARIA::encrypt_4blocks`].
pub const LANES: usize = 4;

/// The ARIA keyed permutation, parameterised by key length, constant-time.
///
/// Use the aliases [`ARIA_128`], [`ARIA_192`] and [`ARIA_256`] rather than naming this directly. `P`
/// is sealed to the three parameter sets of RFC 5794, so no fourth instantiation exists.
///
/// The only state is the encryption round keys, held in a [`Secret`] so that they are zeroized on
/// drop and redacted from `Debug`. There is no direction flag and no initialisation state:
/// decryption uses the same rounds with the decryption round keys of Sec 2.2 (`dk1 = ek{n+1}`,
/// `dk{i} = A(ek{n+2-i})`, `dk{n+1} = ek1`), which are derived from the stored encryption keys as
/// each round needs them, so both directions work from one stored schedule and a constructed
/// value is always ready to use -- there is no `init()` or `reset()`, unlike an engine that lays
/// the keys out differently depending on the direction it is initialised for.
pub struct ARIA<P: ARIAParams> {
    schedule: Secret<P::Schedule>,
}

/// ARIA-128: 16-byte key, 12 rounds (RFC 5794 Sec 2.3.1.1).
#[allow(non_camel_case_types)]
pub type ARIA_128 = ARIA<ARIA128Params>;
/// ARIA-192: 24-byte key, 14 rounds (RFC 5794 Sec 2.3.1.2).
#[allow(non_camel_case_types)]
pub type ARIA_192 = ARIA<ARIA192Params>;
/// ARIA-256: 32-byte key, 16 rounds (RFC 5794 Sec 2.3.1.3).
#[allow(non_camel_case_types)]
pub type ARIA_256 = ARIA<ARIA256Params>;

impl<P: ARIAParams> ARIA<P> {
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
                "ARIA requires a key of type KeyType::SymmetricCipherKey.",
            )
            .into());
        }
        if key.key_len() != P::KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }
        if key.security_strength() < SecurityStrength::from_bytes(P::KEY_LEN) {
            return Err(KeyMaterialError::SecurityStrength(
                "The provided key has a lower security strength than the ARIA key length implies.",
            )
            .into());
        }
        Ok(())
    }

    /// Encrypts four independent blocks in place (Sec 2.3.1): the encryption round keys
    /// `ek1 .. ek{n+1}` in order.
    ///
    /// This is the natural unit of work. Each S-box circuit substitutes 16 bytes per pass and a
    /// substitution layer sends four bytes of each block through each of the four S-boxes, so four
    /// blocks fill the four passes exactly; fewer blocks cost the same. Modes whose blocks are
    /// independent -- CTR, and the decryption direction of CBC and CFB -- reach it through
    /// the `ElectronicCodeBook` four-block batch; CBC encryption cannot, since its blocks
    /// are serially dependent.
    ///
    /// Infallible: a constructed [`ARIA`] is always usable and every input length is fixed.
    pub fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        let s = self.schedule.as_ref();
        rounds(blocks, P::ROUNDS, |i| ek(s, i));
    }

    /// Decrypts four independent blocks in place (Sec 2.3.2): "the same as the encryption process
    /// except that encryption round keys are replaced by decryption round keys", with Sec 2.2's
    /// `dk1 = ek{n+1}`, `dk{i} = A(ek{n+2-i})` for `i = 2 .. n`, and `dk{n+1} = ek1`, each derived
    /// from the stored encryption keys as the round needs it. See [`ARIA::encrypt_4blocks`].
    pub fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        let s = self.schedule.as_ref();
        let n = P::ROUNDS;
        rounds(blocks, n, |i| -> RoundKey {
            if i == 1 {
                ek(s, n + 1)
            } else if i == n + 1 {
                ek(s, 1)
            } else {
                let mut k = ek(s, n + 2 - i);
                diffuse(&mut k);
                k
            }
        });
    }

    /// Encrypts one block in place.
    ///
    /// The circuits always process four lanes, so a single-block call puts the block in every
    /// lane and discards three results: it does four blocks' worth of work. Use
    /// [`ARIA::encrypt_4blocks`] where independent blocks are
    /// available.
    ///
    /// Filling the spare lanes with copies costs exactly what zeros would, and buys a free
    /// self-check: all four lanes must agree, which `debug_assert` verifies. It is not a security
    /// property; the spare lanes are never returned either way.
    pub(crate) fn encrypt_block(&self, block: &mut Block) {
        let mut lanes = [*block; LANES];
        self.encrypt_4blocks(&mut lanes);
        debug_assert!(lanes.iter().all(|b| *b == lanes[0]), "all lanes must agree");
        *block = lanes[0];
    }

    /// Decrypts one block in place. See [`ElectronicCodeBook::encrypt_block`] for the four-lane caveat.
    pub(crate) fn decrypt_block(&self, block: &mut Block) {
        let mut lanes = [*block; LANES];
        self.decrypt_4blocks(&mut lanes);
        debug_assert!(lanes.iter().all(|b| *b == lanes[0]), "all lanes must agree");
        *block = lanes[0];
    }

    /// Encrypts two blocks in place, in lanes 0 and 1; the other two lanes carry copies of the
    /// first and are discarded. Two blocks for the price of four, but twice as good as two
    /// [`ElectronicCodeBook::encrypt_block`] calls, which is why the trait method uses it.
    pub(crate) fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        let mut lanes = [blocks[0]; LANES];
        lanes[1] = blocks[1];
        self.encrypt_4blocks(&mut lanes);
        *blocks = [lanes[0], lanes[1]];
    }

    /// Decrypts two blocks in place. See [`ElectronicCodeBook::encrypt_2blocks`].
    pub(crate) fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        let mut lanes = [blocks[0]; LANES];
        lanes[1] = blocks[1];
        self.decrypt_4blocks(&mut lanes);
        *blocks = [lanes[0], lanes[1]];
    }
}

impl ARIA_128 {
    /// Expands a 16-byte key into the ARIA-128 round keys (Sec 2.2).
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not [`KeyType::SymmetricCipherKey`].
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    pub(crate) fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<ARIA128Params>(key.ref_to_bytes()) })
    }
}

impl ARIA_192 {
    /// Expands a 24-byte key into the ARIA-192 round keys. See [`ElectronicCodeBook::new`] for the error
    /// cases.
    pub(crate) fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<ARIA192Params>(key.ref_to_bytes()) })
    }
}

impl ARIA_256 {
    /// Expands a 32-byte key into the ARIA-256 round keys. See [`ElectronicCodeBook::new`] for the error
    /// cases.
    pub(crate) fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        Self::validate(key)?;
        Ok(Self { schedule: expand::<ARIA256Params>(key.ref_to_bytes()) })
    }
}

impl Algorithm for ARIA_128 {
    const ALG_NAME: &'static str = ARIA128Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Algorithm for ARIA_192 {
    const ALG_NAME: &'static str = ARIA192Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl Algorithm for ARIA_256 {
    const ALG_NAME: &'static str = ARIA256Params::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

// The three `ElectronicCodeBook` impls are one-line delegations to the inherent methods above,
// written out longhand rather than generated because `cargo mutants` cannot see into macro bodies.
//
// Each fills the lanes in its pair and four-block methods: two blocks in two of the four lanes
// cost one set of circuit passes per round where two single-block calls would cost two, and four
// blocks are one full pass where two pair calls would be two.

impl ElectronicCodeBook<16, BLOCK_LEN> for ARIA_128 {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        ARIA_128::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        ARIA::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        ARIA::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        ARIA::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        ARIA::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        ARIA::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        ARIA::decrypt_4blocks(self, blocks)
    }
}

impl ElectronicCodeBook<24, BLOCK_LEN> for ARIA_192 {
    fn new(key: &KeyMaterial<24>) -> Result<Self, SymmetricCipherError> {
        ARIA_192::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        ARIA::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        ARIA::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        ARIA::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        ARIA::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        ARIA::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        ARIA::decrypt_4blocks(self, blocks)
    }
}

impl ElectronicCodeBook<32, BLOCK_LEN> for ARIA_256 {
    fn new(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        ARIA_256::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        ARIA::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        ARIA::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        ARIA::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        ARIA::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        ARIA::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        ARIA::decrypt_4blocks(self, blocks)
    }
}

impl<P: ARIAParams> core::fmt::Debug for ARIA<P> {
    /// Prints the algorithm name only. The round keys are secret and are never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(P::ALG_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_sizes_are_exactly_the_round_keys() {
        // The "Memory Usage" table in the crate docs quotes these: 13, 15 or 17 round keys of 16
        // bytes and nothing else -- no direction flag, no round counter, no initialised marker.
        assert_eq!(size_of::<ARIA_128>(), 208);
        assert_eq!(size_of::<ARIA_192>(), 240);
        assert_eq!(size_of::<ARIA_256>(), 272);
    }

    #[test]
    fn test_alg_names_and_strengths() {
        assert_eq!(<ARIA_128 as Algorithm>::ALG_NAME, "ARIA-128");
        assert_eq!(<ARIA_192 as Algorithm>::ALG_NAME, "ARIA-192");
        assert_eq!(<ARIA_256 as Algorithm>::ALG_NAME, "ARIA-256");
        assert_eq!(
            <ARIA_128 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(ARIA128Params::KEY_LEN)
        );
        assert_eq!(
            <ARIA_192 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(ARIA192Params::KEY_LEN)
        );
        assert_eq!(
            <ARIA_256 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(ARIA256Params::KEY_LEN)
        );
    }

    #[test]
    fn test_lanes_constant() {
        // The docs and the two-block override both assume four lanes: four 4-byte class words
        // fill the 16 byte positions of the u16 planes.
        assert_eq!(LANES, 4);
        assert_eq!(LANES * 4, 16);
    }

    #[test]
    fn test_decryption_key_order_is_section_2_2() {
        // dk1 = ek{n+1}, dk{i} = A(ek{n+2-i}) for i in 2..=n, dk{n+1} = ek1: check the index map
        // the closure in decrypt_4blocks implements, for n = 12.
        let n = 12;
        let src = |i: usize| {
            if i == 1 {
                n + 1
            } else if i == n + 1 {
                1
            } else {
                n + 2 - i
            }
        };
        assert_eq!(src(1), 13);
        assert_eq!(src(2), 12);
        assert_eq!(src(12), 2);
        assert_eq!(src(13), 1);
    }

    /// Appendix A.1, 128-bit key: the intermediate round values `P1 .. P11` and the ciphertext,
    /// through a literal one-round-at-a-time transcription of Sec 2.3.1.1, which the four-lane
    /// `rounds` must agree with.
    #[test]
    fn test_appendix_a_1_intermediate_values() {
        use crate::round::{fe1, fo1};
        let key_bytes: [u8; 16] = core::array::from_fn(|i| i as u8);
        let key =
            KeyMaterial::<16>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey).unwrap();
        let aria = ARIA_128::new(&key).unwrap();
        let s = aria.schedule.as_ref();
        let to_state = |v: u128| -> RoundKey {
            let b = v.to_be_bytes();
            let (w, _) = b.as_chunks::<4>();
            core::array::from_fn(|i| u32::from_be_bytes(w[i]))
        };
        let expected: [u128; 11] = [
            0x7fc7f12befd0a0791de87fa96b469f52,
            0xac8de17e49f7c5117618993162b189e9,
            0xc3e8d59ec2e62d5249ca2741653cb7dd,
            0x5d4aebb165e141ff759f669e1e85cc45,
            0x7806e469f68874c5004b5f4a046bbcfa,
            0x110f93c9a630cdd51f97d2202413345a,
            0xe054428ef088fef97928241cd3be499e,
            0x5734f38ea1ca3ddd102e71f95e1d5f97,
            0x4903325be3e500cccd52fba4354a39ae,
            0xcb8c508e2c4f87880639dc896d25ec9d,
            0xe7e0d2457ed73d23d481424095afdca0,
        ];
        let mut p = to_state(0x00112233445566778899aabbccddeeff);
        for (i, want) in expected.iter().enumerate() {
            let round = i + 1;
            p = if round % 2 == 1 { fo1(p, &ek(s, round)) } else { fe1(p, &ek(s, round)) };
            assert_eq!(p, to_state(*want), "P{round}");
        }
        // Round 12: C = SL2(P11 ^ ek12) ^ ek13, via the engine on the original plaintext.
        let mut block = 0x00112233445566778899aabbccddeeffu128.to_be_bytes();
        aria.encrypt_block(&mut block);
        assert_eq!(block, 0xd718fbd6ab644c739da95f3be6451778u128.to_be_bytes());
    }
}
