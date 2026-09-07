//! The encryption and decryption algorithm (GB/T 32907-2016, as described in
//! draft-ribose-cfrg-sm4-10 Sec 6 and Sec 7), and the public engine type.

use crate::sbox::tau;
use crate::schedule::{RoundKeys, expand};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, ElectronicCodeBook, SecurityStrength};
use bouncycastle_utils::secret::Secret;

/// The SM4 block length in bytes: 16 (Sec 4, "block size of 128 bits").
pub const BLOCK_LEN: usize = 16;

/// The SM4 key length in bytes: 16 (Sec 4, "key length of 128 bits"). There is only one.
pub const KEY_LEN: usize = 16;

/// One SM4 block.
pub type Block = [u8; BLOCK_LEN];

/// The number of blocks the bit-sliced S-box substitutes at once. See [`SM4::encrypt_4blocks`].
pub const LANES: usize = 4;

/// The SM4 keyed permutation, constant-time.
///
/// The only state is the 32 round keys, held in a [`Secret`] so that they are zeroized on drop and
/// redacted from `Debug`. There is no direction flag and no initialisation state: decryption is
/// encryption with the round keys read backwards (Sec 7.2), so both directions work from the same
/// stored schedule, and a constructed value is always ready to use -- there is no `init()` or
/// `reset()`. This is the one structural departure from BC Java's `SM4Engine`, which expands the
/// key in the order its `init(forEncryption, ..)` call asks for.
pub struct SM4 {
    rk: Secret<RoundKeys>,
}

impl SM4 {
    /// Checks a key is fit to use before it is expanded.
    ///
    /// The key must be tagged [`KeyType::SymmetricCipherKey`], must be exactly [`KEY_LEN`] bytes
    /// of the buffer, and must carry a [`SecurityStrength`] of at least 128 bits -- which is what a
    /// 16-byte key from a correctly-instantiated RNG or KDF will have. The checks exist to catch a
    /// key that arrived from somewhere it should not have: a seed reused as a cipher key, or a
    /// buffer holding material only derived at a lower strength.
    ///
    /// Returns the key bytes as a fixed-size array, so that the length check and the conversion
    /// the schedule needs are one and the same operation.
    fn validate(key: &KeyMaterial<KEY_LEN>) -> Result<&[u8; KEY_LEN], SymmetricCipherError> {
        if key.key_type() != KeyType::SymmetricCipherKey {
            return Err(KeyMaterialError::InvalidKeyType(
                "SM4 requires a key of type KeyType::SymmetricCipherKey.",
            )
            .into());
        }
        // `ref_to_bytes()` is the *populated* part of the buffer, `key_len()` bytes long. The
        // conversion succeeds exactly when that is the whole 16 bytes, so it is the length check.
        let bytes: &[u8; KEY_LEN] =
            key.ref_to_bytes().try_into().map_err(|_| KeyMaterialError::InvalidLength)?;
        if key.security_strength() < SecurityStrength::from_bytes(KEY_LEN) {
            return Err(KeyMaterialError::SecurityStrength(
                "The provided key has a lower security strength than the SM4 key length implies.",
            )
            .into());
        }
        Ok(bytes)
    }

    /// Expands a 16-byte key into the 32 round keys (Sec 7.3).
    ///
    /// # Errors
    /// * [`KeyMaterialError::InvalidKeyType`] if the key is not [`KeyType::SymmetricCipherKey`].
    /// * [`KeyMaterialError::InvalidLength`] if the key is not 16 bytes long.
    /// * [`KeyMaterialError::SecurityStrength`] if the key carries a strength below 128 bits.
    pub(crate) fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        let bytes = Self::validate(key)?;
        Ok(Self { rk: expand(bytes) })
    }

    /// Encrypts four independent blocks in place (Sec 7.1): the round keys in the order
    /// `rk_0, ..., rk_31`.
    ///
    /// This is the natural unit of work. The S-box circuit substitutes 16 bytes per pass and a
    /// round substitutes four bytes per block, so four blocks fill it exactly; fewer blocks cost
    /// the same. Modes whose blocks are independent -- CTR, and the decryption direction of CBC
    /// and CFB -- reach it as the `ElectronicCodeBook` four-block batch; CBC encryption cannot,
    /// since its blocks are serially dependent.
    ///
    /// Infallible: a constructed [`SM4`] is always usable and every input length is fixed.
    pub fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        rounds(blocks, |i| self.rk[i]);
    }

    /// Decrypts four independent blocks in place (Sec 7.2): "an identical process as encryption,
    /// with the only difference the order of the round key sequence", `rk_31, rk_30, ..., rk_0`.
    /// See [`SM4::encrypt_4blocks`].
    pub fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        rounds(blocks, |i| self.rk[31 - i]);
    }

    /// Encrypts one block in place.
    ///
    /// The circuit always processes four lanes, so a single-block call puts the block in every
    /// lane and discards three results: it does four blocks' worth of work. Use
    /// [`SM4::encrypt_4blocks`] where independent blocks are
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
    /// [`ElectronicCodeBook::encrypt_block`] calls, which is why the trait method is overridden.
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

/// `L(B) = B xor (B <<< 2) xor (B <<< 10) xor (B <<< 18) xor (B <<< 24)` (Sec 6.2.2).
#[inline(always)]
fn l(b: u32) -> u32 {
    b ^ b.rotate_left(2) ^ b.rotate_left(10) ^ b.rotate_left(18) ^ b.rotate_left(24)
}

/// The 32 rounds and the reverse transformation `R` (Sec 7.1) on four blocks at once, with
/// `rk(i)` supplying the round key for round `i` -- `rk_i` for encryption, `rk_{31-i}` for
/// decryption (Sec 7.2).
///
/// Sec 7.1 (a): for `i = 0, 1, ..., 31`, `X_{i+4} = F(X_i, X_{i+1}, X_{i+2}, X_{i+3}, rk_i)` with
/// `F(X_0, X_1, X_2, X_3, rk) = X_0 xor T(X_1 xor X_2 xor X_3 xor rk)` (Sec 6.1) and
/// `T(.) = L(tau(.))` (Sec 6.2). Each round consumes the oldest of four live words and produces
/// one new one. Instead of sliding the window, the *roles* of the four slots rotate: in round `i`
/// the oldest word is in slot `i mod 4`, and after four rounds the slots are back in their
/// starting roles -- BC Java's `F0`/`F1`/`F2`/`F3` structure, written as one loop. The literal
/// one-round-at-a-time form is in `tests::literal_rounds`, which pins every intermediate `X_i` of
/// Appendix A.1.1 and A.1.4 and agrees with this function.
///
/// The four blocks are processed together only because `tau` is: the argument
/// `X_{i+1} xor X_{i+2} xor X_{i+3} xor rk_i` is formed per block, all four go through the
/// circuit in one pass, and `L` and the final XOR are again per block. The blocks never mix.
///
/// Sec 7.1 (b): `(Y_0, Y_1, Y_2, Y_3) = R(X_32, X_33, X_34, X_35) = (X_35, X_34, X_33, X_32)`.
/// 32 is a multiple of 4, so after the loop slot `s` holds `X_{32+s}` and the output is the slots
/// in reverse order.
///
/// Words are big-endian, as the worked examples require: Appendix A.1.2 shows the plaintext
/// `01 23 45 67 ...` recovered as `X_4 = 01234567`.
fn rounds(blocks: &mut [Block; LANES], rk: impl Fn(usize) -> u32) {
    // x[b] = (X_0, X_1, X_2, X_3) of block b.
    let mut x = [[0u32; 4]; LANES];
    for (xb, block) in x.iter_mut().zip(blocks.iter()) {
        for (word, bytes) in xb.iter_mut().zip(block.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*bytes);
        }
    }

    // (a) 32 rounds.
    for i in 0..32 {
        let (s0, s1, s2, s3) = (i % 4, (i + 1) % 4, (i + 2) % 4, (i + 3) % 4);
        let k = rk(i);

        // The argument of T, one word per block.
        let mut a = [0u32; LANES];
        for (ab, xb) in a.iter_mut().zip(x.iter()) {
            *ab = xb[s1] ^ xb[s2] ^ xb[s3] ^ k;
        }
        // tau on all four words at once, then L and the XOR into X_i per block.
        tau(&mut a);
        for (ab, xb) in a.iter().zip(x.iter_mut()) {
            xb[s0] ^= l(*ab);
        }
    }

    // (b) reverse transformation R.
    for (xb, block) in x.iter().zip(blocks.iter_mut()) {
        for (word, bytes) in xb.iter().rev().zip(block.as_chunks_mut::<4>().0) {
            *bytes = word.to_be_bytes();
        }
    }
}

impl Algorithm for SM4 {
    /// `"SM4"`, as BC Java's `SM4Engine.getAlgorithmName()` reports it.
    const ALG_NAME: &'static str = "SM4";
    /// 128 bits: the one key length SM4 has (Sec 4). Sec 12 positions it as "an alternative to
    /// AES-128".
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

/// One-line delegations to the inherent methods. The pair and four-block methods are overridden:
/// two blocks in two of the four lanes cost one circuit pass per round where the default would
/// cost two, and four blocks are one full pass where the default (two pair calls) would be two.
impl ElectronicCodeBook<KEY_LEN, BLOCK_LEN> for SM4 {
    fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        SM4::new(key)
    }
    fn encrypt_block(&self, block: &mut Block) {
        SM4::encrypt_block(self, block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        SM4::decrypt_block(self, block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        SM4::encrypt_2blocks(self, blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        SM4::decrypt_2blocks(self, blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        SM4::encrypt_4blocks(self, blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; LANES]) {
        SM4::decrypt_4blocks(self, blocks)
    }
}

impl core::fmt::Debug for SM4 {
    /// Prints the algorithm name only. The round keys are secret and are never formatted.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(Self::ALG_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `T(.) = L(tau(.))` on one word (Sec 6.2), via the four-lane `tau` with the word in every
    /// lane.
    fn t(z: u32) -> u32 {
        let mut words = [z; LANES];
        tau(&mut words);
        assert!(words.iter().all(|&w| w == words[0]), "lanes must agree");
        l(words[0])
    }

    /// The round function `F(X_0, X_1, X_2, X_3, rk) = X_0 xor T(X_1 xor X_2 xor X_3 xor rk)`
    /// (Sec 6.1), on one block.
    fn f(x0: u32, x1: u32, x2: u32, x3: u32, rk: u32) -> u32 {
        x0 ^ t(x1 ^ x2 ^ x3 ^ rk)
    }

    /// Sec 7.1 (a) written literally, one round per step on one block, returning all of
    /// `X_0 .. X_35`.
    ///
    /// This is the reference the slot-rotating, four-lane [`rounds`] is checked against, and it
    /// is what lets the per-round `X_i` columns of Appendix A.1 be pinned rather than only the
    /// final ciphertext.
    fn literal_rounds(block: &Block, rk: &RoundKeys) -> [u32; 36] {
        let mut x = [0u32; 36];
        for (i, w) in block.as_chunks::<4>().0.iter().enumerate() {
            x[i] = u32::from_be_bytes(*w);
        }
        for i in 0..32 {
            x[i + 4] = f(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i]);
        }
        x
    }

    fn check_example(
        key: &[u8; 16],
        plaintext: &Block,
        expected_x: &[u32; 32],
        ciphertext: &Block,
    ) {
        let sm4 = SM4::new(
            &KeyMaterial::<16>::from_bytes_as_type(key, KeyType::SymmetricCipherKey).unwrap(),
        )
        .unwrap();

        // Every intermediate round output X_4 .. X_35 against the appendix.
        let x = literal_rounds(plaintext, &sm4.rk);
        for (i, want) in expected_x.iter().enumerate() {
            assert_eq!(x[i + 4], *want, "X_{}", i + 4);
        }

        // R(X_32, X_33, X_34, X_35) = (X_35, X_34, X_33, X_32) is the ciphertext.
        let mut from_literal = [0u8; 16];
        for (j, word) in [x[35], x[34], x[33], x[32]].iter().enumerate() {
            from_literal[4 * j..4 * j + 4].copy_from_slice(&word.to_be_bytes());
        }
        assert_eq!(&from_literal, ciphertext, "literal Sec 7.1 must give the ciphertext");

        // ...and the slot-rotating four-lane form agrees with the literal one, with the block in
        // any lane and unrelated blocks in the others.
        let lanes: [Block; LANES] = core::array::from_fn(|i| [i as u8 * 17 + 1; 16]);
        let mut alone = lanes;
        for b in alone.iter_mut() {
            sm4.encrypt_block(b);
        }
        for lane in 0..LANES {
            let mut mixed = lanes;
            mixed[lane] = *plaintext;
            sm4.encrypt_4blocks(&mut mixed);
            assert_eq!(mixed[lane], from_literal, "lane {lane} must match the literal form");
            for other in (0..LANES).filter(|&o| o != lane) {
                assert_eq!(mixed[other], alone[other], "lane {other} must be undisturbed");
            }
        }
    }

    /// Appendix A.1.1 (GB/T 32907-2016 Example 1): the per-round X_i column.
    #[test]
    fn test_round_outputs_match_appendix_a_1_1() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let plaintext = key;
        let expected_x: [u32; 32] = [
            0x27FAD345, 0xA18B4CB2, 0x11C1E22A, 0xCC13E2EE, 0xF87C5BD5, 0x33220757, 0x77F4C297,
            0x7A96F2EB, 0x27DAC07F, 0x42DD0F19, 0xB8A5DA02, 0x907127FA, 0x8B952B83, 0xD42B7C59,
            0x2FFC5831, 0xF69E6888, 0xAF2432C4, 0xED1EC85E, 0x55A3BA22, 0x124B18AA, 0x6AE7725F,
            0xF4CBA1F9, 0x1DCDFA10, 0x2FF60603, 0xEFF24FDC, 0x6FE46B75, 0x893450AD, 0x7B938F4C,
            0x536E4246, 0x86B3E94F, 0xD206965E, 0x681EDF34,
        ];
        let ciphertext = [
            0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E, 0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E,
            0x42, 0x46,
        ];
        check_example(&key, &plaintext, &expected_x, &ciphertext);
    }

    /// Appendix A.1.4 (Example 4): the per-round X_i column.
    #[test]
    fn test_round_outputs_match_appendix_a_1_4() {
        let key = [
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let plaintext = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];
        let expected_x: [u32; 32] = [
            0xF7EAEB6A, 0xB4967C0F, 0x5B9B2419, 0xF46BECBA, 0xA8013E25, 0xB38E2ABE, 0x3E7C99A1,
            0x6DD5F47F, 0xB286430C, 0xAB997DE3, 0x80F8F21F, 0x4EF7052E, 0x4462FFAF, 0x14DFD5EA,
            0x6D33EFED, 0x3A4F8B3C, 0x1A435088, 0x4E64B153, 0x0415CEDA, 0xADD88955, 0x73964EF1,
            0xB0085092, 0x554A1293, 0x4BC6D6A8, 0x7BB650E1, 0xDDFB8A61, 0x5C4DFD78, 0xFD9066FD,
            0x55ADB594, 0xAC1B3EA9, 0x13F01ADE, 0xF766678F,
        ];
        let ciphertext = [
            0xF7, 0x66, 0x67, 0x8F, 0x13, 0xF0, 0x1A, 0xDE, 0xAC, 0x1B, 0x3E, 0xA9, 0x55, 0xAD,
            0xB5, 0x94,
        ];
        check_example(&key, &plaintext, &expected_x, &ciphertext);
    }

    #[test]
    fn test_engine_size_is_exactly_the_round_keys() {
        // The "Memory Usage" table in the crate docs quotes 128 bytes: 32 round keys of 32 bits,
        // and nothing else -- no direction flag, no round counter, no initialised marker.
        assert_eq!(size_of::<SM4>(), 128);
        assert_eq!(size_of::<SM4>(), size_of::<RoundKeys>());
    }

    #[test]
    fn test_alg_name_and_strength() {
        assert_eq!(<SM4 as Algorithm>::ALG_NAME, "SM4");
        assert_eq!(
            <SM4 as Algorithm>::MAX_SECURITY_STRENGTH,
            SecurityStrength::from_bytes(KEY_LEN)
        );
    }

    #[test]
    fn test_lanes_constant() {
        // The "Memory Usage" docs and the two-block override both assume four lanes.
        assert_eq!(LANES, 4);
        assert_eq!(
            LANES * 4,
            16,
            "four four-byte words fill the 16 byte positions of the u16 planes"
        );
    }

    #[test]
    fn test_l_is_the_documented_rotation_sum() {
        // L(B) = B xor (B <<< 2) xor (B <<< 10) xor (B <<< 18) xor (B <<< 24)
        assert_eq!(l(1), 1 | (1 << 2) | (1 << 10) | (1 << 18) | (1 << 24));
        assert_eq!(l(0), 0);
    }
}
