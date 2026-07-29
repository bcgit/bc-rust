//! The AES block cipher engine: CIPHER() and INVCIPHER() from FIPS 197 Section 5, together with
//! the key expansion that drives them.
//!
//! This module provides the keyed permutation on a single 128-bit block and nothing more. See the
//! crate-level docs for what that does and does not give you, and for why there is no mode of
//! operation here.

use crate::key_schedule::key_expansion;
use crate::state::{
    AES_BLOCK_LEN, NB, inv_mix_columns, inv_shift_rows, inv_sub_bytes, mix_columns, shift_rows,
    sub_bytes,
};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::traits::{Algorithm, SecurityStrength};
use bouncycastle_utils::secret::Secret;
use core::fmt;

/* *** Algorithm names *** */

/// The library-wide name for AES with a 128-bit key.
pub const AES_128_NAME: &str = "AES-128";
/// The library-wide name for AES with a 192-bit key.
pub const AES_192_NAME: &str = "AES-192";
/// The library-wide name for AES with a 256-bit key.
pub const AES_256_NAME: &str = "AES-256";

/* *** Parameters from FIPS 197 Table 3 (Key-Block-Round Combinations) *** */

/// The AES-128 key length in bytes; `Nk = 4` words.
pub const AES128_KEY_LEN: usize = 16;
/// The AES-192 key length in bytes; `Nk = 6` words.
pub const AES192_KEY_LEN: usize = 24;
/// The AES-256 key length in bytes; `Nk = 8` words.
pub const AES256_KEY_LEN: usize = 32;

/// The number of rounds `Nr` for AES-128.
pub const AES128_NUM_ROUNDS: usize = 10;
/// The number of rounds `Nr` for AES-192.
pub const AES192_NUM_ROUNDS: usize = 12;
/// The number of rounds `Nr` for AES-256.
pub const AES256_NUM_ROUNDS: usize = 14;

/// The length of the AES-128 key schedule, in 32-bit words: `4 * (Nr + 1)` (FIPS 197 Section 5.2).
///
/// Counted in words rather than bytes, hence `WORDS` and not the library's usual `LEN` suffix.
pub const AES128_KEY_SCHEDULE_WORDS: usize = 4 * (AES128_NUM_ROUNDS + 1);
/// The length of the AES-192 key schedule, in 32-bit words: `4 * (Nr + 1)`.
pub const AES192_KEY_SCHEDULE_WORDS: usize = 4 * (AES192_NUM_ROUNDS + 1);
/// The length of the AES-256 key schedule, in 32-bit words: `4 * (Nr + 1)`.
pub const AES256_KEY_SCHEDULE_WORDS: usize = 4 * (AES256_NUM_ROUNDS + 1);

/* *** Key types *** */

/// The [`KeyMaterial`] type that [`AES128::new`] takes: a 128-bit AES key.
///
/// Using a fixed-capacity key type means a key of the wrong size for the variant is a compile
/// error rather than a runtime one.
pub type AES128Key = KeyMaterial<AES128_KEY_LEN>;
/// The [`KeyMaterial`] type that [`AES192::new`] takes: a 192-bit AES key.
pub type AES192Key = KeyMaterial<AES192_KEY_LEN>;
/// The [`KeyMaterial`] type that [`AES256::new`] takes: a 256-bit AES key.
pub type AES256Key = KeyMaterial<AES256_KEY_LEN>;

/* *** The three variants specified by FIPS 197 *** */

/// AES with a 128-bit key: 10 rounds (FIPS 197 Table 3).
pub type AES128 = AES<AES128_KEY_LEN, AES128_NUM_ROUNDS, AES128_KEY_SCHEDULE_WORDS>;
/// AES with a 192-bit key: 12 rounds (FIPS 197 Table 3).
pub type AES192 = AES<AES192_KEY_LEN, AES192_NUM_ROUNDS, AES192_KEY_SCHEDULE_WORDS>;
/// AES with a 256-bit key: 14 rounds (FIPS 197 Table 3).
pub type AES256 = AES<AES256_KEY_LEN, AES256_NUM_ROUNDS, AES256_KEY_SCHEDULE_WORDS>;

impl Algorithm for AES128 {
    const ALG_NAME: &'static str = AES_128_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl Algorithm for AES192 {
    const ALG_NAME: &'static str = AES_192_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_192bit;
}

impl Algorithm for AES256 {
    const ALG_NAME: &'static str = AES_256_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_256bit;
}

// Deliberately no `AlgorithmOID` impl: NIST's Computer Security Objects Register assigns AES OIDs
// per *mode* (id-aes128-CBC, id-aes128-GCM, ...), not to the bare block cipher, so the OIDs belong
// on the mode-of-operation types rather than here.

/// The AES block cipher engine, holding one expanded key schedule.
///
/// You almost certainly want one of the three named variants -- [`AES128`], [`AES192`] or
/// [`AES256`] -- rather than naming this type directly. It is generic only so that the three
/// variants share one implementation, with the key schedule sized exactly at compile time.
///
/// The const parameters are:
///
/// * `KEY_LEN`: cipher key length in bytes, ie `4 * Nk`.
/// * `NR`: number of rounds `Nr`.
/// * `W_WORDS`: key schedule length in 32-bit words, ie `4 * (Nr + 1)`.
///
/// Only the three combinations in FIPS 197 Table 3 are usable: everything on this type is gated on
/// `Self: Algorithm`, and [`Algorithm`] is implemented only for [`AES128`], [`AES192`] and
/// [`AES256`]. Because both that trait and this struct are foreign to downstream crates, the orphan
/// rule prevents anyone adding a fourth combination, so a nonsense parameterization such as
/// `AES<16, 3, 44>` has no constructor and no methods. (FIPS 197 Section 6.3 notes that future
/// revisions might add parameter values; adding one here means adding a variant, its `Algorithm`
/// impl, and its test vectors, which is exactly the review that such a change deserves.)
///
/// # 🚨 Security 🚨
///
/// An instance of this type *is* key material: the key schedule it holds is invertible back to the
/// cipher key. It is stored in a [`Secret`], so it is scrubbed when the engine is dropped, and the
/// [`fmt::Debug`] impl never prints it. Do not clone engines you do not need to clone.
#[derive(Clone)]
pub struct AES<const KEY_LEN: usize, const NR: usize, const W_WORDS: usize> {
    /// The key schedule, `w` in FIPS 197 Section 5.2, as `4 * (Nr + 1)` big-endian words.
    w: Secret<[u32; W_WORDS]>,
}

impl<const KEY_LEN: usize, const NR: usize, const W_WORDS: usize> AES<KEY_LEN, NR, W_WORDS>
where
    Self: Algorithm,
{
    /// A compile-time check that this instantiation is one of the three parameter sets of
    /// FIPS 197 Table 3, and that the derived sizes are self-consistent.
    ///
    /// The `Self: Algorithm` bound above already restricts instantiation to the three variants;
    /// this is a second, independent guard that catches a typo *inside this crate* -- for example
    /// defining [`AES192`] with a 50-word schedule -- at compile time rather than as a wrong answer
    /// at run time.
    const VALID_PARAMS: () = {
        assert!(
            KEY_LEN == 16 || KEY_LEN == 24 || KEY_LEN == 32,
            "AES key length must be 16, 24 or 32 bytes (FIPS 197 Table 3)"
        );
        // Table 3: Nr = Nk + 6, where Nk = KEY_LEN / 4.
        assert!(NR == KEY_LEN / 4 + 6, "AES round count must be Nk + 6 (FIPS 197 Table 3)");
        // Section 5.2: the key schedule holds 4 * (Nr + 1) words.
        assert!(
            W_WORDS == 4 * (NR + 1),
            "AES key schedule must hold 4 * (Nr + 1) words (FIPS 197 Section 5.2)"
        );
    };

    /// Creates an engine from a cipher key by running KEYEXPANSION() (FIPS 197 Algorithm 2).
    ///
    /// Expanding the key is the only expensive part of AES, so construct one engine and reuse it
    /// for as many blocks as you have; the per-block operations take `&self`.
    ///
    /// The key must be a [`KeyMaterial`] of exactly `KEY_LEN` bytes whose [`KeyType`] is
    /// [`KeyType::SymmetricCipherKey`] or [`KeyType::CryptographicRandom`], and whose
    /// [`SecurityStrength`] is at least this variant's strength. In other words: use a full-entropy
    /// key of the right length, and tell the library that is what it is.
    ///
    /// # Errors
    ///
    /// * [`SymmetricCipherError::KeyMaterialError`] wrapping
    ///   [`KeyMaterialError::InvalidKeyType`] if the key is not tagged as a symmetric cipher key or
    ///   full-entropy random. Note that an all-zero buffer arrives tagged
    ///   [`KeyType::Zeroized`] and is rejected here -- using one is possible, but only by
    ///   deliberately retagging it inside a
    ///   [`do_hazardous_operations`](bouncycastle_core::key_material::do_hazardous_operations)
    ///   closure.
    /// * ... wrapping [`KeyMaterialError::InvalidLength`] if the key holds fewer than `KEY_LEN`
    ///   bytes. (It can never hold more: the capacity is `KEY_LEN`.)
    /// * ... wrapping [`KeyMaterialError::SecurityStrength`] if the key is tagged at a lower
    ///   security strength than the variant requires; for example a 128-bit-strength key handed to
    ///   [`AES256`].
    pub fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError> {
        // Force the compile-time parameter check for this instantiation. Costs nothing at runtime.
        let () = Self::VALID_PARAMS;

        // Wrong kind of key: refuse to use, say, a MAC key or an unclassified buffer as a cipher
        // key. Key separation between algorithms is a security property, not a formality.
        if !(key.key_type() == KeyType::SymmetricCipherKey
            || key.key_type() == KeyType::CryptographicRandom)
        {
            return Err(KeyMaterialError::InvalidKeyType(
                "AES::new(): key must be a SymmetricCipherKey or CryptographicRandom KeyType",
            )
            .into());
        }

        // The KeyMaterial capacity is KEY_LEN, so the only way to be wrong is to be short, which
        // would mean silently using a key padded with zeros.
        if key.key_len() != KEY_LEN {
            return Err(KeyMaterialError::InvalidLength.into());
        }

        // A key tagged weaker than the algorithm means the caller's key does not actually deliver
        // the security level they think they are getting from this variant.
        if key.security_strength() < Self::MAX_SECURITY_STRENGTH {
            return Err(KeyMaterialError::SecurityStrength(
                "AES::new(): key security strength is lower than the AES variant requires",
            )
            .into());
        }

        // Copy the key into a fixed-size, scrubbed-on-drop buffer so that KEYEXPANSION() can take
        // it as a compile-time-sized array. The length check above guarantees that ref_to_bytes()
        // is exactly KEY_LEN bytes long, so copy_from_slice() cannot panic here.
        let mut key_bytes = Secret::<[u8; KEY_LEN]>::new();
        key_bytes.copy_from_slice(key.ref_to_bytes());

        Ok(Self { w: key_expansion::<KEY_LEN, W_WORDS>(&key_bytes) })
    }

    /// One-shot API: expands `key` and encrypts exactly one block with it.
    ///
    /// Convenient for a single block, but it runs the full key expansion on every call. If you have
    /// more than one block, build an engine with [`AES::new`] once and call
    /// [`AESEngine::encrypt_block`] repeatedly.
    ///
    /// # Errors
    ///
    /// As [`AES::new`].
    pub fn encrypt_single_block(
        key: &KeyMaterial<KEY_LEN>,
        plaintext: &[u8; AES_BLOCK_LEN],
    ) -> Result<[u8; AES_BLOCK_LEN], SymmetricCipherError> {
        // The engine, and with it the key schedule, is scrubbed when it drops at the end of this
        // expression.
        Ok(Self::new(key)?.encrypt_block(plaintext))
    }

    /// One-shot API: expands `key` and decrypts exactly one block with it.
    ///
    /// # Errors
    ///
    /// As [`AES::new`].
    pub fn decrypt_single_block(
        key: &KeyMaterial<KEY_LEN>,
        ciphertext: &[u8; AES_BLOCK_LEN],
    ) -> Result<[u8; AES_BLOCK_LEN], SymmetricCipherError> {
        Ok(Self::new(key)?.decrypt_block(ciphertext))
    }

    /// ADDROUNDKEY(): XORs round key `round` of the schedule into the state
    /// (FIPS 197 Section 5.1.4).
    ///
    /// Eq (5.9) is:
    ///
    /// ```text
    /// [s'(0,c), s'(1,c), s'(2,c), s'(3,c)] = [s(0,c), s(1,c), s(2,c), s(3,c)] XOR w[4*round + c]
    /// ```
    ///
    /// Column `c` of the state is the contiguous run `state[4c .. 4c+4]` and the bytes of `w[i]`
    /// are its big-endian bytes `[a0, a1, a2, a3]`, so this is a straight byte-wise XOR with no
    /// index arithmetic beyond the column offset.
    ///
    /// `round` ranges over `0 ..= Nr`, and `w` has `4 * (Nr + 1)` words, so `4 * round + c` is
    /// always in bounds (Section 5.1.4: ADDROUNDKEY() is invoked `Nr + 1` times).
    #[inline(always)]
    fn add_round_key(state: &mut [u8; AES_BLOCK_LEN], w: &[u32; W_WORDS], round: usize) {
        for c in 0..NB {
            let round_key_word = w[4 * round + c].to_be_bytes();
            state[4 * c] ^= round_key_word[0];
            state[4 * c + 1] ^= round_key_word[1];
            state[4 * c + 2] ^= round_key_word[2];
            state[4 * c + 3] ^= round_key_word[3];
        }
    }

    /// CIPHER(): FIPS 197 Algorithm 1, the forward permutation on one block.
    ///
    /// The line numbers in the comments are Algorithm 1's.
    fn cipher(&self, input: &[u8; AES_BLOCK_LEN], output: &mut [u8; AES_BLOCK_LEN]) {
        // 2: state <- in
        // Section 3.4 Eq (3.6) is s[r, c] = in[r + 4c], which in this layout is a plain copy.
        // Held in a Secret so that the intermediate round states are scrubbed on the way out.
        let mut state = Secret::<[u8; AES_BLOCK_LEN]>::new();
        *state = *input;

        // 3: state <- ADDROUNDKEY(state, w[0..3])
        Self::add_round_key(&mut state, &self.w, 0);

        // 4: for round from 1 to Nr - 1
        for round in 1..NR {
            sub_bytes(&mut state); // 5
            shift_rows(&mut state); // 6
            mix_columns(&mut state); // 7
            Self::add_round_key(&mut state, &self.w, round); // 8
        } // 9: end for

        // 10-12: the final round, which differs in that MIXCOLUMNS() is omitted.
        sub_bytes(&mut state); // 10
        shift_rows(&mut state); // 11
        Self::add_round_key(&mut state, &self.w, NR); // 12

        // 13: return state -- Eq (3.7), out[r + 4c] = s[r, c], again a plain copy.
        *output = *state;
    }

    /// INVCIPHER(): FIPS 197 Algorithm 3, the inverse permutation on one block.
    ///
    /// This is the straight inverse cipher, not the equivalent inverse cipher of Section 5.3.5:
    /// EQINVCIPHER() would let decryption reuse the encryption round structure, but it needs a
    /// separate, INVMIXCOLUMNS()-transformed key schedule (Algorithm 5), which would mean either
    /// storing a second schedule per engine or deriving one per call. Algorithm 3 reuses the one
    /// schedule we already have.
    ///
    /// The line numbers in the comments are Algorithm 3's.
    fn inv_cipher(&self, input: &[u8; AES_BLOCK_LEN], output: &mut [u8; AES_BLOCK_LEN]) {
        // 2: state <- in
        let mut state = Secret::<[u8; AES_BLOCK_LEN]>::new();
        *state = *input;

        // 3: state <- ADDROUNDKEY(state, w[4*Nr .. 4*Nr+3])
        Self::add_round_key(&mut state, &self.w, NR);

        // 4: for round from Nr - 1 downto 1
        for round in (1..NR).rev() {
            inv_shift_rows(&mut state); // 5
            inv_sub_bytes(&mut state); // 6
            Self::add_round_key(&mut state, &self.w, round); // 7
            inv_mix_columns(&mut state); // 8
        } // 9: end for

        // 10-12: the final iteration, which omits INVMIXCOLUMNS().
        inv_shift_rows(&mut state); // 10
        inv_sub_bytes(&mut state); // 11
        Self::add_round_key(&mut state, &self.w, 0); // 12

        // 13: return state
        *output = *state;
    }
}

/// The block-level interface shared by [`AES128`], [`AES192`] and [`AES256`].
///
/// Every method here operates on exactly one 128-bit block and cannot fail: a block cipher is a
/// permutation of blocks (FIPS 197 Section 1), so with the key already validated by [`AES::new`]
/// there is nothing left to reject. The block length is fixed by the type system rather than
/// checked, which is why none of these return a `Result`.
///
/// This trait exists so that code layered on top of AES -- a mode of operation, say -- can be
/// written once against `E: AESEngine` instead of being repeated per variant.
///
/// # 🚨 Security 🚨
///
/// These are raw block operations. Encrypting more than one block by calling
/// [`AESEngine::encrypt_block`] in a loop is ECB mode, which leaks equality of plaintext blocks and
/// is not a secure way to encrypt data. See the crate-level "Security Considerations".
pub trait AESEngine: Algorithm + Sized {
    /// The cipher key length in bytes for this variant: 16, 24 or 32 (FIPS 197 Table 3).
    const KEY_LEN: usize;

    /// The number of rounds `Nr` for this variant: 10, 12 or 14 (FIPS 197 Table 3).
    const NUM_ROUNDS: usize;

    /// The block length in bytes. 128 bits for every AES variant (FIPS 197 Table 3).
    const BLOCK_LEN: usize = AES_BLOCK_LEN;

    /// Applies CIPHER() (FIPS 197 Algorithm 1) to one block, returning the result.
    fn encrypt_block(&self, plaintext: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN];

    /// As [`AESEngine::encrypt_block`], but writes into a caller-provided buffer.
    ///
    /// Returns the number of bytes written, which is always [`AES_BLOCK_LEN`]; it is returned for
    /// consistency with the `_out` conventions elsewhere in the library.
    fn encrypt_block_out(
        &self,
        plaintext: &[u8; AES_BLOCK_LEN],
        ciphertext: &mut [u8; AES_BLOCK_LEN],
    ) -> usize;

    /// Applies INVCIPHER() (FIPS 197 Algorithm 3) to one block, returning the result.
    fn decrypt_block(&self, ciphertext: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN];

    /// As [`AESEngine::decrypt_block`], but writes into a caller-provided buffer.
    ///
    /// Returns the number of bytes written, which is always [`AES_BLOCK_LEN`].
    fn decrypt_block_out(
        &self,
        ciphertext: &[u8; AES_BLOCK_LEN],
        plaintext: &mut [u8; AES_BLOCK_LEN],
    ) -> usize;
}

impl<const KEY_LEN: usize, const NR: usize, const W_WORDS: usize> AESEngine
    for AES<KEY_LEN, NR, W_WORDS>
where
    Self: Algorithm,
{
    const KEY_LEN: usize = KEY_LEN;
    const NUM_ROUNDS: usize = NR;

    fn encrypt_block(&self, plaintext: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN] {
        let mut ciphertext = [0u8; AES_BLOCK_LEN];
        self.cipher(plaintext, &mut ciphertext);
        ciphertext
    }

    fn encrypt_block_out(
        &self,
        plaintext: &[u8; AES_BLOCK_LEN],
        ciphertext: &mut [u8; AES_BLOCK_LEN],
    ) -> usize {
        self.cipher(plaintext, ciphertext);
        AES_BLOCK_LEN
    }

    fn decrypt_block(&self, ciphertext: &[u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN] {
        let mut plaintext = [0u8; AES_BLOCK_LEN];
        self.inv_cipher(ciphertext, &mut plaintext);
        plaintext
    }

    fn decrypt_block_out(
        &self,
        ciphertext: &[u8; AES_BLOCK_LEN],
        plaintext: &mut [u8; AES_BLOCK_LEN],
    ) -> usize {
        self.inv_cipher(ciphertext, plaintext);
        AES_BLOCK_LEN
    }
}

/// Redacting: prints the variant but never any part of the key schedule, so an engine cannot leak
/// key material into a log line or a panic message.
impl<const KEY_LEN: usize, const NR: usize, const W_WORDS: usize> fmt::Debug
    for AES<KEY_LEN, NR, W_WORDS>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "AES {{ key_size: {} bits, rounds: {}, key_schedule: <redacted> }}",
            KEY_LEN * 8,
            NR
        )
    }
}

// No `Drop` impl is needed: the only field is a `Secret`, which volatile-scrubs itself on drop, and
// adding a `Drop` here would only risk getting that ordering wrong.

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 197 Appendix B, "Cipher Example": the round-key column of that worked example is the
    /// AES-128 key schedule for key 2b7e151628aed2a6abf7158809cf4f3c, regrouped into round keys.
    /// This checks that [`AES::add_round_key`] reads the schedule with the round indexing of
    /// Eq (5.9) -- an off-by-one or a transposed word here would still produce a self-consistent
    /// cipher that simply computed the wrong answer.
    #[test]
    fn add_round_key_uses_the_round_key_of_eq_5_9() {
        // w[0..4] of Appendix A.1, ie the key itself, is round key 0.
        let mut w = [0u32; AES128_KEY_SCHEDULE_WORDS];
        w[0] = 0x2b7e1516;
        w[1] = 0x28aed2a6;
        w[2] = 0xabf71588;
        w[3] = 0x09cf4f3c;
        // w[4..8] of Appendix A.1 is round key 1.
        w[4] = 0xa0fafe17;
        w[5] = 0x88542cb1;
        w[6] = 0x23a33939;
        w[7] = 0x2a6c7605;

        // XOR-ing round key 0 into the all-zero state must reproduce the round key itself...
        let mut state = [0u8; AES_BLOCK_LEN];
        AES128::add_round_key(&mut state, &w, 0);
        assert_eq!(
            state,
            [
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c
            ]
        );

        // ... and round 1 must use w[4..8], not w[0..4] again.
        let mut state = [0u8; AES_BLOCK_LEN];
        AES128::add_round_key(&mut state, &w, 1);
        assert_eq!(
            state,
            [
                0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c,
                0x76, 0x05
            ]
        );

        // ADDROUNDKEY() is its own inverse (Section 5.3.4).
        AES128::add_round_key(&mut state, &w, 1);
        assert_eq!(state, [0u8; AES_BLOCK_LEN]);
    }

    /// The initial ADDROUNDKEY() of CIPHER() (Algorithm 1 line 3) is the first thing that happens
    /// to a block, so its output is the plaintext XOR the key. The NIST intermediate-value file for
    /// ECB-AES128 prints this as the first "KeyAddition" line.
    #[test]
    fn initial_add_round_key_matches_nist_intermediate_value() {
        let mut w = [0u32; AES128_KEY_SCHEDULE_WORDS];
        w[0] = 0x2b7e1516;
        w[1] = 0x28aed2a6;
        w[2] = 0xabf71588;
        w[3] = 0x09cf4f3c;

        // plaintext = 6BC1BEE2 2E409F96 E93D7E11 7393172A
        let mut state = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        AES128::add_round_key(&mut state, &w, 0);

        // expected = 40BFABF4 06EE4D30 42CA6B99 7A5C5816
        assert_eq!(
            state,
            [
                0x40, 0xbf, 0xab, 0xf4, 0x06, 0xee, 0x4d, 0x30, 0x42, 0xca, 0x6b, 0x99, 0x7a, 0x5c,
                0x58, 0x16
            ]
        );
    }
}
