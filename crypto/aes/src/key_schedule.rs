//! KEYEXPANSION(): derivation of the AES round keys from the cipher key
//! (FIPS 197 Section 5.2, Algorithm 2).
//!
//! # Word representation
//!
//! FIPS 197 Section 3.5 defines a word as a sequence of four bytes `[a0, a1, a2, a3]` with `a0`
//! leftmost. We hold each key schedule word as a `u32` whose big-endian byte order is that same
//! sequence, ie `a0` is the most significant byte. That makes:
//!
//! * ROTWORD() (Eq 5.10) a single `rotate_left(8)`,
//! * the round constants of Table 5 plain `u32` XOR operands, and
//! * ADDROUNDKEY() (Eq 5.9) a XOR of `w[i].to_be_bytes()` into a column of the state, since a
//!   column of the state and the bytes of a word are indexed the same way.
//!
//! # 🚨 Security 🚨
//!
//! The expanded key schedule is key material: every round key is derived from the cipher key by an
//! invertible transformation, so recovering any four consecutive words of the schedule recovers the
//! cipher key. It is therefore returned wrapped in a [`Secret`], which scrubs it on drop.

use crate::tables::{RCON, SBOX};
use bouncycastle_utils::secret::Secret;

/// SUBWORD(): applies the S-box to each of the four bytes of a word (FIPS 197 Eq 5.11).
#[inline(always)]
const fn sub_word(word: u32) -> u32 {
    let [a0, a1, a2, a3] = word.to_be_bytes();
    u32::from_be_bytes([SBOX[a0 as usize], SBOX[a1 as usize], SBOX[a2 as usize], SBOX[a3 as usize]])
}

/// ROTWORD(): cyclically permutes the four bytes of a word (FIPS 197 Eq 5.10).
///
/// `ROTWORD([a0, a1, a2, a3]) = [a1, a2, a3, a0]`. With `a0` held as the most significant byte,
/// moving every byte one position left in the sequence is a rotate *left* by 8 bits.
#[inline(always)]
const fn rot_word(word: u32) -> u32 {
    word.rotate_left(8)
}

/// KEYEXPANSION(): expands the cipher key into the `4 * (Nr + 1)`-word key schedule `w`
/// (FIPS 197 Algorithm 2).
///
/// * `KEY_LEN` is the cipher key length in bytes, so `Nk = KEY_LEN / 4` words (Table 3).
/// * `W_WORDS` is the length of the key schedule in 32-bit words, ie `4 * (Nr + 1)`.
///
/// Both are compile-time parameters, so this function cannot be called with a mismatched key
/// length or output size, and it has no failure mode: every 16-, 24- or 32-byte input is a valid
/// AES key (FIPS 197 Section 6.2 imposes no keying restrictions).
///
/// The caller ([`crate::aes::AES::new`]) is responsible for checking that the parameter triple is
/// one of the three combinations in Table 3.
pub(crate) fn key_expansion<const KEY_LEN: usize, const W_WORDS: usize>(
    key: &[u8; KEY_LEN],
) -> Secret<[u32; W_WORDS]> {
    // Nk: the number of 32-bit words comprising the key (Section 2.3).
    let nk = KEY_LEN / 4;

    // Allocate the schedule zeroed and fill it in place, so no unprotected copy of the round keys
    // is ever materialized (see the Secret docs in bouncycastle-utils).
    let mut w = Secret::<[u32; W_WORDS]>::new();

    // Alg 2 lines 2-6: the first Nk words of the expanded key are the key itself.
    //     w[i] <- key[4*i .. 4*i+3]
    let mut i = 0;
    while i < nk {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
        i += 1;
    }

    // Alg 2 lines 7-16. The loop bound `i <= 4*Nr + 3` is `i < W_WORDS`, because
    // W_WORDS == 4 * (Nr + 1) == 4*Nr + 4.
    // On entry i == Nk, as the spec notes at line 6.
    while i < W_WORDS {
        // 8: temp <- w[i-1]
        let mut temp = w[i - 1];

        // 9-10: if i mod Nk = 0 then temp <- SUBWORD(ROTWORD(temp)) XOR Rcon[i/Nk]
        if i % nk == 0 {
            // Rcon is 1-indexed in Table 5 and 0-indexed here, hence the -1.
            // i/nk >= 1 here because i >= nk, so this cannot underflow.
            temp = sub_word(rot_word(temp)) ^ RCON[i / nk - 1];
        }
        // 11-12: else if Nk > 6 and i mod Nk = 4 then temp <- SUBWORD(temp)
        // This extra substitution applies only to AES-256 (Nk = 8); see Figure 8.
        else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }

        // 14: w[i] <- w[i-Nk] XOR temp
        w[i] = w[i - nk] ^ temp;

        // 15: i <- i + 1
        i += 1;
    }

    // Note: the branches above are decided entirely by `i` and `Nk`, which are public parameters
    // of the algorithm, never by key material. The expansion is therefore key-independent in its
    // control flow.

    // 17: return w
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::{
        AES128_KEY_LEN, AES128_KEY_SCHEDULE_WORDS, AES192_KEY_LEN, AES192_KEY_SCHEDULE_WORDS,
        AES256_KEY_LEN, AES256_KEY_SCHEDULE_WORDS,
    };

    /// FIPS 197 Eq (5.10), the worked ROTWORD() example implied by Appendix A.1 at i = 4:
    /// ROTWORD(09cf4f3c) = cf4f3c09.
    #[test]
    fn rot_word_matches_fips197() {
        assert_eq!(rot_word(0x09cf4f3c), 0xcf4f3c09);
        // Rotating four times returns the original word.
        let mut word = 0x09cf4f3c;
        for _ in 0..4 {
            word = rot_word(word);
        }
        assert_eq!(word, 0x09cf4f3c);
    }

    /// FIPS 197 Appendix A.1 at i = 4: SUBWORD(cf4f3c09) = 8a84eb01.
    #[test]
    fn sub_word_matches_fips197() {
        assert_eq!(sub_word(0xcf4f3c09), 0x8a84eb01);
        // Appendix A.3 at i = 8: SUBWORD(14dff409) = fa9ebf01.
        assert_eq!(sub_word(0x14dff409), 0xfa9ebf01);
    }

    /// FIPS 197 Appendix A.1: the complete expansion of the 128-bit key
    /// `2b7e151628aed2a6abf7158809cf4f3c`, all 44 words.
    #[test]
    fn key_expansion_matches_fips197_appendix_a1() {
        const KEY: [u8; AES128_KEY_LEN] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        #[rustfmt::skip]
        const EXPECTED: [u32; AES128_KEY_SCHEDULE_WORDS] = [
            // w[0..4] are the key itself
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
            0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605, // i = 4..7
            0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, // i = 8..11
            0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b, // i = 12..15
            0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, // i = 16..19
            0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc, // i = 20..23
            0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd, // i = 24..27
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, // i = 28..31
            0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f, // i = 32..35
            0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, // i = 36..39
            0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6, // i = 40..43
        ];

        let w = key_expansion::<AES128_KEY_LEN, AES128_KEY_SCHEDULE_WORDS>(&KEY);
        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(w[i], *expected, "w[{i}]");
        }
    }

    /// FIPS 197 Appendix A.2: the expansion of the 192-bit key
    /// `8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b`.
    ///
    /// The first six words are the key, and i = 6, 7, 8 exercise the `i mod Nk = 0` branch and the
    /// two words that follow it. The remaining words of this schedule are covered end to end by
    /// the AES-192 known-answer tests in tests/aes_tests.rs, which use this exact key.
    #[test]
    fn key_expansion_matches_fips197_appendix_a2() {
        const KEY: [u8; AES192_KEY_LEN] = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        #[rustfmt::skip]
        const EXPECTED_PREFIX: [u32; 9] = [
            // w[0..6] are the key itself
            0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5, 0x62f8ead2, 0x522c6b7b,
            0xfe0c91f7, // i = 6
            0x2402f5a5, // i = 7
            0xec12068e, // i = 8
        ];

        let w = key_expansion::<AES192_KEY_LEN, AES192_KEY_SCHEDULE_WORDS>(&KEY);
        for (i, expected) in EXPECTED_PREFIX.iter().enumerate() {
            assert_eq!(w[i], *expected, "w[{i}]");
        }
    }

    /// FIPS 197 Appendix A.3: the expansion of the 256-bit key
    /// `603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4`.
    ///
    /// Words 8 through 22 cover both of AES-256's special cases: the `i mod Nk = 0` branch at
    /// i = 8 and i = 16, and the AES-256-only `Nk > 6 and i mod Nk = 4` branch at i = 12 and
    /// i = 20. The rest of the schedule is covered end to end by the AES-256 known-answer tests in
    /// tests/aes_tests.rs, which use this exact key.
    #[test]
    fn key_expansion_matches_fips197_appendix_a3() {
        const KEY: [u8; AES256_KEY_LEN] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        #[rustfmt::skip]
        const EXPECTED_PREFIX: [u32; 23] = [
            // w[0..8] are the key itself
            0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
            0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
            0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde, // i = 8..11
            0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a, // i = 12..15
            0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96, // i = 16..19
            0xb5a9328a, 0x2678a647, 0x98312229,             // i = 20..22
        ];

        let w = key_expansion::<AES256_KEY_LEN, AES256_KEY_SCHEDULE_WORDS>(&KEY);
        for (i, expected) in EXPECTED_PREFIX.iter().enumerate() {
            assert_eq!(w[i], *expected, "w[{i}]");
        }
    }

    /// The expansion must be deterministic, and a single-bit change anywhere in the key must
    /// change every round key from the point of injection onward (the avalanche the recursion of
    /// Alg 2 is designed to produce). A schedule that ignored part of the key -- a plausible
    /// off-by-one in the `w[i - nk]` term -- would fail this.
    #[test]
    fn key_expansion_depends_on_every_key_byte() {
        const KEY: [u8; AES128_KEY_LEN] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let baseline = key_expansion::<AES128_KEY_LEN, AES128_KEY_SCHEDULE_WORDS>(&KEY);

        // Deterministic.
        let again = key_expansion::<AES128_KEY_LEN, AES128_KEY_SCHEDULE_WORDS>(&KEY);
        assert_eq!(*baseline, *again);

        for flipped_byte in 0..AES128_KEY_LEN {
            let mut key = KEY;
            key[flipped_byte] ^= 0x01;
            let w = key_expansion::<AES128_KEY_LEN, AES128_KEY_SCHEDULE_WORDS>(&key);

            assert_ne!(*w, *baseline, "flipping key byte {flipped_byte} changed nothing");
            // The last round key must always differ: every key byte feeds it.
            assert_ne!(
                w[AES128_KEY_SCHEDULE_WORDS - 4..],
                baseline[AES128_KEY_SCHEDULE_WORDS - 4..],
                "flipping key byte {flipped_byte} left the final round key unchanged"
            );
        }
    }

    /// The first `Nk` words must be the key verbatim for all three variants (Alg 2 lines 2-6), and
    /// no word of the schedule may be left at its zero-initialized value for these test keys.
    #[test]
    fn key_expansion_copies_the_key_then_fills_the_schedule() {
        let key128 = [0x11u8; AES128_KEY_LEN];
        let w = key_expansion::<AES128_KEY_LEN, AES128_KEY_SCHEDULE_WORDS>(&key128);
        assert_eq!(w[0..4], [0x1111_1111u32; 4]);
        assert!(w.iter().all(|word| *word != 0), "an unwritten word remained zero");

        let key192 = [0x22u8; AES192_KEY_LEN];
        let w = key_expansion::<AES192_KEY_LEN, AES192_KEY_SCHEDULE_WORDS>(&key192);
        assert_eq!(w[0..6], [0x2222_2222u32; 6]);
        assert!(w.iter().all(|word| *word != 0), "an unwritten word remained zero");

        let key256 = [0x33u8; AES256_KEY_LEN];
        let w = key_expansion::<AES256_KEY_LEN, AES256_KEY_SCHEDULE_WORDS>(&key256);
        assert_eq!(w[0..8], [0x3333_3333u32; 8]);
        assert!(w.iter().all(|word| *word != 0), "an unwritten word remained zero");
    }
}
