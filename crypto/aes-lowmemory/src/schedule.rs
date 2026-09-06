//! KEYEXPANSION() (FIPS 197 Sec 5.2, Algorithm 2) and the per-key-length parameters.
//!
//! # Storage
//!
//! The schedule is `4 * (Nr + 1)` words -- 44, 52 or 60 -- exactly as FIPS 197 Sec 5.2 defines
//! it, so 176, 208 or 240 bytes. It is stored in a **compressed** bit-sliced form: because
//! bit-slicing is a permutation of bits it does not change the size, and because both interleaved
//! blocks are encrypted under the same key the two halves of a bit-sliced round key are
//! identical, so only one of every pair of words needs keeping. [`round_key`] re-doubles a single
//! round key onto the stack when the round loop needs it.
//!
//! The alternative -- storing the doubled 8-plane form -- would need 352, 416 or 480 bytes, and
//! holding the classical schedule *and* a bit-sliced copy would be worse still. Since low memory
//! is the point of this crate, neither is done: [`expand`] writes the classical schedule into the
//! final array and then rewrites it in place, one round key at a time, using eight words of
//! stack. In particular it does not mirror BearSSL's `uint32_t skey[120]` (480-byte) scratch
//! buffer.
//!
//! # Constant-time
//!
//! The key is secret, so SUBWORD() in the expansion has the same table-lookup problem as
//! SUBBYTES() in the cipher, and gets the same treatment: [`sub_word`] routes the word through
//! the bit-sliced circuit in [`crate::sbox`]. A table-driven "light" AES that only removes the
//! tables from the cipher, and not from the key schedule, still leaks through the schedule.

use crate::bitslice::{Planes, ortho};
use crate::sbox::sbox;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};

/// FIPS 197 Sec 5.2, Table 5: the round constants, `Rcon[j]` for `1 <= j <= 10`.
///
/// Table 5 gives each as the word `[x, 00, 00, 00]`; only the leftmost byte is ever non-zero, and
/// words are held little-endian here, so the word `Rcon[j]` is just this byte. Indexing is shifted
/// by one against the spec: `RCON[j - 1]` is the spec's `Rcon[j]`, since the spec counts from 1.
const RCON: [u32; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Prevents a fourth parameter set from being added outside this crate.
///
/// FIPS 197 Sec 6.1 defines exactly three: AES-128, AES-192 and AES-256. Because [`AesParams`]
/// has this private supertrait, only the three types in this module can implement it, so no
/// downstream crate can instantiate the cipher with an unapproved key length or round count.
trait AesParamsSealed {}

/// The per-key-length constants of FIPS 197 Sec 6.1.
///
/// This is a trait rather than const generic parameters because the schedule length
/// `4 * (Nr + 1)` cannot be written as an expression over another const parameter on stable
/// const-generics; each implementation spells its own array type out instead. The same pattern is
/// used by the `HashDRBG80090AParams_*` types in `bouncycastle-rng`.
///
/// Sealed via a private supertrait, so the three types below are the only implementations.
pub trait AesParams: AesParamsSealed {
    /// Key length in bytes: 16, 24 or 32 (FIPS 197 Sec 6.1).
    const KEY_LEN: usize;
    /// `Nk`, the key length in 32-bit words: 4, 6 or 8 (FIPS 197 Sec 6.1).
    const NK: usize;
    /// `Nr`, the number of rounds: 10, 12 or 14 (FIPS 197 Sec 6.1).
    const NR: usize;
    /// The algorithm name, as reported by `Algorithm::ALG_NAME`.
    const ALG_NAME: &'static str;
    /// `[u32; 4 * (NR + 1)]` -- the compressed schedule. See the module docs.
    type Schedule: ZeroizablePrimitive + AsRef<[u32]> + AsMut<[u32]>;
}

/// AES-128 parameters: 16-byte key, `Nk` = 4, `Nr` = 10 (FIPS 197 Sec 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes128Params;
/// AES-192 parameters: 24-byte key, `Nk` = 6, `Nr` = 12 (FIPS 197 Sec 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes192Params;
/// AES-256 parameters: 32-byte key, `Nk` = 8, `Nr` = 14 (FIPS 197 Sec 6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Aes256Params;

impl AesParamsSealed for Aes128Params {}
impl AesParamsSealed for Aes192Params {}
impl AesParamsSealed for Aes256Params {}

impl AesParams for Aes128Params {
    const KEY_LEN: usize = 16;
    const NK: usize = 4;
    const NR: usize = 10;
    const ALG_NAME: &'static str = "AES-128";
    type Schedule = [u32; 44]; // 4 * (10 + 1)
}

impl AesParams for Aes192Params {
    const KEY_LEN: usize = 24;
    const NK: usize = 6;
    const NR: usize = 12;
    const ALG_NAME: &'static str = "AES-192";
    type Schedule = [u32; 52]; // 4 * (12 + 1)
}

impl AesParams for Aes256Params {
    const KEY_LEN: usize = 32;
    const NK: usize = 8;
    const NR: usize = 14;
    const ALG_NAME: &'static str = "AES-256";
    type Schedule = [u32; 60]; // 4 * (14 + 1)
}

/// ROTWORD(): `[a0,a1,a2,a3] -> [a1,a2,a3,a0]` (FIPS 197 Sec 5.2, Eq 5.10).
///
/// Words are held little-endian, so `a0` is the low byte. Moving `a1` down into the low byte and
/// wrapping `a0` to the top is a rotate right by 8 of the whole word.
#[inline(always)]
fn rot_word(word: u32) -> u32 {
    word.rotate_right(8)
}

/// SUBWORD(): applies the S-box to each of the four bytes of a word
/// (FIPS 197 Sec 5.2, Eq 5.11).
///
/// The key is secret, so this must not be a table lookup. It reuses the bit-sliced circuit
/// instead, by replicating `word` into all eight planes before transposing:
///
/// after [`ortho`], plane `q[k]` bit `8L + i` equals bit `8L + k` of the *input* word `q[i]` --
/// and every input word is the same `word`, so that bit is bit `k` of byte `L` of `word`
/// regardless of `i`. In the layout of [`crate::bitslice`], the bit positions `8L + i` for
/// `i = 0..8` are all four columns of row `L`, in both blocks. So the transposed state holds byte
/// `L` of `word` in every position of row `L`, one S-box pass substitutes all four bytes (sixteen
/// times over, redundantly), and transposing back reassembles the word. All eight planes then
/// hold the same result, so `q[0]` is SUBWORD(`word`); `test_sub_word_fills_every_plane` checks
/// that.
///
/// It costs a full 113-gate S-box evaluation to substitute four bytes, which is wasteful, but it
/// happens `Nr` or so times per key rather than per block. Translated from BearSSL
/// `aes_ct.c:sub_word`.
fn sub_word(word: u32) -> u32 {
    let mut q: Planes = [word; 8];
    ortho(&mut q);
    sbox(&mut q);
    ortho(&mut q);
    q[0]
}

/// KEYEXPANSION() (FIPS 197 Sec 5.2, Algorithm 2), returning the compressed bit-sliced schedule.
///
/// `key` must be exactly `P::KEY_LEN` bytes; [`crate::aes`] checks that before calling, so this
/// cannot fail and takes no `Result`.
///
/// Algorithm 2 is followed literally -- lines 2-6 copy the key into `w[0..Nk]`, lines 7-16 derive
/// the rest -- and then the finished schedule is rewritten in place into the storage form
/// described in the module docs. Verified against the worked expansions in FIPS 197
/// Appendix A.1, A.2 and A.3 by the tests at the bottom of this file, which decompress the
/// stored schedule and compare every w[i].
pub(crate) fn expand<P: AesParams>(key: &[u8]) -> Secret<P::Schedule> {
    debug_assert_eq!(key.len(), P::KEY_LEN);

    let mut schedule = Secret::<P::Schedule>::new();
    let w = (*schedule).as_mut();

    // Algorithm 2 lines 2-6: w[i] = key[4i .. 4i+3] for i < Nk.
    for i in 0..P::NK {
        // Cannot fail: `key` is P::KEY_LEN == 4 * P::NK bytes, so this window is in bounds.
        w[i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
    }

    // Algorithm 2 lines 7-16.
    let mut temp = w[P::NK - 1]; // line 8, hoisted: w[i-1] is the temp from the previous pass
    for i in P::NK..w.len() {
        if i % P::NK == 0 {
            // line 10: temp = SUBWORD(ROTWORD(temp)) XOR Rcon[i / Nk]
            temp = sub_word(rot_word(temp)) ^ RCON[i / P::NK - 1];
        } else if P::NK > 6 && i % P::NK == 4 {
            // lines 11-12: the extra substitution that only AES-256 reaches
            temp = sub_word(temp);
        }
        // line 14: w[i] = w[i - Nk] XOR temp
        temp ^= w[i - P::NK];
        w[i] = temp;
    }

    // Rewrite in place into the compressed bit-sliced form, one 4-word round key at a time.
    // Both interleaved blocks use the same key, so each round key is bit-sliced with the word
    // duplicated into both halves; the two halves are then identical and one bit of each pair is
    // redundant, so the even-position bits of the first word and the odd-position bits of the
    // second are packed into a single stored word.
    for base in (0..w.len()).step_by(4) {
        let mut q: Planes = [0u32; 8];
        for j in 0..4 {
            q[2 * j] = w[base + j];
            q[2 * j + 1] = w[base + j];
        }
        ortho(&mut q);
        for j in 0..4 {
            // The two masks are complementary, so the operands are disjoint and `|` and `^` agree.
            // That is why `cargo mutants` reports the `| -> ^` mutant here as surviving.
            w[base + j] = (q[2 * j] & 0x5555_5555) | (q[2 * j + 1] & 0xAAAA_AAAA);
        }
    }

    schedule
}

/// Re-doubles round key `round` of a compressed schedule into its eight-plane form.
///
/// The inverse of the packing at the end of [`expand`]: the even-position bits are spread back
/// over both positions of each pair, and likewise the odd-position bits, giving the two identical
/// halves that [`crate::round::add_round_key`] expects. Eight words of stack, built fresh each
/// round rather than stored.
///
/// Translated from BearSSL `aes_ct.c:br_aes_ct_skey_expand`.
#[inline(always)]
pub(crate) fn round_key<P: AesParams>(schedule: &P::Schedule, round: usize) -> Planes {
    debug_assert!(round <= P::NR);
    let w = schedule.as_ref();
    let mut sk: Planes = [0u32; 8];
    for j in 0..4 {
        let packed = w[4 * round + j];
        let even = packed & 0x5555_5555;
        let odd = packed & 0xAAAA_AAAA;
        // `even` occupies only even bit positions and `even << 1` only odd ones (and vice versa
        // for `odd`), so both spreads combine disjoint operands and `|` and `^` agree. Hence the
        // two `| -> ^` mutants `cargo mutants` reports here as surviving.
        sk[2 * j] = even | (even << 1);
        sk[2 * j + 1] = odd | (odd >> 1);
    }
    sk
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 197 Appendix A.1: every w[i] of the AES-128 key expansion, as printed
    /// (i.e. the byte sequence [a0,a1,a2,a3] read left to right).
    #[rustfmt::skip]
    const APPENDIX_A1_WORDS: [u32; 44] = [
        0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
        0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
        0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
        0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
        0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
        0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
        0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
        0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
        0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
        0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
        0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
    ];

    /// FIPS 197 Appendix A.2: every w[i] of the AES-192 key expansion, as printed.
    #[rustfmt::skip]
    const APPENDIX_A2_WORDS: [u32; 52] = [
        0x8e73b0f7, 0xda0e6452, 0xc810f32b, 0x809079e5,
        0x62f8ead2, 0x522c6b7b, 0xfe0c91f7, 0x2402f5a5,
        0xec12068e, 0x6c827f6b, 0x0e7a95b9, 0x5c56fec2,
        0x4db7b4bd, 0x69b54118, 0x85a74796, 0xe92538fd,
        0xe75fad44, 0xbb095386, 0x485af057, 0x21efb14f,
        0xa448f6d9, 0x4d6dce24, 0xaa326360, 0x113b30e6,
        0xa25e7ed5, 0x83b1cf9a, 0x27f93943, 0x6a94f767,
        0xc0a69407, 0xd19da4e1, 0xec1786eb, 0x6fa64971,
        0x485f7032, 0x22cb8755, 0xe26d1352, 0x33f0b7b3,
        0x40beeb28, 0x2f18a259, 0x6747d26b, 0x458c553e,
        0xa7e1466c, 0x9411f1df, 0x821f750a, 0xad07d753,
        0xca400538, 0x8fcc5006, 0x282d166a, 0xbc3ce7b5,
        0xe98ba06f, 0x448c773c, 0x8ecc7204, 0x01002202,
    ];

    /// FIPS 197 Appendix A.3: every w[i] of the AES-256 key expansion, as printed.
    #[rustfmt::skip]
    const APPENDIX_A3_WORDS: [u32; 60] = [
        0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
        0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4,
        0x9ba35411, 0x8e6925af, 0xa51a8b5f, 0x2067fcde,
        0xa8b09c1a, 0x93d194cd, 0xbe49846e, 0xb75d5b9a,
        0xd59aecb8, 0x5bf3c917, 0xfee94248, 0xde8ebe96,
        0xb5a9328a, 0x2678a647, 0x98312229, 0x2f6c79b3,
        0x812c81ad, 0xdadf48ba, 0x24360af2, 0xfab8b464,
        0x98c5bfc9, 0xbebd198e, 0x268c3ba7, 0x09e04214,
        0x68007bac, 0xb2df3316, 0x96e939e4, 0x6c518d80,
        0xc814e204, 0x76a9fb8a, 0x5025c02d, 0x59c58239,
        0xde136967, 0x6ccc5a71, 0xfa256395, 0x9674ee15,
        0x5886ca5d, 0x2e2f31d7, 0x7e0af1fa, 0x27cf73c3,
        0x749c47ab, 0x18501dda, 0xe2757e4f, 0x7401905a,
        0xcafaaae3, 0xe4d59b34, 0x9adf6ace, 0xbd10190d,
        0xfe4890d1, 0xe6188d0b, 0x046df344, 0x706c631e,
    ];

    /// Recovers the classical `w[i]` from a stored schedule.
    ///
    /// [`round_key`] undoes the pair-compression, and [`ortho`] then undoes the bit-slicing,
    /// leaving the duplicated pre-slicing words with `w[4*round + j]` in position `2j`. This is
    /// what lets the Appendix A vectors test the real [`expand`] output rather than a
    /// reimplementation of it.
    fn classical_word<P: AesParams>(schedule: &P::Schedule, i: usize) -> u32 {
        let mut q = round_key::<P>(schedule, i / 4);
        ortho(&mut q);
        let j = i % 4;
        assert_eq!(q[2 * j], q[2 * j + 1], "both interleaved halves hold the same round key");
        q[2 * j]
    }

    /// Compares a whole expansion against an Appendix A table.
    ///
    /// Appendix A prints a word as the byte sequence `[a0,a1,a2,a3]` left to right, so the
    /// tabulated `u32` has `a0` in its *most* significant byte; words are held little-endian
    /// here, so `swap_bytes` is the conversion.
    fn assert_expansion_matches<P: AesParams>(key: &[u8], expected: &[u32], label: &str) {
        let schedule = expand::<P>(key);
        assert_eq!(expected.len(), 4 * (P::NR + 1), "{label}: table length");
        for (i, &want) in expected.iter().enumerate() {
            let got = classical_word::<P>(&schedule, i).swap_bytes();
            assert_eq!(got, want, "{label}: w[{i}] should be {want:#010x}, got {got:#010x}");
        }
    }

    #[test]
    fn test_key_expansion_matches_fips197_appendix_a1() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        assert_expansion_matches::<Aes128Params>(&key, &APPENDIX_A1_WORDS, "Appendix A.1");
    }

    #[test]
    fn test_key_expansion_matches_fips197_appendix_a2() {
        let key = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];
        assert_expansion_matches::<Aes192Params>(&key, &APPENDIX_A2_WORDS, "Appendix A.2");
    }

    #[test]
    fn test_key_expansion_matches_fips197_appendix_a3() {
        let key = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        assert_expansion_matches::<Aes256Params>(&key, &APPENDIX_A3_WORDS, "Appendix A.3");
    }

    #[test]
    fn test_the_first_nk_schedule_words_are_the_key_itself() {
        // Algorithm 2 lines 2-6, and a check that the expansion is reading the key
        // little-endian consistently with how Appendix A prints it.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let schedule = expand::<Aes128Params>(&key);
        for i in 0..Aes128Params::NK {
            let got = classical_word::<Aes128Params>(&schedule, i);
            assert_eq!(got.to_le_bytes(), key[4 * i..4 * i + 4]);
        }
    }

    #[test]
    fn test_rot_word_matches_equation_5_10() {
        // FIPS 197 Eq 5.10 on the byte sequence [a0,a1,a2,a3] = [0x09,0xcf,0x4f,0x3c], which is
        // the temp at i = 4 of Appendix A.1, whose ROTWORD() the appendix gives as cf4f3c09.
        let word = u32::from_le_bytes([0x09, 0xcf, 0x4f, 0x3c]);
        assert_eq!(rot_word(word).to_le_bytes(), [0xcf, 0x4f, 0x3c, 0x09]);
    }

    #[test]
    fn test_sub_word_matches_the_appendix_a1_example() {
        // Appendix A.1, i = 4: "After ROTWORD()" is cf4f3c09 and "After SUBWORD()" is 8a84eb01.
        // The appendix prints a word as the byte sequence [a0,a1,a2,a3]; words are held
        // little-endian here, so `a0` is the low byte.
        let after_rot = u32::from_le_bytes([0xcf, 0x4f, 0x3c, 0x09]);
        assert_eq!(sub_word(after_rot).to_le_bytes(), [0x8a, 0x84, 0xeb, 0x01]);
    }

    #[test]
    fn test_sub_word_fills_every_plane() {
        // The doc comment claims all eight planes end up holding SUBWORD(word); if that ever
        // stopped being true, picking q[0] would be an arbitrary choice rather than a correct one.
        let word = 0x1234_5678u32;
        let mut q: Planes = [word; 8];
        ortho(&mut q);
        sbox(&mut q);
        ortho(&mut q);
        assert!(q.iter().all(|&plane| plane == q[0]));
        assert_eq!(q[0], sub_word(word));
    }

    #[test]
    fn test_round_key_inverts_the_compression() {
        // Round-tripping a known schedule: expand(), then round_key() for every round, and check
        // the recovered planes match bit-slicing the classical words directly.
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let schedule = expand::<Aes128Params>(&key);

        // Recompute the classical schedule without the compression step.
        let mut w = [0u32; 44];
        for i in 0..4 {
            w[i] = u32::from_le_bytes(key[4 * i..4 * i + 4].try_into().unwrap());
        }
        let mut temp = w[3];
        for i in 4..44 {
            if i % 4 == 0 {
                temp = sub_word(rot_word(temp)) ^ RCON[i / 4 - 1];
            }
            temp ^= w[i - 4];
            w[i] = temp;
        }

        for round in 0..=Aes128Params::NR {
            let got = round_key::<Aes128Params>(&schedule, round);
            let mut expected: Planes = [0u32; 8];
            for j in 0..4 {
                expected[2 * j] = w[4 * round + j];
                expected[2 * j + 1] = w[4 * round + j];
            }
            ortho(&mut expected);
            assert_eq!(got, expected, "round {round}");
        }
    }

    #[test]
    fn test_schedule_lengths_match_four_times_nr_plus_one() {
        // FIPS 197 Sec 5.2: the schedule is 4 * (Nr + 1) words. The array types are written out
        // by hand per parameter set, so this guards against a typo in one of them.
        assert_eq!(
            size_of::<<Aes128Params as AesParams>::Schedule>() / 4,
            4 * (Aes128Params::NR + 1)
        );
        assert_eq!(
            size_of::<<Aes192Params as AesParams>::Schedule>() / 4,
            4 * (Aes192Params::NR + 1)
        );
        assert_eq!(
            size_of::<<Aes256Params as AesParams>::Schedule>() / 4,
            4 * (Aes256Params::NR + 1)
        );
    }

    #[test]
    fn test_key_len_is_four_times_nk() {
        // FIPS 197 Sec 6.1 ties the two together; both are declared independently above.
        assert_eq!(Aes128Params::KEY_LEN, 4 * Aes128Params::NK);
        assert_eq!(Aes192Params::KEY_LEN, 4 * Aes192Params::NK);
        assert_eq!(Aes256Params::KEY_LEN, 4 * Aes256Params::NK);
    }

    #[test]
    fn test_rcon_table_5_values() {
        // FIPS 197 Sec 5.2: "for j > 0, these bytes may be generated by successively applying
        // XTIMES() to the byte represented by x^(j-1)". Derive the table and compare, so a typo
        // in the transcription of Table 5 shows up here.
        let mut expected = [0u32; 10];
        let mut v: u8 = 0x01;
        for slot in expected.iter_mut() {
            *slot = u32::from(v);
            v = (v << 1) ^ if v & 0x80 != 0 { 0x1b } else { 0 };
        }
        assert_eq!(RCON, expected);
        // Spot-check the two values from Table 5 that are not plain powers of two.
        assert_eq!(RCON[8], 0x1b);
        assert_eq!(RCON[9], 0x36);
    }
}
