//! The key schedule (GB/T 32907-2016, as described in draft-ribose-cfrg-sm4-10 Sec 7.3), with the
//! family key `FK` (Sec 7.3.1) and constant key `CK` (Sec 7.3.2).
//!
//! The schedule is the 32 round keys `rk_0 .. rk_31`, one 32-bit word each, so 128 bytes. It is
//! computed once by [`expand`] and stored in a [`Secret`]. Decryption uses the same words in the
//! reverse order (Sec 7.2), so there is no second schedule: this crate stores the encryption order
//! and lets [`crate::SM4::decrypt_block`] index it backwards, rather than expanding a second copy
//! for decryption.
//!
//! Every word is big-endian, as the worked examples in Appendix A.1 require: with the Example 1
//! key `01 23 45 67 ...`, `MK_0` is `0x01234567`.
//!
//! # Constant-time
//!
//! `T'` routes secret key material through the S-box, so the expansion needs the same treatment
//! as the cipher: [`tau`] here is the bit-sliced circuit of [`crate::sbox`], not a table. It costs
//! a full circuit evaluation per round key to substitute four bytes, which is wasteful, but it
//! happens 32 times per key rather than per block.

use crate::LANES;
use crate::sbox::tau;
use bouncycastle_utils::secret::Secret;

/// The 32 round keys, `(rk_0, rk_1, ..., rk_31)` (Sec 5).
pub(crate) type RoundKeys = [u32; 32];

/// The family key `FK = (FK_0, FK_1, FK_2, FK_3)` (Sec 7.3.1).
pub(crate) const FK: [u32; 4] = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

/// The constant key `CK = (CK_0, ..., CK_31)` (Sec 7.3.2).
///
/// Defined by `ck_{i,j} = (4i + j) x 7 (mod 256)` for byte `j` of `CK_i`; the table is the
/// spec's own listing of those values, extracted mechanically from the text of the draft, and
/// `test_ck_matches_its_defining_formula` re-derives every word.
pub(crate) const CK: [u32; 32] = [
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
];

/// `L'(B) = B xor (B <<< 13) xor (B <<< 23)` (Sec 6.2.2).
#[inline(always)]
fn l_prime(b: u32) -> u32 {
    b ^ b.rotate_left(13) ^ b.rotate_left(23)
}

/// `T'(.) = L'(tau(.))` (Sec 6.2): the permutation `T` with `L` replaced by `L'`.
///
/// `tau` works on four words at once; the one word here is placed in every lane, and lane 0 is
/// read back. All four lanes then hold the same result, which `test_t_prime_lanes_agree` checks.
fn t_prime(z: u32) -> u32 {
    let mut words = [z; LANES];
    tau(&mut words);
    l_prime(words[0])
}

/// Expands a 128-bit key into the 32 round keys (Sec 7.3).
///
/// Line by line against Sec 7.3:
///
/// * `MK = (MK_0, MK_1, MK_2, MK_3)` -- the key as four big-endian words;
/// * `(K_0, K_1, K_2, K_3) = (MK_0 xor FK_0, MK_1 xor FK_1, MK_2 xor FK_2, MK_3 xor FK_3)`;
/// * for `i = 0, 1, ..., 31`: `rk_i = K_{i+4} = K_i xor T'(K_{i+1} xor K_{i+2} xor K_{i+3} xor CK_i)`.
///
/// Only the four most recent `K` words are ever read, so they are kept in a sliding four-word
/// window rather than a 36-word array; `test_round_keys_match_appendix_a_1_1` and
/// `test_round_keys_match_appendix_a_1_4` pin every one of the 32 outputs.
pub(crate) fn expand(key: &[u8; 16]) -> Secret<RoundKeys> {
    // MK_0 .. MK_3, then K_i = MK_i xor FK_i. Held in a Secret so the window is scrubbed on return.
    let mut k = Secret::<[u32; 4]>::new();
    for (i, word) in key.as_chunks::<4>().0.iter().enumerate() {
        k[i] = u32::from_be_bytes(*word) ^ FK[i];
    }

    let mut rk = Secret::<RoundKeys>::new();
    for i in 0..32 {
        // K_{i+4} = K_i xor T'(K_{i+1} xor K_{i+2} xor K_{i+3} xor CK_i)
        let next = k[0] ^ t_prime(k[1] ^ k[2] ^ k[3] ^ CK[i]);
        // rk_i = K_{i+4}
        rk[i] = next;
        // Slide the window: (K_{i+1}, K_{i+2}, K_{i+3}, K_{i+4}).
        *k = [k[1], k[2], k[3], next];
    }
    rk
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ck_matches_its_defining_formula() {
        // Sec 7.3.2: ck_{i,j} = (4i + j) x 7 (mod 256), CK_i = (ck_{i,0}, ck_{i,1}, ck_{i,2}, ck_{i,3})
        // with ck_{i,0} the most significant byte.
        for (i, &ck) in CK.iter().enumerate() {
            let bytes: [u8; 4] = core::array::from_fn(|j| (((4 * i + j) * 7) % 256) as u8);
            assert_eq!(ck, u32::from_be_bytes(bytes), "CK_{i}");
        }
    }

    #[test]
    fn test_fk_matches_section_7_3_1() {
        assert_eq!(FK, [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]);
    }

    /// Appendix A.1.1 (GB/T 32907-2016 Example 1): key 0123456789ABCDEFFEDCBA9876543210.
    #[test]
    fn test_round_keys_match_appendix_a_1_1() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let expected: RoundKeys = [
            0xF12186F9, 0x41662B61, 0x5A6AB19A, 0x7BA92077, 0x367360F4, 0x776A0C61, 0xB6BB89B3,
            0x24763151, 0xA520307C, 0xB7584DBD, 0xC30753ED, 0x7EE55B57, 0x6988608C, 0x30D895B7,
            0x44BA14AF, 0x104495A1, 0xD120B428, 0x73B55FA3, 0xCC874966, 0x92244439, 0xE89E641F,
            0x98CA015A, 0xC7159060, 0x99E1FD2E, 0xB79BD80C, 0x1D2115B0, 0x0E228AEB, 0xF1780C81,
            0x428D3654, 0x62293496, 0x01CF72E5, 0x9124A012,
        ];
        let rk = expand(&key);
        for (i, (got, want)) in rk.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "rk_{i}");
        }
    }

    /// Appendix A.1.4 (Example 4): key FEDCBA98765432100123456789ABCDEF.
    #[test]
    fn test_round_keys_match_appendix_a_1_4() {
        let key = [
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
            0xCD, 0xEF,
        ];
        let expected: RoundKeys = [
            0x0D8CC1B4, 0xAC44F213, 0x188C0C40, 0x7537585E, 0x627646F5, 0x54D785AD, 0x51B96DEE,
            0x0C385958, 0x5E494992, 0x32F3FE04, 0x3A3A733D, 0x0EDFB91D, 0x6823CD6B, 0x40F7D825,
            0x4BD68EE5, 0x165A36C8, 0x56608984, 0x23F35FF4, 0x8B592B3E, 0x80F7388A, 0x0415C409,
            0xAFDF1370, 0xCF444772, 0x9AF9901F, 0xC457578C, 0x95701C60, 0x2B0F4EE1, 0x7F826139,
            0xFA37F8D9, 0xD18AF8CE, 0x5BD5D8C6, 0x711138B7,
        ];
        let rk = expand(&key);
        for (i, (got, want)) in rk.iter().zip(expected.iter()).enumerate() {
            assert_eq!(got, want, "rk_{i}");
        }
    }

    #[test]
    fn test_t_prime_lanes_agree() {
        // The single-word T' fills all four lanes with the same word; every lane must come back
        // identical, or lane 0 would not be a valid answer.
        for z in [0u32, 0xFFFF_FFFF, 0x0123_4567, 0xDEAD_BEEF, 0x8000_0001] {
            let mut words = [z; LANES];
            tau(&mut words);
            assert!(words.iter().all(|&w| w == words[0]), "lanes disagree for {z:#010x}");
            assert_eq!(l_prime(words[0]), t_prime(z));
        }
    }

    #[test]
    fn test_l_prime_is_the_documented_rotation_sum() {
        // L'(B) = B xor (B <<< 13) xor (B <<< 23): a single set bit lands in exactly three places.
        assert_eq!(l_prime(1), 1 | (1 << 13) | (1 << 23));
        assert_eq!(l_prime(0), 0);
    }
}
