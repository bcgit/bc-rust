//! The DEA cryptographic engine (SP 800-67r2 Sec 2): the initial and final permutations, the
//! function `f`, and the sixteen iterations.
//!
//! # Bit numbering
//!
//! The spec numbers the bits of a block from 1 at the left (footnote 10). A 64-bit block is held as
//! two `u32` words `L` and `R`, `L` being the first four bytes big-endian, so spec bit `k` of `L`
//! (1..32) is word bit `32 - k`, and spec bit `k` of the block (1..64) is bit `32 - k` of `L` for
//! `k <= 32` and bit `64 - k` of `R` otherwise. The same convention is used for the 32-bit input and
//! output of `f` and `P`. All constants below are written against this layout and the tests check
//! each one against the spec's table with every unit vector, which for a bit permutation is a proof.
//!
//! # The six input planes
//!
//! `E` (Table 1) maps the 32 bits of `R` to eight 6-bit blocks `B1..B8`: block `i` is bits
//! `4i-4, 4i-3, 4i-2, 4i-1, 4i, 4i+1` of `R` (indices taken modulo 32 in 1..32). The middle four are
//! exactly the `i`-th nibble of `R`; the first is the last bit of the nibble before it and the last
//! is the first bit of the nibble after it. So `E` never needs to be materialised as a 48-bit
//! value: [`planes`] builds six words, one per input-bit position, in which nibble `i` holds bit
//! `j` of `Bi` replicated four times. That is precisely the input layout [`crate::sbox::sbox_layer`]
//! wants, and it is obtained with masks, shifts and two rotations by a whole nibble.
//!
//! The round key `Kn` is XORed in the same layout (eq (6), `B1..B8 = K xor E(R)`). The key schedule
//! stores each `Kn` as two words shaped to make that cheap; see [`crate::schedule`].
//!
//! # Provenance
//!
//! The `IP` / `IP^-1` networks are the well-known five-swap form by Richard Outerbridge, taken via
//! Crypto++'s `des.cpp` (public domain) as reproduced in BearSSL's `des_support.c`; the rotation
//! groups of `P` were regenerated from Table 3 and agree with BearSSL's `des_ct.c`. Both are pinned
//! to the spec's tables by the unit-vector tests below.

use crate::sbox::sbox_layer;

/// One expanded DEA key: sixteen round keys `K1..K16`, two words each -- `[lo, hi]` for round `n`
/// at `[2n, 2n + 1]`. See [`crate::schedule`] for the packing.
pub(crate) type Subkeys = [u32; 32];

/// Every nibble's least significant bit.
const NIBBLE_LSB: u32 = 0x1111_1111;

/// Spreads the least significant bit of each nibble to all four bits of that nibble.
///
/// The input must have no other bits set. Written as shifts rather than a multiply by 15 so that
/// nothing depends on the multiplier's timing.
#[inline(always)]
fn spread(v: u32) -> u32 {
    v | (v << 1) | (v << 2) | (v << 3)
}

/// The initial permutation `IP` (Sec 2.1).
///
/// The `IP` table has a structure that a lookup hides: output row `j` (its `j`-th byte) takes one
/// fixed bit position from each input byte, input bytes in the order 8, 7, ..., 1, with rows 1-4
/// taking positions 2, 4, 6, 8 and rows 5-8 taking 1, 3, 5, 7. That is a transposition of the
/// block as an 8x8 bit matrix, with its rows and columns reordered, and a transposition is what
/// this network of five conditional swaps performs. The test checks all 64 unit vectors against
/// the table.
#[inline(always)]
pub(crate) fn ip(l: u32, r: u32) -> (u32, u32) {
    let (mut l, mut r) = (l, r);
    let mut t;
    t = ((l >> 4) ^ r) & 0x0F0F_0F0F;
    r ^= t;
    l ^= t << 4;
    t = ((l >> 16) ^ r) & 0x0000_FFFF;
    r ^= t;
    l ^= t << 16;
    t = ((r >> 2) ^ l) & 0x3333_3333;
    l ^= t;
    r ^= t << 2;
    t = ((r >> 8) ^ l) & 0x00FF_00FF;
    l ^= t;
    r ^= t << 8;
    t = ((l >> 1) ^ r) & 0x5555_5555;
    r ^= t;
    l ^= t << 1;
    (l, r)
}

/// The final permutation `IP^-1` (Sec 2.1): the swaps of [`ip`] in reverse order.
#[inline(always)]
pub(crate) fn inverse_ip(l: u32, r: u32) -> (u32, u32) {
    let (mut l, mut r) = (l, r);
    let mut t;
    t = ((l >> 1) ^ r) & 0x5555_5555;
    r ^= t;
    l ^= t << 1;
    t = ((r >> 8) ^ l) & 0x00FF_00FF;
    l ^= t;
    r ^= t << 8;
    t = ((r >> 2) ^ l) & 0x3333_3333;
    l ^= t;
    r ^= t << 2;
    t = ((l >> 16) ^ r) & 0x0000_FFFF;
    r ^= t;
    l ^= t << 16;
    t = ((l >> 4) ^ r) & 0x0F0F_0F0F;
    r ^= t;
    l ^= t << 4;
    (l, r)
}

/// `K xor E(R)` (Table 1 and eq (6)) as six input planes for the S-box layer.
///
/// `lo` and `hi` are the two words of the round key: nibble `i` of `lo` holds bits 2-5 of `Bi`'s
/// key block in the same positions as `R`'s nibble holds bits 2-5 of `E(R)`, so for those four
/// planes the XOR is done once on the words before spreading. Bits 1 and 6 come from the
/// neighbouring nibbles of `R` -- the nibble above (a rotate right by 4 brings it down) and the
/// nibble below (rotate left by 4) -- and from bits 0 and 1 of `hi`'s nibble.
#[inline(always)]
pub(crate) fn planes(r: u32, lo: u32, hi: u32) -> [u32; 6] {
    let rk = r ^ lo;
    [
        // b1: bit 4i-4 of R, the last bit of the previous nibble (bit 32 for i = 1).
        spread((r.rotate_right(4) & NIBBLE_LSB) ^ (hi & NIBBLE_LSB)),
        // b2..b5: bits 4i-3 .. 4i of R, the nibble itself, most significant first.
        spread((rk >> 3) & NIBBLE_LSB),
        spread((rk >> 2) & NIBBLE_LSB),
        spread((rk >> 1) & NIBBLE_LSB),
        spread(rk & NIBBLE_LSB),
        // b6: bit 4i+1 of R, the first bit of the next nibble (bit 1 for i = 8).
        spread(((r.rotate_left(4) >> 3) & NIBBLE_LSB) ^ ((hi >> 1) & NIBBLE_LSB)),
    ]
}

/// The permutation `P` (Sec 2.3, Table 3).
///
/// Output bit `k` is input bit `P[k]`, which in the word layout is a rotate left by `P[k] - k`
/// (mod 32). The 32 moves fall into nineteen distinct distances, so each line masks the input
/// bits that share a distance and rotates them together. The comment on each line lists those
/// input bits in the spec's numbering. Generated from Table 3 and checked against it by the tests.
#[inline(always)]
fn permute_p(y: u32) -> u32 {
    (y & 0x0000_0004).rotate_left(3) // 30
        | (y & 0x0000_4000).rotate_left(4) // 18
        | (y & 0x1202_0120).rotate_left(5) // 4, 7, 15, 24, 27
        | (y & 0x0010_0000).rotate_left(6) // 12
        | (y & 0x0000_8000).rotate_left(9) // 17
        | (y & 0x0400_0000).rotate_left(10) // 6
        | (y & 0x0000_0001).rotate_left(11) // 32
        | (y & 0x2000_0200).rotate_left(12) // 3, 23
        | (y & 0x0020_0000).rotate_left(13) // 11
        | (y & 0x0000_0040).rotate_left(14) // 26
        | (y & 0x0001_0000).rotate_left(15) // 16
        | (y & 0x0000_0002).rotate_left(16) // 31
        | (y & 0x4080_1800).rotate_left(17) // 2, 9, 20, 21
        | (y & 0x0008_0000).rotate_left(19) // 13
        | (y & 0x0000_0010).rotate_left(21) // 28
        | (y & 0x0100_0000).rotate_left(22) // 8
        | (y & 0x8800_0008).rotate_left(24) // 1, 5, 29
        | (y & 0x0000_0480).rotate_left(25) // 22, 25
        | (y & 0x0044_2000).rotate_left(26) // 10, 14, 19
}

/// The function `f(R, K)` (Sec 2.3): `P(S1(B1) S2(B2) ... S8(B8))` with `B1..B8 = K xor E(R)`,
/// eqs (6) and (7).
#[inline(always)]
fn f(r: u32, lo: u32, hi: u32) -> u32 {
    permute_p(sbox_layer(&planes(r, lo, hi)))
}

/// The sixteen iterations of the DEA on an already-permuted block, returning the pre-output block.
///
/// Forward (Sec 2.1, eq (3)): `Ln = Rn-1`, `Rn = Ln-1 xor f(Rn-1, Kn)` for `n = 1..16`, and the
/// pre-output is `R16 L16` -- the final interchange, which is the `(r, l)` returned.
///
/// Inverse (Sec 2.2, eq (5)): "the very same algorithm ... taking care that at each iteration of
/// the computation, the same block of key bits K is used ... K16 is used in the first iteration,
/// K15 in the second, and so on, with K1 used in the 16th iteration." So `inverse` only reverses
/// the order in which the stored round keys are read; there is no second schedule. The direction
/// is not a secret, so selecting the round key with it is fine.
///
/// `IP` and `IP^-1` are the caller's business: TDEA (Sec 3.1) chains three of these, and the
/// `IP^-1` that ends one DEA transformation cancels the `IP` that begins the next, so
/// [`crate::tdes::TDES`] applies each permutation once around all forty-eight rounds. Every
/// intermediate value is identical to the spec's; only two redundant permutations are skipped.
#[inline(always)]
pub(crate) fn rounds(l: u32, r: u32, sk: &Subkeys, inverse: bool) -> (u32, u32) {
    let (mut l, mut r) = (l, r);
    for n in 0..16 {
        let round = if inverse { 15 - n } else { n };
        let t = l ^ f(r, sk[2 * round], sk[2 * round + 1]);
        l = r;
        r = t;
    }
    (r, l)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `IP` as printed in Sec 2.1: entry `k` (0-based) is the input bit that becomes output bit
    /// `k + 1`.
    #[rustfmt::skip]
    const IP_TABLE: [u8; 64] = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
    ];

    /// `IP^-1` as printed in Sec 2.1.
    #[rustfmt::skip]
    const INVERSE_IP_TABLE: [u8; 64] = [
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25,
    ];

    /// `E`, Table 1: entry `k` is the bit of `R` that becomes bit `k + 1` of the 48-bit `E(R)`.
    #[rustfmt::skip]
    const E_TABLE: [u8; 48] = [
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1,
    ];

    /// `P`, Table 3.
    #[rustfmt::skip]
    const P_TABLE: [u8; 32] = [
        16,  7, 20, 21,
        29, 12, 28, 17,
         1, 15, 23, 26,
         5, 18, 31, 10,
         2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25,
    ];

    /// Applies a table-defined bit permutation to a 64-bit block, spec numbering (bit 1 = MSB).
    fn permute64(table: &[u8; 64], input: u64) -> u64 {
        let mut out = 0u64;
        for (k, &src) in table.iter().enumerate() {
            let bit = (input >> (64 - src as u32)) & 1;
            out |= bit << (63 - k);
        }
        out
    }

    fn to_words(x: u64) -> (u32, u32) {
        ((x >> 32) as u32, x as u32)
    }

    fn from_words(l: u32, r: u32) -> u64 {
        ((l as u64) << 32) | r as u64
    }

    #[test]
    fn test_ip_matches_the_table_on_every_unit_vector() {
        // A bit permutation is linear, so agreement on the 64 unit vectors is agreement everywhere.
        for k in 0..64 {
            let input = 1u64 << k;
            let (l, r) = to_words(input);
            let (l, r) = ip(l, r);
            assert_eq!(from_words(l, r), permute64(&IP_TABLE, input), "IP, input bit {}", 64 - k);
        }
    }

    #[test]
    fn test_inverse_ip_matches_the_table_on_every_unit_vector() {
        for k in 0..64 {
            let input = 1u64 << k;
            let (l, r) = to_words(input);
            let (l, r) = inverse_ip(l, r);
            assert_eq!(
                from_words(l, r),
                permute64(&INVERSE_IP_TABLE, input),
                "IP^-1, bit {}",
                64 - k
            );
        }
    }

    #[test]
    fn test_the_two_tables_are_inverses() {
        // Not a test of this code, but of the transcription: Sec 2.1 says IP^-1 inverts IP.
        for k in 0..64 {
            let input = 1u64 << k;
            assert_eq!(permute64(&INVERSE_IP_TABLE, permute64(&IP_TABLE, input)), input);
        }
    }

    #[test]
    fn test_p_matches_table_3_on_every_unit_vector() {
        for k in 0..32 {
            let input = 1u32 << k;
            let mut expected = 0u32;
            for (o, &src) in P_TABLE.iter().enumerate() {
                let bit = (input >> (32 - src as u32)) & 1;
                expected |= bit << (31 - o);
            }
            assert_eq!(permute_p(input), expected, "P, input bit {}", 32 - k);
        }
    }

    /// `E(R)` per Table 1, as the six planes the S-box layer expects: plane `j` holds bit `j + 1` of
    /// `Bi` in all four bits of nibble `i`.
    fn e_planes_reference(r: u32) -> [u32; 6] {
        let mut x = [0u32; 6];
        for (k, &src) in E_TABLE.iter().enumerate() {
            let bit = (r >> (32 - src as u32)) & 1;
            let (i, j) = (k / 6, k % 6); // block i (0-based), input bit j
            x[j] |= spread(bit << (28 - 4 * i));
        }
        x
    }

    /// The compact round-key words unpacked to the same plane layout: `lo`'s nibble `i` holds key
    /// block bits 2-5 (bit 2 at the top), `hi`'s nibble holds bit 1 at bit 0 and bit 6 at bit 1.
    fn key_planes_reference(lo: u32, hi: u32) -> [u32; 6] {
        let mut x = [0u32; 6];
        for i in 0..8 {
            let shift = 28 - 4 * i;
            let nib_lo = (lo >> shift) & 0xF;
            let nib_hi = (hi >> shift) & 0xF;
            let bits = [
                nib_hi & 1,
                nib_lo >> 3,
                (nib_lo >> 2) & 1,
                (nib_lo >> 1) & 1,
                nib_lo & 1,
                (nib_hi >> 1) & 1,
            ];
            for j in 0..6 {
                x[j] |= spread(bits[j] << shift);
            }
        }
        x
    }

    #[test]
    fn test_planes_match_table_1_on_every_unit_vector() {
        for k in 0..32 {
            let r = 1u32 << k;
            assert_eq!(planes(r, 0, 0), e_planes_reference(r), "E, input bit {}", 32 - k);
        }
    }

    #[test]
    fn test_planes_xor_the_round_key_in_the_documented_layout() {
        let mut seed = 0x9E37_79B9u32;
        let mut next = || {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            seed
        };
        for _ in 0..500 {
            let r = next();
            let lo = next();
            let hi = next() & 0x3333_3333; // only bits 0 and 1 of each nibble are used
            let e = e_planes_reference(r);
            let kp = key_planes_reference(lo, hi);
            let expected: [u32; 6] = core::array::from_fn(|j| e[j] ^ kp[j]);
            assert_eq!(planes(r, lo, hi), expected);
        }
    }

    #[test]
    fn test_inverse_rounds_undo_forward_rounds() {
        // With arbitrary round keys the sixteen iterations are still a permutation, and reading the
        // keys backwards inverts it (Sec 2.2). This checks the Feistel plumbing independently of
        // the key schedule.
        let mut sk = [0u32; 32];
        for (i, w) in sk.iter_mut().enumerate() {
            *w = (i as u32).wrapping_mul(0x9E37_79B9) ^ 0x5A5A_1234;
        }
        for (l, r) in [(0u32, 0u32), (u32::MAX, 0), (0x0123_4567, 0x89AB_CDEF), (1, 1 << 31)] {
            let (a, b) = rounds(l, r, &sk, false);
            assert_ne!((a, b), (l, r));
            assert_eq!(rounds(a, b, &sk, true), (l, r));
        }
    }
}
