//! The key schedule `KS` (SP 800-67r2 Sec 2.1 eq (2), Appendix A: PC-1, the schedule of left
//! shifts, and PC-2), and the weak-key test of Sec 3.3.2.
//!
//! # Storage
//!
//! `KS(n, KEY)` is a 48-bit block, `Kn`. Each is stored as two words, `[lo, hi]`, already arranged
//! for the round function: eq (6) splits `K xor E(R)` into eight 6-bit blocks, and
//! [`crate::des::planes`] builds `E(R)` nibble by nibble, so the key bits are packed to line up
//! with the nibble their block belongs to. For block `i` (1..8) of `Kn`, whose six bits are
//! `Kn[6i-5 .. 6i]`:
//!
//! ```text
//! lo, nibble i:  bit 3 = Kn[6i-4]   bit 2 = Kn[6i-3]   bit 1 = Kn[6i-2]   bit 0 = Kn[6i-1]
//! hi, nibble i:  bit 1 = Kn[6i]     bit 0 = Kn[6i-5]   (bits 2 and 3 unused)
//! ```
//!
//! Nibble 1 is the most significant nibble of the word, matching the block layout in
//! [`crate::des`]. Sixteen round keys of two words each is 128 bytes per DEA key, 384 bytes for a
//! TDEA bundle, against 48 x 16 = 768 bits = 96 bytes for the raw `Kn` values: the packing costs a
//! third more space and saves the round function from doing PC-2 or any per-round rearrangement.
//! The six full planes are not stored (that would be three times the size again); they are
//! spread from `lo` and `hi` on the stack, in the same operations that spread `E(R)`.
//!
//! # Constant time
//!
//! The key is secret. PC-1 and PC-2 are applied by iterating over their tables -- public constants
//! -- and extracting the named bit of the key with a shift by a public amount, so the only
//! data-dependent quantity is the bit value being ORed in. The 28-bit rotations are shifts by
//! public amounts. Nothing indexes memory by a key bit.

use crate::des::Subkeys;
use bouncycastle_utils::ct::ct_eq_zero_bytes;

/// PC-1 (Appendix A). Entries are bit numbers of `KEY` (1..64); the first 28 select `C0`, the
/// last 28 select `D0`: "The bits of C(0) are respectively bits 57, 49, 41, ..., 44 and 36 of
/// Key_i, with the bits of D(0) being bits 63, 55, 47, ..., 12 and 4 of Key_i."
#[rustfmt::skip]
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
];

/// The schedule of left shifts (Appendix A), iterations 1 to 16: "by a single left shift is meant
/// a rotation of the bits one place to the left".
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// PC-2 (Appendix A). Entries are bit numbers of `Cn Dn` (1..56): "the first bit of Kn is the 14th
/// bit of CnDn, the second bit of Kn is the 17th bit of CnDn, and so on, with the 47th bit of Kn as
/// the 29th bit of CnDn, and the 48th bit of Kn as the 32nd bit of CnDn."
#[rustfmt::skip]
const PC2: [u8; 48] = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
];

/// Clears the parity bit of each key byte: "Bits 8, 16, ..., 64 are used for assuring that each
/// byte is of odd parity. (Note that these eight parity bits have no effect on the operation of
/// the algorithm.)" -- Appendix A. PC-1 never selects them.
pub(crate) const PARITY_MASK: u64 = 0xFEFE_FEFE_FEFE_FEFE;

/// Bit `n` (1..64, bit 1 leftmost) of a 64-bit `KEY`.
#[inline(always)]
fn key_bit(key: u64, n: u8) -> u32 {
    ((key >> (64 - n as u32)) & 1) as u32
}

/// Bit `n` (1..56, bit 1 leftmost) of the 56-bit `Cn Dn`.
#[inline(always)]
fn cd_bit(cd: u64, n: u8) -> u32 {
    ((cd >> (56 - n as u32)) & 1) as u32
}

/// A left rotation of a 28-bit block held in the low 28 bits of a word.
#[inline(always)]
fn rotl28(x: u32, s: u32) -> u32 {
    ((x << s) | (x >> (28 - s))) & 0x0FFF_FFFF
}

/// PC-1: `(C0, D0)`, each 28 bits in the low bits of a word with its first bit uppermost.
fn pc1(key: u64) -> (u32, u32) {
    let mut c = 0u32;
    let mut d = 0u32;
    for j in 0..28 {
        c = (c << 1) | key_bit(key, PC1[j]);
        d = (d << 1) | key_bit(key, PC1[28 + j]);
    }
    (c, d)
}

/// Computes `K1..K16` for one 64-bit key and stores them packed as described in the module docs.
///
/// Appendix A: `Cn` and `Dn` are obtained from `Cn-1` and `Dn-1` by the schedule of left shifts,
/// and `Kn` is PC-2 applied to `Cn Dn`.
pub(crate) fn expand(key: u64, out: &mut Subkeys) {
    let (mut c, mut d) = pc1(key);
    for n in 0..16 {
        c = rotl28(c, SHIFTS[n]);
        d = rotl28(d, SHIFTS[n]);
        // Cn Dn as a 56-bit string, bit 1 uppermost.
        let cd = ((c as u64) << 28) | d as u64;

        let mut lo = 0u32;
        let mut hi = 0u32;
        for i in 0..8 {
            // Block i (0-based) of Kn is Kn bits 6i+1 .. 6i+6, i.e. PC2[6i] .. PC2[6i + 5].
            let b = |j: usize| cd_bit(cd, PC2[6 * i + j]);
            // Nibble i (0-based, nibble 0 uppermost) is word bits shift + 3 .. shift.
            let shift = 28 - 4 * i;
            lo |= ((b(1) << 3) | (b(2) << 2) | (b(3) << 1) | b(4)) << shift;
            hi |= (b(0) | (b(5) << 1)) << shift;
        }
        out[2 * n] = lo;
        out[2 * n + 1] = hi;
    }
}

/// Whether a DEA key is one of the 64 keys Sec 3.3.2 says to avoid: the 4 weak keys, the 12
/// semi-weak keys, or the 48 "possibly weak" keys "that produce only four distinct subkeys
/// (instead of 16)".
///
/// All three lists share one structure, which is what this checks instead of comparing against a
/// table: after PC-1, `C0` and `D0` are each a 28-bit pattern of period 4 (all zeros, all ones,
/// `0101...`, `1010...`, `0011...`, `0110...`, `1100...` or `1001...`). The schedule only ever
/// rotates `C` and `D`, and a period-4 pattern has at most four distinct rotations, hence at most
/// four distinct subkeys -- one for the weak keys (period 1), two for the semi-weak (period 2),
/// four for the possibly weak. Eight patterns for `C0` times eight for `D0` is exactly 64 keys,
/// and PC-1 is a bijection on the 56 non-parity bits, so no other key has the property. The tests
/// enumerate the spec's three lists against this predicate and against that count.
///
/// Parity bits are not consulted (PC-1 does not select them), which is also how the spec's lists
/// are meant: "the weak keys listed above and the semi-weak keys and the possibly weak keys listed
/// below are expressed with odd parity".
///
/// Constant time: the two rotations and the comparison to zero do not branch on the key.
pub(crate) fn is_weak(key: u64) -> bool {
    let (c, d) = pc1(key);
    let period4 = (rotl28(c, 4) ^ c) | (rotl28(d, 4) ^ d);
    ct_eq_zero_bytes(&period4.to_be_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unpacks a stored round key back to its 48-bit `Kn` (bit 1 uppermost of the low 48 bits).
    fn unpack(lo: u32, hi: u32) -> u64 {
        let mut k = 0u64;
        for i in 0..8 {
            let shift = 28 - 4 * i;
            let nib_lo = ((lo >> shift) & 0xF) as u64;
            let nib_hi = ((hi >> shift) & 0xF) as u64;
            let block = ((nib_hi & 1) << 5) | (nib_lo << 1) | ((nib_hi >> 1) & 1);
            k = (k << 6) | block;
        }
        k
    }

    /// `KS(n, KEY)` written out the long way from Appendix A, as a 48-bit value.
    fn ks_reference(n: usize, key: u64) -> u64 {
        let (mut c, mut d) = pc1(key);
        for i in 0..n {
            c = rotl28(c, SHIFTS[i]);
            d = rotl28(d, SHIFTS[i]);
        }
        let cd = ((c as u64) << 28) | d as u64;
        let mut k = 0u64;
        for &src in PC2.iter() {
            k = (k << 1) | cd_bit(cd, src) as u64;
        }
        k
    }

    #[test]
    fn test_pc1_selects_no_parity_bit() {
        for &n in PC1.iter() {
            assert_ne!(n % 8, 0, "PC-1 must not select parity bit {n}");
        }
        // ...and selects each of the other 56 bits exactly once.
        let mut seen = [false; 65];
        for &n in PC1.iter() {
            assert!(!seen[n as usize], "PC-1 selects bit {n} twice");
            seen[n as usize] = true;
        }
        assert_eq!(seen.iter().filter(|&&s| s).count(), 56);
    }

    #[test]
    fn test_pc2_selects_48_distinct_bits() {
        let mut seen = [false; 57];
        for &n in PC2.iter() {
            assert!((1..=56).contains(&n));
            assert!(!seen[n as usize], "PC-2 selects bit {n} twice");
            seen[n as usize] = true;
        }
        assert_eq!(seen.iter().filter(|&&s| s).count(), 48);
    }

    #[test]
    fn test_shifts_total_28() {
        // Sixteen iterations bring C and D back to C0 and D0: the shifts sum to 28.
        assert_eq!(SHIFTS.iter().sum::<u32>(), 28);
    }

    #[test]
    fn test_packed_round_keys_unpack_to_the_reference_schedule() {
        let mut seed = 0x0123_4567_89AB_CDEFu64;
        for _ in 0..200 {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let key = seed;
            let mut sk = [0u32; 32];
            expand(key, &mut sk);
            for n in 0..16 {
                assert_eq!(
                    unpack(sk[2 * n], sk[2 * n + 1]),
                    ks_reference(n + 1, key),
                    "K{}",
                    n + 1
                );
                // Only bits 0 and 1 of each nibble of `hi` are ever set.
                assert_eq!(sk[2 * n + 1] & !0x3333_3333, 0);
            }
        }
    }

    #[test]
    fn test_parity_bits_do_not_affect_the_schedule() {
        let key = 0x0123_4567_89AB_CDEFu64;
        let mut a = [0u32; 32];
        let mut b = [0u32; 32];
        expand(key, &mut a);
        expand(key ^ !PARITY_MASK, &mut b);
        assert_eq!(a, b);
    }
}
