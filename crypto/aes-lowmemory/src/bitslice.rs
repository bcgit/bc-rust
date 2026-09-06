//! Conversion functions between AES blocks and the bit-sliced representation the round functions act on.
//!
//! The round functions in [`crate::round`] and the S-box in [`crate::sbox`] opperate accourding to
//! circuit `SLP_AES_113.txt` from
//! Peralta's circuit collection, described in J. Boyar and R. Peralta, "A new combinational logic
//! minimization technique with applications to cryptology", <https://eprint.iacr.org/2009/191.pdf>.
//! Its fundamental innovation is to take the 16 bytes of the state and effectively transpose it into
//! 8 u16's where the i'th u16 holds the i'th bit of each byte of the state.
//! That is what lets the S-box be a Boolean circuit: one
//! `&` or `^` on a plane applies that gate to all sixteen byte positions at once, and no memory
//! access is ever indexed by a secret value.
//! This implementation handles two input blocks at a time, so the planes are in fact u32's still with
//! 8 lanes.

use crate::aes::Block;
use bouncycastle_utils::secret::Secret;

/// The eight bit-planes holding two blocks. See the module docs for the layout.
pub(crate) type Planes = [u32; 8];

/// Transposes bytes into bit-planes, and back -- it is its own inverse.
///
/// Translated from BearSSL `aes_ct.c:br_aes_ct_ortho` (the `SWAP2`/`SWAP4`/`SWAP8` macros).
pub(crate) fn ortho(q: &mut Planes) {
    /// One masked swap: exchanges the `cl`-selected fields of `y` into `x` and the `ch`-selected
    /// fields of `x` into `y`, moving them by `s` bit positions.
    ///
    /// `cl` and `ch` are complementary, and `s` is exactly the field width, so in each returned
    /// word the two combined operands occupy disjoint bits: `(x & cl)` and `(y & cl) << s` cannot
    /// both be set in the same position.
    ///
    /// Mutants note: `|` and `^` compute the same function here.
    #[inline(always)]
    fn swap(cl: u32, ch: u32, s: u32, x: u32, y: u32) -> (u32, u32) {
        ((x & cl) | ((y & cl) << s), ((x & ch) >> s) | (y & ch))
    }

    // Stage 1: swap single bits between adjacent words (0x55 = even bits, 0xAA = odd bits).
    for (a, b) in [(0, 1), (2, 3), (4, 5), (6, 7)] {
        (q[a], q[b]) = swap(0x5555_5555, 0xAAAA_AAAA, 1, q[a], q[b]);
    }
    // Stage 2: swap 2-bit fields between words two apart.
    for (a, b) in [(0, 2), (1, 3), (4, 6), (5, 7)] {
        (q[a], q[b]) = swap(0x3333_3333, 0xCCCC_CCCC, 2, q[a], q[b]);
    }
    // Stage 3: swap nibbles between words four apart.
    for (a, b) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
        (q[a], q[b]) = swap(0x0F0F_0F0F, 0xF0F0_F0F0, 4, q[a], q[b]);
    }
}

/// Loads two blocks into the bit-planes.
///
/// Block `a` goes into the even words and block `b` into the odd words as little-endian `u32`s,
/// then [`ortho`] transposes them into planes.
///
/// As this represents the working state of the block cipher, it is wrapped in [`Secret`].
pub(crate) fn pack(a: &Block, b: &Block) -> Secret<Planes> {
    let mut q = Secret::<[u32; 8]>::new();
    for c in 0..4 {
        // `try_into` cannot fail: the slice is a fixed 4-byte window of a 16-byte array.
        q[2 * c] = u32::from_le_bytes(a[4 * c..4 * c + 4].try_into().unwrap());
        q[2 * c + 1] = u32::from_le_bytes(b[4 * c..4 * c + 4].try_into().unwrap());
    }
    ortho(&mut q);
    q
}

/// Reads two blocks back out of the bit-planes; the exact inverse of [`pack`].
pub(crate) fn unpack(q: &Planes, a: &mut Block, b: &mut Block) {
    let mut q = *q;
    ortho(&mut q);
    for c in 0..4 {
        a[4 * c..4 * c + 4].copy_from_slice(&q[2 * c].to_le_bytes());
        b[4 * c..4 * c + 4].copy_from_slice(&q[2 * c + 1].to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic byte generator, so the tests do not depend on an RNG crate.
    pub(crate) fn pseudo_random_block(seed: u32) -> Block {
        let mut state = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        let mut out = [0u8; 16];
        for byte in out.iter_mut() {
            // xorshift32; quality is irrelevant, only that it varies every bit position.
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = (state >> 24) as u8;
        }
        out
    }

    #[test]
    fn test_layout_matches_the_documented_table() {
        // Pins the module doc table: q[k] bit (8r + 2c) is bit k of s[r,c] of block A, and
        // bit (8r + 2c + 1) is bit k of s[r,c] of block B. Every mask in `round` depends on it.
        let a = pseudo_random_block(1);
        let b = pseudo_random_block(2);
        let q = pack(&a, &b);

        for j in 0..16 {
            let (r, c) = (j % 4, j / 4);
            let pos = 8 * r + 2 * c;
            for (k, plane) in q.iter().enumerate() {
                assert_eq!(
                    (plane >> pos) & 1,
                    u32::from((a[j] >> k) & 1),
                    "block A: plane {k} bit {pos} should be bit {k} of byte {j}"
                );
                assert_eq!(
                    (plane >> (pos + 1)) & 1,
                    u32::from((b[j] >> k) & 1),
                    "block B: plane {k} bit {} should be bit {k} of byte {j}",
                    pos + 1
                );
            }
        }
    }

    #[test]
    fn test_ortho_is_an_involution() {
        let mut q = [
            0x0123_4567, 0x89AB_CDEF, 0xFEDC_BA98, 0x7654_3210, 0xDEAD_BEEF, 0x0000_0001,
            0xFFFF_FFFF, 0xA5A5_5A5A,
        ];
        let original = q;
        ortho(&mut q);
        assert_ne!(q, original, "ortho should actually move bits");
        ortho(&mut q);
        assert_eq!(q, original);
    }

    #[test]
    fn test_unpack_inverts_pack() {
        for seed in 0..64 {
            let a = pseudo_random_block(seed);
            let b = pseudo_random_block(seed + 1000);
            let mut out_a = [0u8; 16];
            let mut out_b = [0u8; 16];
            unpack(&pack(&a, &b), &mut out_a, &mut out_b);
            assert_eq!(out_a, a);
            assert_eq!(out_b, b);
        }
    }

    #[test]
    fn test_the_two_halves_are_independent() {
        // Changing block B must not disturb block A anywhere in the round-function pipeline;
        // this pins that the interleave really is bit-parallel and not overlapping.
        let a = pseudo_random_block(7);
        let mut out_a1 = [0u8; 16];
        let mut out_a2 = [0u8; 16];
        let mut scratch = [0u8; 16];
        unpack(&pack(&a, &[0u8; 16]), &mut out_a1, &mut scratch);
        unpack(&pack(&a, &pseudo_random_block(9)), &mut out_a2, &mut scratch);
        assert_eq!(out_a1, out_a2);
        assert_eq!(out_a1, a);
    }
}
