//! Conversion between AES blocks and the bit-sliced representation the round functions act on.
//!
//! # What "bit-sliced" means here
//!
//! The round functions in [`crate::round`] and the S-box in [`crate::sbox`] do not operate on
//! bytes. They operate on eight `u32` *bit-planes*, `q[0]..q[7]`, where plane `q[k]` collects
//! bit `k` of every byte of the state. That is what lets the S-box be a Boolean circuit: one
//! `&` or `^` on a plane applies that gate to all sixteen byte positions at once, and no memory
//! access is ever indexed by a secret value.
//!
//! Eight 32-bit planes hold 256 bits = 32 bytes, which is *two* 16-byte AES blocks. Both blocks
//! are always processed together; see the crate docs for why, and [`crate::aes`] for how a
//! single-block call fills the unused half.
//!
//! # The layout, derived
//!
//! [`ortho`] transposes, within each byte-lane of the eight words, the 8x8 bit matrix indexed by
//! (word number, bit number within the lane):
//!
//! ```text
//! after ortho:  q[k] bit (8L + i)  ==  before ortho:  q[i] bit (8L + k)
//! ```
//!
//! [`pack`] loads block A as four little-endian `u32`s into the even words and block B into the
//! odd words, so before `ortho` byte-lane `L` of word `2c` holds `A[4c + L]`. Substituting
//! `j = 4c + L` for the byte index, and FIPS 197 Eq (3.6) `s[r,c] = in[r + 4c]` -- which makes
//! `r = j mod 4` and `c = j div 4` -- gives the layout every mask in this crate depends on:
//!
//! ```text
//! q[k] bit (8r + 2c)      ==  bit k of s[r,c] of block A
//! q[k] bit (8r + 2c + 1)  ==  bit k of s[r,c] of block B
//! ```
//!
//! In words: **the byte-lane of the word selects the state row `r`, and the bit-pair within that
//! lane selects the state column `c`; the low bit of the pair is block A and the high bit is
//! block B.** Written out, the bit position of `s[r,c]` within every plane is:
//!
//! ```text
//!            c=0   c=1   c=2   c=3
//!    r=0 |    0     2     4     6
//!    r=1 |    8    10    12    14      (bit position of block A;
//!    r=2 |   16    18    20    22       add 1 for block B)
//!    r=3 |   24    26    28    30
//! ```
//!
//! This is why SHIFTROWS() becomes a rotation *within* a byte-lane (row `r` lives entirely in
//! lane `r`, and one column step is two bit positions), and why MIXCOLUMNS() uses rotations by
//! 8 and 16 (one and two rows). Both are derived from this table in [`crate::round`].
//!
//! `test_layout_matches_the_documented_table` below pins the table exhaustively; every mask in
//! this crate is only correct relative to it.
//!
//! # Provenance
//!
//! The three-stage masked-swap transpose and the even/odd two-block packing are translated from
//! BearSSL `src/symcipher/aes_ct.c` (`br_aes_ct_ortho`) and `aes_ct_cbcdec.c` (the `q[0]`,
//! `q[2]`, `q[4]`, `q[6]` load order), by Thomas Pornin, MIT licensed.

/// One 16-byte AES block, in the order of FIPS 197 Eq (3.6): `block[r + 4c] == s[r,c]`.
pub type Block = [u8; crate::BLOCK_LEN];

/// The eight bit-planes holding two blocks. See the module docs for the layout.
pub(crate) type Planes = [u32; 8];

/// Transposes bytes into bit-planes, and back -- it is its own inverse.
///
/// Three stages of masked swaps exchange bit-fields of width 1, 2 and 4 between pairs of words,
/// which together transpose the 8x8 bit matrix inside each byte-lane. See the module docs for
/// the resulting layout.
///
/// Translated from BearSSL `aes_ct.c:br_aes_ct_ortho` (the `SWAP2`/`SWAP4`/`SWAP8` macros).
pub(crate) fn ortho(q: &mut Planes) {
    /// One masked swap: exchanges the `cl`-selected fields of `y` into `x` and the `ch`-selected
    /// fields of `x` into `y`, moving them by `s` bit positions.
    ///
    /// `cl` and `ch` are complementary, and `s` is exactly the field width, so in each returned
    /// word the two combined operands occupy disjoint bits: `(x & cl)` and `(y & cl) << s` cannot
    /// both be set in the same position. `|` and `^` therefore compute the same function here,
    /// which is why `cargo mutants` reports the `| -> ^` mutants in this function as surviving --
    /// they are equivalent programs. `test_ortho_is_an_involution` and
    /// `test_layout_matches_the_documented_table` are what actually pin this code.
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
pub(crate) fn pack(a: &Block, b: &Block) -> Planes {
    let mut q = [0u32; 8];
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
