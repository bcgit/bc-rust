//! Bit-plane transposition for the constant-time S-box layer.
//!
//! # Layout
//!
//! The F-function substitutes the eight bytes of one 64-bit word per round (RFC 3713 Sec 2.4.1,
//! `t1 .. t8`). To evaluate the S-boxes as a Boolean circuit, the 64-bit inputs of four blocks
//! are split into 32-bit halves -- eight words -- and transposed so that plane `q[k]` holds bit
//! `k` of every one of the 32 bytes:
//!
//! ```text
//! before ortho:  q[w] bit (8L + k)  ==  bit k of byte L of word w
//! after ortho:   q[k] bit (8L + w)  ==  bit k of byte L of word w
//! ```
//!
//! That is, within each byte-lane `L` of the eight words, the 8x8 bit matrix indexed by
//! (word, bit-within-lane) is transposed. Byte `L` is bits `8L .. 8L+7` of the word. The S-box
//! layer in [`crate::sbox`] loads word `b` with the high half (`t1 .. t4`) of block `b`'s input
//! and word `4 + b` with the low half (`t5 .. t8`), so that within a plane the bits `8L .. 8L+3`
//! are byte `L` of the four high halves and `8L+4 .. 8L+7` byte `L` of the four low halves. Which
//! of the four S-boxes a byte position gets is therefore a public 32-bit mask.
//!
//! `test_layout_matches_the_documented_table` pins the identity above exhaustively.
//!
//! # Why 32-bit planes
//!
//! Eight `u64` planes would hold the whole input of eight blocks and double the throughput on a
//! 64-bit machine, at the cost of doubling every buffer in the round: the working state, the
//! planes, and their copy during the byte rotations. This crate takes the smaller working set --
//! that is what "lowmemory" means here -- and processes four blocks per pass.
//!
//! # Provenance
//!
//! The three-stage masked-swap transpose is the same one `bouncycastle-aes` and
//! `bouncycastle-sm4` use, all three translated from BearSSL `src/symcipher/aes_ct.c`
//! (`br_aes_ct_ortho`) by Thomas Pornin, MIT licensed. It is duplicated rather than shared because
//! it is each crate's private detail and none should depend on another.

/// The eight bit-planes holding the two 32-bit halves of one word from each of four blocks. See
/// the module docs.
pub(crate) type Planes = [u32; 8];

/// Transposes bytes into bit-planes, and back -- it is its own inverse.
///
/// Three stages of masked swaps exchange bit-fields of width 1, 2 and 4 between pairs of words,
/// which together transpose the 8x8 bit matrix inside each byte-lane.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ortho_is_an_involution() {
        let mut q: Planes = core::array::from_fn(|i| 0x0123_4567u32.wrapping_mul(i as u32 + 3));
        let original = q;
        ortho(&mut q);
        assert_ne!(q, original, "ortho must actually move bits");
        ortho(&mut q);
        assert_eq!(q, original);
    }

    #[test]
    fn test_layout_matches_the_documented_table() {
        // A single set bit at (word w, byte-lane L, bit k) must land at (plane k, lane L, bit w).
        for w in 0..8 {
            for lane in 0..4 {
                for k in 0..8 {
                    let mut q: Planes = [0; 8];
                    q[w] = 1 << (8 * lane + k);
                    ortho(&mut q);
                    let mut expected: Planes = [0; 8];
                    expected[k] = 1 << (8 * lane + w);
                    assert_eq!(q, expected, "word {w}, lane {lane}, bit {k}");
                }
            }
        }
    }
}
