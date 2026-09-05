//! Bit-plane transposition for the constant-time S-box.
//!
//! # Layout
//!
//! The S-box is applied to the four bytes of one 32-bit word per round (`tau`, Sec 6.2.1). To
//! evaluate it as a Boolean circuit, eight such words -- one per block, for eight independent
//! blocks -- are transposed so that plane `q[k]` holds bit `k` of every one of the 32 bytes:
//!
//! ```text
//! before ortho:  q[b] bit (8L + k)  ==  bit k of byte L of block b's word
//! after ortho:   q[k] bit (8L + b)  ==  bit k of byte L of block b's word
//! ```
//!
//! That is, within each byte-lane `L` of the eight words, the 8x8 bit matrix indexed by
//! (word, bit-within-lane) is transposed. Which byte of the word is "byte `L`" does not matter
//! to the S-box, which is applied to every byte independently; only that the same byte comes back
//! to the same place, which [`ortho`] being its own inverse guarantees.
//!
//! `test_layout_matches_the_documented_table` pins the identity above exhaustively.
//!
//! # Provenance
//!
//! The three-stage masked-swap transpose is the same one `bouncycastle-aes` uses, both
//! translated from BearSSL `src/symcipher/aes_ct.c` (`br_aes_ct_ortho`) by Thomas Pornin, MIT
//! licensed. It is duplicated rather than shared because it is the AES crate's private detail
//! and neither crate should depend on the other.

/// The eight bit-planes holding one 32-bit word from each of eight blocks. See the module docs.
pub(crate) type Planes = [u32; 8];

/// Transposes bytes into bit-planes, and back -- it is its own inverse.
///
/// Three stages of masked swaps exchange bit-fields of width 1, 2 and 4 between pairs of words,
/// which together transpose the 8x8 bit matrix inside each byte-lane.
pub(crate) fn ortho(q: &mut Planes) {
    /// One masked swap: exchanges the `cl`-selected fields of `y` into `x` and the `ch`-selected
    /// fields of `x` into `y`, moving them by `s` bit positions.
    ///
    /// `cl` and `ch` are complementary and `s` is exactly the field width, so in each returned
    /// word the two combined operands occupy disjoint bits and `|` and `^` compute the same
    /// function. `cargo mutants` therefore reports the `| -> ^` mutants here as surviving; they
    /// are equivalent programs, and `test_ortho_is_an_involution` and
    /// `test_layout_matches_the_documented_table` are what pin this code.
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
        // A single set bit at (word b, byte-lane L, bit k) must land at (plane k, lane L, bit b).
        for b in 0..8 {
            for lane in 0..4 {
                for k in 0..8 {
                    let mut q: Planes = [0; 8];
                    q[b] = 1 << (8 * lane + k);
                    ortho(&mut q);
                    let mut expected: Planes = [0; 8];
                    expected[k] = 1 << (8 * lane + b);
                    assert_eq!(q, expected, "word {b}, lane {lane}, bit {k}");
                }
            }
        }
    }
}
