//! Bit-plane transposition for the constant-time S-boxes.
//!
//! # Layout
//!
//! A substitution layer applies one of the four S-boxes to each byte of the state (RFC 5794
//! Sec 2.4.2). The four bytes of a block that share an S-box form one 32-bit *class word* (see
//! [`crate::round`]). To evaluate an S-box as a Boolean circuit, the class words of four
//! independent blocks are split into 16-bit halves, eight words in all, and transposed so that
//! plane `q[k]` holds bit `k` of every one of the 16 bytes:
//!
//! ```text
//! before ortho:  q[w] bit (8L + k)  ==  bit k of byte L of half-word w
//! after ortho:   q[k] bit (8L + w)  ==  bit k of byte L of half-word w
//! ```
//!
//! That is, within each byte-lane `L` of the eight half-words, the 8x8 bit matrix indexed by
//! (half-word, bit-within-lane) is transposed. Which byte of which word is "byte `L` of half-word
//! `w`" does not matter to an S-box, which is applied to every byte independently; only that the
//! same byte comes back to the same place, which [`ortho`] being its own inverse guarantees.
//!
//! `test_layout_matches_the_documented_table` pins the identity above exhaustively.
//!
//! # Why 16-bit planes
//!
//! Eight `u32` planes would hold one class word from each of eight blocks and double the
//! throughput on a 32- or 64-bit machine, at the cost of doubling every buffer in the round: the
//! working state and the planes. This crate takes the smaller working set -- that is what
//! "lowmemory" means here -- and processes four blocks per pass.
//!
//! # Provenance
//!
//! The three-stage masked-swap transpose is the one `bouncycastle-aes` and
//! `bouncycastle-camellia` use on `u32` words and `bouncycastle-sm4` on
//! `u16`: it transposes within each byte-lane, so the number of byte-lanes per word does not enter
//! into it. All of them are translated from BearSSL `src/symcipher/aes_ct.c` (`br_aes_ct_ortho`)
//! by Thomas Pornin, MIT licensed. It is duplicated rather than shared because it is each crate's
//! private detail and none should depend on another.

/// The eight bit-planes holding the two 16-bit halves of one word from each of four blocks. See
/// the module docs.
pub(crate) type Planes = [u16; 8];

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
    fn swap(cl: u16, ch: u16, s: u32, x: u16, y: u16) -> (u16, u16) {
        ((x & cl) | ((y & cl) << s), ((x & ch) >> s) | (y & ch))
    }

    // Stage 1: swap single bits between adjacent words (0x55 = even bits, 0xAA = odd bits).
    for (a, b) in [(0, 1), (2, 3), (4, 5), (6, 7)] {
        (q[a], q[b]) = swap(0x5555, 0xAAAA, 1, q[a], q[b]);
    }
    // Stage 2: swap 2-bit fields between words two apart.
    for (a, b) in [(0, 2), (1, 3), (4, 6), (5, 7)] {
        (q[a], q[b]) = swap(0x3333, 0xCCCC, 2, q[a], q[b]);
    }
    // Stage 3: swap nibbles between words four apart.
    for (a, b) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
        (q[a], q[b]) = swap(0x0F0F, 0xF0F0, 4, q[a], q[b]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ortho_is_an_involution() {
        let mut q: Planes = core::array::from_fn(|i| 0x0123u16.wrapping_mul(i as u16 * 37 + 3));
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
            for lane in 0..2 {
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
