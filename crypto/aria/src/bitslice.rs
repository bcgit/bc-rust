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
//! The transpose is [`bouncycastle_utils::bitslice::ortho`], shared with the other bit-sliced
//! ciphers; it transposes within each byte-lane, so the number of byte-lanes per word does not
//! enter into it, and this crate instantiates it at `u16`.

/// The eight bit-planes holding the two 16-bit halves of one word from each of four blocks. See
/// the module docs.
pub(crate) type Planes = [u16; 8];

pub(crate) use bouncycastle_utils::bitslice::ortho;

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
