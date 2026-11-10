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
//! The transpose is [`bouncycastle_utils::bitslice::ortho`], shared with the other bit-sliced
//! ciphers; it transposes within each byte-lane, so the number of byte-lanes per word does not
//! enter into it, and this crate instantiates it at `u32`.

/// The eight bit-planes holding the two 32-bit halves of one word from each of four blocks. See
/// the module docs.
pub(crate) type Planes = [u32; 8];

pub(crate) use bouncycastle_utils::bitslice::ortho;

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
