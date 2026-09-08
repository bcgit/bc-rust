//! The selection functions S1..S8 (SP 800-67r2 Sec 2.3 and Appendix A), evaluated as a Boolean
//! circuit rather than by table lookup.
//!
//! # The tables are only used at compile time
//!
//! [`S_BOXES`] is Appendix A transcribed verbatim, in the spec's own row/column layout so that it can
//! be checked against the document by eye. Nothing indexes it at run time. Instead [`ANF`] is
//! derived from it in a `const fn`, and the run-time S-box layer is a fixed straight-line program
//! over that derived constant: every step is an AND or an XOR of whole words, so no memory access
//! and no branch depends on the data.
//!
//! # T-boxes
//!
//! The eight 6-to-4-bit S-boxes are viewed as thirty-two 6-to-1-bit functions, one per output bit
//! -- "T-boxes", in BearSSL's terminology. T-box `pos` (0..32) produces bit `pos` of the 32-bit
//! block `S1(B1) S2(B2) ... S8(B8)` of eq (7), so it belongs to S-box `8 - pos / 4` and is its
//! output bit `4 - pos % 4` (the spec numbers the four output bits of an S-box left to right, and
//! spec bit 1 of the 32-bit block is the most significant bit of the word).
//!
//! A T-box is a Boolean function of six inputs, and every Boolean function has a unique algebraic
//! normal form (ANF): an XOR of monomials, each monomial an AND of some subset of the inputs. With
//! the inputs of S-box `i` replicated across the four bit positions of its T-boxes (see
//! [`crate::des`] for how the six input planes are built), a single `&` or `^` on a `u32` applies
//! one gate to all thirty-two T-boxes at once. [`ANF`] holds the coefficients: `ANF[k]` bit `pos`
//! is the coefficient, in T-box `pos`, of the monomial whose variables are the set bits of `k`
//! (bit 5 of `k` is `b1`, bit 0 is `b6`, matching the spec's left-to-right order of the six input
//! bits). It is computed from the truth tables by the Mobius transform, the standard butterfly
//! that turns a truth table into ANF coefficients.
//!
//! # Evaluating the ANF
//!
//! [`sbox_layer`] evaluates all thirty-two ANFs by Horner's scheme over one variable at a time:
//! `f = g ^ (b & h)`, where `g` collects the monomials without `b` and `h` those with it, each a
//! smaller ANF in the remaining variables. Peeling off `b6`, then `b5`, and so on to `b1` gives a
//! binary tree of 63 such steps -- 32 on the constants, 16, 8, 4, 2 and 1 -- i.e. 63 ANDs and 63
//! XORs for the whole S-box layer. BearSSL's `des_ct.c` describes the same tree as "fake
//! multiplexers"; the coefficients here are derived rather than hard-coded, so that the S-box
//! tables remain the only DES-specific constants in the source.
//!
//! One consequence worth knowing: every output bit of every DES S-box is a balanced function (each
//! row of each table is a permutation of 0..15), and a balanced function never contains the
//! full-degree monomial, so `ANF[63]` is zero and the compiler drops that AND. The tests pin both
//! facts.

/// The eight selection functions, SP 800-67r2 Appendix A (identical in FIPS 46-3 Appendix 1).
///
/// `S_BOXES[i][row][col]` is the entry S-box `i + 1` gives for the 6-bit input `B` whose first and
/// last bits form `row` and whose middle four bits form `col` (Sec 2.3, the paragraph under
/// Table 2). Laid out exactly as printed in the standard, four rows of sixteen per box.
#[rustfmt::skip]
pub(crate) const S_BOXES: [[[u8; 16]; 4]; 8] = [
    // S1
    [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    // S2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    // S3
    [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    // S4
    [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    // S5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    ],
    // S6
    [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    // S7
    [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    // S8
    [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ],
];

/// `Si(B)` exactly as Sec 2.3 describes the lookup: `B` is the 6-bit input with its first bit as
/// bit 5 and its last bit as bit 0; the first and last bits select the row, the middle four the
/// column.
///
/// Used only at compile time (by [`anf_constants`]) and in the tests. Never on secret data.
pub(crate) const fn lookup(sbox: usize, b: usize) -> u8 {
    let row = ((b >> 5) & 1) << 1 | (b & 1);
    let col = (b >> 1) & 0xF;
    S_BOXES[sbox][row][col]
}

/// T-box `pos`: bit `pos` of the 32-bit block `S1(B1) ... S8(B8)` (eq (7)) as a function of the
/// 6-bit input of its own S-box.
///
/// S1's four output bits are spec bits 1-4 of the block, i.e. word bits 31 down to 28, so S-box
/// `8 - pos / 4` (numbered from 1) feeds `pos`, and `pos % 4 == 3` is that S-box's leftmost output
/// bit -- the most significant bit of the table entry.
const fn tbox(pos: usize, b: usize) -> u32 {
    let entry = lookup(7 - pos / 4, b) as u32;
    (entry >> (pos % 4)) & 1
}

/// Derives [`ANF`]: truth tables first, then the Mobius transform.
///
/// The transform is the usual butterfly -- for each variable, XOR the value at "variable clear"
/// into the value at "variable set" -- and because it is bitwise it runs on all 32 T-boxes at once,
/// one word per input value.
const fn anf_constants() -> [u32; 64] {
    // c[b] bit pos = T-box pos evaluated at input b: the truth tables, one word per input.
    let mut c = [0u32; 64];
    let mut b = 0;
    while b < 64 {
        let mut pos = 0;
        while pos < 32 {
            c[b] |= tbox(pos, b) << pos;
            pos += 1;
        }
        b += 1;
    }

    // Mobius transform: afterwards c[k] is the coefficient of the monomial over the set bits of k.
    let mut var = 1;
    while var < 64 {
        let mut k = 0;
        while k < 64 {
            if k & var != 0 {
                c[k] ^= c[k ^ var];
            }
            k += 1;
        }
        var <<= 1;
    }
    c
}

/// ANF coefficients of all thirty-two T-boxes. See the module docs.
///
/// Index `k` names a monomial by its variables: bit 5 of `k` is `b1` (the first of the six input
/// bits, in the spec's order), bit 0 is `b6`. Bit `pos` of `ANF[k]` is that monomial's coefficient
/// in T-box `pos`.
pub(crate) const ANF: [u32; 64] = anf_constants();

/// The S-box layer: `S1(B1) S2(B2) ... S8(B8)` for all eight S-boxes at once (eq (7)).
///
/// `x[j]` is the input plane for `b(j+1)`: for every S-box `i`, all four bit positions of the
/// nibble that will hold `Si(Bi)` carry input bit `j+1` of `Bi`. The result has `Si(Bi)` in that
/// nibble, leftmost output bit in the nibble's most significant bit -- which is the spec's
/// bit order for the consolidated 32-bit block, so the result feeds `P` directly.
///
/// Horner's scheme over the ANF, one variable per level, `b6` first. At each level `y[w]` becomes
/// the ANF in the remaining variables of the monomials that agree with the bits of `w` on the
/// variables already consumed; the pair `(y[2w], y[2w+1])` differs only in the variable being
/// consumed, so `y[2w] ^ (b & y[2w+1])` fixes it.
#[inline(always)]
pub(crate) fn sbox_layer(x: &[u32; 6]) -> u32 {
    let mut y = [0u32; 32];
    // Level b6: pairs of constants, ANF[2u] (monomials without b6) and ANF[2u + 1] (with it).
    for (u, yu) in y.iter_mut().enumerate() {
        *yu = ANF[2 * u] ^ (x[5] & ANF[2 * u + 1]);
    }
    // Levels b5 down to b2. Each writes y[w] from y[2w] and y[2w + 1]; ascending w never reads an
    // entry already overwritten at this level, because 2w >= w.
    for w in 0..16 {
        y[w] = y[2 * w] ^ (x[4] & y[2 * w + 1]);
    }
    for w in 0..8 {
        y[w] = y[2 * w] ^ (x[3] & y[2 * w + 1]);
    }
    for w in 0..4 {
        y[w] = y[2 * w] ^ (x[2] & y[2 * w + 1]);
    }
    for w in 0..2 {
        y[w] = y[2 * w] ^ (x[1] & y[2 * w + 1]);
    }
    // Level b1: the root.
    y[0] ^ (x[0] & y[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Puts the 6-bit input `b` into the plane layout for S-box `sbox` (0-based) only; every other
    /// S-box sees an all-zero input.
    fn planes_for(sbox: usize, b: usize) -> [u32; 6] {
        let nibble = 0xFu32 << (28 - 4 * sbox);
        let mut x = [0u32; 6];
        for (j, plane) in x.iter_mut().enumerate() {
            // b's bit 5 is b1, i.e. x[0].
            if (b >> (5 - j)) & 1 == 1 {
                *plane = nibble;
            }
        }
        x
    }

    #[test]
    fn test_every_row_of_every_sbox_is_a_permutation() {
        // A property of the DES S-boxes (each row is a permutation of 0..15), and a cheap check on
        // the transcription: a repeated or dropped digit breaks it.
        for (i, sbox) in S_BOXES.iter().enumerate() {
            for (r, row) in sbox.iter().enumerate() {
                let mut seen = [false; 16];
                for &v in row {
                    assert!(!seen[v as usize], "S{} row {r}: {v} appears twice", i + 1);
                    seen[v as usize] = true;
                }
            }
        }
    }

    #[test]
    fn test_lookup_matches_the_worked_example_in_sec_2_3() {
        // "for input 011011, the row is 01 (i.e., row 1), and the column is determined by 1101
        // (i.e., column 13). The number 5 appears in row 1, column 13, so the output is 0101."
        assert_eq!(lookup(0, 0b011011), 5);
    }

    #[test]
    fn test_sbox_layer_matches_the_tables_exhaustively() {
        // 8 S-boxes x 64 inputs, one S-box at a time so the other nibbles can be masked away.
        for sbox in 0..8 {
            for b in 0..64 {
                let out = sbox_layer(&planes_for(sbox, b));
                let nibble = (out >> (28 - 4 * sbox)) & 0xF;
                assert_eq!(
                    nibble as u8,
                    lookup(sbox, b),
                    "S{} input {b:06b}: circuit gave {nibble:x}",
                    sbox + 1
                );
            }
        }
    }

    #[test]
    fn test_sbox_layer_evaluates_all_eight_independently() {
        // All eight S-boxes at once, with different inputs, must equal eight separate lookups.
        let mut seed = 0x1234_5678u32;
        for _ in 0..2000 {
            let mut inputs = [0usize; 8];
            let mut x = [0u32; 6];
            for (sbox, input) in inputs.iter_mut().enumerate() {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                *input = (seed >> 13) as usize & 0x3F;
                let p = planes_for(sbox, *input);
                for j in 0..6 {
                    x[j] |= p[j];
                }
            }
            let out = sbox_layer(&x);
            for (sbox, &input) in inputs.iter().enumerate() {
                let nibble = (out >> (28 - 4 * sbox)) & 0xF;
                assert_eq!(nibble as u8, lookup(sbox, input));
            }
        }
    }

    #[test]
    fn test_full_degree_monomial_is_absent() {
        // Balanced functions have no degree-6 term, so the top coefficient is zero in every T-box.
        assert_eq!(ANF[63], 0);
        // ...and the constant term is the value at input 0.
        for pos in 0..32 {
            assert_eq!((ANF[0] >> pos) & 1, tbox(pos, 0));
        }
    }
}
