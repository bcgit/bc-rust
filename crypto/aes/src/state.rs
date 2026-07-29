//! The four byte-oriented transformations of the AES state, and their inverses.
//!
//! | Function | FIPS 197 | Inverse | FIPS 197 |
//! |----------|----------|---------|----------|
//! | [`sub_bytes`]    | Sec 5.1.1, Eq 5.2-5.4 | [`inv_sub_bytes`]    | Sec 5.3.2 |
//! | [`shift_rows`]   | Sec 5.1.2, Eq 5.5     | [`inv_shift_rows`]   | Sec 5.3.1, Eq 5.12 |
//! | [`mix_columns`]  | Sec 5.1.3, Eq 5.7-5.8 | [`inv_mix_columns`]  | Sec 5.3.3, Eq 5.14-5.15 |
//!
//! ADDROUNDKEY() is not here because it needs the key schedule; it lives with the engine in
//! [`crate::aes`].
//!
//! # The state layout, and why it is a flat 16-byte array
//!
//! FIPS 197 Section 3.4 defines the state as a 4x4 array of bytes `s[r, c]`, filled from the input
//! block by Eq (3.6):
//!
//! ```text
//! s[r, c] = in[r + 4c]     for 0 <= r < 4 and 0 <= c < 4
//! ```
//!
//! We store the state as a flat `[u8; 16]` in exactly that order, so `state[r + 4 * c]` *is*
//! `s[r, c]`, and copying a block in or out (Eq 3.6 and 3.7) is a plain 16-byte copy with no
//! transposition. In this layout a *column* is a contiguous 4-byte run -- `state[4c .. 4c + 4]` --
//! which is what MIXCOLUMNS() and ADDROUNDKEY() operate on, and it also matches the byte order of
//! a key schedule word (Section 3.5), so those two functions stay index-free.
//!
//! The tradeoff is that a *row* is strided by 4, which only SHIFTROWS() cares about; it is written
//! out longhand below.
//!
//! Every function here takes `&mut [u8; AES_BLOCK_LEN]`, so the block length is enforced by the
//! compiler rather than checked at runtime, and none of them can fail.

use crate::gf::{mul_0b, mul_0d, mul_0e, mul_02, mul_03, mul_09};
use crate::tables::{INVSBOX, SBOX};

/// The AES block length in bytes. Every AES variant has a 128-bit block (FIPS 197 Table 3).
pub const AES_BLOCK_LEN: usize = 16;

/// The number of columns of the state, `Nb` in FIPS 197. This Standard fixes `Nb = 4`
/// (Section 2.3); Rijndael in general allows other values, which is why the spec keeps a name for
/// it at all.
pub(crate) const NB: usize = 4;

/// SUBBYTES(): applies the S-box to each byte of the state independently (FIPS 197 Section 5.1.1).
#[inline(always)]
pub(crate) fn sub_bytes(state: &mut [u8; AES_BLOCK_LEN]) {
    for byte in state.iter_mut() {
        // s'[r, c] = SBOX(s[r, c]). The transformation is per-byte and position-independent, so
        // iterating the flat array in any order is equivalent to the row/column form in Figure 2.
        *byte = SBOX[*byte as usize];
    }
}

/// INVSUBBYTES(): the inverse of [`sub_bytes`], applying INVSBOX() to each byte
/// (FIPS 197 Section 5.3.2).
#[inline(always)]
pub(crate) fn inv_sub_bytes(state: &mut [u8; AES_BLOCK_LEN]) {
    for byte in state.iter_mut() {
        *byte = INVSBOX[*byte as usize];
    }
}

/// SHIFTROWS(): cyclically shifts row `r` of the state left by `r` bytes
/// (FIPS 197 Section 5.1.2).
///
/// Eq (5.5) is `s'[r, c] = s[r, (c + r) mod 4]`. Substituting the flat layout `s[r, c] ==
/// state[r + 4c]` gives `new[r + 4c] = old[r + 4 * ((c + r) mod 4)]`, which for each row is a
/// left-rotation of that row's four (stride-4) bytes by `r` positions -- the leftward movement
/// drawn in Figure 3.
///
/// Written out per row rather than as a loop over a copy of the state, so that no second copy of
/// the state is created (see the crate docs on scrubbing intermediate state).
#[inline(always)]
pub(crate) fn shift_rows(state: &mut [u8; AES_BLOCK_LEN]) {
    // Row 0 (r = 0) is unchanged, per Eq (5.5) with r = 0.

    // Row 1: rotate [s(1,0), s(1,1), s(1,2), s(1,3)] left by 1.
    let row1_c0 = state[1];
    state[1] = state[5]; // s'(1,0) = s(1,1)
    state[5] = state[9]; // s'(1,1) = s(1,2)
    state[9] = state[13]; // s'(1,2) = s(1,3)
    state[13] = row1_c0; // s'(1,3) = s(1,0)

    // Row 2: rotate left by 2, ie swap the two halves of the row.
    let row2_c0 = state[2];
    let row2_c1 = state[6];
    state[2] = state[10]; // s'(2,0) = s(2,2)
    state[6] = state[14]; // s'(2,1) = s(2,3)
    state[10] = row2_c0; // s'(2,2) = s(2,0)
    state[14] = row2_c1; // s'(2,3) = s(2,1)

    // Row 3: rotate left by 3, which is the same as rotating right by 1.
    let row3_c3 = state[15];
    state[15] = state[11]; // s'(3,3) = s(3,2)
    state[11] = state[7]; // s'(3,2) = s(3,1)
    state[7] = state[3]; // s'(3,1) = s(3,0)
    state[3] = row3_c3; // s'(3,0) = s(3,3)
}

/// INVSHIFTROWS(): the inverse of [`shift_rows`], cyclically shifting row `r` right by `r` bytes
/// (FIPS 197 Section 5.3.1).
///
/// Eq (5.12) is `s'[r, c] = s[r, (c - r) mod 4]`; in the flat layout that is a right-rotation of
/// each row by `r`, ie the rightward movement drawn in Figure 9.
#[inline(always)]
pub(crate) fn inv_shift_rows(state: &mut [u8; AES_BLOCK_LEN]) {
    // Row 0 (r = 0) is unchanged.

    // Row 1: rotate right by 1.
    let row1_c3 = state[13];
    state[13] = state[9]; // s'(1,3) = s(1,2)
    state[9] = state[5]; // s'(1,2) = s(1,1)
    state[5] = state[1]; // s'(1,1) = s(1,0)
    state[1] = row1_c3; // s'(1,0) = s(1,3)

    // Row 2: rotate right by 2 -- identical to rotating left by 2, so this is its own inverse.
    let row2_c0 = state[2];
    let row2_c1 = state[6];
    state[2] = state[10]; // s'(2,0) = s(2,2)
    state[6] = state[14]; // s'(2,1) = s(2,3)
    state[10] = row2_c0; // s'(2,2) = s(2,0)
    state[14] = row2_c1; // s'(2,3) = s(2,1)

    // Row 3: rotate right by 3, which is the same as rotating left by 1.
    let row3_c0 = state[3];
    state[3] = state[7]; // s'(3,0) = s(3,1)
    state[7] = state[11]; // s'(3,1) = s(3,2)
    state[11] = state[15]; // s'(3,2) = s(3,3)
    state[15] = row3_c0; // s'(3,3) = s(3,0)
}

/// MIXCOLUMNS(): multiplies each column of the state by the fixed matrix of Eq (5.7)
/// (FIPS 197 Section 5.1.3).
///
/// The four output bytes of each column are Eq (5.8) transcribed literally, with the GF(2^8)
/// products supplied by [`crate::gf`]:
///
/// ```text
/// s'(0,c) = ({02} . s(0,c)) + ({03} . s(1,c)) +          s(2,c)  +          s(3,c)
/// s'(1,c) =          s(0,c)  + ({02} . s(1,c)) + ({03} . s(2,c)) +          s(3,c)
/// s'(2,c) =          s(0,c)  +          s(1,c)  + ({02} . s(2,c)) + ({03} . s(3,c))
/// s'(3,c) = ({03} . s(0,c)) +          s(1,c)  +          s(2,c)  + ({02} . s(3,c))
/// ```
///
/// where `.` is GF(2^8) multiplication and `+` is XOR (Section 4.1).
#[inline(always)]
pub(crate) fn mix_columns(state: &mut [u8; AES_BLOCK_LEN]) {
    for c in 0..NB {
        // A column is contiguous in this layout: state[4c + r] == s(r, c).
        let s0 = state[4 * c];
        let s1 = state[4 * c + 1];
        let s2 = state[4 * c + 2];
        let s3 = state[4 * c + 3];

        state[4 * c] = mul_02(s0) ^ mul_03(s1) ^ s2 ^ s3;
        state[4 * c + 1] = s0 ^ mul_02(s1) ^ mul_03(s2) ^ s3;
        state[4 * c + 2] = s0 ^ s1 ^ mul_02(s2) ^ mul_03(s3);
        state[4 * c + 3] = mul_03(s0) ^ s1 ^ s2 ^ mul_02(s3);
    }
}

/// INVMIXCOLUMNS(): the inverse of [`mix_columns`], multiplying each column by the inverse matrix
/// of Eq (5.14) (FIPS 197 Section 5.3.3).
///
/// This is Eq (5.15) transcribed literally:
///
/// ```text
/// s'(0,c) = ({0e} . s(0,c)) + ({0b} . s(1,c)) + ({0d} . s(2,c)) + ({09} . s(3,c))
/// s'(1,c) = ({09} . s(0,c)) + ({0e} . s(1,c)) + ({0b} . s(2,c)) + ({0d} . s(3,c))
/// s'(2,c) = ({0d} . s(0,c)) + ({09} . s(1,c)) + ({0e} . s(2,c)) + ({0b} . s(3,c))
/// s'(3,c) = ({0b} . s(0,c)) + ({0d} . s(1,c)) + ({09} . s(2,c)) + ({0e} . s(3,c))
/// ```
#[inline(always)]
pub(crate) fn inv_mix_columns(state: &mut [u8; AES_BLOCK_LEN]) {
    for c in 0..NB {
        let s0 = state[4 * c];
        let s1 = state[4 * c + 1];
        let s2 = state[4 * c + 2];
        let s3 = state[4 * c + 3];

        state[4 * c] = mul_0e(s0) ^ mul_0b(s1) ^ mul_0d(s2) ^ mul_09(s3);
        state[4 * c + 1] = mul_09(s0) ^ mul_0e(s1) ^ mul_0b(s2) ^ mul_0d(s3);
        state[4 * c + 2] = mul_0d(s0) ^ mul_09(s1) ^ mul_0e(s2) ^ mul_0b(s3);
        state[4 * c + 3] = mul_0b(s0) ^ mul_0d(s1) ^ mul_09(s2) ^ mul_0e(s3);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a state from the four 32-bit words that NIST's intermediate-value files print for it.
    ///
    /// Those files print the state as `state[0..4] state[4..8] state[8..12] state[12..16]`, each
    /// group as a big-endian hex word -- ie the four *columns* of the state in order, which is the
    /// same as the flat byte order of this implementation (see the module docs).
    const fn state_of(w0: u32, w1: u32, w2: u32, w3: u32) -> [u8; AES_BLOCK_LEN] {
        let (a, b, c, d) = (w0.to_be_bytes(), w1.to_be_bytes(), w2.to_be_bytes(), w3.to_be_bytes());
        [
            a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3], c[0], c[1], c[2], c[3], d[0], d[1],
            d[2], d[3],
        ]
    }

    /* The intermediate values below are from the NIST "AES Core" ECB-AES128 intermediate value
     * file, first block: key = 2B7E1516 28AED2A6 ABF71588 09CF4F3C,
     * plaintext = 6BC1BEE2 2E409F96 E93D7E11 7393172A.
     * Round 1 and round 2 are enough to pin every transformation; the remaining rounds, and the
     * AES-192/AES-256 variants, are covered end to end by the known-answer tests in
     * tests/aes_tests.rs. */

    /// Round 1 input, ie the state after the initial ADDROUNDKEY() ("KeyAddition" in the file).
    const R1_START: [u8; AES_BLOCK_LEN] = state_of(0x40BFABF4, 0x06EE4D30, 0x42CA6B99, 0x7A5C5816);
    /// Round 1 after SUBBYTES() ("Substitution").
    const R1_SUB: [u8; AES_BLOCK_LEN] = state_of(0x090862BF, 0x6F28E304, 0x2C747FEE, 0xDA4A6A47);
    /// Round 1 after SHIFTROWS() ("ShiftRow").
    const R1_SHIFT: [u8; AES_BLOCK_LEN] = state_of(0x09287F47, 0x6F746ABF, 0x2C4A6204, 0xDA08E3EE);
    /// Round 1 after MIXCOLUMNS() ("MixColumn").
    const R1_MIX: [u8; AES_BLOCK_LEN] = state_of(0x529F16C2, 0x978615CA, 0xE01AAE54, 0xBA1A2659);

    /// Round 2 input, ie the state after round 1's ADDROUNDKEY().
    const R2_START: [u8; AES_BLOCK_LEN] = state_of(0xF265E8D5, 0x1FD2397B, 0xC3B9976D, 0x9076505C);
    /// Round 2 after SUBBYTES().
    const R2_SUB: [u8; AES_BLOCK_LEN] = state_of(0x894D9B03, 0xC0B51221, 0x2E56883C, 0x6038534A);
    /// Round 2 after SHIFTROWS().
    const R2_SHIFT: [u8; AES_BLOCK_LEN] = state_of(0x89B5884A, 0xC0565303, 0x2E389B21, 0x604D123C);
    /// Round 2 after MIXCOLUMNS().
    const R2_MIX: [u8; AES_BLOCK_LEN] = state_of(0x0F31E929, 0x319A3558, 0xAEC95893, 0x39F04D87);

    #[test]
    fn sub_bytes_matches_nist_intermediate_values() {
        let mut state = R1_START;
        sub_bytes(&mut state);
        assert_eq!(state, R1_SUB);

        let mut state = R2_START;
        sub_bytes(&mut state);
        assert_eq!(state, R2_SUB);
    }

    #[test]
    fn shift_rows_matches_nist_intermediate_values() {
        let mut state = R1_SUB;
        shift_rows(&mut state);
        assert_eq!(state, R1_SHIFT);

        let mut state = R2_SUB;
        shift_rows(&mut state);
        assert_eq!(state, R2_SHIFT);
    }

    #[test]
    fn mix_columns_matches_nist_intermediate_values() {
        let mut state = R1_SHIFT;
        mix_columns(&mut state);
        assert_eq!(state, R1_MIX);

        let mut state = R2_SHIFT;
        mix_columns(&mut state);
        assert_eq!(state, R2_MIX);
    }

    /* The inverse transformations are pinned against the same NIST values, read in the other
     * direction. (The decryption traces in those files apply INVSUBBYTES() and INVSHIFTROWS() in
     * the opposite order to Algorithm 3 -- the two commute, since one is per-byte and the other is
     * a permutation of positions -- so running the encryption values backwards is the unambiguous
     * way to pin these.) */

    #[test]
    fn inv_sub_bytes_matches_nist_intermediate_values() {
        let mut state = R1_SUB;
        inv_sub_bytes(&mut state);
        assert_eq!(state, R1_START);

        let mut state = R2_SUB;
        inv_sub_bytes(&mut state);
        assert_eq!(state, R2_START);
    }

    #[test]
    fn inv_shift_rows_matches_nist_intermediate_values() {
        let mut state = R1_SHIFT;
        inv_shift_rows(&mut state);
        assert_eq!(state, R1_SUB);

        let mut state = R2_SHIFT;
        inv_shift_rows(&mut state);
        assert_eq!(state, R2_SUB);
    }

    #[test]
    fn inv_mix_columns_matches_nist_intermediate_values() {
        let mut state = R1_MIX;
        inv_mix_columns(&mut state);
        assert_eq!(state, R1_SHIFT);

        let mut state = R2_MIX;
        inv_mix_columns(&mut state);
        assert_eq!(state, R2_SHIFT);
    }

    /// Each transformation composed with its inverse must be the identity, for a spread of states
    /// including the two degenerate ones (all-zero and all-ones) that a vector-only test set can
    /// easily miss.
    #[test]
    fn every_transformation_round_trips() {
        let mut states = [[0u8; AES_BLOCK_LEN]; 4];
        states[1] = [0xFF; AES_BLOCK_LEN];
        // A state with every byte distinct catches transposition and off-by-one row errors.
        for (i, byte) in states[2].iter_mut().enumerate() {
            *byte = i as u8;
        }
        states[3] = R1_START;

        for original in states.iter() {
            let mut state = *original;

            sub_bytes(&mut state);
            inv_sub_bytes(&mut state);
            assert_eq!(&state, original, "sub_bytes round trip");

            shift_rows(&mut state);
            inv_shift_rows(&mut state);
            assert_eq!(&state, original, "shift_rows round trip");

            mix_columns(&mut state);
            inv_mix_columns(&mut state);
            assert_eq!(&state, original, "mix_columns round trip");
        }
    }

    /// SHIFTROWS() must leave row 0 alone and must be a pure permutation of the other rows: it can
    /// neither change any byte's value nor move a byte out of its row.
    #[test]
    fn shift_rows_permutes_within_rows_only() {
        let mut state = [0u8; AES_BLOCK_LEN];
        for (i, byte) in state.iter_mut().enumerate() {
            // Encode the row in the low nibble and the column in the high nibble.
            *byte = ((i / NB) as u8) << 4 | (i % NB) as u8;
        }
        let original = state;
        shift_rows(&mut state);

        for r in 0..4 {
            for c in 0..NB {
                let moved = state[r + 4 * c];
                // The row index (low nibble here, since i % NB == r for index r + 4c) is preserved.
                assert_eq!(moved & 0x0f, (r as u8) & 0x0f, "byte left its row at ({r},{c})");
            }
        }
        // Row 0 is untouched.
        for c in 0..NB {
            assert_eq!(state[4 * c], original[4 * c], "row 0 changed at column {c}");
        }
        // And every other row genuinely moved (r = 1, 2, 3 all have non-zero shifts).
        for r in 1..4 {
            assert_ne!(
                [state[r], state[r + 4], state[r + 8], state[r + 12]],
                [original[r], original[r + 4], original[r + 8], original[r + 12]],
                "row {r} did not move"
            );
        }
    }

    /// MIXCOLUMNS() treats the four columns independently (Section 5.1.3: it "mixes their data
    /// independently of one another"), so changing one column must not disturb the others.
    #[test]
    fn mix_columns_keeps_columns_independent() {
        let mut baseline = R1_SHIFT;
        mix_columns(&mut baseline);

        for c in 0..NB {
            let mut perturbed = R1_SHIFT;
            perturbed[4 * c] ^= 0xFF;
            mix_columns(&mut perturbed);

            for other in 0..NB {
                if other == c {
                    continue;
                }
                assert_eq!(
                    perturbed[4 * other..4 * other + 4],
                    baseline[4 * other..4 * other + 4],
                    "column {c} leaked into column {other}"
                );
            }
        }
    }
}
