//! The three linear round transformations, on bit-planes.
//!
//! | Function | FIPS 197 | Inverse | FIPS 197 |
//! |---|---|---|---|
//! | [`add_round_key`] | Sec 5.1.4, Eq 5.9 | itself (XOR) | Sec 5.3.4 |
//! | [`shift_rows`] | Sec 5.1.2, Eq 5.5 | [`inv_shift_rows`] | Sec 5.3.1, Eq 5.12 |
//! | [`mix_columns`] | Sec 5.1.3, Eq 5.8 | [`inv_mix_columns`] | Sec 5.3.3, Eq 5.15 |
//!
//! SUBBYTES() is in [`crate::sbox`], because it is the only non-linear step and the only one that
//! needs a circuit rather than masks and rotations.
//!
//! Everything here is XOR, AND with a constant mask, and rotation by a constant. No operation
//! depends on the data, so all of it is inherently constant-time.
//!
//! # How the layout turns row and column arithmetic into shifts
//!
//! From the layout derived in [`crate::bitslice`], within every plane the bit holding `s[r,c]`
//! of block A sits at bit position `8r + 2c` (and block B at `8r + 2c + 1`). Two consequences
//! drive every constant below:
//!
//! * **A row is a byte-lane.** All of row `r` lives in bits `8r..8r+8` of every plane, and
//!   stepping one column along that row is a step of two bit positions. So SHIFTROWS(), which
//!   only permutes within rows, is a rotation *inside* each byte-lane, by `2r` positions.
//! * **Rotating a whole plane by 8 changes the row.** `x.rotate_right(8)` brings the contents of
//!   lane `r+1` into lane `r`, so `rotate_right(8)` reads "the next row down" and
//!   `rotate_right(16)` reads "two rows down". MIXCOLUMNS(), which combines the four rows of a
//!   column, is therefore expressible with those two rotations and no shuffling at all.
//!
//! Provenance: the mask and rotation constants are translated from BearSSL
//! `src/symcipher/aes_ct_enc.c` and `aes_ct_dec.c` (MIT, Thomas Pornin). Each is re-derived from
//! the layout in the comments below, and each is pinned by a test in this file against a
//! byte-wise reference written directly from the FIPS 197 equations.

use crate::bitslice::Planes;

/// ADDROUNDKEY(): XORs a round key into the state (FIPS 197 Sec 5.1.4, Eq 5.9).
///
/// Eq 5.9 XORs word `w[4*round + c]` into column `c`. Here the round key has already been
/// bit-sliced into the same plane layout as the state by [`crate::schedule`], so the whole
/// transformation -- all four columns of both blocks -- is eight XORs.
///
/// This is its own inverse, which is why FIPS 197 Sec 5.3.4 needs no separate INVADDROUNDKEY().
#[inline(always)]
pub(crate) fn add_round_key(q: &mut Planes, round_key: &Planes) {
    for (plane, key_plane) in q.iter_mut().zip(round_key.iter()) {
        *plane ^= *key_plane;
    }
}

/// SHIFTROWS(): cyclically shifts row `r` left by `r` columns (FIPS 197 Sec 5.1.2, Eq 5.5).
///
/// Eq 5.5 is `s'[r,c] = s[r,(c + r) mod 4]`. Row `r` occupies byte-lane `r` of every plane and
/// one column is two bit positions, so the new column `c` must take what is two-bits-times-`r`
/// further up the lane: a **rotate right by `2r` within lane `r`**. Rotating right, not left,
/// because taking from a higher column index means pulling data down towards bit 0.
///
/// Written out per lane rather than as a loop, so the shift amounts stay compile-time constants:
///
/// * lane 0 (`r = 0`): rotate by 0, so bits `0..8` pass through untouched.
/// * lane 1 (`r = 1`): rotate right by 2. Bits 10..16 drop to 8..14; bits 8..10 wrap to 14..16.
/// * lane 2 (`r = 2`): rotate right by 4. Bits 20..24 drop to 16..20; bits 16..20 wrap up.
/// * lane 3 (`r = 3`): rotate right by 6. Bits 30..32 drop to 24..26; bits 24..30 wrap up.
///
/// Both interleaved blocks move together, since a column step of two positions carries the A and
/// B bits of that column as a pair.
///
/// Translated from BearSSL `aes_ct_enc.c:shift_rows`.
#[inline(always)]
pub(crate) fn shift_rows(q: &mut Planes) {
    for plane in q.iter_mut() {
        let x = *plane;
        *plane = (x & 0x0000_00FF)
            | ((x & 0x0000_FC00) >> 2)
            | ((x & 0x0000_0300) << 6)
            | ((x & 0x00F0_0000) >> 4)
            | ((x & 0x000F_0000) << 4)
            | ((x & 0xC000_0000) >> 6)
            | ((x & 0x3F00_0000) << 2);
    }
}

/// INVSHIFTROWS(): cyclically shifts row `r` right by `r` columns
/// (FIPS 197 Sec 5.3.1, Eq 5.12).
///
/// Eq 5.12 is `s'[r,c] = s[r,(c - r) mod 4]`, so this is [`shift_rows`] with every lane rotation
/// reversed: **rotate left by `2r` within lane `r`**. The masks are the complementary halves of
/// the forward ones.
///
/// Translated from BearSSL `aes_ct_dec.c:inv_shift_rows`.
#[inline(always)]
pub(crate) fn inv_shift_rows(q: &mut Planes) {
    for plane in q.iter_mut() {
        let x = *plane;
        *plane = (x & 0x0000_00FF)
            | ((x & 0x0000_3F00) << 2)
            | ((x & 0x0000_C000) >> 6)
            | ((x & 0x000F_0000) << 4)
            | ((x & 0x00F0_0000) >> 4)
            | ((x & 0x0300_0000) << 6)
            | ((x & 0xFC00_0000) >> 2);
    }
}

/// MIXCOLUMNS(): multiplies every column by the fixed matrix of Eq 5.7
/// (FIPS 197 Sec 5.1.3).
///
/// # Derivation
///
/// Eq 5.8 gives each output byte of a column. Collecting the four rows, and writing `s[r]` for
/// the byte in row `r` of the column being processed, every row obeys the same rule:
///
/// ```text
/// s'[r] = {02}.s[r] ^ {03}.s[r+1] ^ s[r+2] ^ s[r+3]        (rows mod 4)
///       = {02}.(s[r] ^ s[r+1]) ^ s[r+1] ^ s[r+2] ^ s[r+3]
/// ```
///
/// using `{03} = {02} ^ {01}`. Because "the next row" is `rotate_right(8)` and "two rows down" is
/// `rotate_right(16)` (see the module docs), with `p` the state planes and `r` = `p` rotated by 8:
///
/// * `p[k]` is bit `k` of `s[r]`, `r[k]` is bit `k` of `s[r+1]`,
/// * `rotate_right(16)` of those two gives bit `k` of `s[r+2]` and of `s[r+3]`.
///
/// So `s[r+2] ^ s[r+3]` is `(p[k] ^ r[k]).rotate_right(16)`, which is the `rotr16(..)` term in
/// every line below, and `s[r+1]` is the bare `r[k]`.
///
/// The remaining `{02}.(s[r] ^ s[r+1])` is XTIMES() (Eq 4.5) in the plane basis. Multiplying by
/// `x` shifts every bit up one plane, and the degree-8 term that falls off the top is reduced by
/// XOR-ing `{1b} = 0b0001_1011` -- bits 0, 1, 3 and 4. So with `v[k] = p[k] ^ r[k]`, plane `k` of
/// `{02}.v` is:
///
/// * `v[k-1]` from the shift, for `k >= 1` (plane 0 gets nothing from the shift), and
/// * `v[7]`, the reduction, for `k` in {0, 1, 3, 4} only.
///
/// That is exactly where the extra `p[7] ^ r[7]` terms appear below: in the lines for planes 0, 1,
/// 3 and 4, and nowhere else. Plane 0 is the one line with no `p[k-1] ^ r[k-1]` term.
///
/// Translated from BearSSL `aes_ct_enc.c:mix_columns`; the equivalence to Eq 5.8 is pinned by
/// `test_mix_columns_matches_equation_5_8`.
#[inline(always)]
pub(crate) fn mix_columns(q: &mut Planes) {
    let p = *q;
    // r[k] holds the same bit position of the next row down.
    let r: Planes = core::array::from_fn(|k| p[k].rotate_right(8));

    // The `p[7] ^ r[7]` term is the {1b} reduction, present only in planes 0, 1, 3 and 4.
    q[0] = p[7] ^ r[7] ^ r[0] ^ (p[0] ^ r[0]).rotate_right(16);
    q[1] = p[0] ^ r[0] ^ p[7] ^ r[7] ^ r[1] ^ (p[1] ^ r[1]).rotate_right(16);
    q[2] = p[1] ^ r[1] ^ r[2] ^ (p[2] ^ r[2]).rotate_right(16);
    q[3] = p[2] ^ r[2] ^ p[7] ^ r[7] ^ r[3] ^ (p[3] ^ r[3]).rotate_right(16);
    q[4] = p[3] ^ r[3] ^ p[7] ^ r[7] ^ r[4] ^ (p[4] ^ r[4]).rotate_right(16);
    q[5] = p[4] ^ r[4] ^ r[5] ^ (p[5] ^ r[5]).rotate_right(16);
    q[6] = p[5] ^ r[5] ^ r[6] ^ (p[6] ^ r[6]).rotate_right(16);
    q[7] = p[6] ^ r[6] ^ r[7] ^ (p[7] ^ r[7]).rotate_right(16);
}

/// INVMIXCOLUMNS(): multiplies every column by the inverse matrix of Eq 5.14
/// (FIPS 197 Sec 5.3.3).
///
/// The same shape as [`mix_columns`] -- `r` is the next row down, `rotate_right(16)` reaches two
/// rows further -- but the defining word of Sec 4.3 is `[{0e},{09},{0d},{0b}]` (Eq 5.13) instead
/// of `[{02},{01},{01},{03}]` (Eq 5.6). Those have degree up to 3, so expanding each product
/// through XTIMES()
/// in the plane basis produces many more terms than the forward direction, and the per-plane term
/// lists below are that expansion of Eq 5.15 rather than something readable line by line.
///
/// The reduction terms are not confined to planes 0, 1, 3 and 4 here, because the higher-degree
/// coefficients feed carries into every plane.
///
/// Translated from BearSSL `aes_ct_dec.c:inv_mix_columns`. Rather than trust the expansion by
/// inspection, `test_inv_mix_columns_matches_equation_5_15` checks it against a byte-wise
/// reference written straight from Eq 5.15, and `test_inv_mix_columns_inverts_mix_columns`
/// checks the two are inverses.
#[inline(always)]
#[rustfmt::skip]
pub(crate) fn inv_mix_columns(q: &mut Planes) {
    let p = *q;
    let r: Planes = core::array::from_fn(|k| p[k].rotate_right(8));

    q[0] = p[5] ^ p[6] ^ p[7] ^ r[0] ^ r[5] ^ r[7]
        ^ (p[0] ^ p[5] ^ p[6] ^ r[0] ^ r[5]).rotate_right(16);
    q[1] = p[0] ^ p[5] ^ r[0] ^ r[1] ^ r[5] ^ r[6] ^ r[7]
        ^ (p[1] ^ p[5] ^ p[7] ^ r[1] ^ r[5] ^ r[6]).rotate_right(16);
    q[2] = p[0] ^ p[1] ^ p[6] ^ r[1] ^ r[2] ^ r[6] ^ r[7]
        ^ (p[0] ^ p[2] ^ p[6] ^ r[2] ^ r[6] ^ r[7]).rotate_right(16);
    q[3] = p[0] ^ p[1] ^ p[2] ^ p[5] ^ p[6] ^ r[0] ^ r[2] ^ r[3] ^ r[5]
        ^ (p[0] ^ p[1] ^ p[3] ^ p[5] ^ p[6] ^ p[7] ^ r[0] ^ r[3] ^ r[5] ^ r[7]).rotate_right(16);
    q[4] = p[1] ^ p[2] ^ p[3] ^ p[5] ^ r[1] ^ r[3] ^ r[4] ^ r[5] ^ r[6] ^ r[7]
        ^ (p[1] ^ p[2] ^ p[4] ^ p[5] ^ p[7] ^ r[1] ^ r[4] ^ r[5] ^ r[6]).rotate_right(16);
    q[5] = p[2] ^ p[3] ^ p[4] ^ p[6] ^ r[2] ^ r[4] ^ r[5] ^ r[6] ^ r[7]
        ^ (p[2] ^ p[3] ^ p[5] ^ p[6] ^ r[2] ^ r[5] ^ r[6] ^ r[7]).rotate_right(16);
    q[6] = p[3] ^ p[4] ^ p[5] ^ p[7] ^ r[3] ^ r[5] ^ r[6] ^ r[7]
        ^ (p[3] ^ p[4] ^ p[6] ^ p[7] ^ r[3] ^ r[6] ^ r[7]).rotate_right(16);
    q[7] = p[4] ^ p[5] ^ p[6] ^ r[4] ^ r[6] ^ r[7]
        ^ (p[4] ^ p[5] ^ p[7] ^ r[4] ^ r[7]).rotate_right(16);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitslice::{pack, unpack};

    /// Runs a plane transformation over one block placed in both halves, returning the A half.
    fn apply(f: fn(&mut Planes), block: [u8; 16]) -> [u8; 16] {
        let mut q = pack(&block, &block);
        f(&mut q);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        unpack(&q, &mut a, &mut b);
        assert_eq!(a, b, "the two interleaved blocks must transform identically");
        a
    }

    /// A block whose bytes are all distinct, so any mask error that moves a byte to the wrong
    /// position is visible.
    fn distinct_block() -> [u8; 16] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3))
    }

    // ---- byte-wise references, written from the FIPS 197 equations ----------------------
    // These use `state[r + 4c] == s[r,c]` (Eq 3.6). They exist only to check the plane
    // implementations and are deliberately naive.

    /// Eq 5.5: `s'[r,c] = s[r,(c + r) mod 4]`.
    fn ref_shift_rows(s: &[u8; 16]) -> [u8; 16] {
        let mut o = [0u8; 16];
        for r in 0..4 {
            for c in 0..4 {
                o[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
            }
        }
        o
    }

    /// Eq 5.12: `s'[r,c] = s[r,(c - r) mod 4]`.
    fn ref_inv_shift_rows(s: &[u8; 16]) -> [u8; 16] {
        let mut o = [0u8; 16];
        for r in 0..4 {
            for c in 0..4 {
                o[r + 4 * c] = s[r + 4 * ((c + 4 - r) % 4)];
            }
        }
        o
    }

    /// Eq 4.5 XTIMES(): multiply by `{02}` in GF(2^8).
    fn xtimes(b: u8) -> u8 {
        (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
    }

    /// General GF(2^8) multiplication. Test-only; it branches on `b` and must never see secrets.
    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 {
                product ^= a;
            }
            b >>= 1;
            a = xtimes(a);
        }
        product
    }

    /// Multiplication of a column by a fixed matrix, exactly as FIPS 197 Sec 4.3 defines it.
    ///
    /// Eq 4.8 gives the output word `[d0,d1,d2,d3]` from the input word `[b0,b1,b2,b3]` and the
    /// matrix word `[a0,a1,a2,a3]`:
    ///
    /// ```text
    /// d0 = (a0.b0) + (a3.b1) + (a2.b2) + (a1.b3)
    /// d1 = (a1.b0) + (a0.b1) + (a3.b2) + (a2.b3)
    /// d2 = (a2.b0) + (a1.b1) + (a0.b2) + (a3.b3)
    /// d3 = (a3.b0) + (a2.b1) + (a1.b2) + (a0.b3)
    /// ```
    ///
    /// so entry `(r,k)` of the matrix is `a[(r - k) mod 4]`, which is what the indexing below is.
    /// Both MIXCOLUMNS() and INVMIXCOLUMNS() use this same convention; only the word differs.
    fn ref_mix_columns(s: &[u8; 16], coeffs: [u8; 4]) -> [u8; 16] {
        let mut o = [0u8; 16];
        for c in 0..4 {
            for r in 0..4 {
                let mut v = 0u8;
                for k in 0..4 {
                    v ^= gf_mul(s[k + 4 * c], coeffs[(r + 4 - k) % 4]);
                }
                o[r + 4 * c] = v;
            }
        }
        o
    }

    /// Eq 5.6: `[a0, a1, a2, a3] = [{02}, {01}, {01}, {03}]`.
    ///
    /// Note the order: it is *not* `[{02},{03},{01},{01}]`, which is the first row of the matrix
    /// in Eq 5.7 rather than the defining word. Feeding the matrix row in here instead of the
    /// word silently transposes the matrix, which happens to leave INVMIXCOLUMNS() passing, so
    /// this is a comment worth keeping.
    const MIX_COEFFS: [u8; 4] = [0x02, 0x01, 0x01, 0x03];
    /// Eq 5.13: `[a0, a1, a2, a3] = [{0e}, {09}, {0d}, {0b}]`.
    const INV_MIX_COEFFS: [u8; 4] = [0x0e, 0x09, 0x0d, 0x0b];

    /// Eq 5.8, transcribed literally, as a cross-check on [`ref_mix_columns`].
    ///
    /// ```text
    /// s'0,c = ({02}.s0,c) + ({03}.s1,c) +          s2,c  +          s3,c
    /// s'1,c =          s0,c  + ({02}.s1,c) + ({03}.s2,c) +          s3,c
    /// s'2,c =          s0,c  +          s1,c  + ({02}.s2,c) + ({03}.s3,c)
    /// s'3,c = ({03}.s0,c) +          s1,c  +          s2,c  + ({02}.s3,c)
    /// ```
    #[rustfmt::skip]
    fn ref_mix_columns_literal(s: &[u8; 16]) -> [u8; 16] {
        let mut o = [0u8; 16];
        for c in 0..4 {
            let (s0, s1, s2, s3) = (s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]);
            o[4 * c] = gf_mul(0x02, s0) ^ gf_mul(0x03, s1) ^ s2 ^ s3;
            o[4 * c + 1] = s0 ^ gf_mul(0x02, s1) ^ gf_mul(0x03, s2) ^ s3;
            o[4 * c + 2] = s0 ^ s1 ^ gf_mul(0x02, s2) ^ gf_mul(0x03, s3);
            o[4 * c + 3] = gf_mul(0x03, s0) ^ s1 ^ s2 ^ gf_mul(0x02, s3);
        }
        o
    }

    /// Eq 5.15, transcribed literally, as a cross-check on [`ref_mix_columns`].
    ///
    /// ```text
    /// s'0,c = ({0e}.s0,c) + ({0b}.s1,c) + ({0d}.s2,c) + ({09}.s3,c)
    /// s'1,c = ({09}.s0,c) + ({0e}.s1,c) + ({0b}.s2,c) + ({0d}.s3,c)
    /// s'2,c = ({0d}.s0,c) + ({09}.s1,c) + ({0e}.s2,c) + ({0b}.s3,c)
    /// s'3,c = ({0b}.s0,c) + ({0d}.s1,c) + ({09}.s2,c) + ({0e}.s3,c)
    /// ```
    #[rustfmt::skip]
    fn ref_inv_mix_columns_literal(s: &[u8; 16]) -> [u8; 16] {
        let mut o = [0u8; 16];
        for c in 0..4 {
            let (s0, s1, s2, s3) = (s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]);
            o[4 * c] = gf_mul(0x0e, s0) ^ gf_mul(0x0b, s1) ^ gf_mul(0x0d, s2) ^ gf_mul(0x09, s3);
            o[4 * c + 1] = gf_mul(0x09, s0) ^ gf_mul(0x0e, s1) ^ gf_mul(0x0b, s2) ^ gf_mul(0x0d, s3);
            o[4 * c + 2] = gf_mul(0x0d, s0) ^ gf_mul(0x09, s1) ^ gf_mul(0x0e, s2) ^ gf_mul(0x0b, s3);
            o[4 * c + 3] = gf_mul(0x0b, s0) ^ gf_mul(0x0d, s1) ^ gf_mul(0x09, s2) ^ gf_mul(0x0e, s3);
        }
        o
    }

    // ---- tests --------------------------------------------------------------------------

    #[test]
    fn test_the_two_reference_forms_agree() {
        // Eq 5.7 (matrix, via the Sec 4.3 convention) against Eq 5.8 (explicit bytes), and the
        // same for Eq 5.14 against Eq 5.15. This is what pins the coefficient word order: get
        // MIX_COEFFS wrong and these disagree, independently of the plane implementation.
        for seed in 0..32u8 {
            let block: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ seed);
            assert_eq!(ref_mix_columns(&block, MIX_COEFFS), ref_mix_columns_literal(&block));
            assert_eq!(
                ref_mix_columns(&block, INV_MIX_COEFFS),
                ref_inv_mix_columns_literal(&block)
            );
        }
    }

    #[test]
    fn test_xtimes_reference_matches_the_spec_example() {
        // FIPS 197 Sec 4.2 works through {57} . {13}; the intermediate XTIMES() chain from
        // Eq 4.5 is {57}, {ae}, {47}, {8e}, {07}.
        assert_eq!(xtimes(0x57), 0xae);
        assert_eq!(xtimes(0xae), 0x47);
        assert_eq!(xtimes(0x47), 0x8e);
        assert_eq!(xtimes(0x8e), 0x07);
        // and the product itself, {57} . {13} = {fe}.
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
    }

    #[test]
    fn test_shift_rows_matches_equation_5_5() {
        for seed in 0..32u8 {
            let block: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(31) ^ seed);
            assert_eq!(apply(shift_rows, block), ref_shift_rows(&block));
        }
        assert_eq!(apply(shift_rows, distinct_block()), ref_shift_rows(&distinct_block()));
    }

    #[test]
    fn test_inv_shift_rows_matches_equation_5_12() {
        for seed in 0..32u8 {
            let block: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(31) ^ seed);
            assert_eq!(apply(inv_shift_rows, block), ref_inv_shift_rows(&block));
        }
    }

    #[test]
    fn test_inv_shift_rows_inverts_shift_rows() {
        let block = distinct_block();
        let mut q = pack(&block, &block);
        shift_rows(&mut q);
        inv_shift_rows(&mut q);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        unpack(&q, &mut a, &mut b);
        assert_eq!(a, block);
    }

    #[test]
    fn test_shift_rows_is_a_bit_permutation() {
        // Push a single set bit through and require exactly one bit out, with the induced map on
        // bit positions a bijection. That is the real invariant behind the seven masked terms:
        // their destination ranges are pairwise disjoint and together cover all 32 bits.
        //
        // It also explains a known `cargo mutants` result. The `| -> ^` mutants in [`shift_rows`]
        // and [`inv_shift_rows`] survive, because on disjoint operands `|` and `^` compute the
        // same function -- they are equivalent programs, not a gap in the tests, and no test can
        // kill them. What *would* be a bug is masks that overlap or fail to cover, and this test
        // is what rules that out.
        for (name, f) in [
            ("shift_rows", shift_rows as fn(&mut Planes)),
            ("inv_shift_rows", inv_shift_rows as fn(&mut Planes)),
        ] {
            let mut destinations = [false; 32];
            for bit in 0..32 {
                let mut q: Planes = [1u32 << bit; 8];
                f(&mut q);
                for plane in q {
                    assert_eq!(
                        plane.count_ones(),
                        1,
                        "{name}: bit {bit} must map to exactly one bit, got {plane:#034b}"
                    );
                }
                let dest = q[0].trailing_zeros() as usize;
                assert!(!destinations[dest], "{name}: two source bits both map to bit {dest}");
                destinations[dest] = true;
            }
            assert!(
                destinations.iter().all(|&hit| hit),
                "{name}: the masks must cover all 32 bit positions"
            );
        }
    }

    #[test]
    fn test_shift_rows_leaves_row_zero_alone() {
        // Row 0 is bytes 0, 4, 8, 12 in the Eq 3.6 layout, and Eq 5.5 does not move it.
        let block = distinct_block();
        let out = apply(shift_rows, block);
        for c in 0..4 {
            assert_eq!(out[4 * c], block[4 * c], "row 0, column {c}");
        }
    }

    #[test]
    fn test_mix_columns_matches_equation_5_8() {
        for seed in 0..32u8 {
            let block: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ seed);
            assert_eq!(apply(mix_columns, block), ref_mix_columns(&block, MIX_COEFFS));
        }
        assert_eq!(
            apply(mix_columns, distinct_block()),
            ref_mix_columns(&distinct_block(), MIX_COEFFS)
        );
    }

    #[test]
    fn test_inv_mix_columns_matches_equation_5_15() {
        for seed in 0..32u8 {
            let block: [u8; 16] = core::array::from_fn(|i| (i as u8).wrapping_mul(37) ^ seed);
            assert_eq!(apply(inv_mix_columns, block), ref_mix_columns(&block, INV_MIX_COEFFS));
        }
    }

    #[test]
    fn test_inv_mix_columns_inverts_mix_columns() {
        let block = distinct_block();
        let mut q = pack(&block, &block);
        mix_columns(&mut q);
        inv_mix_columns(&mut q);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        unpack(&q, &mut a, &mut b);
        assert_eq!(a, block);
    }

    #[test]
    fn test_add_round_key_is_its_own_inverse() {
        let block = distinct_block();
        let key = pack(&[0xA5u8; 16], &[0x5Au8; 16]);
        let mut q = pack(&block, &block);
        add_round_key(&mut q, &key);
        add_round_key(&mut q, &key);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        unpack(&q, &mut a, &mut b);
        assert_eq!(a, block);
    }

    #[test]
    fn test_add_round_key_xors_the_expected_bytes() {
        let block = distinct_block();
        let key_block = [0xA5u8; 16];
        let key = pack(&key_block, &key_block);
        let mut q = pack(&block, &block);
        add_round_key(&mut q, &key);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        unpack(&q, &mut a, &mut b);
        for i in 0..16 {
            assert_eq!(a[i], block[i] ^ key_block[i]);
        }
    }
}
