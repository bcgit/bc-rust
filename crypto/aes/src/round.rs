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
//! sits at bit position `4r + c` of the block's 16-bit lane. Two consequences drive every
//! constant below:
//!
//! * **A row is a nibble.** All of row `r` lives in bits `4r..4r+4` of the lane, and stepping one
//!   column along that row is a step of one bit position. So SHIFTROWS(), which only permutes
//!   within rows, is a rotation *inside* each nibble, by `r` positions.
//! * **Rotating a lane by 4 changes the row.** `x.rotate_lanes_right(4)` brings the contents of
//!   nibble `r+1` into nibble `r`, so a rotation by 4 reads "the next row down" and one by 8 reads
//!   "two rows down". MIXCOLUMNS(), which combines the four rows of a column, is therefore
//!   expressible with those two rotations and no shuffling at all.
//!
//! Both are the same at every plane width, because a wider plane is just more 16-bit lanes: the
//! masks are 16-bit patterns [`PlaneWord::splat`] replicates into every lane, and the rotations
//! are [`PlaneWord::rotate_lanes_right`], which rotates each lane on its own. That is the whole
//! of what these functions know about the width.
//!
//! Provenance: the structure of each function -- seven masked terms for SHIFTROWS(), the `p`/`r`
//! and rotate-by-two-rows shape of MIXCOLUMNS() and the per-plane term lists of INVMIXCOLUMNS()
//! -- is translated from BearSSL `src/symcipher/aes_ct_enc.c` and `aes_ct_dec.c` (MIT, Thomas
//! Pornin). The mask and rotation constants are not BearSSL's, because the bit layout is not (see
//! the provenance note in [`crate::bitslice`]); each is derived from the layout in the comments
//! below. There are no unit tests here: the FIPS 197 Appendix B, SP 800-38A F.1 and ACVP
//! known-answer tests in `tests/` reach every mask and rotation through the public API, and
//! `cargo mutants` confirms they kill every mutant in this file that is not an equivalent program.

use crate::bitslice::{PlaneWord, Planes};

/// ADDROUNDKEY(): XORs a round key into the state (FIPS 197 Sec 5.1.4, Eq 5.9).
///
/// Eq 5.9 XORs word `w[4*round + c]` into column `c`. Here the round key has already been
/// bit-sliced into the same plane layout as the state, and replicated into every block's lane, by
/// [`crate::schedule::round_key`], so the whole transformation -- all four columns of every block
/// -- is eight XORs.
///
/// This is its own inverse, which is why FIPS 197 Sec 5.3.4 needs no separate INVADDROUNDKEY().
#[inline(always)]
pub(crate) fn add_round_key<T: PlaneWord>(q: &mut Planes<T>, round_key: &Planes<T>) {
    for (plane, key_plane) in q.iter_mut().zip(round_key.iter()) {
        *plane ^= *key_plane;
    }
}

/// SHIFTROWS(): cyclically shifts row `r` left by `r` columns (FIPS 197 Sec 5.1.2, Eq 5.5).
///
/// Eq 5.5 is `s'[r,c] = s[r,(c + r) mod 4]`. Row `r` occupies nibble `r` of every lane and one
/// column is one bit position, so the new column `c` must take what is `r` positions further up
/// the nibble: a **rotate right by `r` within nibble `r`**. Rotating right, not left, because
/// taking from a higher column index means pulling data down towards bit 0.
///
/// Written out per nibble rather than as a loop, so the shift amounts stay compile-time
/// constants:
///
/// * nibble 0 (`r = 0`): rotate by 0, so bits `0..4` pass through untouched.
/// * nibble 1 (`r = 1`): rotate right by 1. Bits 5..8 drop to 4..7; bit 4 wraps to 7.
/// * nibble 2 (`r = 2`): rotate right by 2. Bits 10..12 drop to 8..10; bits 8..10 wrap up.
/// * nibble 3 (`r = 3`): rotate right by 3. Bit 15 drops to 12; bits 12..15 wrap up.
///
/// The masks are 16-bit patterns, `splat` into every lane, so every block moves together and no
/// bit crosses from one block's lane into another's.
///
/// The seven masks have pairwise disjoint destination ranges that together cover all 16 bits of
/// a lane, so the `|`s combine disjoint operands and `|` and `^` compute the same function. That
/// is why `cargo mutants` reports every `| -> ^` mutant here and in [`inv_shift_rows`] as
/// surviving: they are equivalent programs, not a gap in the tests. Masks that overlapped or
/// failed to cover would be a bug, and the known-answer tests would catch it.
///
/// Translated from BearSSL `aes_ct_enc.c:shift_rows`, with the constants re-derived as above.
#[inline(always)]
pub(crate) fn shift_rows<T: PlaneWord>(q: &mut Planes<T>) {
    for plane in q.iter_mut() {
        let x = *plane;
        *plane = (x & T::splat(0x000F))
            | ((x & T::splat(0x00E0)) >> 1)
            | ((x & T::splat(0x0010)) << 3)
            | ((x & T::splat(0x0C00)) >> 2)
            | ((x & T::splat(0x0300)) << 2)
            | ((x & T::splat(0x8000)) >> 3)
            | ((x & T::splat(0x7000)) << 1);
    }
}

/// INVSHIFTROWS(): cyclically shifts row `r` right by `r` columns
/// (FIPS 197 Sec 5.3.1, Eq 5.12).
///
/// Eq 5.12 is `s'[r,c] = s[r,(c - r) mod 4]`, so this is [`shift_rows`] with every nibble rotation
/// reversed: **rotate left by `r` within nibble `r`**. The masks are the complementary halves of
/// the forward ones.
///
/// Translated from BearSSL `aes_ct_dec.c:inv_shift_rows`, with the constants re-derived as above.
#[inline(always)]
pub(crate) fn inv_shift_rows<T: PlaneWord>(q: &mut Planes<T>) {
    for plane in q.iter_mut() {
        let x = *plane;
        *plane = (x & T::splat(0x000F))
            | ((x & T::splat(0x0070)) << 1)
            | ((x & T::splat(0x0080)) >> 3)
            | ((x & T::splat(0x0300)) << 2)
            | ((x & T::splat(0x0C00)) >> 2)
            | ((x & T::splat(0x1000)) << 3)
            | ((x & T::splat(0xE000)) >> 1);
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
/// using `{03} = {02} ^ {01}`. Because "the next row" is a lane rotation by 4 and "two rows
/// down" is one by 8 (see the module docs), with `p` the state planes and `r` = `p` rotated by 4:
///
/// * `p[k]` is bit `k` of `s[r]`, `r[k]` is bit `k` of `s[r+1]`,
/// * rotating those two by 8 gives bit `k` of `s[r+2]` and of `s[r+3]`.
///
/// So `s[r+2] ^ s[r+3]` is `(p[k] ^ r[k]).rotate_lanes_right(8)`, which is the rotated term in
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
/// the known-answer tests in `tests/`.
#[inline(always)]
pub(crate) fn mix_columns<T: PlaneWord>(q: &mut Planes<T>) {
    let p = *q;
    // r[k] holds the same bit position of the next row down.
    let r: Planes<T> = core::array::from_fn(|k| p[k].rotate_lanes_right(4));
    // Two rows down.
    let rr = |v: T| v.rotate_lanes_right(8);

    // The `p[7] ^ r[7]` term is the {1b} reduction, present only in planes 0, 1, 3 and 4.
    q[0] = p[7] ^ r[7] ^ r[0] ^ rr(p[0] ^ r[0]);
    q[1] = p[0] ^ r[0] ^ p[7] ^ r[7] ^ r[1] ^ rr(p[1] ^ r[1]);
    q[2] = p[1] ^ r[1] ^ r[2] ^ rr(p[2] ^ r[2]);
    q[3] = p[2] ^ r[2] ^ p[7] ^ r[7] ^ r[3] ^ rr(p[3] ^ r[3]);
    q[4] = p[3] ^ r[3] ^ p[7] ^ r[7] ^ r[4] ^ rr(p[4] ^ r[4]);
    q[5] = p[4] ^ r[4] ^ r[5] ^ rr(p[5] ^ r[5]);
    q[6] = p[5] ^ r[5] ^ r[6] ^ rr(p[6] ^ r[6]);
    q[7] = p[6] ^ r[6] ^ r[7] ^ rr(p[7] ^ r[7]);
}

/// INVMIXCOLUMNS(): multiplies every column by the inverse matrix of Eq 5.14
/// (FIPS 197 Sec 5.3.3).
///
/// The same shape as [`mix_columns`] -- `r` is the next row down, a lane rotation by 8 reaches two
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
/// inspection, the decryption known-answer tests in `tests/` (SP 800-38A F.1.2/4/6, ACVP) pin it,
/// and the ECB conformance suite checks the two directions are inverses.
#[inline(always)]
#[rustfmt::skip]
pub(crate) fn inv_mix_columns<T: PlaneWord>(q: &mut Planes<T>) {
    let p = *q;
    let r: Planes<T> = core::array::from_fn(|k| p[k].rotate_lanes_right(4));
    let rr = |v: T| v.rotate_lanes_right(8);

    q[0] = p[5] ^ p[6] ^ p[7] ^ r[0] ^ r[5] ^ r[7]
        ^ rr(p[0] ^ p[5] ^ p[6] ^ r[0] ^ r[5]);
    q[1] = p[0] ^ p[5] ^ r[0] ^ r[1] ^ r[5] ^ r[6] ^ r[7]
        ^ rr(p[1] ^ p[5] ^ p[7] ^ r[1] ^ r[5] ^ r[6]);
    q[2] = p[0] ^ p[1] ^ p[6] ^ r[1] ^ r[2] ^ r[6] ^ r[7]
        ^ rr(p[0] ^ p[2] ^ p[6] ^ r[2] ^ r[6] ^ r[7]);
    q[3] = p[0] ^ p[1] ^ p[2] ^ p[5] ^ p[6] ^ r[0] ^ r[2] ^ r[3] ^ r[5]
        ^ rr(p[0] ^ p[1] ^ p[3] ^ p[5] ^ p[6] ^ p[7] ^ r[0] ^ r[3] ^ r[5] ^ r[7]);
    q[4] = p[1] ^ p[2] ^ p[3] ^ p[5] ^ r[1] ^ r[3] ^ r[4] ^ r[5] ^ r[6] ^ r[7]
        ^ rr(p[1] ^ p[2] ^ p[4] ^ p[5] ^ p[7] ^ r[1] ^ r[4] ^ r[5] ^ r[6]);
    q[5] = p[2] ^ p[3] ^ p[4] ^ p[6] ^ r[2] ^ r[4] ^ r[5] ^ r[6] ^ r[7]
        ^ rr(p[2] ^ p[3] ^ p[5] ^ p[6] ^ r[2] ^ r[5] ^ r[6] ^ r[7]);
    q[6] = p[3] ^ p[4] ^ p[5] ^ p[7] ^ r[3] ^ r[5] ^ r[6] ^ r[7]
        ^ rr(p[3] ^ p[4] ^ p[6] ^ p[7] ^ r[3] ^ r[6] ^ r[7]);
    q[7] = p[4] ^ p[5] ^ p[6] ^ r[4] ^ r[6] ^ r[7]
        ^ rr(p[4] ^ p[5] ^ p[7] ^ r[4] ^ r[7]);
}
