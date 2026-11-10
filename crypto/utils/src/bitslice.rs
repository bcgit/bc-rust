//! What the bit-sliced block ciphers share: the plane-word trait their circuits are generic over,
//! the byte-lane transpose that moves bytes into bit-planes and back, and the non-linear section
//! of the Boyar-Peralta AES S-box circuit, which computes the GF(2^8) inversion every one of
//! their S-boxes is built around.
//!
//! A bit-sliced cipher keeps its state as eight *bit-planes*, `q[0]..q[7]`, where plane `q[k]`
//! holds bit `k` of every byte in the state. An S-box is then a Boolean circuit over the planes:
//! one `&` or `^` on a plane applies that gate to every byte position at once, and no memory
//! access is ever indexed by a secret value. How many bytes a plane holds is the word width,
//! which is why everything here is generic over [`PlaneWord`]: `bouncycastle-aes` uses `u16`,
//! `u32` and `u64` planes for one, two and four blocks, `bouncycastle-aria` and `bouncycastle-sm4`
//! `u16` planes for four blocks' worth of one word each, and `bouncycastle-camellia` `u32` planes.
//! Each crate's own `bitslice` module says which bytes it puts where; nothing here depends on it.
//!
//! # Provenance
//!
//! The three-stage masked-swap transpose [`ortho`] is translated from BearSSL
//! `src/symcipher/aes_ct.c` (`br_aes_ct_ortho`), by Thomas Pornin, MIT licensed. The non-linear
//! section [`gf256_inverse_nonlinear`] is the middle 62 gates of the 113-gate straight-line
//! program `SLP_AES_113.txt` in Peralta's circuit collection, described in J. Boyar and
//! R. Peralta, "A new combinational logic minimization technique with applications to
//! cryptology", <https://eprint.iacr.org/2009/191.pdf>; the same gates appear in BearSSL's
//! `br_aes_ct_bitslice_Sbox`, whose variable naming is kept so the two can be diffed. The
//! transcription is the one `bouncycastle-aes` carried, and `test_aes_sbox_through_the_section`
//! below pins it against FIPS 197 Table 4 through AES's own affine layers.

use crate::ct;
use core::ops::{BitAnd, BitOr, BitXor, BitXorAssign, Not, Shl, Shr};

/// Targets whose integer multiply is fixed-latency, so the lane widening in [`PlaneWord::splat`]
/// may be left for LLVM to fold into one. A `const` rather than a `cfg` on the two bodies, so
/// both compile on every target.
const MULTIPLY_IS_FIXED_LATENCY: bool = cfg!(any(target_arch = "x86_64", target_arch = "aarch64"));

/// The eight bit-planes of a bit-sliced state: plane `k` holds bit `k` of every byte.
pub type Planes<T> = [T; 8];

/// A plane word: `u16`, `u32` or `u64`, holding as many bytes as it has bytes, in 16-bit lanes.
///
/// The operator bounds are what the circuits use; the methods are the width-specific parts.
/// Each width is implemented longhand below rather than through a macro, so that every mask and
/// shift is visible to `cargo mutants` and to a reviewer.
pub trait PlaneWord:
    Copy
    + Eq
    + core::fmt::Debug
    + BitAnd<Output = Self>
    + BitOr<Output = Self>
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + Shl<u32, Output = Self>
    + Shr<u32, Output = Self>
{
    /// Replicates a 16-bit pattern into every 16-bit lane: the mask that applies `pattern` to
    /// one lane, applied to all of them.
    fn splat(pattern: u16) -> Self;

    /// Rotates every 16-bit lane right by `n` bits, each lane independently, for `0 < n < 16`.
    ///
    /// A whole-word rotation would carry the bottom of one lane into the top of the next; this
    /// keeps each lane's bits inside it. The bits that stay inside their lane move down by `n`
    /// and are the low `16 - n` bits of it; the `n` bits that would fall out of the bottom of
    /// each lane re-enter as its top `n` bits. Each mask also discards what the shift carried in
    /// from the neighbouring lane. The two masks are complementary, so the operands are disjoint
    /// and `|` and `^` agree here (a known surviving `cargo mutants`).
    ///
    /// Provided for every width; `u16`, having a single lane, overrides it with the word
    /// rotation.
    #[inline(always)]
    fn rotate_lanes_right(self, n: u32) -> Self {
        debug_assert!(0 < n && n < 16);
        ((self >> n) & Self::splat(0xFFFF >> n))
            | ((self << (16 - n)) & Self::splat(0xFFFF << (16 - n)))
    }
}

impl PlaneWord for u16 {
    #[inline(always)]
    fn splat(pattern: u16) -> Self {
        pattern
    }

    #[inline(always)]
    fn rotate_lanes_right(self, n: u32) -> Self {
        self.rotate_right(n)
    }
}

impl PlaneWord for u32 {
    /// Shift-and-or rather than the equivalent `u32::from(pattern) * 0x0001_0001`, because
    /// integer multiplication is not constant-time on every target. LLVM knows the two are the
    /// same and folds this back into a multiply where one is fixed-latency, so the
    /// [`ct::value_barrier`] stands between them only on the targets where that would matter.
    #[inline(always)]
    fn splat(pattern: u16) -> Self {
        let x = u32::from(pattern);
        let x = if MULTIPLY_IS_FIXED_LATENCY { x } else { ct::value_barrier(x) };
        x | (x << 16)
    }
}

impl PlaneWord for u64 {
    /// See the `u32` impl.
    #[inline(always)]
    fn splat(pattern: u16) -> Self {
        let x = u64::from(pattern);
        let x = if MULTIPLY_IS_FIXED_LATENCY { x } else { ct::value_barrier(x) };
        x | (x << 16) | (x << 32) | (x << 48)
    }
}

/// Transposes, within each byte-lane of the eight words, the 8x8 bit matrix indexed by (word
/// number, bit number within the byte): afterwards `q[k]` bit `8L + i` is what `q[i]` bit
/// `8L + k` was. It is its own inverse, so it moves bytes into bit-planes and back.
///
/// Three stages of masked swaps exchange bit-fields of width 1, 2 and 4 between pairs of words.
/// In each swap `cl` and `ch` are complementary and `s` is exactly the field width, so in each
/// returned word the two combined operands occupy disjoint bits: `(x & cl)` and `(y & cl) << s`
/// cannot both be set in the same position. `|` and `^` therefore compute the same function
/// there, which is why `cargo mutants` reports the `| -> ^` mutants in `swap` as surviving; the
/// involution and layout tests are what pin this code.
#[inline]
pub fn ortho<T: PlaneWord>(q: &mut Planes<T>) {
    #[inline(always)]
    fn swap<T: PlaneWord>(cl: T, ch: T, s: u32, x: T, y: T) -> (T, T) {
        ((x & cl) | ((y & cl) << s), ((x & ch) >> s) | (y & ch))
    }

    // Stage 1: swap single bits between adjacent words (0x55 = even bits, 0xAA = odd bits).
    for (a, b) in [(0, 1), (2, 3), (4, 5), (6, 7)] {
        (q[a], q[b]) = swap(T::splat(0x5555), T::splat(0xAAAA), 1, q[a], q[b]);
    }
    // Stage 2: swap 2-bit fields between words two apart.
    for (a, b) in [(0, 2), (1, 3), (4, 6), (5, 7)] {
        (q[a], q[b]) = swap(T::splat(0x3333), T::splat(0xCCCC), 2, q[a], q[b]);
    }
    // Stage 3: swap nibbles between words four apart.
    for (a, b) in [(0, 4), (1, 5), (2, 6), (3, 7)] {
        (q[a], q[b]) = swap(T::splat(0x0F0F), T::splat(0xF0F0), 4, q[a], q[b]);
    }
}

/// The 22 signals the non-linear section consumes: the straight-line program's `U7` and
/// `Y1 .. Y21`, which a cipher's top affine layer produces from its eight input planes.
#[derive(Clone, Copy)]
pub struct InverseInputs<T> {
    /// The program's `U7`.
    pub u7: T,
    /// The program's `Y1`.
    pub y1: T,
    /// The program's `Y2`.
    pub y2: T,
    /// The program's `Y3`.
    pub y3: T,
    /// The program's `Y4`.
    pub y4: T,
    /// The program's `Y5`.
    pub y5: T,
    /// The program's `Y6`.
    pub y6: T,
    /// The program's `Y7`.
    pub y7: T,
    /// The program's `Y8`.
    pub y8: T,
    /// The program's `Y9`.
    pub y9: T,
    /// The program's `Y10`.
    pub y10: T,
    /// The program's `Y11`.
    pub y11: T,
    /// The program's `Y12`.
    pub y12: T,
    /// The program's `Y13`.
    pub y13: T,
    /// The program's `Y14`.
    pub y14: T,
    /// The program's `Y15`.
    pub y15: T,
    /// The program's `Y16`.
    pub y16: T,
    /// The program's `Y17`.
    pub y17: T,
    /// The program's `Y18`.
    pub y18: T,
    /// The program's `Y19`.
    pub y19: T,
    /// The program's `Y20`.
    pub y20: T,
    /// The program's `Y21`.
    pub y21: T,
}

/// The 18 signals the non-linear section produces: the program's `Z0 .. Z17`, the coordinates of
/// the inverse in the tower-field basis, which a cipher's bottom affine layer maps to its eight
/// output planes.
#[derive(Clone, Copy)]
pub struct InverseOutputs<T> {
    /// The program's `Z0`.
    pub z0: T,
    /// The program's `Z1`.
    pub z1: T,
    /// The program's `Z2`.
    pub z2: T,
    /// The program's `Z3`.
    pub z3: T,
    /// The program's `Z4`.
    pub z4: T,
    /// The program's `Z5`.
    pub z5: T,
    /// The program's `Z6`.
    pub z6: T,
    /// The program's `Z7`.
    pub z7: T,
    /// The program's `Z8`.
    pub z8: T,
    /// The program's `Z9`.
    pub z9: T,
    /// The program's `Z10`.
    pub z10: T,
    /// The program's `Z11`.
    pub z11: T,
    /// The program's `Z12`.
    pub z12: T,
    /// The program's `Z13`.
    pub z13: T,
    /// The program's `Z14`.
    pub z14: T,
    /// The program's `Z15`.
    pub z15: T,
    /// The program's `Z16`.
    pub z16: T,
    /// The program's `Z17`.
    pub z17: T,
}

/// The non-linear section of the Boyar-Peralta AES S-box circuit: 62 gates, 32 AND and 30 XOR,
/// computing the GF(2^8) inversion in a tower-field representation, and the only ANDs in any of
/// the S-boxes built on it. One pass evaluates it at every byte position the planes hold.
///
/// The gate list is a mechanical transcription of `SLP_AES_113.txt` (`+` is `^`, `x` is `&`),
/// with the SLP's variable names; it is not meaningful line by line and should not be "tidied".
/// Every S-box over it -- AES's own, ARIA's four, Camellia's and SM4's -- is pinned against its
/// specification's table by an exhaustive 256-input test in its crate, and the AES one again in
/// this module.
#[inline(always)]
pub fn gf256_inverse_nonlinear<T: PlaneWord>(i: InverseInputs<T>) -> InverseOutputs<T> {
    let InverseInputs {
        u7,
        y1,
        y2,
        y3,
        y4,
        y5,
        y6,
        y7,
        y8,
        y9,
        y10,
        y11,
        y12,
        y13,
        y14,
        y15,
        y16,
        y17,
        y18,
        y19,
        y20,
        y21,
    } = i;

    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & u7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ y20;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ t14;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;
    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    // `cargo mutants` reports the `^ -> |` mutant on the next line as surviving. That is a true
    // equivalence, not a gap: `t36` and `t34` are never both 1 for any of the 256 possible input
    // bytes, so XOR and OR agree here. It is the only one of the section's XOR gates with that
    // property; every other `^ -> |` mutant is killed by the S-box tests.
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    InverseOutputs {
        z0: t44 & y15,
        z1: t37 & y6,
        z2: t33 & u7,
        z3: t43 & y16,
        z4: t40 & y1,
        z5: t29 & y7,
        z6: t42 & y11,
        z7: t45 & y17,
        z8: t41 & y10,
        z9: t44 & y12,
        z10: t37 & y3,
        z11: t33 & y4,
        z12: t43 & y13,
        z13: t40 & y5,
        z14: t29 & y2,
        z15: t42 & y9,
        z16: t45 & y14,
        z17: t41 & y8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_ortho_is_an_involution<T: PlaneWord>(seed: T) {
        let mut q: Planes<T> = [seed; 8];
        for (i, plane) in q.iter_mut().enumerate() {
            for _ in 0..i {
                *plane = *plane ^ (*plane << 3) ^ T::splat(0x9E37);
            }
        }
        let original = q;
        ortho(&mut q);
        assert_ne!(q, original, "ortho must actually move bits");
        ortho(&mut q);
        assert_eq!(q, original);
    }

    #[test]
    fn test_ortho_is_an_involution_at_every_width() {
        check_ortho_is_an_involution(0x0123u16);
        check_ortho_is_an_involution(0x0123_4567u32);
        check_ortho_is_an_involution(0x0123_4567_89AB_CDEFu64);
    }

    /// A single set bit at (word w, byte-lane L, bit k) must land at (plane k, lane L, bit w).
    fn check_layout<T: PlaneWord>(lanes: u32) {
        for w in 0..8 {
            for lane in 0..lanes {
                for k in 0..8 {
                    let mut q: Planes<T> = [T::splat(0); 8];
                    q[w] = T::splat(1) << (8 * lane + k as u32);
                    ortho(&mut q);
                    let mut expected: Planes<T> = [T::splat(0); 8];
                    expected[k] = T::splat(1) << (8 * lane + w as u32);
                    assert_eq!(q, expected, "word {w}, lane {lane}, bit {k}");
                }
            }
        }
    }

    #[test]
    fn test_layout_matches_the_documented_table() {
        // `splat(1) << n` for n past the first lane is a plain shift of the whole word, which is
        // what the single set bit needs here.
        check_layout::<u16>(2);
        check_layout::<u32>(4);
        check_layout::<u64>(8);
    }

    #[test]
    fn test_splat_replicates_into_every_lane() {
        assert_eq!(u16::splat(0xBEEF), 0xBEEF);
        assert_eq!(u32::splat(0xBEEF), 0xBEEF_BEEF);
        assert_eq!(u64::splat(0xBEEF), 0xBEEF_BEEF_BEEF_BEEF);
    }

    #[test]
    fn test_rotate_lanes_right_rotates_each_lane_on_its_own() {
        for n in 1..16 {
            let one = 0x8001u16.rotate_right(n);
            assert_eq!(u16::splat(0x8001).rotate_lanes_right(n), one);
            assert_eq!(u32::splat(0x8001).rotate_lanes_right(n), u32::splat(one));
            assert_eq!(u64::splat(0x8001).rotate_lanes_right(n), u64::splat(one));
            // Lanes with different contents stay independent.
            let w = 0x8001_0000u32 | 0x0180;
            let expected =
                (u32::from(0x8001u16.rotate_right(n)) << 16) | u32::from(0x0180u16.rotate_right(n));
            assert_eq!(w.rotate_lanes_right(n), expected);
        }
    }

    /// FIPS 197 Table 4, the AES S-box, row-major; the copy the ARIA crate pins its `SB1`
    /// against (RFC 5794 Sec 2.4.2, which is the same table). Test data only.
    #[rustfmt::skip]
    const AES_SBOX: [u8; 256] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

    /// The AES S-box through the section: the top linear transformation and the bottom affine
    /// map of `SLP_AES_113.txt`, as `bouncycastle-aes` writes them, around
    /// [`gf256_inverse_nonlinear`]. Plane `q[k]` holds bit `k`; the SLP's `U0` is the MSB.
    fn aes_sbox(q: &mut Planes<u16>) {
        let u0 = q[7];
        let u1 = q[6];
        let u2 = q[5];
        let u3 = q[4];
        let u4 = q[3];
        let u5 = q[2];
        let u6 = q[1];
        let u7 = q[0];

        let y14 = u3 ^ u5;
        let y13 = u0 ^ u6;
        let y9 = u0 ^ u3;
        let y8 = u0 ^ u5;
        let t0 = u1 ^ u2;
        let y1 = t0 ^ u7;
        let y4 = y1 ^ u3;
        let y12 = y13 ^ y14;
        let y2 = y1 ^ u0;
        let y5 = y1 ^ u6;
        let y3 = y5 ^ y8;
        let t1 = u4 ^ y12;
        let y15 = t1 ^ u5;
        let y20 = t1 ^ u1;
        let y6 = y15 ^ u7;
        let y10 = y15 ^ t0;
        let y11 = y20 ^ y9;
        let y7 = u7 ^ y11;
        let y17 = y10 ^ y11;
        let y19 = y10 ^ y8;
        let y16 = t0 ^ y11;
        let y21 = y13 ^ y16;
        let y18 = u0 ^ y16;

        let InverseOutputs {
            z0,
            z1,
            z2,
            z3,
            z4,
            z5,
            z6,
            z7,
            z8,
            z9,
            z10,
            z11,
            z12,
            z13,
            z14,
            z15,
            z16,
            z17,
        } = gf256_inverse_nonlinear(InverseInputs {
            u7,
            y1,
            y2,
            y3,
            y4,
            y5,
            y6,
            y7,
            y8,
            y9,
            y10,
            y11,
            y12,
            y13,
            y14,
            y15,
            y16,
            y17,
            y18,
            y19,
            y20,
            y21,
        });

        let tc1 = z15 ^ z16;
        let tc2 = z10 ^ tc1;
        let tc3 = z9 ^ tc2;
        let tc4 = z0 ^ z2;
        let tc5 = z1 ^ z0;
        let tc6 = z3 ^ z4;
        let tc7 = z12 ^ tc4;
        let tc8 = z7 ^ tc6;
        let tc9 = z8 ^ tc7;
        let tc10 = tc8 ^ tc9;
        let tc11 = tc6 ^ tc5;
        let tc12 = z3 ^ z5;
        let tc13 = z13 ^ tc1;
        let tc14 = tc4 ^ tc12;
        let s3 = tc3 ^ tc11;
        let tc16 = z6 ^ tc8;
        let tc17 = z14 ^ tc10;
        let tc18 = tc13 ^ tc14;
        let s7 = !(z12 ^ tc18);
        let tc20 = z15 ^ tc16;
        let tc21 = tc2 ^ z11;
        let s0 = tc3 ^ tc16;
        let s6 = !(tc10 ^ tc18);
        let s4 = tc14 ^ s3;
        let s1 = !(s3 ^ tc16);
        let tc26 = tc17 ^ tc20;
        let s2 = !(tc26 ^ z17);
        let s5 = tc21 ^ tc17;

        q[7] = s0;
        q[6] = s1;
        q[5] = s2;
        q[4] = s3;
        q[3] = s4;
        q[2] = s5;
        q[1] = s6;
        q[0] = s7;
    }

    /// Every input byte at once: byte `x` sits at bit position `x mod 16` of planes built from
    /// sixteen inputs at a time, so sixteen passes cover all 256.
    #[test]
    fn test_aes_sbox_through_the_section() {
        for group in 0..16u16 {
            let inputs: [u8; 16] = core::array::from_fn(|i| (16 * group as usize + i) as u8);
            let mut q: Planes<u16> = [0; 8];
            for (pos, &x) in inputs.iter().enumerate() {
                for (k, plane) in q.iter_mut().enumerate() {
                    *plane |= u16::from((x >> k) & 1) << pos;
                }
            }
            aes_sbox(&mut q);
            for (pos, &x) in inputs.iter().enumerate() {
                let mut y = 0u8;
                for (k, plane) in q.iter().enumerate() {
                    y |= (((plane >> pos) & 1) as u8) << k;
                }
                assert_eq!(y, AES_SBOX[x as usize], "S({x:#04x})");
            }
        }
    }
}
