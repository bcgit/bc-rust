//! The S-box `S` and the nonlinear transformation `tau` as a Boolean circuit
//! (GB/T 32907-2016, as described in draft-ribose-cfrg-sm4-10 Sec 6.2.1 and Sec 6.2.3).
//!
//! # Why a circuit and not a table
//!
//! Sec 6.2.3 presents the S-box as a 256-entry lookup table (Figure 1), and BC Java's `SM4Engine`
//! stores it as one. A table indexed by a byte of the state is indexed by *secret data*, and on
//! any CPU with a data cache the access pattern -- hence the timing -- depends on that secret.
//! That is the standard cache-timing side channel of every table-driven block cipher, and it
//! cannot be closed while keeping the lookup.
//!
//! So this module has no table (outside its tests). It computes the same function as Figure 1
//! with AND, XOR, XNOR and NOT gates applied to the bit-planes of [`crate::bitslice`]. Every
//! operation is a straight-line word operation on public *positions*, so there is no
//! secret-dependent memory access and no secret-dependent branch. This is the only place in the
//! crate where secret data meets non-linear logic; everything else is XOR and rotate.
//!
//! Because the planes hold the four bytes of one word from each of four blocks -- as two 16-bit
//! halves each -- one pass of the circuit is `tau` for four blocks at once.
//!
//! # What the circuit computes, and where it came from
//!
//! The SM4 S-box has the same algebraic shape as the AES one: an affine map, inversion in
//! GF(2^8), and another affine map. Specifically, with `A` the circulant matrix whose rows are
//! `A7 4F 9E 3D 7A F4 E9 D3` (row `i` is the mask of input bits XORed into output bit `i`, bit 0
//! least significant) and `C = 0xD3`,
//!
//! ```text
//! S(x) = A * inv(A * x xor C) xor C,     inv in GF(2^8) mod x^8 + x^7 + x^6 + x^5 + x^4 + x^2 + 1
//! ```
//!
//! This decomposition was **found by search, not recalled**: every circulant affine map, every
//! constant and every irreducible degree-8 polynomial was tried against the Figure 1 table
//! extracted from the text of the draft, and exactly one decomposition (plus its bit-reversed
//! mirror) reproduces all 256 entries. It agrees with the analysis of Liu, Ji, Hu, Ding and Lv,
//! "Analysis of the SMS4 Block Cipher" (ACISP 2007).
//!
//! Because both S-boxes are inversion between affine maps, a field isomorphism `phi` from the
//! SM4 representation to the AES one (`x^8 + x^4 + x^3 + x + 1`) lets the AES inversion circuit
//! do SM4's work: `inv_sm4(w) = phi^-1(inv_aes(phi(w)))`. The circuit below is therefore
//!
//! * a **top affine layer**, generated: `phi(A * x xor C)` composed with the Boyar-Peralta input
//!   basis change, as one affine map from the eight input planes to the 22 signals the
//!   non-linear section consumes;
//! * the **non-linear section** of the 113-gate Boyar-Peralta AES circuit, **copied verbatim**
//!   from `bouncycastle-aes` (`src/sbox.rs`, itself a transcription of Peralta's
//!   `SLP_AES_113.txt`): 32 AND and 30 XOR gates computing the inverse in a tower-field
//!   representation;
//! * a **bottom affine layer**, generated: the tower field back to the AES polynomial basis,
//!   `phi^-1`, then `A * . xor C`, as one affine map from the 18 non-linear outputs to the eight
//!   output planes.
//!
//! The two affine layers were fitted by linear algebra over GF(2) (the bottom one by solving for
//! the linear map from the non-linear section's outputs to `inv_aes`, on all 256 inputs) and
//! reduced with a greedy common-subexpression pass; `phi` was chosen among the eight roots of the
//! SM4 polynomial in the AES field to minimise the gate count. The result is 127 gates: 32 AND,
//! 82 XOR, 12 XNOR, 1 NOT. The generator verified the assembled circuit against the table before
//! any of it was written here, and `test_sbox_matches_figure_1` re-verifies all 256 inputs in
//! Rust. The gate list is not meaningful line by line and should not be "tidied".
//!
//! # Bit numbering
//!
//! Plane `k` holds bit `k` of every byte (bit 0 least significant), for inputs and outputs alike.
//! The Boyar-Peralta section keeps its own signal names (`y*`, `t*`, `z*`) so it can be diffed
//! against the AES crate; its inputs are bound from the generated top layer, so its `U0`-is-MSB
//! convention never appears here.

use crate::LANES;
use crate::bitslice::{Planes, ortho};

/// `S` applied to every byte position of the eight words in `q` (Sec 6.2.3, Figure 1), on
/// bit-planes: `q[k]` holds bit `k` of each byte on entry and on exit.
///
/// See the module docs for what the three sections are and where they come from.
pub(crate) fn sbox(q: &mut Planes) {
    // Inputs: plane k holds bit k of every byte.
    let x0 = q[0];
    let x1 = q[1];
    let x2 = q[2];
    let x3 = q[3];
    let x4 = q[4];
    let x5 = q[5];
    let x6 = q[6];
    let x7 = q[7];

    // Top affine layer (32 XOR/XNOR gates, generated): the SM4 input affine map, the field
    // isomorphism into the AES representation, and the Boyar-Peralta input basis change, folded
    // into one linear map over x0..x7. NOTs carry the affine constants.
    let a1 = x2 ^ x4;
    let a2 = x0 ^ x3;
    let a3 = x1 ^ x7;
    let a4 = a1 ^ x5;
    let a5 = a2 ^ x1;
    let a6 = a2 ^ a3;
    let a7 = x2 ^ x6;
    let a8 = a1 ^ x7;
    let a9 = a4 ^ x6;
    let a10 = a6 ^ x4;
    let a11 = a5 ^ x5;
    let a12 = a3 ^ x3;
    let a13 = a9 ^ x7;
    let a14 = a11 ^ a7;
    let a15 = x3 ^ x5;
    let a16 = !(a15 ^ x7);
    let a17 = a2 ^ a8;
    let a18 = a17 ^ x6;
    let a19 = a3 ^ a9;
    let a20 = a7 ^ x1;
    let a21 = !(a3 ^ a4);
    let a22 = !(x2 ^ x7);
    let a23 = !(a4 ^ x3);
    let a24 = !(a1 ^ a5);
    let a25 = !(a8 ^ x0);
    let a26 = a10 ^ x5;
    let a27 = a26 ^ x6;
    let a28 = a2 ^ a4;
    let a29 = a4 ^ a5;
    let a30 = a3 ^ x0;
    let a31 = a30 ^ x4;
    let a32 = !(a31 ^ x6);
    let u7 = a12;
    let y14 = a13;
    let y13 = x1;
    let y9 = a10;
    let y8 = a14;
    let y1 = a16;
    let y4 = a18;
    let y12 = a19;
    let y2 = a20;
    let y5 = a7;
    let y3 = a11;
    let y15 = a21;
    let y20 = a22;
    let y6 = a23;
    let y10 = a8;
    let y11 = a24;
    let y7 = a25;
    let y17 = !a6;
    let y19 = a27;
    let y16 = a28;
    let y21 = a29;
    let y18 = a32;

    // Non-linear section (62 gates): GF(2^8) inversion, copied verbatim from the Boyar-Peralta
    // AES circuit in `bouncycastle-aes` (`src/sbox.rs`). It consumes the signals bound
    // above and produces the tower-field coordinates of the inverse.
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
    // bytes, so XOR and OR agree here. It is the only one of the circuit's 82 XOR gates with that
    // property -- every other `^ -> |` mutant is killed by `test_sbox_matches_figure_1` -- and it
    // is the same gate the AES crate documents, since this section is copied from there.
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & u7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom affine layer (32 XOR/XNOR gates, generated): tower field back to the AES polynomial
    // basis, the isomorphism back to the SM4 field, and the SM4 output affine map, folded into
    // one affine map over the inverse's coordinates; XNORs and NOTs carry the 0xD3 constant.
    let b1 = z0 ^ z10;
    let b2 = z15 ^ z9;
    let b3 = b1 ^ z1;
    let b4 = z13 ^ z14;
    let b5 = b4 ^ z6;
    let b6 = b2 ^ b3;
    let b7 = z5 ^ z8;
    let b8 = b5 ^ z4;
    let b9 = b6 ^ b7;
    let b10 = b9 ^ z16;
    let b11 = z3 ^ z7;
    let b12 = b8 ^ z11;
    let b13 = b2 ^ z17;
    let b14 = !(b10 ^ b11);
    let b15 = b12 ^ b3;
    let b16 = !(b15 ^ b7);
    let b17 = b11 ^ b13;
    let b18 = b17 ^ b8;
    let b19 = b18 ^ z10;
    let b20 = b13 ^ z11;
    let b21 = b10 ^ z4;
    let b22 = !(b21 ^ z6);
    let b23 = b5 ^ b6;
    let b24 = b23 ^ z17;
    let b25 = b24 ^ z7;
    let b26 = b1 ^ b12;
    let b27 = b26 ^ z2;
    let b28 = b27 ^ z5;
    let b29 = !(b28 ^ z7);
    let b30 = z12 ^ z13;
    let b31 = b30 ^ z15;
    let b32 = !(b31 ^ z16);

    // Outputs: plane j receives bit j of S(x).
    q[0] = b14;
    q[1] = b16;
    q[2] = b19;
    q[3] = b20;
    q[4] = b22;
    q[5] = b25;
    q[6] = b29;
    q[7] = b32;
}

/// `tau(A) = (S(a_0), S(a_1), S(a_2), S(a_3))` (Sec 6.2.1), on one word from each of four
/// blocks at once.
///
/// Each word is split into its two 16-bit halves -- the high halves in plane words `0 .. 4`, the
/// low halves in `4 .. 8` -- the eight half-words are transposed into bit-planes, every byte
/// position is substituted by one pass of [`sbox`], the planes are transposed back and the halves
/// rejoined. The byte order within a word is irrelevant to `tau`, which substitutes each byte
/// independently; [`ortho`] being its own inverse is what returns each substituted byte to its
/// original position.
pub(crate) fn tau(words: &mut [u32; LANES]) {
    let mut q: Planes = [0; 8];
    for b in 0..LANES {
        q[b] = (words[b] >> 16) as u16;
        q[LANES + b] = words[b] as u16;
    }
    ortho(&mut q);
    sbox(&mut q);
    ortho(&mut q);
    for b in 0..LANES {
        // The two halves occupy disjoint bit ranges, so `|` and `^` agree here -- a surviving
        // `cargo mutants` equivalence, not a gap.
        words[b] = ((q[b] as u32) << 16) | q[LANES + b] as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Figure 1, "SM4 S-box Values", row-major: `SBOX[16 * row + column]`. Extracted mechanically
    /// from the text of the draft; byte-for-byte the `Sbox` array in BC Java's `SM4Engine`. Test
    /// data only -- the engine never reads it.
    const SBOX: [u8; 256] = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c,
        0x05, 0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86,
        0x06, 0x99, 0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed,
        0xcf, 0xac, 0x62, 0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa,
        0x75, 0x8f, 0x3f, 0xa6, 0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c,
        0x19, 0xe6, 0x85, 0x4f, 0xa8, 0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb,
        0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35, 0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25,
        0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87, 0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
        0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e, 0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38,
        0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1, 0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34,
        0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3, 0x1d, 0xf6, 0xe2, 0x2e, 0x82,
        0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f, 0xd5, 0xdb, 0x37, 0x45,
        0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51, 0x8d, 0x1b, 0xaf,
        0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8, 0x0a, 0xc1,
        0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0, 0x89,
        0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
        0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39,
        0x48,
    ];

    /// The table-driven `tau` of BC Java, on one word. Test reference only.
    fn tau_table(a: u32) -> u32 {
        let [a0, a1, a2, a3] = a.to_be_bytes();
        u32::from_be_bytes([
            SBOX[a0 as usize], SBOX[a1 as usize], SBOX[a2 as usize], SBOX[a3 as usize],
        ])
    }

    #[test]
    fn test_table_matches_the_worked_example() {
        // Sec 6.2.3: "input 'EF' will produce an output read from the S-box table row E and
        // column F, giving the result S(EF) = 84." Pins the row-major flattening of the test data.
        assert_eq!(SBOX[0xEF], 0x84);
        assert_eq!(SBOX[0x00], 0xD6);
        assert_eq!(SBOX[0x0F], 0x05);
        assert_eq!(SBOX[0xF0], 0x18);
        assert_eq!(SBOX[0xFF], 0x48);
    }

    #[test]
    fn test_sbox_matches_figure_1() {
        // Exhaustive: all 256 inputs. 16 byte positions per pass, so sixteen passes cover them
        // all, with the byte value `16 * pass + position` at each position. This is what makes the
        // generated gate list trustworthy, so it must stay exhaustive.
        for pass in 0..16u16 {
            let mut q: Planes = core::array::from_fn(|w| {
                let base = 16 * pass + 2 * w as u16;
                u16::from_le_bytes([base as u8, base as u8 + 1])
            });
            let inputs = q;
            ortho(&mut q);
            sbox(&mut q);
            ortho(&mut q);
            for (w, (got, input)) in q.iter().zip(inputs.iter()).enumerate() {
                for (byte, expected) in got
                    .to_le_bytes()
                    .iter()
                    .zip(input.to_le_bytes().iter().map(|&b| SBOX[b as usize]))
                {
                    assert_eq!(*byte, expected, "pass {pass}, word {w}, input {input:#06x}");
                }
            }
        }
    }

    #[test]
    fn test_tau_matches_the_table_form() {
        // Four different words at once, against the byte-by-byte table lookup, twice.
        for mut words in [
            [0xEF00_0000u32, 0x00EF_0000, 0x0000_EF00, 0x0000_00EF],
            [0x0123_4567, 0x89AB_CDEF, 0xFFFF_FFFF, 0x0000_0000],
        ] {
            let expected: [u32; LANES] = core::array::from_fn(|i| tau_table(words[i]));
            tau(&mut words);
            assert_eq!(words, expected);
        }
        // Sec 6.2.1: the bytes are independent, most significant byte first.
        let mut words = [0xEF00_0000u32, 0x00EF_0000, 0x0000_EF00, 0x0000_00EF];
        tau(&mut words);
        assert_eq!(words[0], 0x84D6_D6D6);
        assert_eq!(words[3], 0xD6D6_D684);
    }

    #[test]
    fn test_tau_lanes_are_independent() {
        // Changing one word must not change any other word's output.
        let base: [u32; LANES] =
            core::array::from_fn(|i| 0x1111_1111u32.wrapping_mul(i as u32 + 1));
        let mut expected = base;
        tau(&mut expected);
        for lane in 0..LANES {
            let mut words = base;
            words[lane] ^= 0xA5A5_5A5A;
            tau(&mut words);
            for other in (0..LANES).filter(|&o| o != lane) {
                assert_eq!(words[other], expected[other], "lane {lane} disturbed lane {other}");
            }
            assert_eq!(words[lane], tau_table(base[lane] ^ 0xA5A5_5A5A));
        }
    }
}
