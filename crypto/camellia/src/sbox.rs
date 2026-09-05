//! `SBOX1` .. `SBOX4` (RFC 3713 Sec 2.4.1) as a Boolean circuit over bit-planes.
//!
//! # Why a circuit and not a table
//!
//! Sec 2.4.1 defines `SBOX1` by a 256-entry table and the other three in terms of it, and BC
//! Java's `CamelliaEngine` and `CamelliaLightEngine` both store tables (four 1 KiB `u32` tables
//! with the P-function folded in, and one 256-byte table, respectively). A table indexed by a
//! byte of the state is indexed by *secret data*, and on any CPU with a data cache the access
//! pattern -- hence the timing -- depends on that secret. That is the standard cache-timing side
//! channel of every table-driven block cipher, and it cannot be closed while keeping the lookup.
//!
//! So this module has no table (outside its tests). It computes the same function as the Sec 2.4.1
//! table with AND, XOR, XNOR and NOT gates applied to the bit-planes of [`crate::bitslice`]. Every
//! operation is a straight-line word operation on public *positions*, so there is no
//! secret-dependent memory access and no secret-dependent branch. This is the only place in the
//! crate where secret data meets non-linear logic; everything else is XOR, AND/OR with key words,
//! and rotates.
//!
//! Because the planes hold the eight bytes of one F-function input from each of four blocks, one
//! pass of the circuit is the whole S-box layer of a round for four blocks at once.
//!
//! # What the circuit computes, and where it came from
//!
//! `SBOX1` has the same algebraic shape as the AES S-box: an affine map, inversion in GF(2^8), and
//! another affine map. Writing `inv` for inversion in the AES field (`x^8 + x^4 + x^3 + x + 1`,
//! with `inv(0) = 0`), and `M`, `N` for 8x8 matrices over GF(2) given by their columns (column
//! `i` is the image of input bit `i`, bit 0 least significant):
//!
//! ```text
//! SBOX1(x) = N * inv(M * x xor 0x82) xor 0x6e
//!
//!   M columns: 0x38, 0x84, 0xe7, 0xbb, 0x94, 0xff, 0x0d, 0x50
//!   N columns: 0xeb, 0x38, 0x5c, 0x19, 0xc5, 0xf8, 0xb5, 0x41
//! ```
//!
//! The input constant `0x82` is `M * 0xc5`, so equivalently `SBOX1(x) = N * inv(M * (x xor
//! 0xc5)) xor 0x6e`. This decomposition was **found by search, not recalled**: for each of the
//! 256 possible input constants the remaining linear equivalence to `inv` was searched
//! exhaustively (the search fixes the multiplicative and Frobenius self-equivalences of `inv`,
//! which is what makes it finite), against the table extracted from the text of RFC 3713. Exactly
//! one constant, `0xc5`, admits a decomposition, and it is unique up to those self-equivalences.
//! The 2040 equivalent forms give circuits of different sizes; the one above was chosen for the
//! fewest gates.
//!
//! Because both S-boxes are inversion between affine maps, the AES inversion circuit does
//! Camellia's work directly -- the field isomorphism is absorbed into `M` and `N`, since the
//! search was carried out in the AES representation. The circuit below is therefore
//!
//! * a **top affine layer**, generated: `M * x xor 0x82` composed with the Boyar-Peralta input
//!   basis change, as one affine map from the eight input planes to the 22 signals the
//!   non-linear section consumes;
//! * the **non-linear section** of the 113-gate Boyar-Peralta AES circuit, **copied verbatim**
//!   from `bouncycastle-aes` (`src/sbox.rs`, itself a transcription of Peralta's
//!   `SLP_AES_113.txt`): 32 AND and 30 XOR gates computing the inverse in a tower-field
//!   representation;
//! * a **bottom affine layer**, generated: the tower field back to the AES polynomial basis, then
//!   `N * . xor 0x6e`, as one affine map from the 18 non-linear outputs to the eight output planes.
//!
//! The two affine layers were fitted by linear algebra over GF(2) (the bottom one by solving for
//! the linear map from the non-linear section's outputs to `inv`, on all 256 inputs) and reduced
//! with a greedy common-subexpression pass. The result is 121 gates: 32 AND, 74 XOR, 9 XNOR,
//! 6 NOT (31 in the top layer, 62 in the non-linear section, 28 in the bottom layer). The
//! generator verified the assembled circuit -- the emitted text, re-evaluated -- against the table
//! before any of it was written here, and `test_sbox_matches_rfc_3713_sbox1` re-verifies all 256
//! inputs in Rust. The gate list is not meaningful line by line and should not be "tidied".
//!
//! # The other three S-boxes
//!
//! Sec 2.4.1 defines `SBOX2[x] = SBOX1[x] <<< 1`, `SBOX3[x] = SBOX1[x] <<< 7` and
//! `SBOX4[x] = SBOX1[x <<< 1]`: rotations of the output byte, or of the input byte, by one bit.
//! On bit-planes a byte rotation is a *renumbering of the planes*, so [`sboxes`] runs the one
//! circuit for all 32 byte positions and applies the rotations only at the positions that need
//! them, with public position masks derived from the layout of [`crate::bitslice`]: plane `k` at
//! those positions is
//! taken from plane `k - 1` (rotate left) or `k + 1` (rotate right). No second circuit, and no
//! secret-dependent selection -- the masks are compile-time constants.
//!
//! # Bit numbering
//!
//! Plane `k` holds bit `k` of every byte (bit 0 least significant), for inputs and outputs alike.
//! The Boyar-Peralta section keeps its own signal names (`y*`, `t*`, `z*`) so it can be diffed
//! against the AES and SM4 crates; its inputs are bound from the generated top layer, so its
//! `U0`-is-MSB convention never appears here.

use crate::LANES;
use crate::bitslice::{Planes, ortho};

// The position masks. [`sboxes`] loads plane word `b` with the high 32 bits of block `b`'s
// F-function input (`t1 t2 t3 t4`, most significant byte first) and word `4 + b` with the low 32
// bits (`t5 t6 t7 t8`), so after `ortho` the bits `8L .. 8L+3` of every plane are byte `L` of the
// four high halves and `8L+4 .. 8L+7` byte `L` of the four low halves. Byte `L = 3` of the high
// half is `t1` and byte `L = 0` is `t4`; of the low half, `t5` and `t8`. So a byte position's
// S-box is a public 32-bit mask, and the four masks partition the word.
//
// The `|` in each constant joins disjoint nibbles, so `|` and `^` compute the same constant;
// `cargo mutants` reports those `| -> ^` mutants as surviving, and they are equivalences.

/// The positions that go through `SBOX2`: `t2` (high half, byte 2) and `t5` (low half, byte 3).
const SBOX2_LANES: u32 = (0x0F << 16) | (0xF0 << 24);
/// The positions that go through `SBOX3`: `t3` (high half, byte 1) and `t6` (low half, byte 2).
const SBOX3_LANES: u32 = (0x0F << 8) | (0xF0 << 16);
/// The positions that go through `SBOX4`: `t4` (high half, byte 0) and `t7` (low half, byte 1).
const SBOX4_LANES: u32 = 0x0F | (0xF0 << 8);

/// `SBOX1` applied to every byte position of the eight words in `q` (Sec 2.4.1), on bit-planes:
/// `q[k]` holds bit `k` of each byte on entry and on exit.
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

    // Top affine layer (31 gates, generated): the input affine map `M * x xor 0x82` and the
    // Boyar-Peralta input basis change, folded into one affine map over x0..x7. NOTs and XNORs
    // carry the constant.
    let a1 = x3 ^ x6;
    let a2 = x0 ^ x7;
    let a3 = x2 ^ a1;
    let a4 = x1 ^ x4;
    let a5 = a1 ^ a2;
    let a6 = x2 ^ a2;
    let a7 = x4 ^ a3;
    let a8 = x2 ^ x3;
    let a9 = x0 ^ x1;
    let a10 = x1 ^ x7;
    let a11 = a4 ^ a5;
    let a12 = x5 ^ a3;
    let a13 = x5 ^ x6;
    let a14 = a13 ^ a6;
    let a15 = x5 ^ a8;
    let a16 = a15 ^ a10;
    let a17 = !(x5 ^ a11);
    let a18 = !(x1 ^ a6);
    let a19 = a1 ^ a9;
    let a20 = !(a4 ^ a6);
    let a21 = a2 ^ a7;
    let a22 = x1 ^ a2;
    let a23 = a22 ^ a3;
    let a24 = x6 ^ a10;
    let a25 = !(a4 ^ a8);
    let a26 = !(x7 ^ a7);
    let u7 = a12;
    let y1 = a14;
    let y2 = !a11;
    let y3 = a2;
    let y4 = a7;
    let y5 = !a5;
    let y6 = a16;
    let y7 = a17;
    let y8 = !a1;
    let y9 = a18;
    let y10 = a19;
    let y11 = a20;
    let y12 = a21;
    let y13 = a4;
    let y14 = a23;
    let y15 = a24;
    let y16 = a25;
    let y17 = a26;
    let y18 = x5;
    let y19 = !a9;
    let y20 = x4;
    let y21 = !a8;

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
    // bytes, so XOR and OR agree here. It is the same gate the AES and SM4 crates document, since
    // this section is copied from there; `test_sbox_matches_rfc_3713_sbox1` kills every other
    // `^ -> |` mutant in the circuit.
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

    // Bottom affine layer (28 gates, generated): tower field back to the AES polynomial basis
    // and the output affine map `N * . xor 0x6e`, folded into one affine map over the inverse's
    // coordinates; XNORs and NOTs carry the constant. Plane j receives bit j of SBOX1(x).
    let b1 = z9 ^ z15;
    let b2 = z2 ^ z8;
    let b3 = z3 ^ z6;
    let b4 = z10 ^ b1;
    let b5 = z13 ^ z14;
    let b6 = z1 ^ b2;
    let b7 = z4 ^ b3;
    let b8 = z11 ^ b1;
    let b9 = z17 ^ b4;
    let b10 = b5 ^ b9;
    let b11 = z7 ^ z12;
    let b12 = b11 ^ z14;
    let b13 = b12 ^ z15;
    let b14 = b13 ^ z17;
    let b15 = b14 ^ b6;
    let b16 = !(z17 ^ b8);
    let b17 = z5 ^ z8;
    let b18 = b17 ^ b3;
    let b19 = !(b18 ^ b10);
    let b20 = z16 ^ b5;
    let b21 = !(b20 ^ b8);
    let b22 = z16 ^ b4;
    let b23 = b22 ^ b6;
    let b24 = b23 ^ b7;
    let b25 = !(z7 ^ b7);
    let b26 = z0 ^ z6;
    let b27 = b26 ^ b2;
    q[0] = b15;
    q[1] = b16;
    q[2] = b19;
    q[3] = b21;
    q[4] = b24;
    q[5] = b25;
    q[6] = !b10;
    q[7] = b27;
}

/// Rotates the byte at every position selected by `lanes` one bit to the left, on bit-planes:
/// bit `k` of the output byte is bit `k - 1` of the input byte, so plane `k` takes plane
/// `k - 1` (mod 8) at those positions and is unchanged elsewhere.
///
/// `lanes` is a public constant, so this is a fixed data movement, not a secret-dependent one.
/// The two operands of the `|` occupy disjoint bits (`lanes` and its complement), so `|` and `^`
/// compute the same function here; `cargo mutants` reports that as a surviving mutant, and
/// `test_sboxes_apply_the_four_tables_to_the_right_bytes` is what pins the code.
fn rotate_bytes_left_at(q: &mut Planes, lanes: u32) {
    let old = *q;
    for k in 0..8 {
        q[k] = (old[k] & !lanes) | (old[(k + 7) % 8] & lanes);
    }
}

/// Rotates the byte at every position selected by `lanes` one bit to the right: plane `k` takes
/// plane `k + 1` (mod 8) at those positions. See [`rotate_bytes_left_at`].
fn rotate_bytes_right_at(q: &mut Planes, lanes: u32) {
    let old = *q;
    for k in 0..8 {
        q[k] = (old[k] & !lanes) | (old[(k + 1) % 8] & lanes);
    }
}

/// The S-box layer of the F-function (Sec 2.4.1): `t1 = SBOX1[t1]; t2 = SBOX2[t2]; t3 = SBOX3[t3];
/// t4 = SBOX4[t4]; t5 = SBOX2[t5]; t6 = SBOX3[t6]; t7 = SBOX4[t7]; t8 = SBOX1[t8]`, on the
/// 64-bit `x` of one F-function from each of four blocks at once.
///
/// `x[b]` is `x` for block `b`, big-endian as Sec 2.4.1 reads it: `t1 = x >> 56` is the most
/// significant byte. Each word is split into its two 32-bit halves -- the high halves in plane
/// words `0 .. 4`, the low halves in `4 .. 8` -- and the eight words are transposed into
/// bit-planes; the bytes bound for `SBOX4` are rotated left one bit (`SBOX4[x] = SBOX1[x <<< 1]`);
/// one pass of [`sbox`] substitutes all 32 bytes; the bytes that came from `SBOX2` positions are
/// rotated left (`SBOX2[x] = SBOX1[x] <<< 1`) and those from `SBOX3` positions right
/// (`SBOX3[x] = SBOX1[x] <<< 7`, which on a byte is a rotate right by one); the planes are
/// transposed back and the halves rejoined. [`ortho`] being its own inverse is what returns each
/// substituted byte to its original position.
pub(crate) fn sboxes(x: &mut [u64; LANES]) {
    let mut q: Planes = [0; 8];
    for b in 0..LANES {
        q[b] = (x[b] >> 32) as u32;
        q[LANES + b] = x[b] as u32;
    }
    ortho(&mut q);
    rotate_bytes_left_at(&mut q, SBOX4_LANES);
    sbox(&mut q);
    rotate_bytes_left_at(&mut q, SBOX2_LANES);
    rotate_bytes_right_at(&mut q, SBOX3_LANES);
    ortho(&mut q);
    for b in 0..LANES {
        // The two halves occupy disjoint bit ranges, so `|` and `^` agree here (a surviving
        // `cargo mutants` equivalence, as in `round::p`).
        x[b] = ((q[b] as u64) << 32) | q[LANES + b] as u64;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Sec 2.4.1, the `SBOX1` table, row-major: `SBOX1[16 * row + column]`. Extracted mechanically
    /// from the text of RFC 3713 (the table is decimal there, and is kept decimal here so it can
    /// be diffed against the RFC); byte-for-byte the `SBOX1` array in BC Java's
    /// `CamelliaLightEngine`. Test data only -- the engine never reads it.
    #[rustfmt::skip]
    pub(crate) const SBOX1: [u8; 256] = [
        112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
         35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
        134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
        166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
        139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
        223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
         20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
        254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
        170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
         16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
        135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
         82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
        233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
        120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
        114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
         64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158,
    ];

    /// `SBOX2[x] = SBOX1[x] <<< 1` (Sec 2.4.1).
    fn sbox2(x: u8) -> u8 {
        SBOX1[x as usize].rotate_left(1)
    }
    /// `SBOX3[x] = SBOX1[x] <<< 7` (Sec 2.4.1).
    fn sbox3(x: u8) -> u8 {
        SBOX1[x as usize].rotate_left(7)
    }
    /// `SBOX4[x] = SBOX1[x <<< 1]` (Sec 2.4.1).
    fn sbox4(x: u8) -> u8 {
        SBOX1[x.rotate_left(1) as usize]
    }

    /// The table-driven S-box layer, on one word: `t1 .. t8` through `SBOX1, 2, 3, 4, 2, 3, 4, 1`.
    pub(crate) fn sboxes_table(x: u64) -> u64 {
        let [t1, t2, t3, t4, t5, t6, t7, t8] = x.to_be_bytes();
        u64::from_be_bytes([
            SBOX1[t1 as usize],
            sbox2(t2),
            sbox3(t3),
            sbox4(t4),
            sbox2(t5),
            sbox3(t6),
            sbox4(t7),
            SBOX1[t8 as usize],
        ])
    }

    #[test]
    fn test_table_matches_the_worked_example() {
        // Sec 2.4.1: "For example, SBOX1[0x3d] equals 86." Pins the row-major flattening.
        assert_eq!(SBOX1[0x3d], 86);
        assert_eq!(SBOX1[0x00], 112);
        assert_eq!(SBOX1[0x0f], 65);
        assert_eq!(SBOX1[0xf0], 64);
        assert_eq!(SBOX1[0xff], 158);
        // A permutation of 0..=255.
        let mut seen = [false; 256];
        for &v in SBOX1.iter() {
            seen[v as usize] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }

    #[test]
    fn test_sbox_matches_rfc_3713_sbox1() {
        // Exhaustive: all 256 inputs. 32 byte positions per pass, so eight passes cover them all,
        // with the byte value `32 * pass + position` at each position. This is what makes the
        // generated gate list trustworthy, so it must stay exhaustive.
        for pass in 0..8u32 {
            let mut q: Planes = core::array::from_fn(|w| {
                let base = 32 * pass + 4 * w as u32;
                u32::from_le_bytes(core::array::from_fn(|j| (base + j as u32) as u8))
            });
            let inputs = q;
            ortho(&mut q);
            sbox(&mut q);
            ortho(&mut q);
            for (w, (got, input)) in q.iter().zip(inputs.iter()).enumerate() {
                for (byte, expected) in got
                    .to_le_bytes()
                    .iter()
                    .zip(input.to_le_bytes().iter().map(|&b| SBOX1[b as usize]))
                {
                    assert_eq!(*byte, expected, "pass {pass}, word {w}, input {input:#010x}");
                }
            }
        }
    }

    #[test]
    fn test_sboxes_apply_the_four_tables_to_the_right_bytes() {
        // Exhaustive per value: every byte position holds the same value v, in all four lanes, so
        // each position's output must be its own table's entry for v. This is what pins the three
        // position masks and the direction of each rotation.
        for v in 0..=255u8 {
            let word = u64::from_be_bytes([v; 8]);
            let mut words = [word; LANES];
            sboxes(&mut words);
            let expected = sboxes_table(word);
            for (lane, got) in words.iter().enumerate() {
                assert_eq!(*got, expected, "value {v:#04x}, lane {lane}");
            }
            assert_eq!(
                expected.to_be_bytes(),
                [
                    SBOX1[v as usize],
                    sbox2(v),
                    sbox3(v),
                    sbox4(v),
                    sbox2(v),
                    sbox3(v),
                    sbox4(v),
                    SBOX1[v as usize]
                ]
            );
        }
    }

    #[test]
    fn test_sboxes_lanes_are_independent() {
        // Changing one word must not change any other word's output, and each word must get the
        // table-driven answer for its own bytes.
        let base: [u64; LANES] =
            core::array::from_fn(|i| 0x0123_4567_89AB_CDEFu64.wrapping_mul(2 * i as u64 + 1));
        let mut expected = base;
        sboxes(&mut expected);
        for (lane, e) in expected.iter().enumerate() {
            assert_eq!(*e, sboxes_table(base[lane]), "lane {lane}");
        }
        for lane in 0..LANES {
            let mut words = base;
            words[lane] ^= 0xA5A5_5A5A_0F0F_F0F0;
            sboxes(&mut words);
            for other in (0..LANES).filter(|&o| o != lane) {
                assert_eq!(words[other], expected[other], "lane {lane} disturbed lane {other}");
            }
            assert_eq!(words[lane], sboxes_table(base[lane] ^ 0xA5A5_5A5A_0F0F_F0F0));
        }
    }

    #[test]
    fn test_rotations_move_exactly_the_selected_lanes() {
        // A single set bit at plane k, position p: rotate-left moves it to plane k+1 if p is in
        // the mask and leaves it alone otherwise; rotate-right, to plane k-1.
        for k in 0..8 {
            for p in 0..32 {
                let mut q: Planes = [0; 8];
                q[k] = 1 << p;
                let mut l = q;
                rotate_bytes_left_at(&mut l, SBOX2_LANES);
                let mut r = q;
                rotate_bytes_right_at(&mut r, SBOX2_LANES);
                let mut el: Planes = [0; 8];
                let mut er: Planes = [0; 8];
                if SBOX2_LANES >> p & 1 == 1 {
                    el[(k + 1) % 8] = 1 << p;
                    er[(k + 7) % 8] = 1 << p;
                } else {
                    el[k] = 1 << p;
                    er[k] = 1 << p;
                }
                assert_eq!(l, el, "left, plane {k}, position {p}");
                assert_eq!(r, er, "right, plane {k}, position {p}");
            }
        }
    }

    #[test]
    fn test_position_masks_are_the_documented_bytes() {
        // Byte L of a half is bits 8L..8L+7 of a plane, of which the low nibble is the four high
        // halves (t1 = byte 3 .. t4 = byte 0) and the high nibble the four low halves
        // (t5 = byte 3 .. t8 = byte 0).
        let high = |l: u32| 0x0Fu32 << (8 * l);
        let low = |l: u32| 0xF0u32 << (8 * l);
        assert_eq!(SBOX2_LANES, high(2) | low(3), "t2 and t5");
        assert_eq!(SBOX3_LANES, high(1) | low(2), "t3 and t6");
        assert_eq!(SBOX4_LANES, high(0) | low(1), "t4 and t7");
        assert_eq!(SBOX2_LANES & SBOX3_LANES, 0);
        assert_eq!(SBOX2_LANES & SBOX4_LANES, 0);
        assert_eq!(SBOX3_LANES & SBOX4_LANES, 0);
        assert_eq!(!(SBOX2_LANES | SBOX3_LANES | SBOX4_LANES), high(3) | low(0), "t1 and t8");
    }

    #[test]
    fn test_sboxes_places_the_halves_where_the_masks_expect() {
        // A single byte set in block b's input must be substituted by the S-box the RFC assigns to
        // that byte and land back in the same place, with the other three blocks untouched.
        for b in 0..LANES {
            for (i, sbox_i) in
                [(0usize, 1u8), (1, 2), (2, 3), (3, 4), (4, 2), (5, 3), (6, 4), (7, 1)]
            {
                let mut x = [0u64; LANES];
                let mut bytes = [0u8; 8];
                bytes[i] = 0x3d;
                x[b] = u64::from_be_bytes(bytes);
                let mut got = x;
                sboxes(&mut got);
                let mut expected = [sboxes_table(0); LANES];
                expected[b] = sboxes_table(x[b]);
                assert_eq!(got, expected, "block {b}, t{} through SBOX{sbox_i}", i + 1);
            }
        }
    }
}
