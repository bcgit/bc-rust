//! `SB1`, `SB2`, `SB3` and `SB4` (RFC 5794 Sec 2.4.2) as Boolean circuits over bit-planes.
//!
//! # Why circuits and not tables
//!
//! Sec 2.4.2 defines the four S-boxes by 256-entry tables, and BC Java's `ARIAEngine` stores them
//! as such (OpenSSL's `aria.c` as four 1 KiB `u32` tables with part of the diffusion folded in). A
//! table indexed by a byte of the state is indexed by *secret data*, and on any CPU with a data
//! cache the access pattern -- hence the timing -- depends on that secret. That is the standard
//! cache-timing side channel of every table-driven block cipher, and it cannot be closed while
//! keeping the lookup.
//!
//! So this module has no tables (outside its tests). It computes the same four functions with AND,
//! XOR, XNOR and NOT gates applied to the bit-planes of [`crate::bitslice`]. Every operation is a
//! straight-line word operation on public *positions*, so there is no secret-dependent memory
//! access and no secret-dependent branch. This is the only place in the crate where secret data
//! meets non-linear logic; everything else is XOR, rotation and byte permutation.
//!
//! Because the planes hold one class word (four bytes) from each of four blocks, one pass of a
//! circuit is that S-box's share of a substitution layer for four blocks at once.
//!
//! # What the circuits compute, and where they came from
//!
//! `SB1` is the AES S-box (Sec 2.4.2's table is FIPS 197 Table 4, which `test_sb1_is_the_aes_sbox`
//! checks), so [`sb1`] is the 113-gate Boyar-Peralta straight-line program for it, copied verbatim
//! from `bouncycastle-aes` (`src/sbox.rs`, a transcription of Peralta's
//! `SLP_AES_113.txt`), with the SLP's `U0`-is-MSB input convention mapped onto the planes.
//!
//! The other three have the same algebraic shape -- an affine map, inversion in GF(2^8), and
//! another affine map. Writing `inv` for inversion in the AES field (`x^8 + x^4 + x^3 + x + 1`,
//! with `inv(0) = 0`), and `M`, `N` for 8x8 matrices over GF(2) given by their columns (column `i`
//! is the image of input bit `i`, bit 0 least significant):
//!
//! ```text
//! SB2(x) = N * inv(M * x xor 0x00) xor 0xe2
//!   M columns: 0x20, 0x80, 0x36, 0xd8, 0x4d, 0x2f, 0xbc, 0xc6
//!   N columns: 0xce, 0x83, 0xd5, 0x26, 0xae, 0xa7, 0x87, 0xfb
//! SB3(x) = N * inv(M * x xor 0xff) xor 0x00
//!   M columns: 0xf1, 0x89, 0xe2, 0xa2, 0xce, 0xfe, 0x79, 0x7b
//!   N columns: 0x54, 0x55, 0x18, 0xe2, 0xa8, 0xaa, 0x30, 0xdf
//! SB4(x) = N * inv(M * x xor 0xa0) xor 0x00
//!   M columns: 0x2b, 0x61, 0x64, 0x80, 0xe7, 0x4d, 0xd4, 0x58
//!   N columns: 0x59, 0xb6, 0xb2, 0x77, 0x7f, 0xee, 0xfe, 0xc7
//! ```
//!
//! These decompositions were **found by search, not recalled** (`SB3 = SB1^-1` and `SB4 = SB2^-1`
//! make theirs a consequence of `SB1`'s and `SB2`'s, but each was searched for independently and
//! the results agree): for each of the 256 possible input constants the remaining linear
//! equivalence to `inv` was searched exhaustively (the search fixes the multiplicative and
//! Frobenius self-equivalences of `inv`, which is what makes it finite), against the tables
//! extracted from the text of RFC 5794. For each S-box exactly one constant admits a
//! decomposition -- `0x00` for `SB2` (whose input affine map is therefore linear, as `SB1`'s is),
//! `0x63` for `SB3` and `0xe2` for `SB4`, the output constants of `SB1` and `SB2` -- and it is
//! unique up to those self-equivalences. The 2040 equivalent forms of each give circuits of
//! different sizes; the ones above were chosen for the fewest gates.
//!
//! Each generated circuit is therefore a **top affine layer** (generated: `M * x xor c` composed
//! with the Boyar-Peralta input basis change, as one affine map from the eight input planes to the
//! 22 signals the non-linear section consumes), the **non-linear section** of the Boyar-Peralta
//! circuit (**copied verbatim**: 32 AND and 30 XOR gates computing the inverse in a tower-field
//! representation), and a **bottom affine layer** (generated: the tower field back to the AES
//! polynomial basis, then `N * . xor d`, as one affine map from the 18 non-linear outputs to the
//! eight output planes). The affine layers were fitted by linear algebra over GF(2) and reduced
//! with a greedy common-subexpression pass. Gate counts:
//!
//! | S-box | AND | XOR | XNOR | NOT | total |
//! |---|---|---|---|---|---|
//! | `SB1` (Boyar-Peralta) | 32 | 77 | 4 | 0 | 113 |
//! | `SB2` | 32 | 83 | 4 | 0 | 119 |
//! | `SB3` | 32 | 87 | 5 | 0 | 124 |
//! | `SB4` | 32 | 78 | 11 | 1 | 122 |
//!
//! The generator verified every assembled circuit -- the emitted text, re-evaluated -- against its
//! table before any of it was written here, and `test_sboxes_match_rfc_5794_tables` re-verifies all
//! 256 inputs of all four in Rust. The gate lists are not meaningful line by line and should not
//! be "tidied".
//!
//! # Bit numbering
//!
//! Plane `k` holds bit `k` of every byte (bit 0 least significant), for inputs and outputs alike.
//! The Boyar-Peralta sections keep their signal names (`y*`, `t*`, `z*`) so they can be diffed
//! against the AES, SM4 and Camellia crates. In [`sb1`] the SLP's own input and output names
//! `U0 .. U7` / `S0 .. S7` appear with `U0` the most significant bit, i.e. plane `q[7]`; in the
//! generated circuits the inputs are bound from the top layer, so that convention never appears.

use crate::bitslice::Planes;

/// `SB1` (Sec 2.4.2) -- the AES S-box -- applied to every byte position of the planes: `q[k]`
/// holds bit `k` of each byte on entry and on exit. The 113-gate Boyar-Peralta program; see the
/// module docs.
pub(crate) fn sb1(q: &mut Planes) {
    // SLP inputs U0..U7, most-significant bit first, so U0 is the highest plane.
    let u0 = q[7];
    let u1 = q[6];
    let u2 = q[5];
    let u3 = q[4];
    let u4 = q[3];
    let u5 = q[2];
    let u6 = q[1];
    let u7 = q[0];

    // Top linear transformation (23 gates): the input basis change.
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

    // Non-linear section (62 gates): the GF(2^8) inversion, and the only ANDs in the circuit.
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
    // bytes, so XOR and OR agree here. It is the same gate the AES, SM4 and Camellia crates
    // document, since this section is copied from there.
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

    // Bottom linear transformation (28 gates): the output basis change and the AES affine map,
    // whose `{63}` constant is the four XNORs.
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

    // SLP outputs S0..S7, most-significant bit first, mirroring the input mapping.
    q[7] = s0;
    q[6] = s1;
    q[5] = s2;
    q[4] = s3;
    q[3] = s4;
    q[2] = s5;
    q[1] = s6;
    q[0] = s7;
}

/// `SB2` (Sec 2.4.2) applied to every byte position of the planes. Generated; see the module docs.
pub(crate) fn sb2(q: &mut Planes) {
    // Inputs: plane k holds bit k of every byte.
    let x0 = q[0];
    let x1 = q[1];
    let x2 = q[2];
    let x3 = q[3];
    let x4 = q[4];
    let x5 = q[5];
    let x6 = q[6];
    let x7 = q[7];

    // Top affine layer (29 gates, generated): the input affine map `M * x xor 0x00` and the
    // Boyar-Peralta input basis change, folded into one affine map over x0..x7.
    let a1 = x1 ^ x2;
    let a2 = x3 ^ x6;
    let a3 = x4 ^ x5;
    let a4 = x0 ^ a1;
    let a5 = x5 ^ a2;
    let a6 = x0 ^ x7;
    let a7 = x2 ^ a2;
    let a8 = a1 ^ a3;
    let a9 = x7 ^ a3;
    let a10 = x7 ^ a1;
    let a11 = x7 ^ a4;
    let a12 = x4 ^ x6;
    let a13 = a6 ^ a7;
    let a14 = a4 ^ a12;
    let a15 = x0 ^ a5;
    let a16 = x1 ^ a5;
    let a17 = x3 ^ a8;
    let a18 = x5 ^ a11;
    let a19 = a10 ^ a12;
    let a20 = a1 ^ a5;
    let a21 = x3 ^ a9;
    let a22 = x1 ^ x4;
    let a23 = a22 ^ a2;
    let a24 = x0 ^ a7;
    let a25 = x4 ^ a4;
    let a26 = x3 ^ x4;
    let a27 = a26 ^ a6;
    let a28 = x0 ^ x1;
    let a29 = a28 ^ x5;
    let u7 = a3;
    let y1 = a13;
    let y2 = a4;
    let y3 = a14;
    let y4 = a6;
    let y5 = a15;
    let y6 = a16;
    let y7 = x7;
    let y8 = a17;
    let y9 = a10;
    let y10 = a18;
    let y11 = a9;
    let y12 = a19;
    let y13 = a20;
    let y14 = a21;
    let y15 = a23;
    let y16 = a24;
    let y17 = a25;
    let y18 = a11;
    let y19 = a27;
    let y20 = a8;
    let y21 = a29;

    // Non-linear section (62 gates): GF(2^8) inversion, copied verbatim from the Boyar-Peralta
    // AES circuit in `bouncycastle-aes` (`src/sbox.rs`).
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
    // bytes, so XOR and OR agree here. It is the same gate the AES, SM4 and Camellia crates
    // document, since this section is copied from there.
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
    // and the output affine map `N * . xor 0xe2`. Plane j receives bit j of the output.
    let b1 = z11 ^ z17;
    let b2 = z0 ^ b1;
    let b3 = z1 ^ z7;
    let b4 = z16 ^ b3;
    let b5 = z15 ^ b2;
    let b6 = z9 ^ b5;
    let b7 = z12 ^ z13;
    let b8 = z1 ^ z3;
    let b9 = z8 ^ b4;
    let b10 = z4 ^ b8;
    let b11 = z2 ^ b9;
    let b12 = z15 ^ b7;
    let b13 = z6 ^ b3;
    let b14 = b13 ^ b6;
    let b15 = z10 ^ b1;
    let b16 = !(b15 ^ b12);
    let b17 = z6 ^ z10;
    let b18 = b17 ^ b2;
    let b19 = b18 ^ b4;
    let b20 = z2 ^ z3;
    let b21 = b20 ^ z5;
    let b22 = b21 ^ b6;
    let b23 = z0 ^ b10;
    let b24 = z13 ^ z14;
    let b25 = b24 ^ z17;
    let b26 = !(b25 ^ b11);
    let b27 = !(b6 ^ b10);
    let b28 = !(b11 ^ b12);
    q[0] = b14;
    q[1] = b16;
    q[2] = b19;
    q[3] = b22;
    q[4] = b23;
    q[5] = b26;
    q[6] = b27;
    q[7] = b28;
}

/// `SB3 = SB1^-1` (Sec 2.4.2) applied to every byte position of the planes. Generated; see the
/// module docs.
pub(crate) fn sb3(q: &mut Planes) {
    // Inputs: plane k holds bit k of every byte.
    let x0 = q[0];
    let x1 = q[1];
    let x2 = q[2];
    let x3 = q[3];
    let x4 = q[4];
    let x5 = q[5];
    let x6 = q[6];
    let x7 = q[7];

    // Top affine layer (29 gates, generated): the input affine map `M * x xor 0xff` and the
    // Boyar-Peralta input basis change, folded into one affine map over x0..x7.
    let a1 = x0 ^ x1;
    let a2 = x4 ^ x6;
    let a3 = x7 ^ a1;
    let a4 = x2 ^ x3;
    let a5 = x5 ^ x6;
    let a6 = x0 ^ a2;
    let a7 = x1 ^ a2;
    let a8 = x2 ^ a5;
    let a9 = x3 ^ a3;
    let a10 = x7 ^ a4;
    let a11 = !(x6 ^ a3);
    let a12 = !(a2 ^ a9);
    let a13 = x7 ^ a8;
    let a14 = x3 ^ a5;
    let a15 = x1 ^ x3;
    let a16 = a15 ^ x4;
    let a17 = a16 ^ x5;
    let a18 = a1 ^ a8;
    let a19 = !(a1 ^ a2);
    let a20 = !(x3 ^ x6);
    let a21 = a1 ^ a4;
    let a22 = a7 ^ a10;
    let a23 = x3 ^ x7;
    let a24 = x7 ^ a6;
    let a25 = x4 ^ x7;
    let a26 = x4 ^ a3;
    let a27 = !(x5 ^ a10);
    let a28 = x2 ^ a3;
    let a29 = x2 ^ a6;
    let u7 = a11;
    let y1 = a12;
    let y2 = a13;
    let y3 = a14;
    let y4 = a17;
    let y5 = a18;
    let y6 = a19;
    let y7 = a20;
    let y8 = a21;
    let y9 = a22;
    let y10 = a23;
    let y11 = a9;
    let y12 = a7;
    let y13 = a3;
    let y14 = a24;
    let y15 = a25;
    let y16 = a26;
    let y17 = a1;
    let y18 = a27;
    let y19 = a28;
    let y20 = a29;
    let y21 = x4;

    // Non-linear section (62 gates): GF(2^8) inversion, copied verbatim from the Boyar-Peralta
    // AES circuit in `bouncycastle-aes` (`src/sbox.rs`).
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
    // bytes, so XOR and OR agree here. It is the same gate the AES, SM4 and Camellia crates
    // document, since this section is copied from there.
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

    // Bottom affine layer (33 gates, generated): tower field back to the AES polynomial basis
    // and the output affine map `N * . xor 0x00`. Plane j receives bit j of the output.
    let b1 = z7 ^ z8;
    let b2 = z4 ^ b1;
    let b3 = z0 ^ z12;
    let b4 = z5 ^ b2;
    let b5 = z10 ^ z13;
    let b6 = z1 ^ z14;
    let b7 = z2 ^ z16;
    let b8 = z6 ^ b3;
    let b9 = z9 ^ b4;
    let b10 = z11 ^ z14;
    let b11 = z15 ^ z17;
    let b12 = z7 ^ b6;
    let b13 = b12 ^ b8;
    let b14 = b13 ^ b11;
    let b15 = z11 ^ b9;
    let b16 = b15 ^ b11;
    let b17 = b5 ^ b10;
    let b18 = z3 ^ z10;
    let b19 = b18 ^ z15;
    let b20 = b19 ^ b2;
    let b21 = b20 ^ b3;
    let b22 = b21 ^ b7;
    let b23 = b22 ^ b10;
    let b24 = z12 ^ b5;
    let b25 = b24 ^ b9;
    let b26 = z2 ^ z8;
    let b27 = b26 ^ z9;
    let b28 = b27 ^ b5;
    let b29 = b28 ^ b8;
    let b30 = z13 ^ z17;
    let b31 = b30 ^ b1;
    let b32 = b31 ^ b6;
    let b33 = b32 ^ b7;
    q[0] = b4;
    q[1] = b14;
    q[2] = b16;
    q[3] = b17;
    q[4] = b23;
    q[5] = b25;
    q[6] = b29;
    q[7] = b33;
}

/// `SB4 = SB2^-1` (Sec 2.4.2) applied to every byte position of the planes. Generated; see the
/// module docs.
pub(crate) fn sb4(q: &mut Planes) {
    // Inputs: plane k holds bit k of every byte.
    let x0 = q[0];
    let x1 = q[1];
    let x2 = q[2];
    let x3 = q[3];
    let x4 = q[4];
    let x5 = q[5];
    let x6 = q[6];
    let x7 = q[7];

    // Top affine layer (30 gates, generated): the input affine map `M * x xor 0xa0` and the
    // Boyar-Peralta input basis change, folded into one affine map over x0..x7.
    let a1 = x3 ^ x7;
    let a2 = x1 ^ x4;
    let a3 = x0 ^ x6;
    let a4 = x2 ^ x5;
    let a5 = a1 ^ a3;
    let a6 = x5 ^ a2;
    let a7 = x7 ^ a3;
    let a8 = x1 ^ a1;
    let a9 = a4 ^ a5;
    let a10 = x0 ^ a6;
    let a11 = x6 ^ x7;
    let a12 = !(a11 ^ a2);
    let a13 = x1 ^ a9;
    let a14 = !(x1 ^ a7);
    let a15 = x0 ^ x3;
    let a16 = !(a15 ^ a2);
    let a17 = !(x3 ^ a4);
    let a18 = !(x4 ^ a1);
    let a19 = !(x4 ^ a9);
    let a20 = !(x3 ^ a3);
    let a21 = x4 ^ x7;
    let a22 = a21 ^ a4;
    let a23 = !(x3 ^ x5);
    let a24 = !(a2 ^ a7);
    let a25 = a5 ^ a6;
    let a26 = x0 ^ a8;
    let a27 = !(a4 ^ a7);
    let a28 = !(x5 ^ a8);
    let a29 = a1 ^ a2;
    let u7 = a10;
    let y1 = a12;
    let y2 = a8;
    let y3 = a13;
    let y4 = !a2;
    let y5 = a14;
    let y6 = a16;
    let y7 = x0;
    let y8 = a17;
    let y9 = a18;
    let y10 = a5;
    let y11 = a6;
    let y12 = a19;
    let y13 = a20;
    let y14 = a22;
    let y15 = a23;
    let y16 = a24;
    let y17 = a25;
    let y18 = a26;
    let y19 = a27;
    let y20 = a28;
    let y21 = a29;

    // Non-linear section (62 gates): GF(2^8) inversion, copied verbatim from the Boyar-Peralta
    // AES circuit in `bouncycastle-aes` (`src/sbox.rs`).
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
    // bytes, so XOR and OR agree here. It is the same gate the AES, SM4 and Camellia crates
    // document, since this section is copied from there.
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

    // Bottom affine layer (30 gates, generated): tower field back to the AES polynomial basis
    // and the output affine map `N * . xor 0x00`. Plane j receives bit j of the output.
    let b1 = z0 ^ z6;
    let b2 = z4 ^ z10;
    let b3 = z1 ^ z9;
    let b4 = z3 ^ b2;
    let b5 = z8 ^ b1;
    let b6 = z12 ^ z13;
    let b7 = z2 ^ b5;
    let b8 = z6 ^ z7;
    let b9 = z9 ^ b6;
    let b10 = z11 ^ z17;
    let b11 = z15 ^ b3;
    let b12 = b4 ^ b8;
    let b13 = b9 ^ b12;
    let b14 = z5 ^ z16;
    let b15 = b14 ^ b2;
    let b16 = b15 ^ b5;
    let b17 = b16 ^ b11;
    let b18 = z10 ^ b9;
    let b19 = z13 ^ z14;
    let b20 = b19 ^ z16;
    let b21 = b20 ^ z17;
    let b22 = b21 ^ b7;
    let b23 = z0 ^ b3;
    let b24 = b23 ^ b4;
    let b25 = b24 ^ b6;
    let b26 = z16 ^ b10;
    let b27 = b26 ^ b12;
    let b28 = z7 ^ b1;
    let b29 = b28 ^ b10;
    let b30 = b29 ^ b11;
    q[0] = b13;
    q[1] = b17;
    q[2] = b18;
    q[3] = b7;
    q[4] = b22;
    q[5] = b25;
    q[6] = b27;
    q[7] = b30;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bitslice::ortho;

    /// Sec 2.4.2 `SB1`, row-major: `SB1[16 * row + column]`. Extracted mechanically from the text
    /// of RFC 5794; byte-for-byte BC Java's `SB1_sbox`. Test data only -- the engine never reads it.
    #[rustfmt::skip]
    pub(crate) const SB1: [u8; 256] = [
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

    /// Sec 2.4.2 `SB2`; byte-for-byte BC Java's `SB2_sbox`. Test data only.
    #[rustfmt::skip]
    pub(crate) const SB2: [u8; 256] = [
        0xe2, 0x4e, 0x54, 0xfc, 0x94, 0xc2, 0x4a, 0xcc, 0x62, 0x0d, 0x6a, 0x46, 0x3c, 0x4d, 0x8b, 0xd1,
        0x5e, 0xfa, 0x64, 0xcb, 0xb4, 0x97, 0xbe, 0x2b, 0xbc, 0x77, 0x2e, 0x03, 0xd3, 0x19, 0x59, 0xc1,
        0x1d, 0x06, 0x41, 0x6b, 0x55, 0xf0, 0x99, 0x69, 0xea, 0x9c, 0x18, 0xae, 0x63, 0xdf, 0xe7, 0xbb,
        0x00, 0x73, 0x66, 0xfb, 0x96, 0x4c, 0x85, 0xe4, 0x3a, 0x09, 0x45, 0xaa, 0x0f, 0xee, 0x10, 0xeb,
        0x2d, 0x7f, 0xf4, 0x29, 0xac, 0xcf, 0xad, 0x91, 0x8d, 0x78, 0xc8, 0x95, 0xf9, 0x2f, 0xce, 0xcd,
        0x08, 0x7a, 0x88, 0x38, 0x5c, 0x83, 0x2a, 0x28, 0x47, 0xdb, 0xb8, 0xc7, 0x93, 0xa4, 0x12, 0x53,
        0xff, 0x87, 0x0e, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8e, 0x37, 0x74, 0x32, 0xca, 0xe9, 0xb1,
        0xb7, 0xab, 0x0c, 0xd7, 0xc4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xd9, 0xb6, 0xb9, 0x11, 0x40,
        0xec, 0x20, 0x8c, 0xbd, 0xa0, 0xc9, 0x84, 0x04, 0x49, 0x23, 0xf1, 0x4f, 0x50, 0x1f, 0x13, 0xdc,
        0xd8, 0xc0, 0x9e, 0x57, 0xe3, 0xc3, 0x7b, 0x65, 0x3b, 0x02, 0x8f, 0x3e, 0xe8, 0x25, 0x92, 0xe5,
        0x15, 0xdd, 0xfd, 0x17, 0xa9, 0xbf, 0xd4, 0x9a, 0x7e, 0xc5, 0x39, 0x67, 0xfe, 0x76, 0x9d, 0x43,
        0xa7, 0xe1, 0xd0, 0xf5, 0x68, 0xf2, 0x1b, 0x34, 0x70, 0x05, 0xa3, 0x8a, 0xd5, 0x79, 0x86, 0xa8,
        0x30, 0xc6, 0x51, 0x4b, 0x1e, 0xa6, 0x27, 0xf6, 0x35, 0xd2, 0x6e, 0x24, 0x16, 0x82, 0x5f, 0xda,
        0xe6, 0x75, 0xa2, 0xef, 0x2c, 0xb2, 0x1c, 0x9f, 0x5d, 0x6f, 0x80, 0x0a, 0x72, 0x44, 0x9b, 0x6c,
        0x90, 0x0b, 0x5b, 0x33, 0x7d, 0x5a, 0x52, 0xf3, 0x61, 0xa1, 0xf7, 0xb0, 0xd6, 0x3f, 0x7c, 0x6d,
        0xed, 0x14, 0xe0, 0xa5, 0x3d, 0x22, 0xb3, 0xf8, 0x89, 0xde, 0x71, 0x1a, 0xaf, 0xba, 0xb5, 0x81,
    ];

    /// Sec 2.4.2 `SB3`; byte-for-byte BC Java's `SB3_sbox`. Test data only.
    #[rustfmt::skip]
    pub(crate) const SB3: [u8; 256] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    ];

    /// Sec 2.4.2 `SB4`; byte-for-byte BC Java's `SB4_sbox`. Test data only. (The RFC prints the
    /// entry for `0x0d` as a bare `9`; it is `0x09`.)
    #[rustfmt::skip]
    pub(crate) const SB4: [u8; 256] = [
        0x30, 0x68, 0x99, 0x1b, 0x87, 0xb9, 0x21, 0x78, 0x50, 0x39, 0xdb, 0xe1, 0x72, 0x09, 0x62, 0x3c,
        0x3e, 0x7e, 0x5e, 0x8e, 0xf1, 0xa0, 0xcc, 0xa3, 0x2a, 0x1d, 0xfb, 0xb6, 0xd6, 0x20, 0xc4, 0x8d,
        0x81, 0x65, 0xf5, 0x89, 0xcb, 0x9d, 0x77, 0xc6, 0x57, 0x43, 0x56, 0x17, 0xd4, 0x40, 0x1a, 0x4d,
        0xc0, 0x63, 0x6c, 0xe3, 0xb7, 0xc8, 0x64, 0x6a, 0x53, 0xaa, 0x38, 0x98, 0x0c, 0xf4, 0x9b, 0xed,
        0x7f, 0x22, 0x76, 0xaf, 0xdd, 0x3a, 0x0b, 0x58, 0x67, 0x88, 0x06, 0xc3, 0x35, 0x0d, 0x01, 0x8b,
        0x8c, 0xc2, 0xe6, 0x5f, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1e, 0xe5, 0xe2, 0x54, 0xd8, 0x10, 0xce,
        0x7a, 0xe8, 0x08, 0x2c, 0x12, 0x97, 0x32, 0xab, 0xb4, 0x27, 0x0a, 0x23, 0xdf, 0xef, 0xca, 0xd9,
        0xb8, 0xfa, 0xdc, 0x31, 0x6b, 0xd1, 0xad, 0x19, 0x49, 0xbd, 0x51, 0x96, 0xee, 0xe4, 0xa8, 0x41,
        0xda, 0xff, 0xcd, 0x55, 0x86, 0x36, 0xbe, 0x61, 0x52, 0xf8, 0xbb, 0x0e, 0x82, 0x48, 0x69, 0x9a,
        0xe0, 0x47, 0x9e, 0x5c, 0x04, 0x4b, 0x34, 0x15, 0x79, 0x26, 0xa7, 0xde, 0x29, 0xae, 0x92, 0xd7,
        0x84, 0xe9, 0xd2, 0xba, 0x5d, 0xf3, 0xc5, 0xb0, 0xbf, 0xa4, 0x3b, 0x71, 0x44, 0x46, 0x2b, 0xfc,
        0xeb, 0x6f, 0xd5, 0xf6, 0x14, 0xfe, 0x7c, 0x70, 0x5a, 0x7d, 0xfd, 0x2f, 0x18, 0x83, 0x16, 0xa5,
        0x91, 0x1f, 0x05, 0x95, 0x74, 0xa9, 0xc1, 0x5b, 0x4a, 0x85, 0x6d, 0x13, 0x07, 0x4f, 0x4e, 0x45,
        0xb2, 0x0f, 0xc9, 0x1c, 0xa6, 0xbc, 0xec, 0x73, 0x90, 0x7b, 0xcf, 0x59, 0x8f, 0xa1, 0xf9, 0x2d,
        0xf2, 0xb1, 0x00, 0x94, 0x37, 0x9f, 0xd0, 0x2e, 0x9c, 0x6e, 0x28, 0x3f, 0x80, 0xf0, 0x3d, 0xd3,
        0x25, 0x8a, 0xb5, 0xe7, 0x42, 0xb3, 0xc7, 0xea, 0xf7, 0x4c, 0x11, 0x33, 0x03, 0xa2, 0xac, 0x60,
    ];

    #[test]
    fn test_tables_match_the_worked_examples() {
        // Sec 2.4.2: "SB1(0x23) = 0x26 and SB4(0xef) = 0xd3".
        assert_eq!(SB1[0x23], 0x26);
        assert_eq!(SB4[0xef], 0xd3);
        // "SB3 and SB4 are the inverse functions of SB1 and SB2, respectively."
        for x in 0..=255u8 {
            assert_eq!(SB3[SB1[x as usize] as usize], x);
            assert_eq!(SB1[SB3[x as usize] as usize], x);
            assert_eq!(SB4[SB2[x as usize] as usize], x);
            assert_eq!(SB2[SB4[x as usize] as usize], x);
        }
    }

    #[test]
    fn test_sb1_is_the_aes_sbox() {
        // FIPS 197 Sec 5.1.1's worked example, S(0x53) = 0xed, and Table 4's first and last rows.
        assert_eq!(SB1[0x53], 0xed);
        assert_eq!(&SB1[..4], &[0x63, 0x7c, 0x77, 0x7b]);
        assert_eq!(&SB1[252..], &[0xb0, 0x54, 0xbb, 0x16]);
    }

    /// Runs a circuit on every one of the 256 byte values -- 16 positions per pass, sixteen
    /// passes -- and checks each against the table. Exhaustive; must stay so.
    fn check_exhaustive(name: &str, circuit: fn(&mut Planes), table: &[u8; 256]) {
        for pass in 0..16u16 {
            let mut q: Planes = core::array::from_fn(|w| {
                let base = 16 * pass + 2 * w as u16;
                u16::from_le_bytes([base as u8, base as u8 + 1])
            });
            let inputs = q;
            ortho(&mut q);
            circuit(&mut q);
            ortho(&mut q);
            for (w, (got, input)) in q.iter().zip(inputs.iter()).enumerate() {
                for (byte, expected) in got
                    .to_le_bytes()
                    .iter()
                    .zip(input.to_le_bytes().iter().map(|&b| table[b as usize]))
                {
                    assert_eq!(
                        *byte, expected,
                        "{name}: pass {pass}, word {w}, input {input:#06x}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_sboxes_match_rfc_5794_tables() {
        check_exhaustive("SB1", sb1, &SB1);
        check_exhaustive("SB2", sb2, &SB2);
        check_exhaustive("SB3", sb3, &SB3);
        check_exhaustive("SB4", sb4, &SB4);
    }

    #[test]
    fn test_sb3_and_sb4_invert_sb1_and_sb2_on_planes() {
        // Sec 2.4.2's inverse relation, on the circuits themselves rather than the tables.
        let mut seed = 0xACE1u16;
        for _ in 0..64 {
            let q0: Planes = core::array::from_fn(|_| {
                seed ^= seed << 7;
                seed ^= seed >> 9;
                seed ^= seed << 8;
                seed
            });
            let mut q = q0;
            sb1(&mut q);
            sb3(&mut q);
            assert_eq!(q, q0, "SB3(SB1(x)) = x");
            sb2(&mut q);
            sb4(&mut q);
            assert_eq!(q, q0, "SB4(SB2(x)) = x");
            sb4(&mut q);
            sb2(&mut q);
            assert_eq!(q, q0, "SB2(SB4(x)) = x");
        }
    }
}
