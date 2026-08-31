//! SUBBYTES() and INVSUBBYTES() as a Boolean circuit (FIPS 197 Sec 5.1.1 and Sec 5.3.2).
//!
//! # Why a circuit and not a table
//!
//! FIPS 197 Sec 5.1.1 presents the S-box as a 256-entry lookup table (Table 4). A table lookup
//! indexed by a byte of the state is indexed by *secret data*, and on any CPU with a data cache
//! the access pattern -- hence the timing -- depends on that secret. That is the standard AES
//! cache-timing side channel, and it cannot be closed while keeping the lookup.
//!
//! So this module does not have a table. It computes the same function as Table 4 with AND, XOR
//! and XNOR gates applied to the bit-planes described in [`crate::bitslice`]. Every operation is
//! a straight-line word operation on public *positions*, so there is no secret-dependent memory
//! access and no secret-dependent branch. The two functions here are the only place in the crate
//! where secret data meets non-linear logic; everything else is XOR, rotate and mask.
//!
//! Because the planes hold sixteen byte positions of two blocks at once, one pass of the circuit
//! substitutes all 32 bytes -- the whole SUBBYTES() transformation of two blocks -- rather than
//! one byte.
//!
//! # What the circuit computes
//!
//! FIPS 197 Sec 5.1.1 defines the S-box as inversion in GF(2^8) followed by an affine map
//! (Eq. 5.2), tabulated in Table 4. The circuit below is the 113-gate straight-line program of
//! Boyar and Peralta -- 32 AND, 77 XOR and 4 XNOR gates -- which computes exactly that,
//! including the affine map and its `{63}` constant (the constant is folded into the four XNORs
//! at the end of the bottom linear transformation).
//!
//! Sources:
//! * The straight-line program `SLP_AES_113.txt`, from Peralta's circuit collection.
//! * J. Boyar and R. Peralta, "A new combinational logic minimization technique with
//!   applications to cryptology", <https://eprint.iacr.org/2009/191.pdf>.
//! * The same circuit appears in BearSSL `aes_ct.c:br_aes_ct_bitslice_Sbox` (MIT, Thomas
//!   Pornin), whose variable naming is kept here so the two can be diffed. BearSSL re-associates
//!   two gates in the non-linear section (its `t17`/`t21` differ from the SLP file, computing the
//!   same `t21`) and uses a different but equivalent bottom linear transformation; where they
//!   disagree this file follows `SLP_AES_113.txt`.
//!
//! The gate list is a mechanical transcription of `SLP_AES_113.txt`: `+` became `^`, `x` became
//! `&`, `#` became `!(.. ^ ..)`, and the SLP variable names are unchanged apart from case. It is
//! not independently meaningful line by line and should not be "tidied"; it is verified as a
//! whole by `test_sbox_matches_fips197_table_4`, which checks all 256 inputs against Table 4.
//!
//! # Bit numbering
//!
//! The SLP numbers its inputs `U0..U7` and outputs `S0..S7` with **`U0` as the most significant
//! bit** of the byte, which is the reverse of the plane index. So `U0` is plane `q[7]` and `U7`
//! is plane `q[0]`, and likewise for the outputs. `test_sbox_matches_fips197_table_4` is what
//! pins this down -- reversing it produces a wrong S-box, not a subtly different one.

use crate::bitslice::Planes;

/// SUBBYTES(): applies the AES S-box to every byte position of both blocks in `q`
/// (FIPS 197 Sec 5.1.1, the transformation tabulated in Table 4).
///
/// The 113-gate Boyar-Peralta circuit, transcribed from `SLP_AES_113.txt`. See the module docs.
pub(crate) fn sbox(q: &mut Planes) {
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
    // bytes, so XOR and OR agree here. It is the only one of the circuit's 77 XOR gates with that
    // property -- every other `^ -> |` mutant is killed by `test_sbox_matches_fips197_table_4`.
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

    // Bottom linear transformation (28 gates): the output basis change and the affine map of
    // Eq. 5.2, whose `{63}` constant is the four XNORs below.
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

/// INVSUBBYTES(): applies the inverse AES S-box to every byte position of both blocks in `q`
/// (FIPS 197 Sec 5.3.2, the transformation tabulated in Table 6).
///
/// Rather than a second 113-gate circuit, this reuses [`sbox`] by conjugating it with the
/// inverse of its affine layer. Writing the S-box of Eq. 5.2 as `S(x) = A(I(x)) ^ {63}`, where
/// `I` is inversion in GF(2^8) and `A` the linear part, and letting `B` be the inverse of `A`:
///
/// ```text
/// iS(x) = B(S(B(x ^ {63})) ^ {63})
/// ```
///
/// which holds because `I` is an involution:
/// `iS(S(y)) = B(A(I(B(A(I(y)) ^ {63} ^ {63})))  ^ {63} ^ {63}) = y`.
///
/// So applying [`inv_affine`], then the forward circuit, then [`inv_affine`] again yields the
/// inverse S-box, at the cost of 16 extra XORs and 8 complements instead of a whole second
/// circuit. Verified exhaustively against Table 6 by `test_inv_sbox_matches_fips197_table_6`.
///
/// The derivation and the layer below are from BearSSL `aes_ct_dec.c`
/// (`br_aes_ct_bitslice_invSbox`).
pub(crate) fn inv_sbox(q: &mut Planes) {
    inv_affine(q);
    sbox(q);
    inv_affine(q);
}

/// `B(x ^ {63})`: the inverse of the affine layer of Eq. 5.2, composed with the constant.
///
/// The complements on planes 0, 1, 5 and 6 are the `^ {63}`; the eight three-term XORs are `B`.
/// Translated from BearSSL `aes_ct_dec.c:br_aes_ct_bitslice_invSbox`.
fn inv_affine(q: &mut Planes) {
    let q0 = !q[0];
    let q1 = !q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = !q[5];
    let q6 = !q[6];
    let q7 = q[7];
    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitslice::{pack, unpack};

    /// FIPS 197 Table 4 (SBOX), transcribed from the published PDF. Test-only: the
    /// implementation evaluates the S-box as a Boolean circuit and never indexes a table.
    #[rustfmt::skip]
    const SBOX_TABLE_4: [u8; 256] = [
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

    /// FIPS 197 Table 6 (INVSBOX), transcribed from the published PDF. Test-only.
    #[rustfmt::skip]
    const INVSBOX_TABLE_6: [u8; 256] = [
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

    /// Runs a plane transformation over a block placed in both halves, returning the A half.
    ///
    /// Filling both halves means a wrong interleave shows up as a difference between the two
    /// blocks rather than silently passing.
    fn apply(f: fn(&mut Planes), block: [u8; 16]) -> [u8; 16] {
        let mut q = pack(&block, &block);
        f(&mut q);
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        unpack(&q, &mut a, &mut b);
        assert_eq!(a, b, "the two interleaved blocks must transform identically");
        a
    }

    #[test]
    fn test_sbox_matches_fips197_table_4() {
        // Exhaustive over the whole domain: this is the test that makes the 113 gates
        // trustworthy, so it must stay exhaustive.
        for x in 0..=255u8 {
            let out = apply(sbox, [x; 16]);
            assert!(
                out.iter().all(|&b| b == out[0]),
                "all 16 byte positions must substitute alike, x={x:#04x}"
            );
            assert_eq!(
                out[0], SBOX_TABLE_4[x as usize],
                "SBOX({x:#04x}) should be {:#04x}",
                SBOX_TABLE_4[x as usize]
            );
        }
    }

    #[test]
    fn test_inv_sbox_matches_fips197_table_6() {
        for x in 0..=255u8 {
            let out = apply(inv_sbox, [x; 16]);
            assert_eq!(
                out[0], INVSBOX_TABLE_6[x as usize],
                "INVSBOX({x:#04x}) should be {:#04x}",
                INVSBOX_TABLE_6[x as usize]
            );
        }
    }

    #[test]
    fn test_inv_sbox_inverts_sbox() {
        for x in 0..=255u8 {
            let mut q = pack(&[x; 16], &[x.wrapping_add(1); 16]);
            sbox(&mut q);
            inv_sbox(&mut q);
            let mut a = [0u8; 16];
            let mut b = [0u8; 16];
            unpack(&q, &mut a, &mut b);
            assert_eq!(a, [x; 16]);
            assert_eq!(b, [x.wrapping_add(1); 16]);
        }
    }

    #[test]
    fn test_sbox_worked_example_from_section_5_1_1() {
        // FIPS 197 Sec 5.1.1: "if s(r,c) = {53} ... s'(r,c) = {ed}".
        assert_eq!(apply(sbox, [0x53; 16])[0], 0xed);
        assert_eq!(SBOX_TABLE_4[0x53], 0xed);
    }

    #[test]
    fn test_the_two_spec_tables_are_inverses() {
        // Guards the transcription of both tables against a typo in either one.
        for x in 0..=255u8 {
            assert_eq!(INVSBOX_TABLE_6[SBOX_TABLE_4[x as usize] as usize], x);
        }
    }

    #[test]
    fn test_sbox_operates_on_each_byte_position_independently() {
        // A block of distinct values, so a mask error that mixes byte positions is caught.
        let block: [u8; 16] = core::array::from_fn(|i| (i as u8) * 17);
        let out = apply(sbox, block);
        for i in 0..16 {
            assert_eq!(out[i], SBOX_TABLE_4[block[i] as usize], "byte position {i}");
        }
    }
}
