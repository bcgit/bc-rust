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
//! Because the planes hold all sixteen byte positions of every block in the state at once -- one,
//! two or four blocks, by the plane width (see [`crate::bitslice`]) -- one pass of the circuit is
//! the whole SUBBYTES() transformation of all of them, rather than one byte. The circuit is the
//! same gates whatever the width: nothing in it knows where one block ends and the next begins.
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
//! whole by the known-answer tests in `tests/` (FIPS 197 Appendix B, SP 800-38A F.1 and the ACVP
//! vectors), which push every one of the 256 byte values through it many times over, and
//! `cargo mutants` confirms those tests kill every gate mutation but the one noted at `t37`.
//! There are no unit tests in this file for that reason.
//!
//! # Bit numbering
//!
//! The SLP numbers its inputs `U0..U7` and outputs `S0..S7` with **`U0` as the most significant
//! bit** of the byte, which is the reverse of the plane index. So `U0` is plane `q[7]` and `U7`
//! is plane `q[0]`, and likewise for the outputs. The known-answer tests are what pin this down
//! -- reversing it produces a wrong S-box, not a subtly different one.

use crate::bitslice::{PlaneWord, Planes};

/// SUBBYTES(): applies the AES S-box to every byte position of every block in `q`
/// (FIPS 197 Sec 5.1.1, the transformation tabulated in Table 4).
///
/// The 113-gate Boyar-Peralta circuit, transcribed from `SLP_AES_113.txt`. See the module docs.
// `#[inline(always)]` is a measured choice:
// Inlining lets the planes live in registers across the whole round.
// On x86-64 that is worth about 15-20%.
#[inline(always)]
pub(crate) fn sbox<T: PlaneWord>(q: &mut Planes<T>) {
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
    // property -- every other `^ -> |` mutant is killed by the known-answer tests in `tests/`.
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

/// INVSUBBYTES(): applies the inverse AES S-box to every byte position of every block in `q`
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
/// circuit. Verified against Table 6 by the decryption known-answer tests in `tests/`
/// (SP 800-38A F.1.2/4/6 and the ACVP decrypt vectors), and against [`sbox`] by the ECB
/// conformance suite's inverse checks.
///
/// The derivation and the layer below are from BearSSL `aes_ct_dec.c`
/// (`br_aes_ct_bitslice_invSbox`).
#[inline(always)]
pub(crate) fn inv_sbox<T: PlaneWord>(q: &mut Planes<T>) {
    inv_affine(q);
    sbox(q);
    inv_affine(q);
}

/// `B(x ^ {63})`: the inverse of the affine layer of Eq. 5.2, composed with the constant.
///
/// The complements on planes 0, 1, 5 and 6 are the `^ {63}`; the eight three-term XORs are `B`.
/// Translated from BearSSL `aes_ct_dec.c:br_aes_ct_bitslice_invSbox`.
#[inline(always)]
fn inv_affine<T: PlaneWord>(q: &mut Planes<T>) {
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
