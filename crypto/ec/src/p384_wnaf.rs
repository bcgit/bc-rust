//! Interleaved windowed-NAF (wNAF) Shamir's-trick multiplication: `[u]G + [v]Q`, for P-384 ECDSA
//! verification. Identical algorithm to [`crate::p256_wnaf`] -- see that module's docs for the
//! full derivation and verification methodology -- with the width and limb count swapped for
//! P-384's (`WNAF_LEN = 385`, one more than `n`'s 384-bit length, same margin as P-256's `257 =
//! 256 + 1`).
//!
//! `G`'s odd multiples are a compile-time affine table (`p384_wnaf_table`, width 7) added by mixed
//! addition; only `Q`'s table is built per call. See [`crate::p256_wnaf`].

use crate::nat;
use crate::p384::P384FieldElement;
use crate::p384_point::P384JacobianPoint;
use crate::p384_scalar::P384PublicScalar;
use crate::p384_wnaf_table::{G_ODD_MULTIPLES_X, G_ODD_MULTIPLES_Y};

/// Window for `Q`, whose odd multiples are computed per call: 8 point additions to build the
/// table, one addition per ~6 digits to use it.
const WIDTH: usize = 5;
/// Window for `G`, whose odd multiples are a compile-time table
/// ([`G_ODD_MULTIPLES_X`]/[`G_ODD_MULTIPLES_Y`]): nothing to build, so the widest window a
/// signed `i8` digit allows, giving one addition per ~8 digits instead of ~6, and every one of
/// them a mixed addition against an affine entry.
const G_WIDTH: usize = 7;
const WNAF_LEN: usize = 385;
const ODD_MULTIPLE_COUNT: usize = 1 << (WIDTH - 2);

/// `[u]G + [v]Q`.
pub fn shamir_multiply(
    u: &P384PublicScalar,
    v: &P384PublicScalar,
    q: &P384JacobianPoint,
) -> P384JacobianPoint {
    let du = compute_wnaf(u.to_limbs(), G_WIDTH);
    let dv = compute_wnaf(v.to_limbs(), WIDTH);

    let table_q = odd_multiples(q);

    let mut r = P384JacobianPoint::INFINITY;
    for i in (0..WNAF_LEN).rev() {
        r = r.double();
        if let Some((x, y)) = lookup_signed_g(du[i]) {
            r = r.add_vartime_affine(&x, &y);
        }
        if let Some(add_q) = lookup_signed(&table_q, dv[i]) {
            r = r.add_vartime(&add_q);
        }
    }
    r
}

fn shr1(limbs: &[u64; 6]) -> [u64; 6] {
    [
        (limbs[0] >> 1) | ((limbs[1] & 1) << 63),
        (limbs[1] >> 1) | ((limbs[2] & 1) << 63),
        (limbs[2] >> 1) | ((limbs[3] & 1) << 63),
        (limbs[3] >> 1) | ((limbs[4] & 1) << 63),
        (limbs[4] >> 1) | ((limbs[5] & 1) << 63),
        limbs[5] >> 1,
    ]
}

/// The width-`width` wNAF digits of `k` (`width` at most 7, so a digit fits an `i8`), LSB-first; unused trailing entries are `0`. Not
/// constant time: only ever called on public scalars (see the module docs).
fn compute_wnaf(k_limbs: [u64; 6], width: usize) -> [i8; WNAF_LEN] {
    let mut digits = [0i8; WNAF_LEN];
    let mut k = k_limbs;
    let mut pos = 0;
    while k != [0, 0, 0, 0, 0, 0] {
        if k[0] & 1 == 1 {
            let mut digit = (k[0] & ((1 << width) - 1)) as i16;
            if digit >= 1 << (width - 1) {
                digit -= 1 << width;
            }
            k = if digit >= 0 {
                let (new_k, borrow) = nat::sub(&k, &[digit as u64, 0, 0, 0, 0, 0]);
                debug_assert_eq!(borrow, 0);
                new_k
            } else {
                let (new_k, carry) = nat::add(&k, &[(-digit) as u64, 0, 0, 0, 0, 0]);
                debug_assert_eq!(carry, 0);
                new_k
            };
            debug_assert!(pos < WNAF_LEN, "wNAF encoding overflowed its verified bound");
            digits[pos] = digit as i8;
        }
        k = shr1(&k);
        pos += 1;
    }
    digits
}

/// The odd multiples `1*p, 3*p, 5*p, ..., (2*ODD_MULTIPLE_COUNT - 1)*p`, indexed so entry `i`
/// holds `(2i+1)*p`.
fn odd_multiples(p: &P384JacobianPoint) -> [P384JacobianPoint; ODD_MULTIPLE_COUNT] {
    let double_p = p.double();
    let mut table = [*p; ODD_MULTIPLE_COUNT];
    let mut cur = *p;
    for entry in table.iter_mut() {
        *entry = cur;
        cur = cur.add_vartime(&double_p);
    }
    table
}

/// `digit * p` where `p` is the point `table` was built from ([`odd_multiples`]), or `None` for
/// digit `0`.
fn lookup_signed(
    table: &[P384JacobianPoint; ODD_MULTIPLE_COUNT],
    digit: i8,
) -> Option<P384JacobianPoint> {
    if digit == 0 {
        None
    } else if digit > 0 {
        Some(table[(digit as usize - 1) / 2])
    } else {
        Some(table[(-digit as usize - 1) / 2].negate())
    }
}

/// `digit * G` for a width-[`G_WIDTH`] digit, read from the compile-time table of odd multiples
/// of `G` as affine coordinates (negating `y` for a negative digit), or `None` for digit `0`.
fn lookup_signed_g(digit: i8) -> Option<(P384FieldElement, P384FieldElement)> {
    if digit == 0 {
        return None;
    }
    let index = (digit.unsigned_abs() as usize - 1) / 2;
    let x = P384FieldElement::from_limbs(G_ODD_MULTIPLES_X[index]);
    let y = P384FieldElement::from_limbs(G_ODD_MULTIPLES_Y[index]);
    Some(if digit > 0 { (x, y) } else { (x, y.negate()) })
}
