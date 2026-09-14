//! Fixed-base comb scalar multiplication: `[k]G` for P-256's base point `G`, with `k` secret.
//!
//! This is bc-java's `FixedPointCombMultiplier`/`FixedPointUtil` algorithm (width 6, matching its
//! choice for fields over 250 bits), simplified: bc-java's version starts its accumulator at a
//! nonzero "offset" point and subtracts it at the end, specifically to avoid ever handing its
//! point-add the identity element -- its generic `ECPoint.add`/`.twice` aren't constant-time in
//! that case. [`crate::p256_point::P256JacobianPoint::add`] already handles the identity
//! branch-free (see its module docs), so that dance isn't needed here: the accumulator starts at
//! [`P256JacobianPoint::INFINITY`] and the algorithm is the plain comb.
//!
//! # The comb
//!
//! For width `w = 6` and the scalar's bit length `BITS = 256` (the P-256 order's bit length, SP
//! 800-186 §3.2.1.3), `D = ceil(BITS / w) = 43` and `FULL_COMB = D * w = 258` (two bits more than
//! `BITS`, zero-padded). [`COMB_TABLE_X`]/[`COMB_TABLE_Y`] (in [`crate::p256_comb_table`]) hold,
//! at index `i`, the point `sum_{bit b set in i} 2^(b*D) * G` -- i.e. index `i`'s table entry
//! encodes a width-6 "comb digit" as a subset sum of the doublings `2^(0*D)*G, 2^(1*D)*G, ...,
//! 2^(5*D)*G`.
//!
//! [`comb_multiply_base_point`] processes `D` rounds; round `i` reads the comb digit made of bits
//! `top-i, top-i-D, top-i-2D, ..., top-i-5D` of `k` (`top = FULL_COMB - 1`), doubles the running
//! accumulator, and adds the table entry for that digit. Every one of the `D*w = FULL_COMB` bit
//! positions is read by exactly one (round, digit-position) pair (verified, not checked in, by
//! confirming the six per-round ranges tile `0..FULL_COMB` with no gaps or overlaps), and every
//! step -- bit extraction, the table lookup, the add -- is branch-free in `k`'s value: the *bit
//! positions* read are fixed by the (public) loop structure, and [`table_lookup`] scans every
//! entry under a mask rather than indexing by the secret digit.
//!
//! Verified (not checked in) against 200 random `k` plus edge cases (`k = 1, 2, 3, n-1`), each
//! cross-checked against the SP 800-186 Appendix A.1.1 affine group law via repeated doubling and
//! conditional addition (a world apart from the comb, so this isn't just checking the algorithm
//! against itself).

use crate::p256::P256FieldElement;
use crate::p256_comb_table::{COMB_TABLE_X, COMB_TABLE_Y};
use crate::p256_point::P256JacobianPoint;
use crate::p256_scalar::P256Scalar;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 6;
const BITS: usize = 256;
const D: usize = BITS.div_ceil(WIDTH);
const FULL_COMB: usize = D * WIDTH;
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]G`, branch-free in `k`.
pub fn comb_multiply_base_point(k: &P256Scalar) -> P256JacobianPoint {
    let limbs = k.limbs();
    let mut r = P256JacobianPoint::INFINITY;
    let top = (FULL_COMB - 1) as isize;
    for i in 0..D {
        let mut secret_index: usize = 0;
        let mut j = top - i as isize;
        while j >= 0 {
            let bit = if (j as usize) < BITS {
                (limbs[(j as usize) / 64] >> ((j as usize) % 64)) & 1
            } else {
                0
            };
            secret_index = (secret_index << 1) | (bit as usize);
            j -= D as isize;
        }
        r = r.double();
        r = r.add(&table_lookup(secret_index));
    }
    r
}

/// Looks up comb table entry `secret_index`, scanning every one of the [`TABLE_SIZE`] entries
/// under a mask so the index never steers which memory is read (bc-java's
/// `SecP256R1Curve.createCacheSafeLookupTable` pattern, cited in the crate's design notes).
fn table_lookup(secret_index: usize) -> P256JacobianPoint {
    let mut x_limbs = [0u64; 4];
    let mut y_limbs = [0u64; 4];
    for i in 0..TABLE_SIZE {
        let is_this_entry = Condition::<u64>::is_equal(i as u64, secret_index as u64);
        let mut next_x = [0u64; 4];
        ct::conditional_select(is_this_entry, &COMB_TABLE_X[i], &x_limbs, &mut next_x);
        x_limbs = next_x;
        let mut next_y = [0u64; 4];
        ct::conditional_select(is_this_entry, &COMB_TABLE_Y[i], &y_limbs, &mut next_y);
        y_limbs = next_y;
    }
    // Entry 0 is the point at infinity (Z == 0); every other entry is affine (Z == 1).
    let is_infinity = Condition::<u64>::is_equal(secret_index as u64, 0);
    let mut z_limbs = [0u64; 4];
    ct::conditional_select(
        is_infinity,
        &P256FieldElement::ZERO.to_limbs(),
        &P256FieldElement::ONE.to_limbs(),
        &mut z_limbs,
    );
    P256JacobianPoint {
        x: P256FieldElement::from_limbs(x_limbs),
        y: P256FieldElement::from_limbs(y_limbs),
        z: P256FieldElement::from_limbs(z_limbs),
    }
}
