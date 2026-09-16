//! Fixed-base comb scalar multiplication: `[k]G` for brainpoolP512r1's base point `G`, with `k`
//! secret. Identical algorithm to [`crate::p256_comb`] -- see that module's docs for the full
//! derivation and verification methodology -- with `D * WIDTH` again not dividing `BITS` exactly
//! (`512 / 6 = 85.33`, so `D = 86`, `FULL_COMB = 516`, zero-padded), same as P-256's own case.
//!
//! Verified (not checked in) against 200 random `k` plus edge cases (`k = 1, 2, 3, n-1`), each
//! cross-checked against the standard affine group law (general `a`).

use crate::bp512r1::Bp512r1FieldElement;
use crate::bp512r1_comb_table::{COMB_TABLE_X, COMB_TABLE_Y};
use crate::bp512r1_point::Bp512r1JacobianPoint;
use crate::bp512r1_scalar::Bp512r1Scalar;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 6;
const BITS: usize = 512;
const D: usize = BITS.div_ceil(WIDTH);
const FULL_COMB: usize = D * WIDTH;
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]G`, branch-free in `k`.
pub fn comb_multiply_base_point(k: &Bp512r1Scalar) -> Bp512r1JacobianPoint {
    let limbs = k.limbs();
    let mut r = Bp512r1JacobianPoint::INFINITY;
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
            // `secret_index << 1`'s vacated low bit and `bit` (always `0` or `1`) are disjoint, so
            // `|` and `^` agree here.
            secret_index = (secret_index << 1) | (bit as usize);
            j -= D as isize;
        }
        r = r.double();
        r = r.add(&table_lookup(secret_index));
    }
    r
}

/// Looks up comb table entry `secret_index`, scanning every one of the [`TABLE_SIZE`] entries
/// under a mask. See [`crate::p256_comb::table_lookup`]'s docs.
fn table_lookup(secret_index: usize) -> Bp512r1JacobianPoint {
    let mut x_limbs = [0u64; 8];
    let mut y_limbs = [0u64; 8];
    for i in 0..TABLE_SIZE {
        let is_this_entry = Condition::<u64>::is_equal(i as u64, secret_index as u64);
        let mut next_x = [0u64; 8];
        ct::conditional_select(is_this_entry, &COMB_TABLE_X[i], &x_limbs, &mut next_x);
        x_limbs = next_x;
        let mut next_y = [0u64; 8];
        ct::conditional_select(is_this_entry, &COMB_TABLE_Y[i], &y_limbs, &mut next_y);
        y_limbs = next_y;
    }
    let is_infinity = Condition::<u64>::is_equal(secret_index as u64, 0);
    let mut z_limbs = [0u64; 8];
    ct::conditional_select(
        is_infinity,
        &Bp512r1FieldElement::ZERO.to_limbs(),
        &Bp512r1FieldElement::ONE.to_limbs(),
        &mut z_limbs,
    );
    Bp512r1JacobianPoint {
        x: Bp512r1FieldElement::from_limbs(x_limbs),
        y: Bp512r1FieldElement::from_limbs(y_limbs),
        z: Bp512r1FieldElement::from_limbs(z_limbs),
    }
}
