//! Fixed-base comb scalar multiplication: `[k]G` for brainpoolP256r1's base point `G`, with `k`
//! secret. Identical algorithm to [`crate::p256_comb`] -- see that module's docs for the full
//! derivation and verification methodology -- with `D * WIDTH` again not dividing `BITS` exactly
//! (`256 / 6 = 42.67`, so `D = 43`, `FULL_COMB = 258`, zero-padded), same as P-256's own case.
//!
//! Verified (not checked in) against 200 random `k` plus edge cases (`k = 1, 2, 3, n-1`), each
//! cross-checked against the standard affine group law (general `a`).

use crate::bp256r1::Bp256r1FieldElement;
use crate::bp256r1_comb_table::{COMB_TABLE_X, COMB_TABLE_Y};
use crate::bp256r1_point::Bp256r1JacobianPoint;
use crate::bp256r1_scalar::Bp256r1Scalar;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 6;
const BITS: usize = 256;
const D: usize = BITS.div_ceil(WIDTH);
const FULL_COMB: usize = D * WIDTH;
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]G`, branch-free in `k`.
pub fn comb_multiply_base_point(k: &Bp256r1Scalar) -> Bp256r1JacobianPoint {
    let limbs = k.limbs();
    let mut r = Bp256r1JacobianPoint::INFINITY;
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
        let (x, y, is_infinity) = table_lookup(secret_index);
        r = r.add_affine(&x, &y, is_infinity);
    }
    r
}

/// Looks up comb table entry `secret_index`, scanning every one of the [`TABLE_SIZE`] entries
/// under a mask. See [`crate::p256_comb::table_lookup`]'s docs.
fn table_lookup(secret_index: usize) -> (Bp256r1FieldElement, Bp256r1FieldElement, Condition<u64>) {
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
    // Entry 0 is the point at infinity; every other entry is affine (Z == 1). The accumulator's
    // `add_affine` takes the identity as a flag rather than as a `Z == 0` coordinate.
    let is_infinity = Condition::<u64>::is_equal(secret_index as u64, 0);
    (
        Bp256r1FieldElement::from_limbs(x_limbs),
        Bp256r1FieldElement::from_limbs(y_limbs),
        is_infinity,
    )
}
