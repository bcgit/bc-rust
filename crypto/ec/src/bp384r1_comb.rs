//! Fixed-base comb scalar multiplication: `[k]G` for brainpoolP384r1's base point `G`, with `k`
//! secret. Identical algorithm to [`crate::p256_comb`] -- see that module's docs for the full
//! derivation and verification methodology -- with `D * WIDTH` dividing `BITS` exactly here (`384
//! / 6 = 64`, so `D = 64`, `FULL_COMB = 384`), unlike P-256/secp256k1/brainpoolP256r1's own
//! zero-padded case.
//!
//! Verified (not checked in) against 200 random `k` plus edge cases (`k = 1, 2, 3, n-1`), each
//! cross-checked against the standard affine group law (general `a`).

use crate::bp384r1::Bp384r1FieldElement;
use crate::bp384r1_comb_table::{COMB_TABLE_X, COMB_TABLE_Y};
use crate::bp384r1_point::Bp384r1JacobianPoint;
use crate::bp384r1_scalar::Bp384r1Scalar;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 6;
const BITS: usize = 384;
const D: usize = BITS.div_ceil(WIDTH);
const FULL_COMB: usize = D * WIDTH;
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]G`, branch-free in `k`.
pub fn comb_multiply_base_point(k: &Bp384r1Scalar) -> Bp384r1JacobianPoint {
    let limbs = k.limbs();
    let mut r = Bp384r1JacobianPoint::INFINITY;
    let top = (FULL_COMB - 1) as isize;
    for i in 0..D {
        let mut secret_index: usize = 0;
        let mut j = top - i as isize;
        while j >= 0 {
            // Mutating `<` to `<=` here is an accepted mutant, not a bug: unlike every other
            // curve's own comb multiplier (where `FULL_COMB > BITS` zero-pads, making the `else`
            // branch reachable), this curve's `D * WIDTH == BITS` exactly (see the module docs),
            // so `j` here never reaches `BITS` at all (`top = FULL_COMB - 1 = BITS - 1`) -- the
            // `else` branch is unreachable, so both comparisons always select the same arm.
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
fn table_lookup(secret_index: usize) -> (Bp384r1FieldElement, Bp384r1FieldElement, Condition<u64>) {
    let mut x_limbs = [0u64; 6];
    let mut y_limbs = [0u64; 6];
    for i in 0..TABLE_SIZE {
        let is_this_entry = Condition::<u64>::is_equal(i as u64, secret_index as u64);
        let mut next_x = [0u64; 6];
        ct::conditional_select(is_this_entry, &COMB_TABLE_X[i], &x_limbs, &mut next_x);
        x_limbs = next_x;
        let mut next_y = [0u64; 6];
        ct::conditional_select(is_this_entry, &COMB_TABLE_Y[i], &y_limbs, &mut next_y);
        y_limbs = next_y;
    }
    // Entry 0 is the point at infinity; every other entry is affine (Z == 1). The accumulator's
    // `add_affine` takes the identity as a flag rather than as a `Z == 0` coordinate.
    let is_infinity = Condition::<u64>::is_equal(secret_index as u64, 0);
    (
        Bp384r1FieldElement::from_limbs(x_limbs),
        Bp384r1FieldElement::from_limbs(y_limbs),
        is_infinity,
    )
}
