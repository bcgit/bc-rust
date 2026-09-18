//! Fixed-base comb scalar multiplication: `[k]G` for secp256k1's base point `G`, with `k` secret.
//! Identical algorithm to [`crate::p256_comb`] -- see that module's docs for the full derivation
//! and verification methodology -- with `D * WIDTH` again not dividing `BITS` exactly (`256 / 6 =
//! 42.67`, so `D = 43`, `FULL_COMB = 258`, zero-padded), same as P-256's own case.
//!
//! Verified (not checked in) against 200 random `k` plus edge cases (`k = 1, 2, 3, n-1`), each
//! cross-checked against the standard affine group law (`a = 0`).

use crate::p256k1::P256K1FieldElement;
use crate::p256k1_comb_table::{COMB_TABLE_X, COMB_TABLE_Y};
use crate::p256k1_point::P256K1JacobianPoint;
use crate::p256k1_scalar::P256K1Scalar;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 6;
const BITS: usize = 256;
const D: usize = BITS.div_ceil(WIDTH);
const FULL_COMB: usize = D * WIDTH;
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]G`, branch-free in `k`.
pub fn comb_multiply_base_point(k: &P256K1Scalar) -> P256K1JacobianPoint {
    let limbs = k.limbs();
    let mut r = P256K1JacobianPoint::INFINITY;
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
fn table_lookup(secret_index: usize) -> P256K1JacobianPoint {
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
    let is_infinity = Condition::<u64>::is_equal(secret_index as u64, 0);
    let mut z_limbs = [0u64; 4];
    ct::conditional_select(
        is_infinity,
        &P256K1FieldElement::ZERO.internal_limbs(),
        &P256K1FieldElement::ONE.internal_limbs(),
        &mut z_limbs,
    );
    P256K1JacobianPoint {
        x: P256K1FieldElement::from_internal_limbs(x_limbs),
        y: P256K1FieldElement::from_internal_limbs(y_limbs),
        z: P256K1FieldElement::from_internal_limbs(z_limbs),
    }
}
