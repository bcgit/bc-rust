//! Fixed-base comb scalar multiplication: `[k]G` for P-521's base point `G`, with `k` secret.
//! Identical algorithm to [`crate::p256_comb`] -- see that module's docs for the full derivation
//! and verification methodology -- except `D * WIDTH = 87 * 6 = 522` here, one bit more than
//! `BITS = 521` (a single bit of zero-padding, same idea as P-256's two).
//!
//! Verified (not checked in) against 200 random `k` plus edge cases (`k = 1, 2, 3, n-1`), each
//! cross-checked against the SP 800-186 Appendix A.1.1 affine group law.

use crate::p521::P521FieldElement;
use crate::p521_comb_table::{COMB_TABLE_X, COMB_TABLE_Y};
use crate::p521_point::P521JacobianPoint;
use crate::p521_scalar::P521Scalar;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 6;
const BITS: usize = 521;
const D: usize = BITS.div_ceil(WIDTH);
const FULL_COMB: usize = D * WIDTH;
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]G`, branch-free in `k`.
pub fn comb_multiply_base_point(k: &P521Scalar) -> P521JacobianPoint {
    let limbs = k.limbs();
    let mut r = P521JacobianPoint::INFINITY;
    let top = (FULL_COMB - 1) as isize;
    for i in 0..D {
        let mut secret_index: usize = 0;
        let mut j = top - i as isize;
        while j >= 0 {
            // `< BITS` vs `<= BITS` only differ at `j == BITS` (521): both give `0` there in
            // practice, since `limbs` is always a canonical (`< n < 2^521`) scalar, whose bit 521
            // is `0` regardless of which branch reads it -- an accepted mutant, not a bug.
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
fn table_lookup(secret_index: usize) -> P521JacobianPoint {
    let mut x_limbs = [0u64; 9];
    let mut y_limbs = [0u64; 9];
    for i in 0..TABLE_SIZE {
        let is_this_entry = Condition::<u64>::is_equal(i as u64, secret_index as u64);
        let mut next_x = [0u64; 9];
        ct::conditional_select(is_this_entry, &COMB_TABLE_X[i], &x_limbs, &mut next_x);
        x_limbs = next_x;
        let mut next_y = [0u64; 9];
        ct::conditional_select(is_this_entry, &COMB_TABLE_Y[i], &y_limbs, &mut next_y);
        y_limbs = next_y;
    }
    let is_infinity = Condition::<u64>::is_equal(secret_index as u64, 0);
    let mut z_limbs = [0u64; 9];
    ct::conditional_select(
        is_infinity,
        &P521FieldElement::ZERO.internal_limbs(),
        &P521FieldElement::ONE.internal_limbs(),
        &mut z_limbs,
    );
    P521JacobianPoint {
        x: P521FieldElement::from_internal_limbs(x_limbs),
        y: P521FieldElement::from_internal_limbs(y_limbs),
        z: P521FieldElement::from_internal_limbs(z_limbs),
    }
}
