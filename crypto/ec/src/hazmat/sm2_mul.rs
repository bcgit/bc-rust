//! Constant-time variable-base scalar multiplication on the SM2 curve: `[k]Q` for a secret `k` and
//! a point `Q` that is not the base point, such as a peer's public key or a point received from a
//! peer. Identical in shape to [`crate::hazmat::p256_mul`] -- see its docs for why neither
//! [`crate::hazmat::sm2_comb`] nor [`crate::hazmat::sm2_wnaf`] covers this case, for the
//! fixed-window design, and for the width-4 choice, all of which apply unchanged here. The table
//! is `16 * size_of::<Sm2JacobianPoint>()` = 1536 bytes of stack, scrubbed before returning to the
//! extent described there.
//!
//! Verified against [`crate::hazmat::sm2_comb`] (for `Q = G`), against
//! [`crate::hazmat::sm2_wnaf`] and against `[a k mod n]G` (for `Q = [a]G`) in `sm2_mul_tests.rs`,
//! with the same edge cases as P-256's, and against known answers computed outside this crate.

use crate::hazmat::sm2_point::{Sm2JacobianPoint, select_point};
use crate::hazmat::sm2_scalar::Sm2Scalar;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 4;
const BITS: usize = 256;
const ROUNDS: usize = BITS.div_ceil(WIDTH);
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]Q`, branch-free in `k`. `k` may be any value in `[0, n-1]`, and `[0]Q` is the identity.
///
/// `Q` must be a point on this curve -- the identity included -- which means the output of
/// [`crate::hazmat::sm2_sec1::decode_point`], whose validation includes the on-curve check, or of
/// this crate's own arithmetic. A `debug_assert!` rejects any other `Q` in debug builds; release
/// builds do not check, and the formulas never read `b`, so a `Q` off the curve is multiplied, in
/// the same constant time, on whichever curve `y^2 = x^3 + ax + b'` it does lie on, and the result
/// then gives away `k` modulo the small factors of that curve's order (the invalid-curve attack).
/// The caller validates a peer's point before calling this.
pub fn multiply_point(k: &Sm2Scalar, q: &Sm2JacobianPoint) -> Sm2JacobianPoint {
    debug_assert!(
        q.to_affine().is_none_or(|(x, y)| Sm2JacobianPoint::is_on_curve(&x, &y)),
        "Q is not on the curve"
    );
    let mut table = [Sm2JacobianPoint::INFINITY; TABLE_SIZE];
    table[1] = *q;
    for i in 2..TABLE_SIZE {
        // Which entry is built how depends only on the (public) index, never on `k` or `Q`.
        table[i] = if i % 2 == 0 { table[i / 2].double() } else { table[i - 1].add(q) };
    }

    let limbs = k.limbs();
    let mut r = Sm2JacobianPoint::INFINITY;
    // The lookup's copy of the selected entry; declared here so one scrub after the loop covers it.
    let mut entry = Sm2JacobianPoint::INFINITY;
    for round in 0..ROUNDS {
        let low_bit = (ROUNDS - 1 - round) * WIDTH;
        let window = window_at(limbs, low_bit);
        for _ in 0..WIDTH {
            r = r.double();
        }
        entry = table_lookup(&table, window);
        r = r.add(&entry);
    }

    entry.zeroize();
    for entry in table.iter_mut() {
        entry.zeroize();
    }
    r
}

/// The `WIDTH` bits of `limbs` from bit `low_bit` up, as a window value in `0..TABLE_SIZE`. Bits
/// at or above `BITS` read as zero. The bit positions are public; the shifts and masks are
/// branch-free in the limb values.
fn window_at(limbs: &[u64; 4], low_bit: usize) -> usize {
    let mut window = 0usize;
    for j in (low_bit..low_bit + WIDTH).rev() {
        let bit = if j < BITS { (limbs[j / 64] >> (j % 64)) & 1 } else { 0 };
        window = (window << 1) | (bit as usize);
    }
    window
}

/// Table entry `secret_index`, selected by scanning every entry under a mask so the index never
/// steers which memory is read.
fn table_lookup(table: &[Sm2JacobianPoint; TABLE_SIZE], secret_index: usize) -> Sm2JacobianPoint {
    let mut r = Sm2JacobianPoint::INFINITY;
    for (i, entry) in table.iter().enumerate() {
        let is_this_entry = Condition::<u64>::is_equal(i as u64, secret_index as u64);
        r = select_point(is_this_entry, entry, &r);
    }
    r
}
