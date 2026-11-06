//! Constant-time variable-base scalar multiplication on brainpoolP256r1: `[k]Q` for a secret `k`
//! and a point `Q` that is not the base point, for the ECC CDH primitive of SP 800-56A Rev. 3
//! Section 5.7.1.2. Identical in shape to [`crate::p256_mul`] -- see its docs for why neither
//! [`crate::bp256r1_comb`] nor [`crate::bp256r1_wnaf`] covers this case, for the fixed-window
//! design, and for the cost comparison and the width-4 choice, all of which apply unchanged here.
//! The table is `16 * size_of::<Bp256r1JacobianPoint>()` = 1536 bytes of stack, scrubbed before
//! returning to the extent described there.
//!
//! Verified against [`crate::bp256r1_comb`] (for `Q = G`), against [`crate::bp256r1_wnaf`] and
//! against `[a k mod n]G` (for `Q = [a]G`) in `bp256r1_mul_tests.rs`, with the same edge cases as
//! P-256's.

use crate::bp256r1_point::{Bp256r1JacobianPoint, select_point};
use crate::bp256r1_scalar::Bp256r1Scalar;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 4;
const BITS: usize = 256;
const ROUNDS: usize = BITS.div_ceil(WIDTH);
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]Q`, branch-free in `k`. `k` may be any value in `[0, n-1]`, and `[0]Q` is the identity.
///
/// `Q` must be a point on this curve -- the identity included -- which means the output of
/// [`crate::bp256r1_sec1::decode_point`], whose validation includes the on-curve check, or of this
/// crate's own arithmetic. A `debug_assert!` rejects any other `Q` in debug builds; release builds
/// do not check, and the formulas never read `b`, so a `Q` off the curve is multiplied, in the same
/// constant time, on whichever curve `y^2 = x^3 + ax + b'` it does lie on, and the result then
/// gives away `k` modulo the small factors of that curve's order (the invalid-curve attack). The
/// key-agreement layer validates the peer's key before calling this; see the crate's Security
/// Considerations.
pub fn multiply_point(k: &Bp256r1Scalar, q: &Bp256r1JacobianPoint) -> Bp256r1JacobianPoint {
    debug_assert!(
        q.to_affine().is_none_or(|(x, y)| Bp256r1JacobianPoint::is_on_curve(&x, &y)),
        "Q is not on the curve"
    );
    let mut table = [Bp256r1JacobianPoint::INFINITY; TABLE_SIZE];
    table[1] = *q;
    for i in 2..TABLE_SIZE {
        // Which entry is built how depends only on the (public) index, never on `k` or `Q`.
        table[i] = if i % 2 == 0 { table[i / 2].double() } else { table[i - 1].add(q) };
    }

    let limbs = k.limbs();
    let mut r = Bp256r1JacobianPoint::INFINITY;
    // The lookup's copy of the selected entry; declared here so one scrub after the loop covers it.
    let mut entry = Bp256r1JacobianPoint::INFINITY;
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
/// at or above `BITS` read as zero, so on a curve whose `BITS` is not a multiple of `WIDTH`
/// (P-521) the top window sees only the scalar. The bit positions are public; the shifts and
/// masks are branch-free in the limb values.
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
fn table_lookup(
    table: &[Bp256r1JacobianPoint; TABLE_SIZE],
    secret_index: usize,
) -> Bp256r1JacobianPoint {
    let mut r = Bp256r1JacobianPoint::INFINITY;
    for (i, entry) in table.iter().enumerate() {
        let is_this_entry = Condition::<u64>::is_equal(i as u64, secret_index as u64);
        r = select_point(is_this_entry, entry, &r);
    }
    r
}
