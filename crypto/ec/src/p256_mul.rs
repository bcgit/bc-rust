//! Constant-time variable-base scalar multiplication: `[k]Q` for a secret `k` and a point `Q`
//! that is not the base point -- a peer's public key, for the ECC CDH primitive of SP 800-56A
//! Rev. 3 Section 5.7.1.2 (`P = h d_A Q_B`).
//!
//! The crate's other two multipliers do not cover this case: [`crate::p256_comb`] is fixed-base
//! (`[k]G` from a compile-time table of multiples of `G`), and [`crate::p256_wnaf`] takes
//! [`crate::p256_scalar::P256PublicScalar`] and is variable-time by design. This one takes
//! [`P256Scalar`], the secret type, and is branch-free in `k` throughout.
//!
//! # Fixed window, width 4
//!
//! `[k]Q` is computed left to right over `ROUNDS = ceil(BITS / 4)` windows of 4 bits: each round
//! doubles the accumulator four times and adds `[w]Q` for the round's window value `w`, read off
//! `k`'s limbs at positions fixed by the loop (so *which* bits are read is public, only their
//! values are secret). `[w]Q` comes from a table of `[0]Q .. [15]Q` built per call in Jacobian
//! coordinates -- entry 0 is the identity, the rest by doubling and adding `Q` -- and is read by
//! `table_lookup`, which scans every entry under a mask rather than indexing by `w`, as the
//! comb's lookup does. The accumulator's addition is the complete [`P256JacobianPoint::add`]: it
//! masks in the identity, same-point and opposite-point cases, so the accumulator may be the
//! identity (it starts there and stays there through leading zero windows), a table entry may be
//! the identity (`w = 0`), and `Q` itself may be added to a multiple of `Q`; the comb's "no
//! offset" argument carries over unchanged.
//!
//! Cost: `4 * ROUNDS` doublings, `ROUNDS` full additions, `ROUNDS` masked scans of the table and
//! 14 point operations to build it: on P-256 about three times the fixed-base comb (whose table
//! is precomputed and whose additions are mixed) and 1.3 times the variable-time wNAF multiplier
//! (136 us against 44 us and 106 us in `p256_point_benches` / `p256_scalar_benches`). The table
//! is `16 * size_of::<P256JacobianPoint>()` bytes of stack. Width 4 over width 5 keeps
//! that table at 1.5 KiB on P-256 and 3.4 KiB on P-521 for one fewer addition in five; a Montgomery
//! ladder would need an addition per bit. The table and the lookup's copy of the selected entry are
//! zeroized before returning, as defence in depth in the sense of
//! [`crate::p256::P256FieldElement::zeroize`]: the accumulator's superseded values (each round's
//! `double` and `add` return by value), the window index and the intermediates in the point
//! operations' own frames are not reached. The caller owns the result and scrubs it when it is
//! done.
//!
//! Verified against [`crate::p256_comb`] (for `Q = G`), against [`crate::p256_wnaf`] and against
//! `[a k mod n]G` (for `Q = [a]G`) in `p256_mul_tests.rs`, including `k = 0`, `k = 1`, `k = n-1`,
//! `Q` the identity, `Q` negated and `Q` in a non-canonical-`Z` representation.

use crate::p256_point::{P256JacobianPoint, select_point};
use crate::p256_scalar::P256Scalar;
use bouncycastle_utils::ct::Condition;

const WIDTH: usize = 4;
const BITS: usize = 256;
const ROUNDS: usize = BITS.div_ceil(WIDTH);
const TABLE_SIZE: usize = 1 << WIDTH;

/// `[k]Q`, branch-free in `k`. `k` may be any value in `[0, n-1]`, and `[0]Q` is the identity.
///
/// `Q` must be a point on this curve -- the identity included -- which means the output of
/// [`crate::p256_sec1::decode_point`], whose validation includes the on-curve check, or of this
/// crate's own arithmetic. A `debug_assert!` rejects any other `Q` in debug builds; release builds
/// do not check, and the formulas never read `b`, so a `Q` off the curve is multiplied, in the same
/// constant time, on whichever curve `y^2 = x^3 + ax + b'` it does lie on, and the result then
/// gives away `k` modulo the small factors of that curve's order (the invalid-curve attack). The
/// key-agreement layer validates the peer's key before calling this; see the crate's Security
/// Considerations.
pub fn multiply_point(k: &P256Scalar, q: &P256JacobianPoint) -> P256JacobianPoint {
    debug_assert!(
        q.to_affine().is_none_or(|(x, y)| P256JacobianPoint::is_on_curve(&x, &y)),
        "Q is not on the curve"
    );
    let mut table = [P256JacobianPoint::INFINITY; TABLE_SIZE];
    table[1] = *q;
    for i in 2..TABLE_SIZE {
        // Which entry is built how depends only on the (public) index, never on `k` or `Q`.
        table[i] = if i % 2 == 0 { table[i / 2].double() } else { table[i - 1].add(q) };
    }

    let limbs = k.limbs();
    let mut r = P256JacobianPoint::INFINITY;
    // The lookup's copy of the selected entry; declared here so one scrub after the loop covers it.
    let mut entry = P256JacobianPoint::INFINITY;
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
fn table_lookup(table: &[P256JacobianPoint; TABLE_SIZE], secret_index: usize) -> P256JacobianPoint {
    let mut r = P256JacobianPoint::INFINITY;
    for (i, entry) in table.iter().enumerate() {
        let is_this_entry = Condition::<u64>::is_equal(i as u64, secret_index as u64);
        r = select_point(is_this_entry, entry, &r);
    }
    r
}
