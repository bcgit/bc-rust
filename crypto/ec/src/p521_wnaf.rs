//! Interleaved windowed-NAF (wNAF) Shamir's-trick multiplication: `[u]G + [v]Q`, for P-521 ECDSA
//! verification. Identical algorithm to [`crate::p256_wnaf`] -- see that module's docs for the
//! full derivation and verification methodology -- with the width and limb count swapped for
//! P-521's (`WNAF_LEN = 522`, one more than `n`'s 521-bit length, same margin as P-256's `257 =
//! 256 + 1`).

use crate::nat;
use crate::p521::P521FieldElement;
use crate::p521_domain::{G_X_LIMBS, G_Y_LIMBS};
use crate::p521_point::P521JacobianPoint;
use crate::p521_scalar::P521PublicScalar;

const WIDTH: usize = 5;
const WNAF_LEN: usize = 522;
// Mutating this expression (e.g. `WIDTH - 2` -> `+ 2`) only grows the table `odd_multiples` builds
// and `lookup_signed` reads from; the actual digit range `compute_wnaf` can produce is bounded by
// `WIDTH` itself (unchanged), so the extra entries are simply never indexed -- an accepted mutant.
const ODD_MULTIPLE_COUNT: usize = 1 << (WIDTH - 2);

/// `[u]G + [v]Q`.
pub fn shamir_multiply(
    u: &P521PublicScalar,
    v: &P521PublicScalar,
    q: &P521JacobianPoint,
) -> P521JacobianPoint {
    let du = compute_wnaf(u.to_limbs());
    let dv = compute_wnaf(v.to_limbs());

    let g = P521JacobianPoint::from_affine(
        P521FieldElement::from_limbs(G_X_LIMBS),
        P521FieldElement::from_limbs(G_Y_LIMBS),
    );
    let table_g = odd_multiples(&g);
    let table_q = odd_multiples(q);

    let mut r = P521JacobianPoint::INFINITY;
    for i in (0..WNAF_LEN).rev() {
        r = r.double();
        if let Some(add_g) = lookup_signed(&table_g, du[i]) {
            r = r.add(&add_g);
        }
        if let Some(add_q) = lookup_signed(&table_q, dv[i]) {
            r = r.add(&add_q);
        }
    }
    r
}

fn shr1(limbs: &[u64; 9]) -> [u64; 9] {
    [
        (limbs[0] >> 1) | ((limbs[1] & 1) << 63),
        (limbs[1] >> 1) | ((limbs[2] & 1) << 63),
        (limbs[2] >> 1) | ((limbs[3] & 1) << 63),
        (limbs[3] >> 1) | ((limbs[4] & 1) << 63),
        (limbs[4] >> 1) | ((limbs[5] & 1) << 63),
        (limbs[5] >> 1) | ((limbs[6] & 1) << 63),
        (limbs[6] >> 1) | ((limbs[7] & 1) << 63),
        (limbs[7] >> 1) | ((limbs[8] & 1) << 63),
        limbs[8] >> 1,
    ]
}

/// The width-[`WIDTH`] wNAF digits of `k`, LSB-first; unused trailing entries are `0`. Not
/// constant time: only ever called on public scalars (see the module docs).
fn compute_wnaf(k_limbs: [u64; 9]) -> [i8; WNAF_LEN] {
    let mut digits = [0i8; WNAF_LEN];
    let mut k = k_limbs;
    let mut pos = 0;
    while k != [0, 0, 0, 0, 0, 0, 0, 0, 0] {
        if k[0] & 1 == 1 {
            // Mutating this mask (e.g. `(1 << WIDTH) - 1` -> `+ 1`, giving 33 instead of 31) is an
            // accepted mutant, not a bug: whatever mask is used, `digit` always keeps `k[0]`'s low
            // (odd) bit, so it's always odd -- the only invariant `lookup_signed` and the
            // subtract-or-add-then-`shr1` step below actually rely on. A degenerate mask just makes
            // this compute a non-minimal (but still exactly reconstructing `k`) signed-digit
            // sequence, e.g. the 33-mask case collapses every digit to `+-1`, a valid if wasteful
            // plain binary representation -- verified (not checked in) that both this crate's
            // cross-checked-against-the-comb-multiplier property test and a hand run of this exact
            // mutation still produce the correct `[k]G` output.
            let mut digit = (k[0] & ((1 << WIDTH) - 1)) as i16;
            if digit >= 1 << (WIDTH - 1) {
                digit -= 1 << WIDTH;
            }
            k = if digit >= 0 {
                let (new_k, borrow) = nat::sub(&k, &[digit as u64, 0, 0, 0, 0, 0, 0, 0, 0]);
                debug_assert_eq!(borrow, 0);
                new_k
            } else {
                let (new_k, carry) = nat::add(&k, &[(-digit) as u64, 0, 0, 0, 0, 0, 0, 0, 0]);
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
fn odd_multiples(p: &P521JacobianPoint) -> [P521JacobianPoint; ODD_MULTIPLE_COUNT] {
    let double_p = p.double();
    let mut table = [*p; ODD_MULTIPLE_COUNT];
    let mut cur = *p;
    for entry in table.iter_mut() {
        *entry = cur;
        cur = cur.add(&double_p);
    }
    table
}

/// `digit * p` where `p` is the point `table` was built from ([`odd_multiples`]), or `None` for
/// digit `0`.
fn lookup_signed(
    table: &[P521JacobianPoint; ODD_MULTIPLE_COUNT],
    digit: i8,
) -> Option<P521JacobianPoint> {
    // Every accepted-mutant survivor below relies on `digit` always being odd (it's built from an
    // odd `k[0]` in `compute_wnaf`, see that function's docs): `digit > 0` vs `>= 0` agree once the
    // `digit == 0` case is already handled above, and for odd `digit`, `(digit - 1) / 2 == digit /
    // 2` (and symmetrically for `-digit`), since integer division already floors an odd numerator
    // down to the same value subtracting 1 first would.
    if digit == 0 {
        None
    } else if digit > 0 {
        Some(table[(digit as usize - 1) / 2])
    } else {
        Some(table[(-digit as usize - 1) / 2].negate())
    }
}
