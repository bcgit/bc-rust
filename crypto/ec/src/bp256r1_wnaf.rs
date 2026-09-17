//! Interleaved windowed-NAF (wNAF) Shamir's-trick multiplication: `[u]G + [v]Q`, for
//! brainpoolP256r1 ECDSA verification. Identical algorithm to [`crate::p256_wnaf`] -- see that
//! module's docs for the full derivation and verification methodology -- with the limb count
//! swapped for brainpoolP256r1's (`WNAF_LEN = 257`, one more than `n`'s 256-bit length, same
//! margin as P-256's own `257 = 256 + 1`).

use crate::bp256r1::Bp256r1FieldElement;
use crate::bp256r1_domain::{G_X_LIMBS, G_Y_LIMBS};
use crate::bp256r1_point::Bp256r1JacobianPoint;
use crate::bp256r1_scalar::Bp256r1PublicScalar;
use crate::nat;

const WIDTH: usize = 5;
const WNAF_LEN: usize = 257;
// Mutating this expression (e.g. `WIDTH - 2` -> `+ 2`) only grows the table `odd_multiples` builds
// and `lookup_signed` reads from; the actual digit range `compute_wnaf` can produce is bounded by
// `WIDTH` itself (unchanged), so the extra entries are simply never indexed -- an accepted mutant.
const ODD_MULTIPLE_COUNT: usize = 1 << (WIDTH - 2);

/// `[u]G + [v]Q`.
pub fn shamir_multiply(
    u: &Bp256r1PublicScalar,
    v: &Bp256r1PublicScalar,
    q: &Bp256r1JacobianPoint,
) -> Bp256r1JacobianPoint {
    let du = compute_wnaf(u.to_limbs());
    let dv = compute_wnaf(v.to_limbs());

    let g = Bp256r1JacobianPoint::from_affine(
        Bp256r1FieldElement::from_limbs(G_X_LIMBS),
        Bp256r1FieldElement::from_limbs(G_Y_LIMBS),
    );
    let table_g = odd_multiples(&g);
    let table_q = odd_multiples(q);

    let mut r = Bp256r1JacobianPoint::INFINITY;
    for i in (0..WNAF_LEN).rev() {
        r = r.double();
        if let Some(add_g) = lookup_signed(&table_g, du[i]) {
            r = r.add_vartime(&add_g);
        }
        if let Some(add_q) = lookup_signed(&table_q, dv[i]) {
            r = r.add_vartime(&add_q);
        }
    }
    r
}

fn shr1(limbs: &[u64; 4]) -> [u64; 4] {
    // Each `limbs[i] >> 1` only occupies bits 0-62 (its own bit 63 is shifted out), and
    // `(limbs[i+1] & 1) << 63` only ever occupies bit 63 -- disjoint, so `|` and `^` agree here.
    [
        (limbs[0] >> 1) | ((limbs[1] & 1) << 63),
        (limbs[1] >> 1) | ((limbs[2] & 1) << 63),
        (limbs[2] >> 1) | ((limbs[3] & 1) << 63),
        limbs[3] >> 1,
    ]
}

/// The width-[`WIDTH`] wNAF digits of `k`, LSB-first; unused trailing entries are `0`. Not
/// constant time: only ever called on public scalars (see the module docs).
fn compute_wnaf(k_limbs: [u64; 4]) -> [i8; WNAF_LEN] {
    let mut digits = [0i8; WNAF_LEN];
    let mut k = k_limbs;
    let mut pos = 0;
    while k != [0, 0, 0, 0] {
        if k[0] & 1 == 1 {
            // Mutating this mask (e.g. `(1 << WIDTH) - 1` -> `+ 1`) is an accepted mutant, not a
            // bug: whatever mask is used, `digit` always keeps `k[0]`'s low (odd) bit, so it's
            // always odd -- the only invariant `lookup_signed` and the subtract-or-add-then-`shr1`
            // step below actually rely on. A degenerate mask just makes this compute a
            // non-minimal (but still exactly reconstructing `k`) signed-digit sequence -- see
            // `crate::p521_wnaf`'s identical case for the full argument and verification.
            let mut digit = (k[0] & ((1 << WIDTH) - 1)) as i16;
            if digit >= 1 << (WIDTH - 1) {
                digit -= 1 << WIDTH;
            }
            k = if digit >= 0 {
                let (new_k, borrow) = nat::sub(&k, &[digit as u64, 0, 0, 0]);
                debug_assert_eq!(borrow, 0);
                new_k
            } else {
                let (new_k, carry) = nat::add(&k, &[(-digit) as u64, 0, 0, 0]);
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
fn odd_multiples(p: &Bp256r1JacobianPoint) -> [Bp256r1JacobianPoint; ODD_MULTIPLE_COUNT] {
    let double_p = p.double();
    let mut table = [*p; ODD_MULTIPLE_COUNT];
    let mut cur = *p;
    for entry in table.iter_mut() {
        *entry = cur;
        cur = cur.add_vartime(&double_p);
    }
    table
}

/// `digit * p` where `p` is the point `table` was built from ([`odd_multiples`]), or `None` for
/// digit `0`.
fn lookup_signed(
    table: &[Bp256r1JacobianPoint; ODD_MULTIPLE_COUNT],
    digit: i8,
) -> Option<Bp256r1JacobianPoint> {
    // Every accepted-mutant survivor below relies on `digit` always being odd (it's built from an
    // odd `k[0]` in `compute_wnaf`, see that function's docs): `digit > 0` vs `>= 0` agree once
    // the `digit == 0` case is already handled above, and for odd `digit`, `(digit - 1) / 2 ==
    // digit / 2` (and symmetrically for `-digit`), since integer division already floors an odd
    // numerator down to the same value subtracting 1 first would.
    if digit == 0 {
        None
    } else if digit > 0 {
        Some(table[(digit as usize - 1) / 2])
    } else {
        Some(table[(-digit as usize - 1) / 2].negate())
    }
}
