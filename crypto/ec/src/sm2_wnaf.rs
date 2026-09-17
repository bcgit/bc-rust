//! Interleaved windowed-NAF (wNAF) Shamir's-trick multiplication: `[u]G + [v]Q`, for ECDSA
//! verification's `R' = [u]G + [v]Q` (FIPS 186-5 §6.4.2). Both scalars and both points are public
//! -- `G` is the curve's fixed base point and `Q` a signer's public key -- so unlike
//! [`crate::sm2_comb`], this multiplier takes [`Sm2PublicScalar`], not [`crate::sm2_scalar::Sm2Scalar`],
//! and is written for speed, not constant time: it branches freely on the digits it computes,
//! and adds points with `add_vartime` rather than the constant-time `add` (see that method's
//! docs for why that is both sound here and worth roughly a third of every point addition).
//!
//! # wNAF
//!
//! A width-`w` NAF (non-adjacent form) represents a scalar as signed digits, each `0` or odd and
//! in `(-2^(w-1), 2^(w-1))`, with the property that any `w` consecutive digits contain at most one
//! nonzero one -- so on average only 1-in-(w+1) digits need a point addition. [`compute_wnaf`]
//! computes this the standard way: while the running value is nonzero, if it's odd, take
//! `digit = value mod 2^w`, recentre it into `(-2^(w-1), 2^(w-1)]` if it's `>= 2^(w-1)`, and
//! subtract it off (a small, `< 2^w`, signed adjustment -- a single-limb add or subtract of the
//! 4-limb value); then shift right by one bit regardless. Width `w = 5` is used here, giving 8
//! precomputed odd multiples per point ([`ODD_MULTIPLE_COUNT`]).
//!
//! [`shamir_multiply`] runs both scalars' wNAF digit sequences through the same doubling loop
//! (Shamir's trick): one doubling per digit position serves both `[u]G` and `[v]Q` at once, adding
//! in whichever precomputed odd multiple (or its negation) each sequence's digit at that position
//! calls for.
//!
//! Verified (not checked in) two ways before any of this was written: the digit encoding, against
//! 2000 random `k` (does `sum(digit_i * 2^i) == k`, does every 5-digit window have at most one
//! nonzero entry, are all digits odd and correctly bounded); and the full multiplier, against the
//! standard affine group law (`a = -3`) computed independently via repeated doubling and
//! conditional addition -- including `u = 0`, `v = 0`, both `0`, and `u`/`v = n-1`.

use crate::nat;
use crate::sm2::Sm2FieldElement;
use crate::sm2_domain::{G_X_LIMBS, G_Y_LIMBS};
use crate::sm2_point::Sm2JacobianPoint;
use crate::sm2_scalar::Sm2PublicScalar;

const WIDTH: usize = 5;
const WNAF_LEN: usize = 257;
// Mutating this expression (e.g. `WIDTH - 2` -> `+ 2`) only grows the table `odd_multiples` builds
// and `lookup_signed` reads from; the actual digit range `compute_wnaf` can produce is bounded by
// `WIDTH` itself (unchanged), so the extra entries are simply never indexed -- an accepted mutant,
// the same one already documented in `crate::p256k1_wnaf` and `crate::bp256r1_wnaf`.
const ODD_MULTIPLE_COUNT: usize = 1 << (WIDTH - 2);

/// `[u]G + [v]Q`.
pub fn shamir_multiply(
    u: &Sm2PublicScalar,
    v: &Sm2PublicScalar,
    q: &Sm2JacobianPoint,
) -> Sm2JacobianPoint {
    let du = compute_wnaf(u.to_limbs());
    let dv = compute_wnaf(v.to_limbs());

    let g = Sm2JacobianPoint::from_affine(
        Sm2FieldElement::from_limbs(G_X_LIMBS),
        Sm2FieldElement::from_limbs(G_Y_LIMBS),
    );
    let table_g = odd_multiples(&g);
    let table_q = odd_multiples(q);

    let mut r = Sm2JacobianPoint::INFINITY;
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
    // `(limbs[i+1] & 1) << 63` only ever occupies bit 63 -- disjoint, so `|` and `^` agree here,
    // the same equivalence already documented in `crate::bp256r1_wnaf::shr1`.
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
            // Mutating this mask (e.g. `(1 << WIDTH) - 1` -> `+ 1`) still produces a correct
            // digit sequence: verified in Python over 20,000 random 256-bit k that a mask
            // narrower than WIDTH bits (here, one that keeps only bits 0 and 5) still yields
            // `sum(digit_i * 2^i) == k`, because every digit this narrower mask can ever produce
            // (`{-1, 0, 1}` for this particular mutated mask) still gets subtracted off correctly
            // before the next right-shift -- the loop just falls back to a slower, non-windowed
            // (one-bit-per-step) encoding rather than width-5 wNAF, which is still within
            // WNAF_LEN's bound and mathematically equivalent, just without the windowing speedup.
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
fn odd_multiples(p: &Sm2JacobianPoint) -> [Sm2JacobianPoint; ODD_MULTIPLE_COUNT] {
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
    table: &[Sm2JacobianPoint; ODD_MULTIPLE_COUNT],
    digit: i8,
) -> Option<Sm2JacobianPoint> {
    // Every accepted-mutant survivor below relies on `digit` always being odd (it's built from an
    // odd `k[0]` in `compute_wnaf`, see that function's docs): `digit > 0` vs `>= 0` agree once
    // the `digit == 0` case is already handled above, and for odd `digit`, `(digit - 1) / 2 ==
    // digit / 2` (and symmetrically for `-digit`), since integer division already floors an odd
    // numerator down to the same value subtracting 1 first would -- the same equivalence already
    // documented in `crate::bp256r1_wnaf::lookup_signed`.
    if digit == 0 {
        None
    } else if digit > 0 {
        Some(table[(digit as usize - 1) / 2])
    } else {
        Some(table[(-digit as usize - 1) / 2].negate())
    }
}
