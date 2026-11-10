//! Constant-time Barrett reduction of a wide value by a modulus that has no arithmetic shortcut
//! (Menezes, van Oorschot & Vanstone, *Handbook of Applied Cryptography*, Algorithm 14.42, in the
//! limb-aligned form below), generic over the limb count `L` like [`crate::nat`].
//!
//! The one user is FIPS 186-5 Appendix A.4.1's `x mod (n - 1)` in `bouncycastle-ecdsa` and
//! `bouncycastle-sm2`: the DRBG output `x` is 64 to 96 bits wider than `n`, and `n - 1` is even, so
//! neither the per-curve Solinas reductions nor Montgomery arithmetic applies. The previous
//! implementation reduced `x` one bit at a time -- a doubling, a conditional carry correction and
//! a conditional subtraction per bit, 320 to 592 times -- which cost 10 to 15 microseconds, more
//! than a field inversion, on every key generation and every randomised signature. Barrett's
//! method does the same job with two `L x L` multiplications and a fixed number of conditional
//! subtractions, every step of it branch-free in the value being reduced.
//!
//! # The algorithm, and its bound
//!
//! Write `k = 64 L`, and require the modulus to fill its top limb: `2^(k-1) < m < 2^k`. Precompute
//! `mu = floor(2^(2k) / m)`; since `m > 2^(k-1)`, `2^k < mu < 2^(k+1)`, so `mu = 2^k + mu_low` with
//! `mu_low < 2^k`, and [`reduce`] takes only `mu_low`. For an input `T < m * 2^k`:
//!
//! ```text
//! t_hi  = floor(T / 2^k)                       (the top L limbs; t_hi < m)
//! q_hat = floor(t_hi * mu / 2^k)
//!       = t_hi + floor(t_hi * mu_low / 2^k)   (the top L limbs of an L x L product)
//! r     = T - q_hat * m
//! ```
//!
//! With `q = floor(T / m)`: `q_hat <= q`, since `t_hi <= T / 2^k` and `mu <= 2^(2k) / m`; and
//! `q_hat >= q - 3`, since `t_hi > T / 2^k - 1`, `mu > 2^(2k) / m - 1`, `T / 2^(2k) < m / 2^k < 1`
//! and `2^k / m < 2`, so `t_hi * mu / 2^k > T / m - 3`. Hence `0 <= r < 4 m`, and three conditional
//! subtractions of `m` finish the reduction. (Measured over the seven moduli this crate's users
//! pass, at most two are ever needed; the third is kept because the bound, not the measurement,
//! is what makes the code correct.)
//!
//! Verified (not checked in) in Python against arbitrary-precision `%` for each of the seven
//! `n - 1` values, over 20,000 pseudorandom inputs per modulus at every byte length up to the
//! maximum, plus the extremes `0`, `1`, `m - 1`, `m`, `m + 1`, `m * 2^k - 1` and the all-ones
//! input of maximum width.

use crate::montgomery::widening_mul;
use crate::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// Packs up to `8 * L2` big-endian bytes into `L2` little-endian limbs, zero-extended at the top.
/// Panics if `bytes` is longer than the limbs can hold: a caller passing the wrong width is a
/// programming error, not a data error.
pub fn limbs_from_be_bytes<const L2: usize>(bytes: &[u8]) -> [u64; L2] {
    assert!(bytes.len() <= 8 * L2, "{} bytes do not fit in {L2} limbs", bytes.len());
    let mut limbs = [0u64; L2];
    for (i, &byte) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= (byte as u64) << (8 * (i % 8));
    }
    limbs
}

/// `t mod m` for a `2L`-limb `t < m * 2^(64L)` and an `L`-limb modulus `2^(64L-1) < m < 2^(64L)`,
/// given `mu_low = floor(2^(128L) / m) - 2^(64L)`. `L2` must be `2L` and `L1` must be `L + 1`
/// (the width `r < 4m` needs before its final subtractions); both are debug-asserted, as are the
/// preconditions on `t` and `m`. Branch-free in `t`.
pub fn reduce<const L: usize, const L2: usize, const L1: usize>(
    t: &[u64; L2],
    m: &[u64; L],
    mu_low: &[u64; L],
) -> [u64; L] {
    debug_assert_eq!(L2, 2 * L, "reduce's L2 must be exactly 2 * L");
    debug_assert_eq!(L1, L + 1, "reduce's L1 must be exactly L + 1");
    debug_assert!(m[L - 1] >> 63 == 1, "reduce needs a modulus with its top bit set");

    // t_hi = floor(t / 2^k), the top L limbs; the precondition t < m * 2^k is t_hi < m.
    let mut t_hi = [0u64; L];
    t_hi.copy_from_slice(&t[L..]);
    debug_assert_eq!(nat::sub(&t_hi, m).1, 1, "reduce needs t < m * 2^(64L)");

    // q_hat = t_hi + floor(t_hi * mu_low / 2^k): the top L limbs of the product, plus t_hi. The
    // sum cannot carry: q_hat <= q = floor(t / m) < 2^k.
    let product = widening_mul::<L, L2>(&t_hi, mu_low);
    let mut product_hi = [0u64; L];
    product_hi.copy_from_slice(&product[L..]);
    let (q_hat, carry) = nat::add(&t_hi, &product_hi);
    debug_assert_eq!(carry, 0, "q_hat overflowed L limbs, contradicting q_hat <= q < 2^(64L)");

    // r = t - q_hat * m, over 2L limbs; never negative since q_hat <= q, and < 4m since
    // q_hat >= q - 3, so it fits in L + 1 limbs.
    let q_hat_m = widening_mul::<L, L2>(&q_hat, m);
    let (r_wide, borrow) = nat::sub(t, &q_hat_m);
    debug_assert_eq!(borrow, 0, "t - q_hat * m went negative, contradicting q_hat <= q");
    debug_assert!(r_wide[L1..].iter().all(|&limb| limb == 0), "r exceeded 4m");
    let mut r = [0u64; L1];
    r.copy_from_slice(&r_wide[..L1]);

    // Three conditional subtractions bring r from [0, 4m) into [0, m). Each is a masked select,
    // so the number performed does not depend on r.
    let mut m_wide = [0u64; L1];
    m_wide[..L].copy_from_slice(m);
    for _ in 0..3 {
        let (diff, borrow) = nat::sub(&r, &m_wide);
        let mut selected = [0u64; L1];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &r, &diff, &mut selected);
        r = selected;
    }
    debug_assert_eq!(r[L], 0, "r still exceeds L limbs after three subtractions");

    let mut out = [0u64; L];
    out.copy_from_slice(&r[..L]);
    out
}
