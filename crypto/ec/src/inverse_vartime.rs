//! Variable-time modular inversion for **public** values: the binary extended Euclidean algorithm
//! (Hankerson, Menezes & Vanstone, *Guide to Elliptic Curve Cryptography*, Algorithm 2.22,
//! "Binary algorithm for inversion in F_p"), generic over the limb count `L` like [`crate::nat`].
//!
//! Every curve's `ScalarField::invert` is a fixed square-and-multiply over the public exponent
//! `n - 2`: the same ~`1.5 * bits` field multiplications whatever the input, which is what a
//! secret `k^-1` needs. ECDSA verification also inverts a scalar, `s` (FIPS 186-5 §6.4.2 step 4),
//! and `s` is part of the signature: it is known to anyone who holds the signature, so nothing
//! about it is protected by taking constant time over it. This algorithm branches and
//! shifts on its operands freely and finishes in a small multiple of `bits` single-limb
//! operations rather than hundreds of full multiplications; measured on P-256, that is a
//! several-fold speedup of the inversion and a few percent of a whole verification.
//!
//! It is reached only through each curve's `PublicScalar::invert_vartime`, so the type system --
//! not a reviewer -- keeps a secret `Scalar` away from it, the same way it keeps one away from
//! the variable-time point multiplier.
//!
//! # The algorithm
//!
//! Algorithm 2.22, for an odd modulus `n` and `0 < a < n` coprime to it:
//!
//! ```text
//! u <- a, v <- n, x1 <- 1, x2 <- 0
//! while u != 1 and v != 1:
//!     while u is even: u <- u/2; x1 <- x1/2 if x1 is even, else (x1 + n)/2
//!     while v is even: v <- v/2; x2 <- x2/2 if x2 is even, else (x2 + n)/2
//!     if u >= v: u <- u - v, x1 <- x1 - x2 (mod n)
//!     else:      v <- v - u, x2 <- x2 - x1 (mod n)
//! return x1 if u == 1, else x2
//! ```
//!
//! `u` and `v` only ever shrink, so both stay below `n` and fit in `L` limbs; `x1` and `x2` are
//! kept reduced mod `n`, so the only intermediate that can exceed `L` limbs is `x + n` before its
//! halving, whose carry bit [`shr1_with_carry`] folds back in. `a = 0` has no inverse and returns
//! `0`, matching the constant-time `invert`'s convention, so callers can substitute one for the
//! other without a special case.

use crate::nat;

/// `a^-1 mod n` for odd `n` and `a < n`, or `0` when `a == 0`, in variable time. See the module
/// docs for what "public values only" means here and why.
pub fn mod_inverse<const L: usize>(a: &[u64; L], n: &[u64; L]) -> [u64; L] {
    debug_assert!(n[0] & 1 == 1, "mod_inverse needs an odd modulus");
    debug_assert_eq!(nat::sub(a, n).1, 1, "mod_inverse needs a < n");

    if nat::is_zero(a).to_bool() {
        return [0u64; L];
    }

    let mut one = [0u64; L];
    one[0] = 1;

    let mut u = *a;
    let mut v = *n;
    let mut x1 = one;
    let mut x2 = [0u64; L];

    while u != one && v != one {
        // Mutating this parity test to `u[0] | 1 == 0` (never halve `u`) is an accepted equivalent
        // mutant, not a gap: the invariant `u == x1 * a (mod n)` holds regardless of whether `u`
        // is halved, and the `v` side and the subtractions alone still drive `u` or `v` down to
        // `1` -- it is the subtractive Euclidean algorithm, slower but correct. (Mutating it to
        // `^`, which halves an odd `u` whose low limb is exactly `1`, breaks the invariant and is
        // caught: the tests feed `2^64 + 1`-shaped inputs for exactly that reason.)
        while u[0] & 1 == 0 {
            u = shr1_with_carry(&u, 0);
            x1 = halve_mod_n(&x1, n);
        }
        while v[0] & 1 == 0 {
            v = shr1_with_carry(&v, 0);
            x2 = halve_mod_n(&x2, n);
        }
        // `u >= v` iff `u - v` does not borrow.
        let (u_minus_v, borrow) = nat::sub(&u, &v);
        if borrow == 0 {
            u = u_minus_v;
            x1 = sub_mod_n(&x1, &x2, n);
        } else {
            v = nat::sub(&v, &u).0;
            x2 = sub_mod_n(&x2, &x1, n);
        }
    }

    if u == one { x1 } else { x2 }
}

/// `(value + carry * 2^(64L)) >> 1`: a right shift by one bit over `L` limbs, with `carry` (0 or
/// 1) entering as the new top bit.
fn shr1_with_carry<const L: usize>(value: &[u64; L], carry: u64) -> [u64; L] {
    let mut out = [0u64; L];
    for i in 0..L {
        let high = if i + 1 < L { value[i + 1] } else { carry };
        // `value[i] >> 1` leaves bit 63 clear and `high << 63` occupies only bit 63, so the two
        // operands are disjoint: mutating this `|` to `^` is an accepted equivalent, not a bug --
        // the same disjoint-OR case the crate's `widening_square` and `p521::reduce` document.
        out[i] = (value[i] >> 1) | (high << 63);
    }
    out
}

/// `x / 2 mod n` for odd `n` and `x < n`: `x >> 1` when `x` is even, else `(x + n) >> 1`. The
/// sum `x + n` is below `2n < 2^(64L+1)`, so its single possible carry bit is what
/// [`shr1_with_carry`] takes.
fn halve_mod_n<const L: usize>(x: &[u64; L], n: &[u64; L]) -> [u64; L] {
    if x[0] & 1 == 0 {
        shr1_with_carry(x, 0)
    } else {
        let (sum, carry) = nat::add(x, n);
        shr1_with_carry(&sum, carry)
    }
}

/// `a - b mod n` for `a, b < n`: the wrapped difference, plus `n` if it borrowed.
fn sub_mod_n<const L: usize>(a: &[u64; L], b: &[u64; L], n: &[u64; L]) -> [u64; L] {
    let (diff, borrow) = nat::sub(a, b);
    if borrow == 1 { nat::add(&diff, n).0 } else { diff }
}
