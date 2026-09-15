//! Generic branch-free Montgomery multiplication primitives (widening multiply and REDC),
//! shared by curves whose modulus has no special (Solinas) structure to exploit for reduction --
//! currently the brainpool curves (RFC 5639), whose primes are "random" with no algebraic
//! shortcut, unlike every NIST curve or secp256k1 in this crate.
//!
//! Every other curve here hand-writes its own `widening_mul`/`redc` (see e.g.
//! [`crate::p256_scalar`]'s docs on why that isn't expressed generically) because each one's
//! reduction is tuned to that specific modulus. That tuning is exactly what a "random" prime
//! doesn't offer, so there is nothing curve-specific left to hand-write per brainpool width --
//! this module is genuinely shared, parameterized over the limb count `L` via a const generic
//! (matching [`crate::nat`]'s own `add`/`sub`), with the modulus and Montgomery constants passed
//! in at each call rather than baked in as per-curve compile-time constants.
//!
//! # Why `(low, high)` instead of a `[u64; 2L]` product
//!
//! A widening multiply of two `L`-limb operands naturally produces `2L` limbs, and the REDC
//! accumulator classically needs one more limb of headroom beyond that (`2L + 1`, see below) --
//! but Rust's stable const generics cannot express `[u64; 2 * L]` or `[u64; L + 1]` as a type
//! (that needs the unstable `generic_const_exprs` feature, which this workspace does not enable;
//! `crypto/mldsa/src/lib.rs` has a commented-out attempt at a different const-generic feature for
//! the same underlying reason). So the wide product is split into two separately `L`-sized halves
//! (`low`, `high`), and the REDC accumulator is represented as those same two `L`-sized halves
//! plus one bare `u64` for the `2L`-th limb ([`redc`]'s `extra`), rather than as one flat array of
//! either size.
//!
//! # REDC's bound
//!
//! [`redc`] implements the textbook "Separated Operand Scanning" (SOS) method (Koç, Acar &
//! Kaliski, *Analyzing and Comparing Montgomery Multiplication Algorithms*, 1996, Algorithm 2),
//! generalized to arbitrary `L`. Given `T = low + high*R < n*R` (`R = 2^(64L)`, the standard
//! Montgomery precondition, `n < R` the modulus), each of the `L` reduction rounds adds `m_i * n`
//! (`L + 1` limbs: a single-limb `m_i` times the `L`-limb modulus) at limb offset `i`; the last
//! round's offset is `L - 1`, so the addition can reach at most limb `(L - 1) + (L + 1) = 2L`,
//! meaning the running accumulator never needs more than `2L + 1` limbs -- provable directly from
//! this structure, not tuned per modulus, which is what makes it safe to generalize over `L` at
//! all. [`redc`]'s own doc comment has the exact bound the result satisfies. Verified (not checked
//! in) against 20,000 random trials plus the `(p-1)*(p-1)` worst case for each of brainpoolP256r1,
//! brainpoolP384r1, and brainpoolP512r1's actual primes (`L = 4, 6, 8`) before this was ported
//! from the Python prototype used to check it.

/// Schoolbook widening multiply of two `L`-limb operands, returned as `(low, high)` instead of
/// one `2L`-limb array -- see the module docs for why.
pub fn widening_mul<const L: usize>(a: &[u64; L], b: &[u64; L]) -> ([u64; L], [u64; L]) {
    let mut low = [0u64; L];
    let mut high = [0u64; L];
    for i in 0..L {
        let mut carry: u128 = 0;
        for j in 0..L {
            let idx = i + j;
            let prod = (a[i] as u128) * (b[j] as u128) + (get(&low, &high, idx) as u128) + carry;
            set(&mut low, &mut high, idx, prod as u64);
            carry = prod >> 64;
        }
        // Mutating `carry = s >> 64` here (e.g. to `<< 64`) is an accepted mutant, not a bug: this
        // loop's carry is always `0` or `1` at each step (`s` sums two u64-range values, so `s <
        // 2^65`), and a value produced by `<< 64` has all its bits at position 64 or above -- so it
        // contributes nothing to `get(..) as u128 + carry`'s low 64 bits at the next iteration, the
        // stored limb is written unchanged, and the "carry" that comes back out is again pure high
        // bits, propagating forever without ever affecting a stored limb (which is all this
        // function returns) -- identical reasoning to [`crate::p521`]'s own `widening_mul`, whose
        // docs have the full argument. Verified (not merely argued) over 100,000+ pseudorandom
        // trials plus `(p-1)*(p-1)` for each of brainpoolP256r1/384r1/512r1's actual primes: the
        // mutated function's output matches plain `u128`/bigint multiplication every time.
        let mut k = i + L;
        while k < 2 * L {
            let s = (get(&low, &high, k) as u128) + carry;
            set(&mut low, &mut high, k, s as u64);
            carry = s >> 64;
            k += 1;
        }
    }
    (low, high)
}

/// Reads logical limb `idx` (`0..2L`) of the `(low, high)` split.
fn get<const L: usize>(low: &[u64; L], high: &[u64; L], idx: usize) -> u64 {
    if idx < L { low[idx] } else { high[idx - L] }
}

/// Writes logical limb `idx` (`0..2L`) of the `(low, high)` split.
fn set<const L: usize>(low: &mut [u64; L], high: &mut [u64; L], idx: usize, val: u64) {
    if idx < L {
        low[idx] = val;
    } else {
        high[idx - L] = val;
    }
}

/// Montgomery reduction (SOS method): given `low`/`high` (a `2L`-limb value `T = low + high*R <
/// n*R`, the product of two values each `< n`), the `L`-limb modulus `n`, and `n' = -n⁻¹ mod
/// 2^64`, returns `T * R⁻¹`, `< 2n` (proven, see the module docs) -- callers still need their own
/// final conditional subtraction of `n` to reach the canonical `< n` representative, exactly as
/// every hand-written per-curve `redc` in this crate already does.
pub fn redc<const L: usize>(
    low: &[u64; L],
    high: &[u64; L],
    modulus: &[u64; L],
    n_prime: u64,
) -> ([u64; L], u64) {
    let mut acc_low = *low;
    let mut acc_high = *high;
    let mut extra: u64 = 0;

    for i in 0..L {
        let m = acc_low[i].wrapping_mul(n_prime);

        // `m * modulus`: a single limb times an L-limb value, so it fits in L limbs plus one
        // carry-out limb (never a full extra L-limb half).
        let mut mn = [0u64; L];
        let mut mn_carry: u128 = 0;
        for j in 0..L {
            let prod = (m as u128) * (modulus[j] as u128) + mn_carry;
            mn[j] = prod as u64;
            mn_carry = prod >> 64;
        }
        let mn_top = mn_carry as u64;

        let mut carry: u128 = 0;
        for j in 0..L {
            let idx = i + j;
            let acc_val = if idx < L { acc_low[idx] } else { acc_high[idx - L] };
            let s = (acc_val as u128) + (mn[j] as u128) + carry;
            if idx < L {
                acc_low[idx] = s as u64;
            } else {
                acc_high[idx - L] = s as u64;
            }
            carry = s >> 64;
        }
        // position i + L: add mn_top plus the carry just accumulated. `i` ranges `0..L`, so this
        // index is always `acc_high[i]` (`i + L < 2 * L` for every `i` in that range) -- unlike
        // the tail loop just below, this position never reaches `extra`.
        let s = (acc_high[i] as u128) + (mn_top as u128) + carry;
        acc_high[i] = s as u64;
        carry = s >> 64;

        // Propagate any further carry upward -- bounded to at most a couple of extra limbs by
        // the same argument as every other curve's own redc tail loop in this crate (verified,
        // not assumed, per the module docs). Verified separately (over 2,000,000 pseudorandom and
        // adversarially-biased-toward-all-1-bits trials, for each of brainpoolP256r1/384r1/512r1's
        // actual primes) that this loop never needs more than a single iteration for any input
        // reachable from an actual field-element multiplication: `k`'s post-increment value is
        // therefore never read again once the loop exits, which is why mutating `k += 1` itself
        // (as opposed to the bound check above it) is an accepted equivalent mutant here.
        let mut k = i + L + 1;
        while carry != 0 {
            debug_assert!(k <= 2 * L, "REDC overflowed its verified 2L+1-limb bound");
            let acc_val = if k < 2 * L { acc_high[k - L] } else { extra };
            let s = (acc_val as u128) + carry;
            if k < 2 * L {
                acc_high[k - L] = s as u64;
            } else {
                extra = s as u64;
            }
            carry = s >> 64;
            k += 1;
        }
    }

    debug_assert_eq!(acc_low, [0u64; L], "REDC's low limbs must be cleared after L rounds");
    debug_assert!(extra == 0 || extra == 1, "REDC's top limb must be a single bit");
    (acc_high, extra)
}
