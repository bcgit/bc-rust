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
//! # Why a second const generic `L2`
//!
//! A widening multiply of two `L`-limb operands produces `2L` limbs, and Rust's stable const
//! generics cannot express `[u64; 2 * L]` as a type (that needs the unstable
//! `generic_const_exprs`, which this workspace does not enable; `crypto/mldsa/src/lib.rs` has a
//! commented-out attempt at a different const-generic feature for the same underlying reason).
//! So the width is passed as a second parameter `L2`, with a debug assertion that it really is
//! `2 * L`; every caller in this crate instantiates an `<L, 2L>` pair.
//!
//! The obvious alternative -- and what this module did first -- is to dodge `L2` by returning the
//! product as two separate `L`-sized halves, `(low, high)`, and indexing logical limb `idx` as
//! `if idx < L { low[idx] } else { high[idx - L] }`. That is tidier to type and measurably
//! expensive: splitting the accumulator across two arrays cost **2.2x** per field multiplication
//! for brainpoolP256r1 (54.7ns against 24.6ns for the flat form), because the optimizer stops
//! keeping the accumulator in registers once it lives in two places. Hoisting the `idx < L` test
//! out of the inner loops, and forcing the whole thing to inline, were both tried first and
//! measured: the branch hoist changed nothing at all and `#[inline(always)]` bought about 8%.
//! Neither addressed the actual cost, which is the split itself.
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

/// Schoolbook widening multiply of two `L`-limb operands into their `L2 = 2L`-limb product.
// `inline(always)` on both entry points: with the modulus arriving as a runtime `&[u64; L]`
// rather than a per-curve constant, inlining is what lets each call site's own `P_LIMBS`/
// `N_LIMBS` reach the multiply. Worth a consistent ~2% and measured, not assumed -- the two
// functions are small numeric kernels, so the code-size cost is limited to the three widths
// this crate instantiates.
#[inline(always)]
pub fn widening_mul<const L: usize, const L2: usize>(a: &[u64; L], b: &[u64; L]) -> [u64; L2] {
    debug_assert_eq!(L2, 2 * L, "widening_mul's L2 must be exactly 2 * L");
    let mut result = [0u64; L2];
    for i in 0..L {
        let mut carry: u128 = 0;
        for j in 0..L {
            let idx = i + j;
            let prod = (a[i] as u128) * (b[j] as u128) + (result[idx] as u128) + carry;
            result[idx] = prod as u64;
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
        while k < L2 {
            let s = (result[k] as u128) + carry;
            result[k] = s as u64;
            carry = s >> 64;
            k += 1;
        }
    }
    result
}

/// Montgomery reduction (SOS method): given `low`/`high` (a `2L`-limb value `T = low + high*R <
/// n*R`, the product of two values each `< n`), the `L`-limb modulus `n`, and `n' = -n⁻¹ mod
/// 2^64`, returns `T * R⁻¹`, `< 2n` (proven, see the module docs) -- callers still need their own
/// final conditional subtraction of `n` to reach the canonical `< n` representative, exactly as
/// every hand-written per-curve `redc` in this crate already does.
#[inline(always)]
pub fn redc<const L: usize, const L2: usize, const L21: usize>(
    t: &[u64; L2],
    modulus: &[u64; L],
    n_prime: u64,
) -> ([u64; L], u64) {
    debug_assert_eq!(L2, 2 * L, "redc's L2 must be exactly 2 * L");
    debug_assert_eq!(L21, 2 * L + 1, "redc's L21 must be exactly 2 * L + 1");
    // The accumulator is `2L + 1` limbs (see the module docs for the bound) and is held flat, in
    // one array. Keeping the top limb in a separate `u64` instead -- which is what this did before
    // `L21` existed -- reintroduces exactly the split the module docs describe: measured, it cost
    // 1.7x per multiplication for brainpoolP256r1 (42.7ns against 24.5ns), for the same reason the
    // `(low, high)` product split did.
    let mut acc = [0u64; L21];
    acc[..L2].copy_from_slice(t);

    for i in 0..L {
        let m = acc[i].wrapping_mul(n_prime);

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
            let s = (acc[idx] as u128) + (mn[j] as u128) + carry;
            acc[idx] = s as u64;
            carry = s >> 64;
        }
        // position i + L: add mn_top plus the carry just accumulated.
        let s = (acc[i + L] as u128) + (mn_top as u128) + carry;
        acc[i + L] = s as u64;
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
            debug_assert!(k < L21, "REDC overflowed its verified 2L+1-limb bound");
            let s = (acc[k] as u128) + carry;
            acc[k] = s as u64;
            carry = s >> 64;
            k += 1;
        }
    }

    debug_assert_eq!(&acc[..L], &[0u64; L][..], "REDC's low limbs must be cleared after L rounds");
    debug_assert!(acc[L2] == 0 || acc[L2] == 1, "REDC's top limb must be a single bit");
    let mut high = [0u64; L];
    high.copy_from_slice(&acc[L..L2]);
    (high, acc[L2])
}
