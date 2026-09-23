//! RSA key pair generation: FIPS 186-5 Appendix A.1.3, "Generation of Random Primes that are
//! Probably Prime", with Appendix B.3.1's Miller-Rabin test (behind Appendix B.7-style trial
//! division) and Appendix A.1.1's criteria on `e`, `p`, `q` and `d`, over this crate's fixed-width
//! limb arithmetic -- there is no arbitrary-precision integer type here, as in the rest of the
//! crate. Structured after BC Java's `org.bouncycastle.crypto.generators.RSAKeyPairGenerator`
//! (its candidate loop, small-factor sieve and `d` lower-bound check are what this follows), with
//! FIPS 186-5 as the reference for every step and cited inline.
//!
//! The concrete sizes wire this up as `keygen`/`keygen_from_rng` in their own modules
//! (`crate::rsa_2048::keygen` and siblings): `nlen` is fixed by the width, `e` by
//! [`PUBLIC_EXPONENT`], and the Miller-Rabin round count and required RNG strength by each size's
//! row of FIPS 186-5 Table B.1 and SP 800-57 Part 1 Table 2.
//!
//! # What is and is not constant-time here
//!
//! Key generation is rejection sampling: how many candidates are drawn, and where each one is
//! rejected (a small factor, the `|p - q|` bound, a Miller-Rabin witness), is inherently
//! data-dependent, and the small-modulus arithmetic on a candidate -- its residues modulo the
//! trial-division primes and modulo `e`, the binary GCD and the one long division behind
//! `lcm(p - 1, q - 1)` -- uses ordinary variable-time integer operations. That is the same
//! position BC Java's `BigInteger`-based generator takes, for a one-off operation with no
//! attacker-supplied input. The secret-exponent work generation does do, `qInv = q^(p - 2) mod p`,
//! goes through [`crate::modexp::mod_pow`]'s constant-time ladder, the same one every signature
//! uses; and the `MontgomeryContext` built over each candidate is the same construction
//! `rsa_core::rsasp1` already builds over the secret primes on every signature.

use crate::keys::{RsaPrivateKey, RsaPublicKey};
use crate::modexp::{MontgomeryContext, mod_pow, mul_mod, reduce_wide};
use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::traits::{RNG, SecurityStrength};
use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
use bouncycastle_utils::secret::Secret;
use core::num::NonZeroUsize;

/// The public exponent every key pair this crate generates uses: `F4 = 2^16 + 1 = 65537`.
/// FIPS 186-5 Appendix A.1.1 criterion 1 asks for an odd `e` with `2^16 < e < 2^256`, "selected
/// prior to generating the primes"; this is the smallest such value and the near-universal choice
/// (it is what Wycheproof's and BC Java's test keys use). Its primality is what lets criterion
/// 2(a), `GCD(p - 1, e) = 1`, be checked as "`e` does not divide `p - 1`" (step 4.5 below).
pub const PUBLIC_EXPONENT: u32 = 65537;

/// Trial-division bound: every prime below this is divided out of a candidate before the
/// Miller-Rabin test runs (FIPS 186-5 Appendix B.7, "if convenient, `c` may be divided by
/// composite numbers" -- the primes are bundled into `u64` products, as BC Java's
/// `Primes.hasAnySmallFactors` does). `2^10` is a round choice well inside Appendix B.8's
/// "typical" `10^3` to `10^5`; about 93% of odd composites are caught here, sparing that many
/// modular exponentiations.
pub const SMALL_PRIME_LIMIT: usize = 1024;

/// `pi(1024)`: the number of primes below [`SMALL_PRIME_LIMIT`].
const SMALL_PRIME_COUNT: usize = 172;

/// The primes below [`SMALL_PRIME_LIMIT`], from a compile-time sieve of Eratosthenes (Appendix
/// B.8's sieve procedure, at its simplest).
const SMALL_PRIMES: [u16; SMALL_PRIME_COUNT] = small_primes();

const fn small_primes() -> [u16; SMALL_PRIME_COUNT] {
    let mut composite = [false; SMALL_PRIME_LIMIT];
    let mut primes = [0u16; SMALL_PRIME_COUNT];
    let mut found = 0;
    let mut i = 2;
    while i < SMALL_PRIME_LIMIT {
        if !composite[i] {
            primes[found] = i as u16;
            found += 1;
            let mut j = i * i;
            while j < SMALL_PRIME_LIMIT {
                composite[j] = true;
                j += i;
            }
        }
        i += 1;
    }
    assert!(found == SMALL_PRIME_COUNT, "SMALL_PRIME_COUNT must be pi(SMALL_PRIME_LIMIT)");
    primes
}

// ---- small-integer helpers over `[u64; N]` little-endian limbs ------------------------------

/// `a mod m` for a small modulus `m`, by schoolbook long division one limb at a time.
fn mod_u64<const N: usize>(a: &[u64; N], m: u64) -> u64 {
    let mut rem: u128 = 0;
    for limb in a.iter().rev() {
        rem = ((rem << 64) | u128::from(*limb)) % u128::from(m);
    }
    rem as u64
}

/// `a * k + add`, as `N` limbs plus the carry limb.
fn mul_u64_add<const N: usize>(a: &[u64; N], k: u64, add: u64) -> ([u64; N], u64) {
    let mut out = [0u64; N];
    let mut carry = u128::from(add);
    for i in 0..N {
        let t = u128::from(a[i]) * u128::from(k) + carry;
        out[i] = t as u64;
        carry = t >> 64;
    }
    (out, carry as u64)
}

/// `(hi || a) / d` and the remainder, for `hi < d`, by schoolbook long division one limb at a
/// time; the quotient then fits in `N` limbs.
fn div_u64<const N: usize>(hi: u64, a: &[u64; N], d: u64) -> ([u64; N], u64) {
    debug_assert!(hi < d, "div_u64: the quotient must fit in N limbs");
    let mut quotient = [0u64; N];
    let mut rem = u128::from(hi);
    for i in (0..N).rev() {
        let cur = (rem << 64) | u128::from(a[i]);
        quotient[i] = (cur / u128::from(d)) as u64;
        rem = cur % u128::from(d);
    }
    (quotient, rem as u64)
}

/// `r^-1 mod e` for prime `e` and `0 < r < e`, as `r^(e - 2) mod e` (Fermat), by a fixed 32-step
/// square-and-multiply.
fn inv_mod_u64_prime(r: u64, e: u64) -> u64 {
    debug_assert!(r != 0 && r < e);
    let exp = e - 2;
    let mut acc: u128 = 1;
    let base = u128::from(r);
    let m = u128::from(e);
    for bit in (0..32).rev() {
        acc = (acc * acc) % m;
        if (exp >> bit) & 1 == 1 {
            acc = (acc * base) % m;
        }
    }
    acc as u64
}

/// `e^-1 mod m` for `m > 1` with `GCD(m, e) = 1`, where `e` is [`PUBLIC_EXPONENT`].
///
/// FIPS 186-5 Appendix B.1 gives the extended Euclidean algorithm for reference and allows
/// "other algorithms that produce an equivalent result". Because `e` is small and prime, the
/// inverse comes without a multi-limb division: with `r = m mod e` and `k = -r^-1 mod e` (so
/// `k*m + 1 ≡ 0 mod e`), `d = (k*m + 1) / e` is an exact integer with `e*d = 1 + k*m ≡ 1 mod m`,
/// and `0 < d < m` since `0 < k < e`. The only multi-limb operations are one multiply by `k` and
/// one exact division by `e`.
fn inverse_of_e_mod<const N: usize>(m: &[u64; N]) -> [u64; N] {
    let e = u64::from(PUBLIC_EXPONENT);
    let r = mod_u64(m, e);
    // `GCD(m, e) = 1` is the caller's invariant: `keygen_from_rng` discards any `p` (or `q`) with
    // `e | p - 1` at step 4.5, and `LCM(p - 1, q - 1)` then cannot be divisible by `e` either.
    debug_assert_ne!(r, 0, "e must not divide m");
    let k = e - inv_mod_u64_prime(r, e);
    let (lo, hi) = mul_u64_add(m, k, 1);
    let (d, rem) = div_u64(hi, &lo, e);
    debug_assert_eq!(rem, 0, "k*m + 1 is divisible by e by construction");
    d
}

// ---- multi-limb helpers ----------------------------------------------------------------------

fn is_zero<const N: usize>(a: &[u64; N]) -> bool {
    nat::is_zero(a).to_bool()
}

/// `a < b`.
fn lt<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    nat::sub(a, b).1 == 1
}

fn trailing_zeros<const N: usize>(a: &[u64; N]) -> u32 {
    let mut count = 0;
    for limb in a {
        if *limb == 0 {
            count += 64;
        } else {
            return count + limb.trailing_zeros();
        }
    }
    count
}

fn leading_zeros<const N: usize>(a: &[u64; N]) -> u32 {
    let mut count = 0;
    for limb in a.iter().rev() {
        if *limb == 0 {
            count += 64;
        } else {
            return count + limb.leading_zeros();
        }
    }
    count
}

/// Clears every bit of `a` at position `bits` or above.
fn mask_to_bits<const N: usize>(a: &mut [u64; N], bits: u32) {
    for (i, limb) in a.iter_mut().enumerate() {
        let lo = 64 * i as u32;
        if bits <= lo {
            *limb = 0;
        } else if bits < lo + 64 {
            *limb &= (1u64 << (bits - lo)) - 1;
        }
    }
}

fn shr<const N: usize>(a: &[u64; N], shift: u32) -> [u64; N] {
    let mut out = [0u64; N];
    let limbs = (shift / 64) as usize;
    let bits = shift % 64;
    for i in 0..N.saturating_sub(limbs) {
        let lo = a[i + limbs] >> bits;
        let hi = if bits != 0 && i + limbs + 1 < N { a[i + limbs + 1] << (64 - bits) } else { 0 };
        out[i] = lo | hi;
    }
    out
}

fn shl<const N: usize>(a: &[u64; N], shift: u32) -> [u64; N] {
    let mut out = [0u64; N];
    let limbs = (shift / 64) as usize;
    let bits = shift % 64;
    for i in limbs..N {
        let lo = a[i - limbs] << bits;
        let hi = if bits != 0 && i > limbs { a[i - limbs - 1] >> (64 - bits) } else { 0 };
        out[i] = lo | hi;
    }
    out
}

/// `a - k` for a small `k <= a`.
fn sub_u64<const N: usize>(a: &[u64; N], k: u64) -> [u64; N] {
    let mut k_limbs = [0u64; N];
    k_limbs[0] = k;
    let (diff, borrow) = nat::sub(a, &k_limbs);
    debug_assert_eq!(borrow, 0);
    diff
}

/// `GCD(a, b)` by Stein's binary algorithm; variable time (see the module docs).
fn gcd<const N: usize>(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    if is_zero(a) {
        return *b;
    }
    if is_zero(b) {
        return *a;
    }
    let common_twos = trailing_zeros(a).min(trailing_zeros(b));
    let mut a = shr(a, trailing_zeros(a));
    let mut b = shr(b, trailing_zeros(b));
    loop {
        // Both odd here, so `a - b` is even (or zero); dividing its powers of two out keeps the
        // invariant, and the larger operand strictly shrinks each round.
        if lt(&a, &b) {
            core::mem::swap(&mut a, &mut b);
        }
        let (diff, _) = nat::sub(&a, &b);
        if is_zero(&diff) {
            break;
        }
        a = shr(&diff, trailing_zeros(&diff));
    }
    shl(&b, common_twos)
}

/// `a / d` for `d != 0`, by bit-serial schoolbook long division; variable time (see the module
/// docs). Used once per key pair, for `(q - 1) / GCD(p - 1, q - 1)`.
fn div<const N: usize>(a: &[u64; N], d: &[u64; N]) -> [u64; N] {
    debug_assert!(!is_zero(d));
    let mut rem = [0u64; N];
    let mut quotient = [0u64; N];
    for limb in (0..N).rev() {
        for bit in (0..64).rev() {
            // rem = 2*rem + next bit; rem < d before, so the true value is < 2d and one
            // conditional subtraction restores rem < d. The bit that leaves the top limb is the
            // "carry" case, in which the subtraction is always due.
            let carry = rem[N - 1] >> 63;
            rem = shl(&rem, 1);
            rem[0] |= (a[limb] >> bit) & 1;
            let (diff, borrow) = nat::sub(&rem, d);
            if carry == 1 || borrow == 0 {
                rem = diff;
                quotient[limb] |= 1 << bit;
            }
        }
    }
    quotient
}

/// Fills `out` with `64 * N` bits from `rng` (FIPS 186-5 Appendix B.2.1: the string is read as a
/// big-endian integer; here limb `N - 1` holds its most significant 64 bits).
fn fill_random<const N: usize>(
    rng: &mut dyn RNG,
    out: &mut [u64; N],
) -> Result<(), SignatureError> {
    let mut buf = [0u8; 8];
    for limb in out.iter_mut() {
        rng.next_bytes_out(&mut buf).map_err(SignatureError::RNGError)?;
        *limb = u64::from_be_bytes(buf);
    }
    Ok(())
}

// ---- primality -------------------------------------------------------------------------------

/// Whether some prime below [`SMALL_PRIME_LIMIT`] divides `w` -- other than `w` itself, so a small
/// prime is not reported as its own factor. The primes are bundled into `u64` products and each
/// bundle costs one multi-limb reduction (Appendix B.7's "may be divided by composite numbers").
fn has_small_factor<const N: usize>(w: &[u64; N]) -> bool {
    let fits_u64 = w[1..].iter().all(|&l| l == 0);
    let mut i = 0;
    while i < SMALL_PRIME_COUNT {
        let start = i;
        let mut product: u64 = 1;
        while i < SMALL_PRIME_COUNT {
            match product.checked_mul(u64::from(SMALL_PRIMES[i])) {
                Some(next) => {
                    product = next;
                    i += 1;
                }
                None => break,
            }
        }
        let r = mod_u64(w, product);
        for &p in &SMALL_PRIMES[start..i] {
            let p = u64::from(p);
            if r % p == 0 && !(fits_u64 && w[0] == p) {
                return true;
            }
        }
    }
    false
}

/// FIPS 186-5 Appendix B.3.1, the Miller-Rabin probabilistic primality test, with `rounds`
/// iterations whose bases come from `rng`: `Ok(true)` is PROBABLY PRIME, `Ok(false)` is COMPOSITE.
/// Preceded by trial division against the primes below [`SMALL_PRIME_LIMIT`] (Appendix B.7),
/// which is conclusive on its own for `w < 2^20` and otherwise only ever rejects.
///
/// `rounds` must be at least the value FIPS 186-5 Table B.1 gives for the candidate's length and
/// the caller's target error probability (see each size module's `keygen` for the value it uses);
/// its type rules out zero rounds at compile time. Bases that fall outside `[2, w - 2]` are
/// redrawn (step 4.2); an RNG that cannot produce one in 128 draws is reported as
/// `Err(GenericError)`, so a broken RNG cannot hang the test.
pub fn is_probable_prime<const N: usize, const N2: usize, const N21: usize>(
    w: &[u64; N],
    rounds: NonZeroUsize,
    rng: &mut dyn RNG,
) -> Result<bool, SignatureError> {
    let mut one = [0u64; N];
    one[0] = 1;
    let mut two = [0u64; N];
    two[0] = 2;
    if is_zero(w) || *w == one {
        return Ok(false);
    }
    if w[0] & 1 == 0 {
        return Ok(*w == two);
    }
    let fits_u64 = w[1..].iter().all(|&l| l == 0);
    if fits_u64 && w[0] < (SMALL_PRIME_LIMIT * SMALL_PRIME_LIMIT) as u64 {
        // Appendix B.7: no prime factor up to sqrt(w) means prime.
        return Ok(!has_small_factor(w));
    }
    if has_small_factor(w) {
        return Ok(false);
    }

    // Steps 1-2: w - 1 = 2^a * m with m odd.
    let w_minus_1 = sub_u64(w, 1);
    let a = trailing_zeros(&w_minus_1);
    let m = shr(&w_minus_1, a);
    // w is odd and nonzero here (both checked above), which is all `MontgomeryContext::new`
    // requires, so this cannot fail.
    let ctx = MontgomeryContext::new(w).expect("w is odd and nonzero");

    // Step 3: wlen = len(w), the bit length of w -- the bases are drawn at that length (not the
    // full limb width), so that for a w well short of the width a draw still lands below w - 1
    // with probability at least 1/2.
    let wlen = 64 * N as u32 - leading_zeros(w);

    // Step 4.
    for _ in 0..rounds.get() {
        // Steps 4.1-4.2: a random base b of wlen bits, redrawn unless in [2, w - 2].
        let mut b = [0u64; N];
        let mut drawn = false;
        for _ in 0..128 {
            fill_random(rng, &mut b)?;
            mask_to_bits(&mut b, wlen);
            if lt(&one, &b) && lt(&b, &w_minus_1) {
                drawn = true;
                break;
            }
        }
        if !drawn {
            return Err(SignatureError::GenericError(
                "RNG produced no usable Miller-Rabin base in 128 draws",
            ));
        }
        // Step 4.3.
        let mut z = mod_pow::<N, N2, N21>(&b, &m, &ctx);
        // Step 4.4.
        if z == one || z == w_minus_1 {
            continue;
        }
        // Step 4.5.
        let mut witness = true;
        for _ in 1..a {
            z = mul_mod::<N, N2, N21>(&z, &z, &ctx);
            if z == w_minus_1 {
                witness = false;
                break;
            }
            if z == one {
                break;
            }
        }
        if witness {
            // Step 4.6.
            return Ok(false);
        }
    }
    // Step 5.
    Ok(true)
}

// ---- key pair generation ---------------------------------------------------------------------

/// A candidate for `p` or `q` (FIPS 186-5 Appendix A.1.3 steps 4.2-4.3 / 5.2-5.3): `64 * N`
/// random bits with the two most significant bits set (step 4.2.1's option) and forced odd (step
/// 4.3, "if p is not odd, then p = p + 1"). Setting both top bits makes step 4.4's lower bound
/// `p >= sqrt(2) * 2^(nlen/2 - 1)` hold by construction -- `0.75 * 2^(nlen/2) > 0.7071 *
/// 2^(nlen/2)` -- and makes `n = p * q` exactly `nlen` bits, so the bound is only
/// `debug_assert`ed rather than tested and retried.
fn candidate<const N: usize>(rng: &mut dyn RNG, out: &mut [u64; N]) -> Result<(), SignatureError> {
    fill_random(rng, out)?;
    out[N - 1] |= 0b11 << 62;
    out[0] |= 1;
    // sqrt(2) * 2^63 = 0xB504F333F9DE6484...: with the top two bits set the top limb is at least
    // 0xC000..., so this cannot fail.
    debug_assert!(out[N - 1] > 0xB504_F333_F9DE_6484, "step 4.4's lower bound");
    Ok(())
}

/// FIPS 186-5 Appendix A.1.3 step 4 or 5: repeatedly draws a candidate until one passes
/// `GCD(p - 1, e) = 1` (step 4.5, as `e` not dividing `p - 1`, since `e` is prime), trial
/// division, and `rounds` of Miller-Rabin (step 4.5.1), giving up after `max_attempts` candidates
/// (step 4.7 / 5.8). `extra_check` is step 5.5's `|p - q|` test for `q`, and nothing for `p`.
fn random_prime<const N: usize, const N2: usize, const N21: usize>(
    rng: &mut dyn RNG,
    rounds: NonZeroUsize,
    max_attempts: usize,
    out: &mut [u64; N],
    extra_check: &dyn Fn(&[u64; N]) -> bool,
) -> Result<(), SignatureError> {
    for _ in 0..max_attempts {
        candidate(rng, out)?;
        if !extra_check(out) {
            continue;
        }
        // Step 4.5: GCD(p - 1, e) = 1, i.e. p mod e != 1 for prime e.
        if mod_u64(out, u64::from(PUBLIC_EXPONENT)) == 1 {
            continue;
        }
        if is_probable_prime::<N, N2, N21>(out, rounds, rng)? {
            return Ok(());
        }
    }
    // Step 4.7 / 5.8: FAILURE. Zero the last candidate before reporting, as the spec's zero
    // outputs do.
    *out = [0u64; N];
    Err(SignatureError::GenericError(
        "RSA key generation exhausted FIPS 186-5 A.1.3's candidate limit without finding a prime",
    ))
}

/// Step 5.5: `|p - q| <= 2^(nlen/2 - 100)` rejects `q` (Appendix A.1.1 criterion 2(d) asks for
/// `|p - q| > 2^(nlen/2 - 100)`). `nlen/2 = 64 * N` here.
fn primes_too_close<const N: usize>(p: &[u64; N], q: &[u64; N]) -> bool {
    let (d1, borrow) = nat::sub(q, p);
    let (d2, _) = nat::sub(p, q);
    let diff = if borrow == 1 { d2 } else { d1 };
    let threshold_bit = 64 * N as u32 - 100;
    let high = shr(&diff, threshold_bit);
    if is_zero(&high) {
        return true; // |p - q| < 2^(nlen/2 - 100)
    }
    let mut one = [0u64; N];
    one[0] = 1;
    // Exactly 2^(nlen/2 - 100) is also "<=": the high part is 1 and nothing is set below it.
    high == one && diff == shl(&one, threshold_bit)
}

/// FIPS 186-5 Appendix A.1.3, the whole process, for a modulus of `HALF2` limbs (`nlen = 64 *
/// HALF2` bits) built from two `HALF`-limb primes. `rounds` is the Miller-Rabin iteration count
/// (Table B.1) and `required_strength` the security strength SP 800-57 Part 1 associates with
/// `nlen`, which the RNG must meet (step 3 and the paragraph above the process). The size modules
/// fix all three; see `crate::rsa_2048::keygen_from_rng` for the RSA-2048 values.
///
/// Returns the pair as this crate's key types: `(n, e)` and the CRT quintuple, with `dP = e^-1 mod
/// (p - 1)`, `dQ = e^-1 mod (q - 1)` (which equal `d mod (p - 1)` and `d mod (q - 1)` for the
/// `d = e^-1 mod LCM(p - 1, q - 1)` of Appendix A.1.1 criterion 3(b)) and `qInv = q^-1 mod p`.
/// Criterion 3(a), `d > 2^(nlen/2)`, is checked on that `d` and the whole process restarts if it
/// fails -- "the extremely rare event" the spec describes, of probability about `2^-(nlen/2)`.
///
/// Errors: `RNGError(SecurityStrengthInsufficientForAlgorithm)` if `rng` is weaker than
/// `required_strength`; `RNGError` for an RNG failure; `GenericError` if the candidate limits of
/// steps 4.7/5.8 (`5 * nlen` for `p`, `10 * nlen` for `q`) are exhausted, which a working RNG
/// does not do.
pub fn keygen_from_rng<const HALF: usize, const HALF2: usize, const HALF21: usize>(
    rng: &mut dyn RNG,
    rounds: NonZeroUsize,
    required_strength: SecurityStrength,
) -> Result<(RsaPublicKey<HALF2>, RsaPrivateKey<HALF2, HALF>), SignatureError> {
    debug_assert_eq!(HALF2, 2 * HALF);
    // Step 3 (and A.1.3's preamble): the DRBG's strength must meet the modulus's.
    if rng.security_strength() < required_strength {
        return Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm));
    }
    let nlen = 64 * HALF2;

    loop {
        // Held in `Secret` so the primes and everything derived from them are scrubbed when this
        // function returns (or restarts), not left on the stack.
        let mut p = Secret::<[u64; HALF]>::new();
        let mut q = Secret::<[u64; HALF]>::new();

        // Step 4: generate p (up to 5 * nlen candidates).
        random_prime::<HALF, HALF2, HALF21>(rng, rounds, 5 * nlen, &mut p, &|_| true)?;
        // Step 5: generate q (up to 10 * nlen candidates), rejecting one too close to p (5.5).
        {
            let p_ref: &[u64; HALF] = &p;
            random_prime::<HALF, HALF2, HALF21>(rng, rounds, 10 * nlen, &mut q, &|cand| {
                !primes_too_close(p_ref, cand)
            })?;
        }

        // Appendix A.1.1 criterion 3: d = e^-1 mod LCM(p - 1, q - 1) must exceed 2^(nlen/2).
        let mut p_minus_1 = Secret::<[u64; HALF]>::new();
        *p_minus_1 = sub_u64(&p, 1);
        let mut q_minus_1 = Secret::<[u64; HALF]>::new();
        *q_minus_1 = sub_u64(&q, 1);
        let mut lcm = Secret::<[u64; HALF2]>::new();
        {
            let g = gcd(&p_minus_1, &q_minus_1);
            let q_minus_1_over_g = div(&q_minus_1, &g);
            *lcm = montgomery::widening_mul::<HALF, HALF2>(&p_minus_1, &q_minus_1_over_g);
        }
        let mut d = Secret::<[u64; HALF2]>::new();
        *d = inverse_of_e_mod(&lcm);
        let d_high = &d[HALF..];
        let d_low = &d[..HALF];
        let mut one_high = [0u64; HALF];
        one_high[0] = 1;
        let d_exceeds_half = d_high.iter().any(|&l| l != 0)
            && !(d_high == one_high && d_low.iter().all(|&l| l == 0));
        if !d_exceeds_half {
            // "then new values for p, q, and d shall be determined."
            continue;
        }

        // The CRT quintuple (RFC 8017 §3.2). dP and dQ are the same inverse taken modulo p - 1
        // and q - 1 directly, which is what `d mod (p - 1)` and `d mod (q - 1)` come to.
        let mut d_p = Secret::<[u64; HALF]>::new();
        *d_p = inverse_of_e_mod(&p_minus_1);
        let mut d_q = Secret::<[u64; HALF]>::new();
        *d_q = inverse_of_e_mod(&q_minus_1);
        // qInv = q^-1 mod p = q^(p - 2) mod p (Fermat; p is prime and does not divide q), through
        // the constant-time ladder with p - 2 as the exponent.
        let mut q_inv = Secret::<[u64; HALF]>::new();
        {
            let q_mod_p = reduce_wide::<HALF, HALF>(&q, &p);
            let p_minus_2 = sub_u64(&p, 2);
            // p is odd by construction (step 4.3), so the context exists.
            let ctx_p = MontgomeryContext::new(&p).expect("p is odd");
            *q_inv = mod_pow::<HALF, HALF2, HALF21>(&q_mod_p, &p_minus_2, &ctx_p);
        }

        let sk = RsaPrivateKey::<HALF2, HALF>::from_crt_components(&p, &q, &d_p, &d_q, &q_inv)?;
        let pk = RsaPublicKey::<HALF2>::new(sk.n(), PUBLIC_EXPONENT)?;
        return Ok((pk, sk));
    }
}
