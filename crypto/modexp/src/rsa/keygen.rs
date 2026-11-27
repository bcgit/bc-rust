//! RSA key pair generation: FIPS 186-5 Appendix A.1.3, "Generation of Random Primes that are
//! Probably Prime", with Appendix B.3.1's Miller-Rabin test (behind Appendix B.7-style trial
//! division) and Appendix A.1.1's criteria on `e`, `p`, `q` and `d`, over this module's fixed-width
//! limb arithmetic -- there is no arbitrary-precision integer type here, as in the rest of the
//! module. Structured after BC Java's `org.bouncycastle.crypto.generators.RSAKeyPairGenerator`
//! (its candidate loop, small-factor sieve and `d` lower-bound check are what this follows), with
//! FIPS 186-5 as the reference for every step and cited inline.
//!
//! The sizes wire this up as `RsaSigningSize::keygen`, which the size markers' generators wrap:
//! `nlen` is fixed by the width, `e` by
//! [`PUBLIC_EXPONENT`], the Miller-Rabin round count by `RsaSigningSize::MR_ROUNDS` and the required
//! RNG strength by each size's row of SP 800-57 Part 1 Table 2.
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
//! goes through [`crate::rsa::modexp::mod_pow`]'s constant-time ladder, the same one every signature
//! uses; and the `MontgomeryContext` built over each candidate is the constant-time construction
//! `rsa_core::rsasp1` builds over the secret primes on every signature.

use crate::rsa::keys::{RsaPrivateComponents, RsaPublicComponents};
use crate::rsa::modexp::{MontgomeryContext, check_widths, mod_pow, mul_mod, reduce_wide};
use crate::rsa::size::{RsaSigningSize, RsaSize};
use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::montgomery;
use bouncycastle_utils::nat;
use bouncycastle_utils::secret::{Secret, zeroize_in_place};
use bouncycastle_utils::stack_wipe::{WipeStackBelowScaledOnDrop, wipe_stack_below_scaled};
use core::num::NonZeroUsize;

/// The public exponent every key pair this module generates uses: `F4 = 2^16 + 1 = 65537`.
/// FIPS 186-5 Appendix A.1.1 criterion 1 asks for an odd `e` with `2^16 < e < 2^256`, "selected
/// prior to generating the primes"; this is the smallest such value and the near-universal choice
/// (it is what Wycheproof's and BC Java's test keys use). Its primality is what lets criterion
/// 2(a), `GCD(p - 1, e) = 1`, be checked as "`e` does not divide `p - 1`" (step 4.5 below).
pub const PUBLIC_EXPONENT: u64 = 65537;

/// Trial-division bound: every prime below this is divided out of a candidate before the
/// Miller-Rabin test runs (FIPS 186-5 Appendix B.7, "if convenient, `c` may be divided by
/// composite numbers" -- the primes are bundled into `u64` products, as BC Java's
/// `Primes.hasAnySmallFactors` does). `2^10` is a round choice well inside Appendix B.8's
/// "typical" `10^3` to `10^5`; about 84% of odd candidates are caught here (the share of odd
/// integers with an odd prime factor below 1024, one minus the product of `1 - 1/p` over those
/// 171 primes, is 0.8387), sparing that many modular exponentiations.
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

/// `r^-1 mod e` for `0 < r < e` with `GCD(r, e) = 1`, by the extended Euclidean algorithm of
/// FIPS 186-5 Appendix B.1 on single words.
fn inv_mod_u64(r: u64, e: u64) -> u64 {
    debug_assert!(r != 0 && r < e);
    // Invariant: t0 * r == r0 and t1 * r == r1 (mod e), with |t0|, |t1| <= e.
    let (mut r0, mut r1) = (i128::from(e), i128::from(r));
    let (mut t0, mut t1) = (0i128, 1i128);
    while r1 != 0 {
        let quotient = r0 / r1;
        (r0, r1) = (r1, r0 - quotient * r1);
        (t0, t1) = (t1, t0 - quotient * t1);
    }
    debug_assert_eq!(r0, 1, "r and e must be coprime");
    t0.rem_euclid(i128::from(e)) as u64
}

/// `e^-1 mod m` for `m > 1` and an `e > 1` with `GCD(m, e) = 1`.
///
/// FIPS 186-5 Appendix B.1 gives the extended Euclidean algorithm for reference and allows
/// "other algorithms that produce an equivalent result". Because `e` is one word, the
/// inverse comes without a multi-limb division: with `r = m mod e` and `k = -r^-1 mod e` (so
/// `k*m + 1 ≡ 0 mod e`), `d = (k*m + 1) / e` is an exact integer with `e*d = 1 + k*m ≡ 1 mod m`,
/// and `0 < d < m` since `0 < k < e`. The only multi-limb operations are one multiply by `k` and
/// one exact division by `e`.
fn inverse_of_e_mod<const N: usize>(m: &[u64; N], e: u64) -> [u64; N] {
    let r = mod_u64(m, e);
    // `GCD(m, e) = 1` is the caller's invariant. `keygen` discards any `p` (or `q`) with
    // `e | p - 1` at step 4.5, and `LCM(p - 1, q - 1)` then cannot be divisible by `e` either;
    // a key's constructor has checked that `e` has an inverse modulo `p - 1` and `q - 1`.
    debug_assert_ne!(r, 0, "e must not divide m");
    let k = e - inv_mod_u64(r, e);
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
            // rem = 2*rem + next bit; rem < d before, so the new value is < 2d and one
            // conditional subtraction restores rem < d. rem never exceeds the bits of `a` read
            // so far, which before the last bit are at most a >> 1 < 2^(64N-1), so the shift
            // cannot carry out of the top limb.
            debug_assert!(rem[N - 1] >> 63 == 0);
            rem = shl(&rem, 1);
            rem[0] |= (a[limb] >> bit) & 1;
            let (diff, borrow) = nat::sub(&rem, d);
            if borrow == 0 {
                rem = diff;
                quotient[limb] |= 1 << bit;
            }
        }
    }
    quotient
}

/// Fills the whole of `out` from `rng`, for every draw this module makes. `RNG::next_bytes_out`
/// returns the number of bytes it wrote, and a count short of the buffer is the RNG failing to
/// deliver: an error, as its own error is, with `out` wiped either way, since what it holds
/// then is part of a prime candidate, a salt, a seed or a key.
pub(in crate::rsa) fn fill_bytes(rng: &mut dyn RNG, out: &mut [u8]) -> Result<(), RNGError> {
    let result = match rng.next_bytes_out(out) {
        Ok(written) if written == out.len() => return Ok(()),
        Ok(_) => Err(RNGError::GenericError("the RNG wrote fewer bytes than it was asked for")),
        Err(e) => Err(e),
    };
    for byte in out.iter_mut() {
        zeroize_in_place(byte);
    }
    result
}

/// Fills `out` with `64 * N` bits from `rng`, eight bytes to a limb in the order drawn: the
/// first eight bytes are limb 0, the least significant, and each eight are big-endian within
/// their limb. FIPS 186-5 Appendix B.2.1 reads a bit string most significant bit first, so the
/// integer here is that reading of the string drawn with its eight-byte groups in reverse
/// order. It is as uniform; a candidate reproduced from a given byte stream needs this order.
fn fill_random<const N: usize>(
    rng: &mut dyn RNG,
    out: &mut [u64; N],
) -> Result<(), SignatureError> {
    let mut buf = [0u8; 8];
    for limb in out.iter_mut() {
        fill_bytes(rng, &mut buf).map_err(SignatureError::RNGError)?;
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
/// For a candidate drawn at random, `rounds` must be at least the value FIPS 186-5 Table B.1
/// gives for its length and the caller's target error probability. For a number from
/// elsewhere only the bound that holds of every composite applies, `4^-rounds`; a key's primes
/// are tested at that bound by `RsaPrivateComponents::validate`. The type rules out zero
/// rounds at compile time. Bases that fall outside `[2, w - 2]` are
/// redrawn (step 4.2); an RNG that cannot produce one in 128 draws is reported as
/// `Err(GenericError)`, so a broken RNG cannot hang the test.
///
/// `N2` is `2 * N` and `N21` is `2 * N + 1`, checked when the function is instantiated:
///
/// ```compile_fail,E0080
/// use bouncycastle_rng::DefaultRNG;
/// use bouncycastle_modexp::rsa::keygen::is_probable_prime;
/// use core::num::NonZeroUsize;
/// let rounds = NonZeroUsize::new(5).unwrap();
/// let _ = is_probable_prime::<2, 4, 6>(&[0xffffffffffffffc5, 0], rounds, &mut DefaultRNG::default());
/// ```
///
/// ```
/// use bouncycastle_rng::DefaultRNG;
/// use bouncycastle_modexp::rsa::keygen::is_probable_prime;
/// use core::num::NonZeroUsize;
/// let rounds = NonZeroUsize::new(5).unwrap();
/// // 2^64 - 59 is the largest prime below 2^64.
/// let prime = is_probable_prime::<2, 4, 5>(&[0xffffffffffffffc5, 0], rounds, &mut DefaultRNG::default());
/// assert_eq!(prime, Ok(true));
/// ```
pub fn is_probable_prime<const N: usize, const N2: usize, const N21: usize>(
    w: &[u64; N],
    rounds: NonZeroUsize,
    rng: &mut dyn RNG,
) -> Result<bool, SignatureError> {
    const { check_widths::<N, N2, N21>() };
    let verdict = is_probable_prime_in_own_frame::<N, N2, N21>(w, rounds, rng);
    // `w` may be a prime of a private key: the context over it and the powers of the bases
    // pass through frames that no `Secret` names, as in the CRT.
    wipe_stack_below_scaled::<[u64; N], PRIMALITY_STACK_PER_LIMB, PRIMALITY_STACK_FIXED>();
    verdict
}

/// What `wipe_stack_below_scaled` overwrites after [`is_probable_prime`]: this many `[u64; N]` values
/// and this many words. Measured in x86-64 release builds (rustc 1.88 and 1.97) with the
/// workspace's hash DRBG as the RNG, the test uses 4600 bytes at 16 limbs (a prime of RSA-2048),
/// 6488 at 24, 8328 at 32 and 13768 at 64; these cover 5504, 7552, 9600 and 17792, the
/// difference being room for a compiler that lays the frames out less tightly.
const PRIMALITY_STACK_PER_LIMB: usize = 32;
const PRIMALITY_STACK_FIXED: usize = 176;

/// [`is_probable_prime`] for a caller that wipes: key generation, whose own frame covers every
/// test it makes. Never inlined, so that what the test leaves lies below its caller's frame.
#[inline(never)]
fn is_probable_prime_in_own_frame<const N: usize, const N2: usize, const N21: usize>(
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

    // Steps 1-2: w - 1 = 2^a * m with m odd. `w` is a candidate for a private prime, so these
    // and the context over `w` are held in `Secret`, scrubbed on each of this function's exits.
    let mut w_minus_1 = Secret::<[u64; N]>::new();
    *w_minus_1 = sub_u64(w, 1);
    let a = trailing_zeros(&w_minus_1);
    let mut m = Secret::<[u64; N]>::new();
    *m = shr(&w_minus_1, a);
    // w is odd and greater than 1 here (checked above), as the constructor requires.
    let mut ctx = Secret::<MontgomeryContext<N>>::new();
    *ctx = MontgomeryContext::for_secret_modulus(w);

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
        let mut z = Secret::<[u64; N]>::new();
        *z = mod_pow::<N, N2, N21>(&b, &m, &ctx);
        // Step 4.4.
        if *z == one || *z == *w_minus_1 {
            continue;
        }
        // Step 4.5.
        let mut witness = true;
        for _ in 1..a {
            *z = mul_mod::<N, N2, N21>(&z, &z, &ctx);
            if *z == *w_minus_1 {
                witness = false;
                break;
            }
            if *z == one {
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
        if mod_u64(out, PUBLIC_EXPONENT) == 1 {
            continue;
        }
        if is_probable_prime_in_own_frame::<N, N2, N21>(out, rounds, rng)? {
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
    let (mut d1, borrow) = nat::sub(q, p);
    let (mut d2, _) = nat::sub(p, q);
    let mut diff = if borrow == 1 { d2 } else { d1 };
    let threshold_bit = 64 * N as u32 - 100;
    let mut high = shr(&diff, threshold_bit);
    let mut one = [0u64; N];
    one[0] = 1;
    // `|p - q| < 2^(nlen/2 - 100)`, or exactly `2^(nlen/2 - 100)`, which is also "<=": the high
    // part is 1 and nothing is set below it.
    let too_close = is_zero(&high) || (high == one && diff == shl(&one, threshold_bit));
    // The differences are functions of both primes: scrubbed before returning.
    zeroize_in_place(&mut d1);
    zeroize_in_place(&mut d2);
    zeroize_in_place(&mut diff);
    zeroize_in_place(&mut high);
    too_close
}

/// FIPS 186-5 Appendix A.1.1 criterion 3(a) on the `d` of criterion 3(b): whether
/// `d = e^-1 mod LCM(p - 1, q - 1)` exceeds `2^(nlen/2)`, `nlen/2` being `64 * HALF`. `e` has an
/// inverse modulo `p - 1` and modulo `q - 1`, which is the caller's to have established.
fn private_exponent_exceeds_half<const HALF: usize, const HALF2: usize>(
    p_minus_1: &[u64; HALF],
    q_minus_1: &[u64; HALF],
    e: u64,
) -> bool {
    let mut lcm = Secret::<[u64; HALF2]>::new();
    {
        let mut g = gcd(p_minus_1, q_minus_1);
        let mut q_minus_1_over_g = div(q_minus_1, &g);
        *lcm = montgomery::widening_mul::<HALF, HALF2>(p_minus_1, &q_minus_1_over_g);
        zeroize_in_place(&mut g);
        zeroize_in_place(&mut q_minus_1_over_g);
    }
    let mut d = Secret::<[u64; HALF2]>::new();
    *d = inverse_of_e_mod(&lcm, e);
    let d_high = &d[HALF..];
    let d_low = &d[..HALF];
    let mut one_high = [0u64; HALF];
    one_high[0] = 1;
    d_high.iter().any(|&l| l != 0) && !(d_high == one_high && d_low.iter().all(|&l| l == 0))
}

/// Whether `x >= sqrt(2) * 2^(64 * HALF - 1)`, the lower bound FIPS 186-5 Appendix A.1.1
/// criteria 2(b) and 2(c) put on a prime of `64 * HALF` bits. `sqrt(2) * 2^k` is not an
/// integer, so this is `x^2 >= 2^(128 * HALF - 1)`: the square's top bit.
fn at_least_sqrt2_scaled<const HALF: usize, const HALF2: usize>(x: &[u64; HALF]) -> bool {
    let mut square = montgomery::widening_square::<HALF, HALF2>(x);
    let top_bit_set = square[HALF2 - 1] >> 63 == 1;
    zeroize_in_place(&mut square);
    top_bit_set
}

/// SP 800-56B Rev. 2 §6.4.1.4.3, `crt_pkv`: validation of a key pair held in the CRT form,
/// whichever way its public exponent was chosen. The steps are §6.4.1.2.1's with that
/// section's replacements, and the ones not computed here hold of every
/// [`RsaPrivateComponents`]: its constructor has checked them, or the type cannot hold a key
/// that fails them. `HALF2` is `2 * HALF` and `HALF21` is `2 * HALF + 1`.
///
/// Not constant time in the key, as key generation is not: the same primality test, GCD and
/// division run over `p` and `q`.
pub(in crate::rsa) fn validate_key_pair<
    K,
    const HALF: usize,
    const HALF2: usize,
    const HALF21: usize,
>(
    sk: &RsaPrivateComponents<K>,
    rng: &mut dyn RNG,
) -> Result<(), SignatureError>
where
    K: RsaSigningSize + RsaSize<HalfLimbs = [u64; HALF], Limbs = [u64; HALF2]>,
{
    const { check_widths::<HALF, HALF2, HALF21>() };
    let verdict = validate_key_pair_in_own_frame::<K, HALF, HALF2, HALF21>(sk, rng);
    // Key generation's wipe: validation makes the same computations over the primes, less
    // the search, and measured 5344, 7304, 9656 and 16392 bytes at the four sizes.
    wipe_stack_below_scaled::<[u64; HALF2], KEYGEN_STACK_PER_LIMB, KEYGEN_STACK_FIXED>();
    verdict
}

/// The work of [`validate_key_pair`]. Never inlined, so that what it leaves lies below its
/// caller's frame, where `wipe_stack_below_scaled` reaches it.
#[inline(never)]
fn validate_key_pair_in_own_frame<K, const HALF: usize, const HALF2: usize, const HALF21: usize>(
    sk: &RsaPrivateComponents<K>,
    rng: &mut dyn RNG,
) -> Result<(), SignatureError>
where
    K: RsaSigningSize + RsaSize<HalfLimbs = [u64; HALF], Limbs = [u64; HALF2]>,
{
    // The Miller-Rabin bases of step 5 come from the RNG (FIPS 186-5 Appendix B.3.1, "an
    // approved deterministic random bit generator"), held to the strength key generation
    // asks of it.
    if rng.security_strength() < K::STRENGTH {
        return Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm));
    }
    // Step 1.a, 1.b: the targeted strength is the size's, which is at least 112 bits.
    // Step 1.c: "If epub is not an odd integer such that 65,537 <= epub < 2^256". Odd by the
    // key's constructor, and below 2^64 by its type.
    if sk.e() < 65_537 {
        return Err(SignatureError::DecodingError("the public exponent is below 65537"));
    }
    // Step 3: n = p * q of exactly nBits bits, by the key's constructor.
    let (p, q) = (sk.p(), sk.q());
    // Step 5.a, 5.b: sqrt(2) * 2^(nBits/2 - 1) <= p, q <= 2^(nBits/2) - 1. The upper bound is
    // the width of a prime.
    if !at_least_sqrt2_scaled::<HALF, HALF2>(p) || !at_least_sqrt2_scaled::<HALF, HALF2>(q) {
        return Err(SignatureError::DecodingError(
            "a prime factor is below sqrt(2) * 2^(nBits/2 - 1)",
        ));
    }
    // Step 5.c: "If |p - q| <= 2^(nBits/2 - 100)".
    if primes_too_close(p, q) {
        return Err(SignatureError::DecodingError("the prime factors are too close together"));
    }
    // Step 5.d, 5.e: GCD(p - 1, e) = GCD(q - 1, e) = 1, since e has the inverses dP and dQ
    // modulo p - 1 and q - 1 (step 7.d, 7.e, checked by the key's constructor).
    // Step 5.f, 5.g: "The probability that p or q may be incorrectly classified as prime by
    // the test used in step 5 shall be less than or equal to 2^-ES(nBits)". The key is someone
    // else's, so the bound is the one that holds of every composite: at most 1/4 of the bases
    // pass one, and ES(nBits) / 2 rounds give 4^-(ES/2).
    let rounds = K::VALIDATION_MR_ROUNDS;
    if !is_probable_prime_in_own_frame::<HALF, HALF2, HALF21>(p, rounds, rng)?
        || !is_probable_prime_in_own_frame::<HALF, HALF2, HALF21>(q, rounds, rng)?
    {
        return Err(SignatureError::DecodingError("a prime factor is composite"));
    }
    // Step 6: 2^(nBits/2) < d < LCM(p - 1, q - 1) and 1 = (d * e) mod LCM(p - 1, q - 1). The
    // key holds no d: it is the inverse 6.b defines, which is below the LCM, so 6.a's lower
    // bound is what is left.
    let mut p_minus_1 = Secret::<[u64; HALF]>::new();
    *p_minus_1 = sub_u64(p, 1);
    let mut q_minus_1 = Secret::<[u64; HALF]>::new();
    *q_minus_1 = sub_u64(q, 1);
    if !private_exponent_exceeds_half::<HALF, HALF2>(&p_minus_1, &q_minus_1, sk.e()) {
        return Err(SignatureError::DecodingError("the private exponent is not above 2^(nBits/2)"));
    }
    // Step 7: the CRT components, by the key's constructor.
    Ok(())
}

/// FIPS 186-5 Appendix A.1.3, the whole process, for a modulus of `HALF2` limbs (`nlen = 64 *
/// HALF2` bits) built from two `HALF`-limb primes. `rounds` is the Miller-Rabin iteration count
/// (at least Table B.1's) and `required_strength` the security strength SP 800-57 Part 1 associates with
/// `nlen`, which the RNG must meet (step 3 and the paragraph above the process). The size modules
/// fix all three; see `RSA2048`'s `RsaSigningSize` impl for the RSA-2048 values.
///
/// Returns the pair as this module's key types: `(n, e)` and the CRT quintuple, with `dP = e^-1 mod
/// (p - 1)`, `dQ = e^-1 mod (q - 1)` (which equal `d mod (p - 1)` and `d mod (q - 1)` for the
/// `d = e^-1 mod LCM(p - 1, q - 1)` of Appendix A.1.1 criterion 3(b)) and `qInv = q^-1 mod p`.
/// Criterion 3(a), `d > 2^(nlen/2)`, is checked on that `d` and the whole process restarts if it
/// fails -- "the extremely rare event" the spec describes, of probability about `2^-(nlen/2)`.
///
/// Errors: `RNGError(SecurityStrengthInsufficientForAlgorithm)` if `rng` is weaker than
/// `required_strength`; `RNGError` for an RNG failure; `GenericError` if the candidate limits of
/// steps 4.7/5.8 (`5 * nlen` for `p`, `10 * nlen` for `q`) are exhausted, which a working RNG
/// does not do.
///
/// `HALF2` is `2 * HALF` and `HALF21` is `2 * HALF + 1`, checked when the function is
/// instantiated:
///
/// ```compile_fail,E0080
/// use bouncycastle_rng::DefaultRNG;
/// use bouncycastle_modexp::rsa::RSA2048;
/// use bouncycastle_modexp::rsa::keygen::keygen_from_rng;
/// use bouncycastle_modexp::rsa::size::{RsaSigningSize, RsaSize};
/// let _ = keygen_from_rng::<RSA2048, 16, 32, 32>(
///     &mut DefaultRNG::default(),
///     RSA2048::MR_ROUNDS,
///     RSA2048::STRENGTH,
/// );
/// ```
///
/// ```no_run
/// use bouncycastle_rng::DefaultRNG;
/// use bouncycastle_modexp::rsa::RSA2048;
/// use bouncycastle_modexp::rsa::keygen::keygen_from_rng;
/// use bouncycastle_modexp::rsa::size::{RsaSigningSize, RsaSize};
/// let _ = keygen_from_rng::<RSA2048, 16, 32, 33>(
///     &mut DefaultRNG::default(),
///     RSA2048::MR_ROUNDS,
///     RSA2048::STRENGTH,
/// );
/// ```
pub fn keygen_from_rng<K, const HALF: usize, const HALF2: usize, const HALF21: usize>(
    rng: &mut dyn RNG,
    rounds: NonZeroUsize,
    required_strength: SecurityStrength,
) -> Result<(RsaPublicComponents<K>, RsaPrivateComponents<K>), SignatureError>
where
    K: RsaSigningSize + RsaSize<HalfLimbs = [u64; HALF], Limbs = [u64; HALF2]>,
{
    const { check_widths::<HALF, HALF2, HALF21>() };
    // The primes, the exponents and what is derived from them pass through locals, return
    // slots and the frames of the primality test that no `Secret` names.
    let _wipe =
        WipeStackBelowScaledOnDrop::<[u64; HALF2], KEYGEN_STACK_PER_LIMB, KEYGEN_STACK_FIXED>::new(
        );
    keygen_in_own_frame::<K, HALF, HALF2, HALF21>(rng, rounds, required_strength)
}

/// [`RsaSigningSize::keygen`]'s pair handed to `finish`, which makes of it what the caller
/// returns: keys for a scheme, key-establishment keys. `finish` runs inside a frame that is
/// wiped, so a caller that ends with this call stages no copy of the new key in a frame of its
/// own, as with `RsaPrivateComponents::from_crt_components_as`.
pub(in crate::rsa) fn keygen_as<K: RsaSigningSize, T, E>(
    rng: &mut dyn RNG,
    finish: impl FnOnce(
        Result<(RsaPublicComponents<K>, RsaPrivateComponents<K>), SignatureError>,
    ) -> Result<T, E>,
) -> Result<T, E> {
    let _wipe =
        WipeStackBelowScaledOnDrop::<K::Limbs, KEYGEN_STACK_PER_LIMB, KEYGEN_STACK_FIXED>::new();
    keygen_as_in_own_frame::<K, T, E>(rng, finish)
}

/// The work of [`keygen_as`]. Never inlined, so that what it leaves lies below its caller's
/// frame, where `wipe_stack_below_scaled` reaches it.
#[inline(never)]
fn keygen_as_in_own_frame<K: RsaSigningSize, T, E>(
    rng: &mut dyn RNG,
    finish: impl FnOnce(
        Result<(RsaPublicComponents<K>, RsaPrivateComponents<K>), SignatureError>,
    ) -> Result<T, E>,
) -> Result<T, E> {
    finish(K::keygen(rng))
}

/// What `wipe_stack_below_scaled` overwrites after key generation: this many `[u64; HALF2]` values
/// and this many words. Measured in x86-64 release builds (rustc 1.88 and 1.97), key
/// generation uses 11480 bytes at RSA-2048, 16600 at RSA-3072, 21976 at RSA-4096 and 41144 at
/// RSA-8192; these cover 13568, 19328, 25088 and 48128, the difference being room for a
/// compiler that lays the frames out less tightly.
const KEYGEN_STACK_PER_LIMB: usize = 45;
const KEYGEN_STACK_FIXED: usize = 256;

/// The work of [`keygen_from_rng`]. Never inlined, so that what it leaves lies below its
/// caller's frame, where `wipe_stack_below_scaled` reaches it.
#[inline(never)]
fn keygen_in_own_frame<K, const HALF: usize, const HALF2: usize, const HALF21: usize>(
    rng: &mut dyn RNG,
    rounds: NonZeroUsize,
    required_strength: SecurityStrength,
) -> Result<(RsaPublicComponents<K>, RsaPrivateComponents<K>), SignatureError>
where
    K: RsaSigningSize + RsaSize<HalfLimbs = [u64; HALF], Limbs = [u64; HALF2]>,
{
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
        if !private_exponent_exceeds_half::<HALF, HALF2>(&p_minus_1, &q_minus_1, PUBLIC_EXPONENT) {
            // "then new values for p, q, and d shall be determined."
            continue;
        }

        // The CRT quintuple (RFC 8017 §3.2). dP and dQ are the same inverse taken modulo p - 1
        // and q - 1 directly, which is what `d mod (p - 1)` and `d mod (q - 1)` come to.
        let mut d_p = Secret::<[u64; HALF]>::new();
        *d_p = inverse_of_e_mod(&p_minus_1, PUBLIC_EXPONENT);
        let mut d_q = Secret::<[u64; HALF]>::new();
        *d_q = inverse_of_e_mod(&q_minus_1, PUBLIC_EXPONENT);
        // qInv = q^-1 mod p = q^(p - 2) mod p (Fermat; p is prime and does not divide q), through
        // the constant-time ladder with p - 2 as the exponent.
        let mut q_inv = Secret::<[u64; HALF]>::new();
        {
            let mut q_mod_p = reduce_wide::<HALF, HALF>(&q, &p);
            let mut p_minus_2 = sub_u64(&p, 2);
            // p is odd by construction (step 4.3), as the constructor requires.
            let mut ctx_p = Secret::<MontgomeryContext<HALF>>::new();
            *ctx_p = MontgomeryContext::for_secret_modulus(&p);
            *q_inv = mod_pow::<HALF, HALF2, HALF21>(&q_mod_p, &p_minus_2, &ctx_p);
            zeroize_in_place(&mut q_mod_p);
            zeroize_in_place(&mut p_minus_2);
        }

        let sk = RsaPrivateComponents::<K>::from_crt_components(
            &p, &q, &d_p, &d_q, &q_inv, PUBLIC_EXPONENT,
        )?;
        let pk = RsaPublicComponents::<K>::new(sk.n(), PUBLIC_EXPONENT)?;
        return Ok((pk, sk));
    }
}

// `primes_too_close` is private and, through `keygen_from_rng`, only ever reached on two
// independently drawn `nlen/2`-bit primes, which land within `2^(nlen/2 - 100)` of each other with
// probability about `2^-100`: no integration test through the public API can exercise its reject
// path or pin its boundary, so the QUALITY_AND_STYLE.md private-function, known-answer exception
// applies. Known answers at `N = 2` (`threshold_bit = 28`): a difference below `2^28`, or exactly
// `2^28`, is too close (Appendix A.1.1 criterion 2(d) is `|p - q| > 2^(nlen/2 - 100)`, so equality
// fails it); `2^28 + 1` and above is not; and the order of `p` and `q` does not matter.
//
// `fill_bytes`'s wipe of a buffer the RNG did not fill is likewise invisible from outside: every
// caller's buffer is a local that an error discards.
//
// `gcd`, `div` and `private_exponent_exceeds_half` reach the outside only as criterion 3(a)'s
// verdict, which hides most errors in them: a wrong LCM leaves `d` above `2^(nlen/2)` for nearly
// every key, a shared power of two of 64 or more needs `p = q = 1 (mod 2^64)`, and
// `d = 2^(nlen/2)` exactly cannot be constructed at a real size. Known answers at small widths
// (Python 3.12, sympy for the factorisations) pin them.
#[cfg(test)]
mod tests {
    use super::*;
    use bouncycastle_core::key_material::KeyMaterialTrait;

    /// An RNG that writes `written` bytes of `0xA5` and returns `result`.
    struct Writes {
        written: usize,
        result: Result<usize, RNGError>,
    }

    impl RNG for Writes {
        fn add_seed_keymaterial(&mut self, _: &dyn KeyMaterialTrait) -> Result<(), RNGError> {
            Err(RNGError::GenericError("not used"))
        }
        fn next_int(&mut self) -> Result<u32, RNGError> {
            Err(RNGError::GenericError("not used"))
        }
        fn next_bytes_out(&mut self, out: &mut [u8]) -> Result<usize, RNGError> {
            out[..self.written].fill(0xA5);
            match &self.result {
                Ok(count) => Ok(*count),
                Err(_) => Err(RNGError::ReseedRequired),
            }
        }
        fn fill_keymaterial_out(
            &mut self,
            _: &mut dyn KeyMaterialTrait,
        ) -> Result<usize, RNGError> {
            Err(RNGError::GenericError("not used"))
        }
        fn security_strength(&self) -> SecurityStrength {
            SecurityStrength::_256bit
        }
    }

    #[test]
    fn fill_bytes_takes_a_full_draw_and_wipes_any_other() {
        let mut out = [0u8; 8];
        assert_eq!(fill_bytes(&mut Writes { written: 8, result: Ok(8) }, &mut out), Ok(()));
        assert_eq!(out, [0xA5; 8]);

        let short = Err(RNGError::GenericError("the RNG wrote fewer bytes than it was asked for"));
        // One byte short, by the count; and a count that is not the length at all.
        for (written, count) in [(7, 7), (4, 4), (0, 0), (8, 7), (8, 9)] {
            let mut out = [0xFFu8; 8];
            assert_eq!(fill_bytes(&mut Writes { written, result: Ok(count) }, &mut out), short);
            assert_eq!(out, [0u8; 8], "wrote {written}, returned {count}");
        }

        // The RNG's own error comes back as it is, over a wiped buffer.
        let mut out = [0xFFu8; 8];
        let mut failing = Writes { written: 3, result: Err(RNGError::ReseedRequired) };
        assert_eq!(fill_bytes(&mut failing, &mut out), Err(RNGError::ReseedRequired));
        assert_eq!(out, [0u8; 8]);
    }

    const P: [u64; 2] = [0x1234_5678_9abc_def1, 0xc000_0000_0000_0001];

    fn p_plus(d: u64) -> [u64; 2] {
        nat::add(&P, &[d, 0]).0
    }

    #[test]
    fn primes_too_close_boundary_cases() {
        assert!(primes_too_close(&P, &p_plus(1)));
        assert!(primes_too_close(&P, &p_plus(4)));
        assert!(primes_too_close(&P, &p_plus(1 << 28)));
        assert!(!primes_too_close(&P, &p_plus((1 << 28) + 1)));
        assert!(!primes_too_close(&P, &p_plus(1 << 29)));
    }

    #[test]
    fn primes_too_close_is_symmetric_in_its_arguments() {
        assert!(primes_too_close(&p_plus(1), &P));
        assert!(primes_too_close(&p_plus(1 << 28), &P));
        assert!(!primes_too_close(&p_plus((1 << 28) + 1), &P));
    }

    /// The same boundary at RSA-2048's width (`threshold_bit = 924`, limb 14 bit 28), where the
    /// shifts cross whole limbs; and a difference of `2^960`, which lies in the top limb alone.
    #[test]
    fn primes_too_close_boundary_cases_at_rsa_2048_width() {
        let mut p = [0u64; 16];
        p[0] = 0x1234_5678_9abc_def1;
        p[15] = 0xc000_0000_0000_0001;
        let p_plus = |limb: usize, bits: u64, low: u64| {
            let mut d = [0u64; 16];
            d[limb] = bits;
            d[0] |= low;
            nat::add(&p, &d).0
        };
        assert!(primes_too_close(&p, &p_plus(14, 1 << 28, 0)));
        assert!(!primes_too_close(&p, &p_plus(14, 1 << 28, 1)));
        assert!(!primes_too_close(&p, &p_plus(15, 1, 0)));
        assert!(!primes_too_close(&p_plus(15, 1, 0), &p));
    }

    #[test]
    fn div_known_answer() {
        let a = [0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210];
        let d = [0x9e37_79b9_7f4a_7c15, 1];
        assert_eq!(div(&a, &d), [0x9d83_75c5_3037_f300, 0]);
        assert_eq!(div(&a, &a), [1, 0]);
        assert_eq!(div(&d, &a), [0, 0]);
    }

    /// `GCD(2^64 * 3g, 2^64 * 5g) = 2^64 * g` for `g = 2^64 + 0x2b`: a common power of two that
    /// is a whole limb.
    #[test]
    fn gcd_known_answer_with_a_whole_limb_of_common_twos() {
        let a = [0, 0x81, 3];
        let b = [0, 0xd7, 5];
        assert_eq!(gcd(&a, &b), [0, 0x2b, 1]);
        assert_eq!(gcd(&b, &a), [0, 0x2b, 1]);
    }

    /// Criterion 3(a) at `HALF = 1`, so the bound is `2^64`: `LCM(x, y)` divides `e * D - 1`,
    /// which makes the private exponent `D` itself. `2^64` is not above the bound; one either
    /// side of it decides as its side does.
    #[test]
    fn private_exponent_exceeds_half_boundary() {
        let exceeds = |x: u64, y: u64, e: u64| private_exponent_exceeds_half::<1, 2>(&[x], &[y], e);
        // d = 2^64 - 1, LCM = 0x10004fffffffffffefffa, GCD = 0x1fa.
        assert!(!exceeds(0x1d90_d24a, 0x111d_a04b_c50e_b22a, 65541));
        // d = 2^64, LCM = 0x10000ffffffffffffffff, GCD = 0xae2f3.
        assert!(!exceeds(0x0241_6138_b67f, 0x04d3_b3f4_7847_de73, 65537));
        // d = 2^64 + 1, LCM = 0x100070000000000010006, GCD = 0x186.
        assert!(exceeds(0x18_c07c_2102, 0x000f_c20f_c1a0_1b92, 65543));
    }
}
