//! Constant-time modular exponentiation over a runtime-supplied odd modulus, built on
//! [`bouncycastle_ec::nat`] and [`bouncycastle_ec::montgomery`].
//!
//! Every curve in `bouncycastle-ec` treats its modulus as a per-curve compile-time constant, with
//! the Montgomery constant `n'` computed once, offline, and hard-coded. RSA's modulus is key
//! material supplied at runtime, so this module computes the Montgomery setup itself:
//!
//! * [`mont_n_prime`] derives `n' = -n0^-1 mod 2^64` from the modulus's low limb by Newton's
//!   method (six doublings of precision from a one-bit-correct seed), rather than requiring it
//!   precomputed.
//! * [`MontgomeryContext::new`] additionally derives `R mod n` and `R^2 mod n` (`R = 2^(64L)`) by
//!   repeated doubling-and-reduction, rather than requiring them precomputed.
//!
//! Both of these operate on the modulus alone, which is public in RSA (shared between the public
//! and private key), so they run in variable time -- the same reasoning
//! [`bouncycastle_ec::inverse_vartime`] documents for operating on public curve/scalar values.
//! [`mod_pow`] is the one piece here that operates on a value that can be secret (the private
//! exponent `d`): it processes every one of the modulus's `64 * L` bits regardless of the
//! exponent's actual value or bit length, using Joye & Yen's Montgomery powering ladder (CHES
//! 2002, "The Montgomery Powering Ladder"), so it performs exactly one multiplication and one
//! squaring per bit, moved into place by a branch-free conditional swap rather than a branch on
//! the bit's value.
//!
//! # Security Considerations
//!
//! [`mod_pow`] is constant-time in the *exponent*, which is what RSA signing needs (`d` is
//! secret). It is not blinded against the message/base: an attacker who can also mount a
//! chosen-message physical side-channel attack (power/cache analysis, not just timing) may still
//! learn about `d` from repeated calls with related bases, per Kocher (1996) and Boneh & Brumley
//! (2003). RSA's private-key signing operation (a later addition to this crate) applies
//! message blinding on top of this primitive; this module does not do that itself; it is a
//! general-purpose engine, not the full defence.

use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
use bouncycastle_utils::ct::Condition;

/// `n' = -n0^-1 mod 2^64` for an odd `n0`, by Newton's method: `x` is correct to one bit at
/// `x = 1` (since `n0` is odd, `n0 * 1` is odd, i.e. `≡ 1 mod 2`), and each round of
/// `x <- x * (2 - n0 * x)` (all mod `2^64`, via wrapping arithmetic) doubles the number of
/// correct low bits, so six rounds carry it from one correct bit to all sixty-four
/// (`1, 2, 4, 8, 16, 32, 64`).
pub fn mont_n_prime(n0: u64) -> u64 {
    debug_assert_eq!(n0 & 1, 1, "mont_n_prime needs an odd modulus");
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
    }
    inv.wrapping_neg()
}

/// `(a * 2) mod n` for `a < n` and odd `n`, in variable time: doubling `a` can carry out of the
/// top limb or land in `[n, 2n)`, either of which means exactly one subtraction of `n` restores
/// the `< n` representative (it cannot need a second: `a < n` implies `2a < 2n`).
fn double_mod_n<const L: usize>(a: &[u64; L], n: &[u64; L]) -> [u64; L] {
    let (doubled, carry) = nat::add(a, a);
    let (diff, borrow) = nat::sub(&doubled, n);
    if carry == 1 || borrow == 0 { diff } else { doubled }
}

/// `2^bits mod n` for odd `n`, by `bits` repeated doublings from `1`. Variable time, like
/// [`double_mod_n`]: the modulus is public.
fn pow2_mod<const L: usize>(bits: u32, n: &[u64; L]) -> [u64; L] {
    let mut acc = [0u64; L];
    acc[0] = 1;
    for _ in 0..bits {
        acc = double_mod_n(&acc, n);
    }
    acc
}

/// Per-limb constant-time select: `mask.select` applied element-wise.
fn ct_select_array<const L: usize>(mask: Condition<u64>, a: &[u64; L], b: &[u64; L]) -> [u64; L] {
    let mut result = [0u64; L];
    for i in 0..L {
        result[i] = mask.select(a[i], b[i]);
    }
    result
}

/// Per-limb constant-time swap, in place.
fn ct_swap_array<const L: usize>(mask: Condition<u64>, a: &mut [u64; L], b: &mut [u64; L]) {
    for i in 0..L {
        let (x, y) = mask.swap(a[i], b[i]);
        a[i] = x;
        b[i] = y;
    }
}

/// A Montgomery-form value of `< 2n` (the bound [`montgomery::redc`] returns), plus the extra bit
/// beyond its `L` limbs, reduced to the canonical `< n` representative.
///
/// `extra` and `high` are never both large enough to matter independently: if `extra == 1` then
/// `high + 2^(64L) >= 2^(64L) > n`, so the value is always `>= n` in that case and a subtraction
/// mask of `extra == 1` alone would be correct for it; the `borrow == 0` (`high >= n`) arm handles
/// the remaining `extra == 0` case, so the two conditions ORed together cover exactly the "value
/// `>= n`" set.
fn redc_normalize<const L: usize, const L2: usize, const L21: usize>(
    t: &[u64; L2],
    modulus: &[u64; L],
    n_prime: u64,
) -> [u64; L] {
    let (high, extra) = montgomery::redc::<L, L2, L21>(t, modulus, n_prime);
    let (diff, borrow) = nat::sub(&high, modulus);
    // Mutating this `|` to `^` is an accepted equivalent, not a gap: the two masks are never both
    // TRUE at once. `extra == 1` forces `high < n` (equivalently `borrow == 1`, so the second mask
    // is FALSE) -- see the doc comment above -- because every caller's `t` comes from
    // `montgomery::redc`'s own `< 2n` bound, never from an unconstrained 2L-limb value.
    let subtract = Condition::<u64>::from_lsb(extra) | Condition::<u64>::from_lsb(borrow ^ 1);
    ct_select_array(subtract, &diff, &high)
}

fn mont_mul<const L: usize, const L2: usize, const L21: usize>(
    a: &[u64; L],
    b: &[u64; L],
    modulus: &[u64; L],
    n_prime: u64,
) -> [u64; L] {
    let t = montgomery::widening_mul::<L, L2>(a, b);
    redc_normalize::<L, L2, L21>(&t, modulus, n_prime)
}

fn mont_square<const L: usize, const L2: usize, const L21: usize>(
    a: &[u64; L],
    modulus: &[u64; L],
    n_prime: u64,
) -> [u64; L] {
    let t = montgomery::widening_square::<L, L2>(a);
    redc_normalize::<L, L2, L21>(&t, modulus, n_prime)
}

/// Precomputed Montgomery constants for a runtime-supplied odd modulus `n`, `L` limbs wide.
///
/// Unlike every curve modulus in `bouncycastle-ec`, `n` here is not known until the key is
/// loaded, so these constants (see the module docs) are derived at construction time rather than
/// hard-coded.
pub struct MontgomeryContext<const L: usize> {
    modulus: [u64; L],
    n_prime: u64,
    /// Montgomery form of `1`, i.e. `R mod n`.
    r_mod_n: [u64; L],
    /// `R^2 mod n`, used to bring a value into Montgomery form.
    r2_mod_n: [u64; L],
}

impl<const L: usize> MontgomeryContext<L> {
    /// Builds the Montgomery context for `modulus`. Returns `None` if `modulus` is even or zero;
    /// Montgomery reduction requires an odd modulus, and RSA's is always odd (a product of two
    /// odd primes).
    pub fn new(modulus: &[u64; L]) -> Option<Self> {
        if modulus[0] & 1 == 0 || nat::is_zero(modulus).to_bool() {
            return None;
        }
        let n_prime = mont_n_prime(modulus[0]);
        let r_mod_n = pow2_mod(64 * L as u32, modulus);
        let r2_mod_n = pow2_mod(128 * L as u32, modulus);
        Some(Self { modulus: *modulus, n_prime, r_mod_n, r2_mod_n })
    }

    /// The modulus this context was built for.
    pub fn modulus(&self) -> &[u64; L] {
        &self.modulus
    }
}

/// `base^exponent mod ctx.modulus()`, constant-time in `exponent`: every one of the modulus's
/// `64 * L` bits is processed, via Joye & Yen's Montgomery powering ladder (see the module docs).
///
/// `base` must be `< ctx.modulus()`; callers reduce first if that is not already guaranteed (RSA
/// callers always pass an already-reduced value: a message digest padded to the modulus width, or
/// a signature, both taken modulo `n` by construction).
pub fn mod_pow<const L: usize, const L2: usize, const L21: usize>(
    base: &[u64; L],
    exponent: &[u64; L],
    ctx: &MontgomeryContext<L>,
) -> [u64; L] {
    debug_assert_eq!(nat::sub(base, &ctx.modulus).1, 1, "mod_pow needs base < modulus");

    let mut base_padded = [0u64; L2];
    base_padded[..L].copy_from_slice(base);
    let base_bar = redc_normalize::<L, L2, L21>(
        &montgomery::widening_mul::<L, L2>(base, &ctx.r2_mod_n),
        &ctx.modulus,
        ctx.n_prime,
    );

    let mut r0 = ctx.r_mod_n;
    let mut r1 = base_bar;

    for limb_index in (0..L).rev() {
        for bit_index in (0..64u32).rev() {
            let mask = Condition::<u64>::is_bit_set(exponent[limb_index], bit_index);
            ct_swap_array(mask, &mut r0, &mut r1);
            let new_r1 = mont_mul::<L, L2, L21>(&r0, &r1, &ctx.modulus, ctx.n_prime);
            let new_r0 = mont_square::<L, L2, L21>(&r0, &ctx.modulus, ctx.n_prime);
            r0 = new_r0;
            r1 = new_r1;
            ct_swap_array(mask, &mut r0, &mut r1);
        }
    }

    let mut r0_padded = [0u64; L2];
    r0_padded[..L].copy_from_slice(&r0);
    redc_normalize::<L, L2, L21>(&r0_padded, &ctx.modulus, ctx.n_prime)
}
