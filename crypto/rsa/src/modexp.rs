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
//! * [`MontgomeryContext`]'s constructors additionally derive `R mod n` and `R^2 mod n`
//!   (`R = 2^(64L)`) by repeated doubling-and-reduction, rather than requiring them precomputed.
//!
//! The modulus is public when it is RSA's `n` and secret when it is one of the primes `p`, `q`
//! of the CRT or a candidate prime in key generation, so the context has one constructor for
//! each: [`MontgomeryContext::for_secret_modulus`], constant time in the modulus, and
//! [`MontgomeryContext::for_public_modulus`], whose doublings branch on it -- the same reasoning
//! [`bouncycastle_ec::inverse_vartime`] documents for operating on public curve/scalar values.
//! [`mod_pow`] operates on an exponent that can be secret (the private
//! exponent `d`): it processes every one of the modulus's `64 * L` bits regardless of the
//! exponent's actual value or bit length, using Joye & Yen's Montgomery powering ladder (CHES
//! 2002, "The Montgomery Powering Ladder"), so it performs exactly one multiplication and one
//! squaring per bit, moved into place by a branch-free conditional swap rather than a branch on
//! the bit's value. [`mod_pow_public_exponent`] is for the public exponent `e` alone: it runs
//! over that exponent's own bits and branches on them.
//!
//! # Security Considerations
//!
//! [`mod_pow`] is constant-time in the *exponent*, which is what RSA signing needs (`d` is
//! secret). It is not blinded against the message/base: an attacker who can also mount a
//! chosen-message physical side-channel attack (power/cache analysis, not just timing) may still
//! learn about `d` from repeated calls with related bases, per Kocher (1996) and Boneh & Brumley
//! (2003). Neither this module nor `crate::rsa_core`'s CRT-based `rsasp1` (the only caller that
//! exponentiates with a secret exponent) applies message blinding on top of it -- see the crate's
//! own `# Security Considerations` for what that means for this crate's signing operation.

use bouncycastle_ec::montgomery;
use bouncycastle_ec::nat;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::{ZeroizablePrimitive, zeroize_in_place};

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
/// the `< n` representative (it cannot need a second: `a < n` implies `2a < 2n`). The branch
/// reveals how `2a` compares with `n`, so `n` must be public.
fn double_mod_n_vartime<const L: usize>(a: &[u64; L], n: &[u64; L]) -> [u64; L] {
    let (doubled, carry) = nat::add(a, a);
    let (diff, borrow) = nat::sub(&doubled, n);
    if carry == 1 || borrow == 0 { diff } else { doubled }
}

/// `2^bits mod n` for odd `n > 1`, by `bits` repeated doublings from `1`. Variable time in `n`,
/// like `double_mod_n_vartime`: for a public modulus only.
fn pow2_mod_vartime<const L: usize>(bits: u32, n: &[u64; L]) -> [u64; L] {
    let mut acc = [0u64; L];
    acc[0] = 1;
    for _ in 0..bits {
        acc = double_mod_n_vartime(&acc, n);
    }
    acc
}

/// `2^bits mod n` for odd `n > 1`, as `pow2_mod_vartime` computes it, in constant time in `n`:
/// each doubling is [`ct_shift_in_bit_mod`]'s masked subtraction, and the trip count is `bits`,
/// which is public.
fn pow2_mod_ct<const L: usize>(bits: u32, n: &[u64; L]) -> [u64; L] {
    let mut acc = [0u64; L];
    acc[0] = 1;
    for _ in 0..bits {
        acc = ct_shift_in_bit_mod(&acc, 0, n);
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

fn to_montgomery<const L: usize, const L2: usize, const L21: usize>(
    a: &[u64; L],
    ctx: &MontgomeryContext<L>,
) -> [u64; L] {
    let t = montgomery::widening_mul::<L, L2>(a, &ctx.r2_mod_n);
    redc_normalize::<L, L2, L21>(&t, &ctx.modulus, ctx.n_prime)
}

fn from_montgomery<const L: usize, const L2: usize, const L21: usize>(
    a_bar: &[u64; L],
    ctx: &MontgomeryContext<L>,
) -> [u64; L] {
    let mut padded = [0u64; L2];
    padded[..L].copy_from_slice(a_bar);
    let result = redc_normalize::<L, L2, L21>(&padded, &ctx.modulus, ctx.n_prime);
    zeroize_in_place(&mut padded);
    result
}

/// `a * b mod ctx.modulus()`, for plain (non-Montgomery) `a`, `b`. Only `b` needs converting into
/// Montgomery form: `REDC(a * (b*R)) = a*b*R*R^-1 mod n = a*b mod n`, the same one-sided-conversion
/// trick [`mod_pow`] itself doesn't need (it stays in Montgomery form throughout its ladder).
/// `a` need only fit in `L` limbs, not be `< ctx.modulus()`, by the same `T < n*R` argument
/// `to_montgomery` relies on -- see the module docs' note on [`montgomery::redc`]'s precondition.
pub fn mul_mod<const L: usize, const L2: usize, const L21: usize>(
    a: &[u64; L],
    b: &[u64; L],
    ctx: &MontgomeryContext<L>,
) -> [u64; L] {
    let mut b_bar = to_montgomery::<L, L2, L21>(b, ctx);
    let mut t = montgomery::widening_mul::<L, L2>(a, &b_bar);
    let result = redc_normalize::<L, L2, L21>(&t, &ctx.modulus, ctx.n_prime);
    zeroize_in_place(&mut b_bar);
    zeroize_in_place(&mut t);
    result
}

/// `(a - b) mod modulus` for `a, b < modulus`, in constant time with respect to `modulus`: RSA's
/// CRT recombination (RFC 8017 §5.2.1 step 2.b.3) needs `(s1 - s2) mod p`, and `p` is private key
/// material, so -- unlike `double_mod_n_vartime`'s public-modulus reasoning -- this must not
/// branch on it.
pub fn sub_mod<const N: usize>(a: &[u64; N], b: &[u64; N], modulus: &[u64; N]) -> [u64; N] {
    let (diff, borrow) = nat::sub(a, b);
    let (corrected, _) = nat::add(&diff, modulus);
    let mask = Condition::<u64>::from_lsb(borrow);
    ct_select_array(mask, &corrected, &diff)
}

/// `(acc * 2 + bit) mod modulus` for `acc < modulus` and odd `modulus`, in constant time in
/// all three: the modulus can be secret (see [`reduce_wide`] and `pow2_mod_ct`).
fn ct_shift_in_bit_mod<const N: usize>(acc: &[u64; N], bit: u64, modulus: &[u64; N]) -> [u64; N] {
    let mut doubled = [0u64; N];
    let mut carry = bit;
    for i in 0..N {
        let next_carry = acc[i] >> 63;
        // Mutating this `|` to `^` is an accepted equivalent, not a gap: `acc[i] << 1` always has
        // bit 0 clear (a left shift's incoming bit), and `carry` is 0 or 1, so OR-ing it into that
        // always-clear bit and XOR-ing it produce identical results.
        doubled[i] = (acc[i] << 1) | carry;
        carry = next_carry;
    }
    // Same accepted OR/XOR equivalence as `redc_normalize`, by the identical argument: `doubled`'s
    // true value is `2*acc + bit < 2*modulus` (`acc < modulus`), so `carry == 1` (the bit that
    // overflowed the top limb) forces the stored `doubled < 2*modulus - 2^(64N) < modulus`, i.e.
    // `borrow == 1` (the other mask FALSE) whenever `carry == 1`.
    let (diff, borrow) = nat::sub(&doubled, modulus);
    let subtract = Condition::<u64>::from_lsb(carry) | Condition::<u64>::from_lsb(borrow ^ 1);
    ct_select_array(subtract, &diff, &doubled)
}

/// `value mod modulus` for a `WIDE`-limb `value` and a `NARROW`-limb odd `modulus`, in constant
/// time with respect to `modulus`. Unlike `pow2_mod_vartime`, which assumes a *public*
/// modulus (true of RSA's own `n`), this brings a value down to a CRT prime's width and the primes
/// are private key material: branching on their value here would leak them the same way branching
/// on the exponent would leak `d`. Used two ways in RSA's CRT recombination (RFC 8017 §5.2.1 step
/// 2.b): with `WIDE > NARROW`, to reduce the `n`-width message `m` down to `m mod p` before
/// exponentiating (step 2.b.1); and with `WIDE == NARROW`, to reduce `s2` (a residue mod `q`) down
/// to `s2 mod p` before the CRT subtraction (step 2.b.3) -- `s2 < q` gives no useful bound
/// relative to `p` in general (RFC 8017 does not require `p` and `q` to be close in magnitude),
/// so this does not special-case a single conditional subtraction the way
/// `double_mod_n_vartime` does for the doubling case. Bit-serial schoolbook long division:
/// every one of `value`'s `64 * WIDE` bits contributes one constant-time doubling-and-conditional-
/// subtract step.
pub fn reduce_wide<const WIDE: usize, const NARROW: usize>(
    value: &[u64; WIDE],
    modulus: &[u64; NARROW],
) -> [u64; NARROW] {
    let mut acc = [0u64; NARROW];
    for limb_index in (0..WIDE).rev() {
        for bit_index in (0..64u32).rev() {
            let bit = (value[limb_index] >> bit_index) & 1;
            acc = ct_shift_in_bit_mod(&acc, bit, modulus);
        }
    }
    acc
}

/// Precomputed Montgomery constants for a runtime-supplied odd modulus `n`, `L` limbs wide.
///
/// Unlike every curve modulus in `bouncycastle-ec`, `n` here is not known until the key is
/// loaded, so these constants (see the module docs) are derived at construction time rather than
/// hard-coded.
#[derive(Clone, Copy)]
pub struct MontgomeryContext<const L: usize> {
    modulus: [u64; L],
    n_prime: u64,
    /// Montgomery form of `1`, i.e. `R mod n`.
    r_mod_n: [u64; L],
    /// `R^2 mod n`, used to bring a value into Montgomery form.
    r2_mod_n: [u64; L],
}

/// A context over a private modulus -- `p` or `q` in the CRT, a candidate prime in key
/// generation -- holds that modulus and constants derived from it, so it is built inside a
/// [`bouncycastle_utils::secret::Secret`] and scrubbed when dropped. One over the public `n`
/// gains nothing from this.
impl<const L: usize> ZeroizablePrimitive for MontgomeryContext<L> {
    const ZEROED: Self = Self { modulus: [0; L], n_prime: 0, r_mod_n: [0; L], r2_mod_n: [0; L] };
}

// There is no plain `new`: a call names what its modulus is, so that a secret one handed to the
// variable-time constructor is wrong on the line that does it.
impl<const L: usize> MontgomeryContext<L> {
    /// Builds the Montgomery context for a modulus that is secret: `p` or `q` of the CRT, or a
    /// candidate prime. Returns `None` if `modulus` is even (zero included); Montgomery
    /// reduction requires an odd modulus. `modulus` must be greater than 1.
    ///
    /// Constant time in `modulus` apart from that test of its low bit: no branch, memory
    /// access or loop count depends on any other bit of it.
    pub fn for_secret_modulus(modulus: &[u64; L]) -> Option<Self> {
        // The one branch on the modulus. It is on bit 0, which is set in every modulus a
        // caller holds (a prime, or a candidate forced odd), so it tells an observer nothing.
        if modulus[0] & 1 == 0 {
            return None;
        }
        let n_prime = mont_n_prime(modulus[0]);
        let r_mod_n = pow2_mod_ct(64 * L as u32, modulus);
        let r2_mod_n = pow2_mod_ct(128 * L as u32, modulus);
        Some(Self { modulus: *modulus, n_prime, r_mod_n, r2_mod_n })
    }

    /// Builds the Montgomery context for a modulus that is public: RSA's `n`. Returns `None`
    /// if `modulus` is even (zero included). `modulus` must be greater than 1. The same context
    /// as [`Self::for_secret_modulus`] builds.
    ///
    /// Variable time in `modulus`: its doublings branch on how the running value compares with
    /// it. Never for `p`, `q` or anything else that is secret.
    pub fn for_public_modulus(modulus: &[u64; L]) -> Option<Self> {
        if modulus[0] & 1 == 0 {
            return None;
        }
        let n_prime = mont_n_prime(modulus[0]);
        let r_mod_n = pow2_mod_vartime(64 * L as u32, modulus);
        let r2_mod_n = pow2_mod_vartime(128 * L as u32, modulus);
        Some(Self { modulus: *modulus, n_prime, r_mod_n, r2_mod_n })
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

    let mut r0 = ctx.r_mod_n;
    let mut r1 = to_montgomery::<L, L2, L21>(base, ctx);
    // The step's two products, declared here so one scrub after the ladder covers them.
    let mut new_r0 = [0u64; L];
    let mut new_r1 = [0u64; L];

    for limb_index in (0..L).rev() {
        for bit_index in (0..64u32).rev() {
            let mask = Condition::<u64>::is_bit_set(exponent[limb_index], bit_index);
            ct_swap_array(mask, &mut r0, &mut r1);
            new_r1 = mont_mul::<L, L2, L21>(&r0, &r1, &ctx.modulus, ctx.n_prime);
            new_r0 = mont_square::<L, L2, L21>(&r0, &ctx.modulus, ctx.n_prime);
            r0 = new_r0;
            r1 = new_r1;
            ct_swap_array(mask, &mut r0, &mut r1);
        }
    }

    let result = from_montgomery::<L, L2, L21>(&r0, ctx);
    // The ladder's state is a function of the exponent's bits, so it is scrubbed before
    // returning (QUALITY_AND_STYLE.md's rule on secret-holding locals). The products inside
    // `mont_mul` and `mont_square` are the callee intermediates that rule does not reach.
    zeroize_in_place(&mut r0);
    zeroize_in_place(&mut r1);
    zeroize_in_place(&mut new_r0);
    zeroize_in_place(&mut new_r1);
    result
}

/// `base^exponent mod ctx.modulus()` for a public exponent, RSA's `e`: left-to-right square and
/// multiply over the exponent's own bits, from its highest set bit down, so the cost is that of
/// the exponent and not of the modulus's width as [`mod_pow`]'s is. `base` need only fit in `L`
/// limbs.
///
/// Variable time in `exponent`, whose bits decide how many squarings are made and where the
/// multiplications fall: never for a private exponent. Constant time in `base`, which can be
/// secret (RSASVE's secret value, a recovered message): the sequence of operations is a
/// function of the exponent alone, and each is the same Montgomery product `mod_pow` uses.
pub fn mod_pow_public_exponent<const L: usize, const L2: usize, const L21: usize>(
    base: &[u64; L],
    exponent: u64,
    ctx: &MontgomeryContext<L>,
) -> [u64; L] {
    let mut base_bar = to_montgomery::<L, L2, L21>(base, ctx);
    // Montgomery form of 1, so that an exponent of zero gives 1.
    let mut acc = ctx.r_mod_n;
    for bit_index in (0..u64::BITS - exponent.leading_zeros()).rev() {
        acc = mont_square::<L, L2, L21>(&acc, &ctx.modulus, ctx.n_prime);
        if (exponent >> bit_index) & 1 == 1 {
            acc = mont_mul::<L, L2, L21>(&acc, &base_bar, &ctx.modulus, ctx.n_prime);
        }
    }
    let result = from_montgomery::<L, L2, L21>(&acc, ctx);
    // Powers of the base, which can be secret: scrubbed as `mod_pow` scrubs its ladder. The
    // values `acc` held before its last assignment are not reached.
    zeroize_in_place(&mut base_bar);
    zeroize_in_place(&mut acc);
    result
}

// A context's constants are private, so that the two constructors build the same context --
// and that each is right -- is not something `tests/` can see: the QUALITY_AND_STYLE.md
// exception for private state with known answers. The answers are Python's (`-pow(n, -1,
// 2**64) % 2**64`, `2**(64*L) % n`, `2**(128*L) % n`).
#[cfg(test)]
mod tests {
    use super::*;

    /// A modulus, then its `n'`, `R mod n` and `R^2 mod n`.
    type Case<const L: usize> = ([u64; L], u64, [u64; L], [u64; L]);

    fn assert_both_constructors_give<const L: usize>(cases: &[Case<L>]) {
        for (n, n_prime, r_mod_n, r2_mod_n) in cases {
            for ctx in [
                MontgomeryContext::for_secret_modulus(n).unwrap(),
                MontgomeryContext::for_public_modulus(n).unwrap(),
            ] {
                assert_eq!(ctx.modulus, *n);
                assert_eq!(ctx.n_prime, *n_prime, "n' for {n:x?}");
                assert_eq!(ctx.r_mod_n, *r_mod_n, "R mod n for {n:x?}");
                assert_eq!(ctx.r2_mod_n, *r2_mod_n, "R^2 mod n for {n:x?}");
            }
        }
    }

    #[test]
    fn both_constructors_give_the_known_constants() {
        assert_both_constructors_give::<2>(&[
            // 2^128 - 1: every limb all ones.
            ([0xffffffffffffffff, 0xffffffffffffffff], 0x0000000000000001, [1, 0], [1, 0]),
            // 2^127 + 1: just above 2^(k-1), the low limb all but zero.
            (
                [0x0000000000000001, 0x8000000000000000],
                0xffffffffffffffff,
                [0xffffffffffffffff, 0x7fffffffffffffff],
                [4, 0],
            ),
            // The top limb all ones, the low limb 1.
            (
                [0x0000000000000001, 0xffffffffffffffff],
                0xffffffffffffffff,
                [0xffffffffffffffff, 0x0000000000000000],
                [0x0000000000000001, 0xfffffffffffffffe],
            ),
            // The top limb all ones over an arbitrary low limb.
            (
                [0x123456789abcdef1, 0xffffffffffffffff],
                0x8848c2974d33adef,
                [0xedcba9876543210f, 0x0000000000000000],
                [0xca4ab582281edee1, 0xdce2b9eafe7ceefa],
            ),
            // 2^127 - 1: the top bit clear.
            ([0xffffffffffffffff, 0x7fffffffffffffff], 0x0000000000000001, [2, 0], [4, 0]),
            // 3: far short of the width.
            ([3, 0], 0x5555555555555555, [1, 0], [1, 0]),
            // An arbitrary full-length value.
            (
                [0x9e3779b97f4a7c15, 0xd1b54a32d192ed03],
                0x0e217c1e66c88cc3,
                [0x61c8864680b583eb, 0x2e4ab5cd2e6d12fc],
                [0xefccadf490c04b25, 0xb0ba6db3c8cd9e51],
            ),
        ]);
        assert_both_constructors_give::<4>(&[
            // 2^255 + 1: just above 2^(k-1), the low limbs zero but for bit 0.
            (
                [1, 0, 0, 0x8000000000000000],
                0xffffffffffffffff,
                [0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff],
                [4, 0, 0, 0],
            ),
            // The top limb all ones, the low limbs zero but for bit 0.
            (
                [1, 0, 0, 0xffffffffffffffff],
                0xffffffffffffffff,
                [0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0],
                [0x0000000000000001, 0xffffffffffffffff, 0xfffffffffffffffe, 0xfffffffffffffffd],
            ),
            // 2^256 - 189.
            (
                [0xffffffffffffff43, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff],
                0xa53fa94fea53fa95,
                [0xbd, 0, 0, 0],
                [0x8b89, 0, 0, 0],
            ),
        ]);
    }

    /// The two constructors agree limb for limb at a CRT prime's width, RSA-2048's 16 limbs,
    /// over 64 moduli stepped from a fixed seed (SplitMix64's increment and mixer, as a source
    /// of varied limbs, not of randomness), each forced odd and, on alternate rounds, given a
    /// top limb of all ones or of only its top bit.
    #[test]
    fn both_constructors_agree_at_a_prime_width() {
        let mut state = 0x243f6a8885a308d3u64;
        let mut next = || {
            state = state.wrapping_add(0x9e3779b97f4a7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
            z ^ (z >> 31)
        };
        for round in 0..64 {
            let mut n = [0u64; 16];
            for limb in n.iter_mut() {
                *limb = next();
            }
            n[0] |= 1;
            match round % 4 {
                1 => n[15] = u64::MAX,
                2 => n[15] = 1 << 63,
                _ => {}
            }
            let secret = MontgomeryContext::for_secret_modulus(&n).unwrap();
            let public = MontgomeryContext::for_public_modulus(&n).unwrap();
            assert_eq!(secret.modulus, public.modulus);
            assert_eq!(secret.n_prime, public.n_prime);
            assert_eq!(secret.r_mod_n, public.r_mod_n, "R mod n for {n:x?}");
            assert_eq!(secret.r2_mod_n, public.r2_mod_n, "R^2 mod n for {n:x?}");
        }
    }
}
