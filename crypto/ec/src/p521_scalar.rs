//! The P-521 scalar field, arithmetic mod the curve order `n` (SP 800-186 §3.2.1.5). Identical in
//! shape to [`crate::p256_scalar`]/[`crate::p384_scalar`] -- Montgomery form (`R = 2^576`, this
//! type's full 9-limb width, not `n`'s 521 bits), the same SOS reduction, the same
//! `Secret`/plain scalar split -- with `n` swapped for P-521's; see [`crate::p256_scalar`]'s docs
//! for the full derivation.
//!
//! Unlike [`crate::p256_scalar::redc`] and [`crate::p384_scalar::redc`], `n` here is not close to
//! `R`: `n < 2^521`, some 55 bits short of `R = 2^576`, so `2n` cannot exceed `R` and REDC's
//! accumulator needs no extra bit of headroom beyond the 18-limb product width. Verified (not
//! checked in) against 30,000 random trials plus the `(n-1)*(n-1)` worst case that the
//! accumulator's top limb is always exactly `0` after the reduction rounds -- kept as a
//! `debug_assert_eq!` rather than removing the (unused) 19th limb, so a future change that makes
//! it false fails loudly rather than silently dropping a bit the way [`crate::p384::reduce`]'s
//! analogous but *wrong* assumption once did.
//!
//! That same 55-bit gap bites a different function, [`reduce_wide`] (used by every `from_limbs` in
//! this module): a raw `[u64; 9]` can hold values up to `2^576 - 1`, so it is not generally `< 2n`
//! the way a same-width raw limb array is for P-256/P-384's closer-to-`R` `n` -- see that
//! function's own docs for the fold this needs and the real bug an earlier, single-subtraction
//! version had.

use crate::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// `n`, the order of the P-521 base point `G`, little-endian `u64` limbs (SP 800-186 §3.2.1.5).
pub const N_LIMBS: [u64; 9] = [
    0xbb6fb71e91386409, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0, 0x51868783bf2f966b,
    0xfffffffffffffffa, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0x00000000000001ff,
];

/// `2^576 mod n`, also the Montgomery representation of `1`.
const R_LIMBS: [u64; 9] = [
    0xfb80000000000000, 0x28a2482470b763cd, 0x17e2251b23bb31dc, 0xca4019ff5b847b2d,
    0x02d73cbc3e206834, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
    0x0000000000000000,
];

/// `R^2 mod n`, used to bring a plain value into Montgomery form.
const R_SQUARED_LIMBS: [u64; 9] = [
    0x137cd04dcf15dd04, 0xf707badce5547ea3, 0x12a78d38794573ff, 0xd3721ef557f75e06,
    0xdd6e23d82e49c7db, 0xcff3d142b7756e3e, 0x5bcc6d61a8e567bc, 0x2d8e03d1492d0d45,
    0x000000000000003d,
];

/// `-n^-1 mod 2^64`, the Montgomery reduction constant.
const N_PRIME: u64 = 0x1d2f5ccd79a995c7;

/// `n - 2`, little-endian `u64` limbs -- the public exponent [`P521ScalarField::invert`] raises
/// its base to.
const N_MINUS_2_LIMBS: [u64; 9] = [
    0xbb6fb71e91386407, 0x3bb5c9b8899c47ae, 0x7fcc0148f709a5d0, 0x51868783bf2f966b,
    0xfffffffffffffffa, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0x00000000000001ff,
];

/// `2^521 mod n`, the fold constant [`reduce_wide`] uses. Unlike [`crate::p521::P521FieldElement`],
/// whose modulus `p = 2^521 - 1` makes `2^521 mod p` trivially `1`, `n` has no such special form,
/// so this is a genuine ~259-bit value computed directly (not a small Solinas-style constant).
const TWO_POW_521_MOD_N_LIMBS: [u64; 9] = [
    0x449048e16ec79bf7, 0xc44a36477663b851, 0x8033feb708f65a2f, 0xae79787c40d06994, 0x5, 0, 0, 0, 0,
];

/// An element of the P-521 scalar field, i.e. an integer mod `n`. Stored internally in Montgomery
/// form; see the module docs.
#[derive(Clone, Copy, Debug)]
pub struct P521ScalarField([u64; 9]);

impl P521ScalarField {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity. Its Montgomery form is `R mod n`, not the literal integer `1`.
    pub const ONE: Self = Self(R_LIMBS);

    /// Builds a scalar-field element from little-endian `u64` limbs (an ordinary, non-Montgomery
    /// value; any of the `2^576` values a raw `[u64; 9]` can represent, not just those `< 2n`),
    /// reducing via [`reduce_wide`], then converting to Montgomery form.
    pub fn from_limbs(limbs: [u64; 9]) -> Self {
        let reduced = reduce_wide(limbs);
        Self(redc(&widening_mul(&reduced, &R_SQUARED_LIMBS)))
    }

    /// Returns the canonical little-endian `u64` limbs (an ordinary, non-Montgomery value), `< n`.
    pub fn to_limbs(&self) -> [u64; 9] {
        let mut wide = [0u64; 18];
        wide[..9].copy_from_slice(&self.0);
        redc(&wide)
    }

    /// TRUE iff this element is the additive identity.
    pub fn is_zero(&self) -> Condition<u64> {
        nat::is_zero(&self.0)
    }

    /// `self + other mod n`. Operates directly on the Montgomery-form limbs: no REDC needed.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = nat::add(&self.0, &other.0);
        let (sum_plus_r, _) = nat::add(&sum, &R_LIMBS);
        let (diff, borrow) = nat::sub(&sum, &N_LIMBS);
        let mut when_no_carry = [0u64; 9];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &sum, &diff, &mut when_no_carry);
        let mut result = [0u64; 9];
        ct::conditional_select(
            Condition::<u64>::from_lsb(carry),
            &sum_plus_r,
            &when_no_carry,
            &mut result,
        );
        Self(result)
    }

    /// `self - other mod n`.
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = nat::sub(&self.0, &other.0);
        let (corrected, _) = nat::add(&diff, &N_LIMBS);
        let mut result = [0u64; 9];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod n`.
    pub fn negate(&self) -> Self {
        let (diff, _) = nat::sub(&N_LIMBS, &self.0);
        let mut result = [0u64; 9];
        ct::conditional_select(self.is_zero(), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod n`, via Montgomery multiplication.
    pub fn mul(&self, other: &Self) -> Self {
        Self(redc(&widening_mul(&self.0, &other.0)))
    }

    /// `self^2 mod n`.
    /// Overwrites this value with zero, through a write the compiler may not elide.
    ///
    /// For the signing path, where a value of this type holds `d`, `k` or `k^-1` and would
    /// otherwise stay legible on the stack after the signature is returned. This type is `Copy`
    /// and carries public values too (verification's `u`, `v`, `e`, `r`, `s`), so it is not
    /// wrapped in [`bouncycastle_utils::secret::Secret`] -- that would cost its `Copy`, its `const
    /// ZERO`/`ONE`, and a scrub on every intermediate including the public ones. The trade is that
    /// scrubbing is the caller's job, on every path out of the function; see
    /// `bouncycastle_ecdsa`'s `sign_with_k` for the intended use.
    ///
    /// This does not reach values the compiler kept in registers or spilled itself, and is
    /// defence in depth rather than a guarantee.
    pub fn zeroize(&mut self) {
        bouncycastle_utils::secret::zeroize_in_place(&mut self.0);
    }

    /// `self^2`, via a dedicated squaring rather than `self.mul(self)` -- see
    /// [`widening_square`].
    ///
    /// Used by the exponentiation loops ([`Self::invert`] and friends), which call it hundreds of
    /// times in a row with nothing else competing for registers. Deliberately *not* used by this
    /// curve's point arithmetic, which squares by calling `mul` with equal arguments: that was
    /// tried and measured on P-256, and despite `square` being ~9% cheaper than `mul` in
    /// isolation it made the constant-time comb multiplier consistently slower, because inlining
    /// a third wide-multiply routine into that loop costs more than the saved partial products
    /// return. See [`crate::p256::P256FieldElement::square`] for the numbers.
    pub fn square(&self) -> Self {
        Self(redc(&widening_square(&self.0)))
    }

    /// Converts a secret scalar (`d` or `k`) into Montgomery form for field arithmetic. See
    /// [`crate::p256_scalar::P256ScalarField::from_secret`]'s docs.
    pub fn from_secret(secret: &P521Scalar) -> Self {
        Self::from_limbs(*secret.limbs())
    }

    /// `self^-1 mod n`, or `0` if `self` is `0`. Fermat's little theorem, by fixed
    /// square-then-conditionally-multiply over the public exponent `n-2`.
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..9).rev() {
            let limb = N_MINUS_2_LIMBS[limb_idx];
            let bit_count = if limb_idx == 8 { 9 } else { 64 };
            for bit in (0..bit_count).rev() {
                result = result.square();
                // `limb` is one word of a compile-time constant exponent and `bit` a loop
                // index, so this branch is on public data only: the sequence of squarings and
                // multiplications is fixed at compile time and identical on every call.
                if (limb >> bit) & 1 == 1 {
                    result = result.mul(self);
                }
            }
        }
        result
    }
}

impl PartialEq for P521ScalarField {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found. Comparing Montgomery-form limbs directly is valid: the map `x -> x*R mod n` is a
    /// bijection.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..9 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for P521ScalarField {}

/// Schoolbook widening multiply, identical in shape to [`crate::p256_scalar`]'s.
fn widening_mul(a: &[u64; 9], b: &[u64; 9]) -> [u64; 18] {
    let mut result = [0u64; 18];
    for i in 0..9 {
        let mut carry: u128 = 0;
        for j in 0..9 {
            let idx = i + j;
            let prod = (a[i] as u128) * (b[j] as u128) + (result[idx] as u128) + carry;
            result[idx] = prod as u64;
            carry = prod >> 64;
        }
        // Mutating `carry = s >> 64` here is an accepted mutant, not a bug -- see
        // `crate::p521::widening_mul`'s identical tail loop for the general argument (this loop's
        // carry is always 0 or 1, and a left-shifted replacement contributes nothing to any later
        // `result[k']`'s low 64 bits, so it never affects the returned `result` regardless of
        // input).
        let mut k = i + 9;
        while k < 18 {
            let s = (result[k] as u128) + carry;
            result[k] = s as u64;
            carry = s >> 64;
            k += 1;
        }
    }
    result
}

/// Schoolbook squaring of a 9-limb value into its 18-limb square.
///
/// `a * a` is symmetric: the product `a_i * a_j` appears twice for every `i != j`. Forming each of
/// those once and doubling costs `L(L+1)/2` limb multiplications -- 45 at this width against
/// the 81 [`widening_mul`] would form for the same value.
///
/// Three passes: the off-diagonal products `a_i * a_j` for `i < j`; a doubling of the whole
/// accumulator; then the diagonal squares `a_i * a_i` added in at limb `2i`. Writing `result[i +
/// 9]` in the first pass is an assignment rather than an accumulation because row `i` only ever
/// reaches limbs `2i + 1 ..= i + 9 - 1`, and no earlier row reaches limb `i + 9` either, so that
/// limb is still zero when the row's final carry lands on it. The doubling cannot overflow: the
/// off-diagonal sum is strictly less than `a^2 / 2`.
///
/// Verified against Python's arbitrary-precision `**2` over 20,000 random 9-limb values plus the
/// all-ones worst case before being written here.
fn widening_square(a: &[u64; 9]) -> [u64; 18] {
    let mut result = [0u64; 18];

    // Off-diagonal products, each formed once.
    for i in 0..9 {
        let mut carry: u128 = 0;
        for j in (i + 1)..9 {
            let idx = i + j;
            let prod = (a[i] as u128) * (a[j] as u128) + (result[idx] as u128) + carry;
            result[idx] = prod as u64;
            carry = prod >> 64;
        }
        result[i + 9] = carry as u64;
    }

    // Every off-diagonal product appears twice in the square.
    let mut carry = 0u64;
    for limb in result.iter_mut() {
        let next_carry = *limb >> 63;
        // `*limb << 1` always leaves bit 0 clear and `carry` is only ever 0 or 1, so the two
        // operands are disjoint: mutating this `|` to `^` is an accepted equivalent, not a bug.
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
    debug_assert_eq!(carry, 0, "doubling the off-diagonal sum overflowed 18 limbs");

    // Diagonal squares.
    let mut carry: u128 = 0;
    for i in 0..9 {
        let square = (a[i] as u128) * (a[i] as u128);
        let low = (result[2 * i] as u128) + ((square as u64) as u128) + carry;
        result[2 * i] = low as u64;
        let high = (result[2 * i + 1] as u128) + (square >> 64) + (low >> 64);
        result[2 * i + 1] = high as u64;
        carry = high >> 64;
    }
    debug_assert_eq!(carry, 0, "adding the diagonal overflowed 18 limbs");

    result
}

/// `m * n`, one limb times the 9-limb modulus `n`, as the 10 limbs such a product can occupy.
///
/// This is exactly what each round of [`redc`]'s SOS reduction needs, and the shape
/// [`crate::montgomery::redc`] has always used for the brainpool curves. Every hand-written scalar
/// REDC in this crate previously formed it with the general 9x9 [`widening_mul`] against a
/// zero-padded `[m, 0, ..., 0]` instead, asking for 81 limb multiplications where 9 are needed.
///
/// Whether that padding costs anything turns out to depend entirely on the width, measured rather
/// than assumed: at four limbs the optimizer eliminates it completely (P-256 and secp256k1 time
/// identically either way), but it stops doing so by six, where the padded form measured 3.2x
/// slower per scalar multiplication for P-384 and 5.2x slower for P-521. All four are written this
/// way regardless, so the four modules read alike and none of them asks for work it does not want.
fn modulus_times_limb(m: u64) -> [u64; 10] {
    let mut out = [0u64; 10];
    let mut carry: u128 = 0;
    for j in 0..9 {
        let prod = (m as u128) * (N_LIMBS[j] as u128) + carry;
        out[j] = prod as u64;
        carry = prod >> 64;
    }
    out[9] = carry as u64;
    out
}

/// Montgomery reduction (SOS method): given an 18-limb value `t < n*R`, returns `t * R^-1 mod n`
/// as 9 limbs. See [`crate::p256_scalar::redc`]'s docs for the algorithm. Unlike that function's
/// 9th limb (or [`crate::p384_scalar::redc`]'s 13th), the accumulator's 19th limb here is always
/// `0` (module docs), so it is not consulted after the reduction rounds beyond a debug assertion.
fn redc(t: &[u64; 18]) -> [u64; 9] {
    let mut acc = [0u64; 19];
    acc[..18].copy_from_slice(t);

    for i in 0..9 {
        let m = acc[i].wrapping_mul(N_PRIME);
        let mn = modulus_times_limb(m);

        let mut carry: u128 = 0;
        for j in 0..10 {
            let idx = i + j;
            let s = (acc[idx] as u128) + (mn[j] as u128) + carry;
            acc[idx] = s as u64;
            carry = s >> 64;
        }
        let mut idx = i + 10;
        while carry != 0 {
            debug_assert!(idx < 19, "REDC overflowed its verified 19-limb bound");
            let s = (acc[idx] as u128) + carry;
            acc[idx] = s as u64;
            carry = s >> 64;
            idx += 1;
        }
    }
    debug_assert_eq!(&acc[..9], &[0u64; 9], "REDC's low limbs must be cleared after 9 rounds");
    debug_assert_eq!(acc[18], 0, "P-521 REDC's 19th limb is always 0 -- see module docs");

    let high: [u64; 9] =
        [acc[9], acc[10], acc[11], acc[12], acc[13], acc[14], acc[15], acc[16], acc[17]];
    let (diff, borrow) = nat::sub(&high, &N_LIMBS);
    let mut result = [0u64; 9];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &high, &diff, &mut result);
    result
}

/// Reduces an arbitrary `[u64; 9]` value (any of the `2^576` values that type can hold, not just
/// those `< 2n`) to its canonical representative `< n`.
///
/// Unlike P-256/P-384 (where `n` is close enough to `2^256`/`2^384` that a raw same-width limb
/// array is always `< 2n`, making a single conditional subtraction sufficient), P-521's `n` is
/// `2^521`-ish while this type's storage is a full `2^576`-wide `[u64; 9]` -- a 55-bit gap a caller
/// can easily fill (e.g. [`P521Scalar::from_be_bytes`]'s 66-byte/528-bit SEC 1 input, or simply any
/// `[u64; 9]` passed to `from_limbs`). An earlier version of this function assumed the gap couldn't
/// be filled and used a single conditional subtraction unconditionally; that assumption was false
/// (a raw `[u64; 9]` can represent values up to `2^576 - 1`), so it under-reduced any input `>=
/// 2n` -- caught not by this crate's own property tests (whose pseudorandom `[u64; 9]` values
/// happened to make the bug's output still self-consistent, see `p521_scalar_tests.rs`'s docs) but
/// by real ECDSA verification math in the wycheproof P-521 suite, where a legitimately-bounded
/// scalar's `redc` calls took a code path this crate's own tests never reached.
///
/// The fix: split `limbs` into `hi = limbs >> 521` (the excess, `< 2^55`) and `lo = limbs mod
/// 2^521` (`< 2^521`), then fold via `value ≡ hi * (2^521 mod n) + lo (mod n)`
/// ([`TWO_POW_521_MOD_N_LIMBS`]). Verified (not checked in) against 300,000 random 9-limb trials
/// plus boundary cases (`n`, `n-1`, `2n-1`, all-ones, max-`hi`-with-max-`lo`) that the folded sum
/// is always `< 2n`, so the single conditional subtraction below remains valid -- the same
/// two-step shape as this crate's Solinas-prime field reductions, just with a genuine ~259-bit fold
/// constant instead of a small one, since `n` has no special algebraic form to exploit.
fn reduce_wide(limbs: [u64; 9]) -> [u64; 9] {
    let hi = limbs[8] >> 9;
    let mut lo = limbs;
    lo[8] &= 0x1ff;

    let mut hi_limbs = [0u64; 9];
    hi_limbs[0] = hi;
    let product = widening_mul(&hi_limbs, &TWO_POW_521_MOD_N_LIMBS);
    let product_low: [u64; 9] = product[..9].try_into().unwrap();
    debug_assert_eq!(
        &product[9..],
        &[0u64; 9],
        "hi * C must fit in 9 limbs (hi < 2^55, C < 2^259)"
    );

    let (folded, carry) = nat::add(&lo, &product_low);
    debug_assert_eq!(carry, 0, "fold sum must fit in 9 limbs (proven < 2n < 2^522)");

    let (diff, borrow) = nat::sub(&folded, &N_LIMBS);
    let mut result = [0u64; 9];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &folded, &diff, &mut result);
    result
}

/// A scalar mod `n`, `< n`, held in `Secret`. See [`crate::p256_scalar::P256Scalar`]'s docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P521Scalar(Secret<[u64; 9]>);

impl P521Scalar {
    /// Builds a secret scalar from little-endian `u64` limbs, reducing via [`reduce_wide`] (valid
    /// for any of the `2^576` values a raw `[u64; 9]` can represent, not just those `< 2n`).
    pub fn from_limbs(limbs: [u64; 9]) -> Self {
        let mut secret = Secret::<[u64; 9]>::new();
        *secret = reduce_wide(limbs);
        Self(secret)
    }

    /// Builds a secret scalar from SEC 1 §2.3.7 big-endian octets, reducing via [`reduce_wide`] --
    /// needed here specifically: 66 bytes is 528 bits, 7 more than `n`'s 521, so this input is not
    /// generally `< 2n` the way P-256/P-384's exactly-sized SEC 1 encodings are.
    pub fn from_be_bytes(bytes: &[u8; 66]) -> Self {
        Self::from_limbs(crate::p521_sec1::limbs_from_be_bytes(bytes))
    }

    /// Encodes to SEC 1 §2.3.7 big-endian octets.
    pub fn to_be_bytes(&self) -> [u8; 66] {
        crate::p521_sec1::be_bytes_from_limbs(&self.0)
    }

    /// The scalar's limbs, for the crate's own multiplier and field-arithmetic implementations to
    /// read. Not exposed outside the crate.
    pub(crate) fn limbs(&self) -> &[u64; 9] {
        &self.0
    }
}

/// A scalar mod `n`, `< n`, held as a plain (non-secret) value. See
/// [`crate::p256_scalar::P256PublicScalar`]'s docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P521PublicScalar([u64; 9]);

impl P521PublicScalar {
    /// Builds a public scalar from little-endian `u64` limbs, reducing via [`reduce_wide`] (valid
    /// for any of the `2^576` values a raw `[u64; 9]` can represent, not just those `< 2n`).
    pub fn from_limbs(limbs: [u64; 9]) -> Self {
        Self(reduce_wide(limbs))
    }

    /// Returns the scalar's little-endian `u64` limbs, `< n`.
    pub fn to_limbs(&self) -> [u64; 9] {
        self.0
    }
}

// `redc`'s carry-propagation loop (`while carry != 0` above) is a genuinely reachable branch --
// verified by instrumenting it with an unconditional `panic!` and confirming it fires during real
// signature verification (the wycheproof P-521 suite in `bouncycastle-ecdsa`) -- but this crate's
// own tests never happened to trigger it: not `algebraic_identities_over_many_pseudorandom_values`
// (hundreds of thousands of `redc` calls via `invert`'s ~585 multiplications per iteration, over
// 1000 iterations, all with uniformly random `< n` operands), nor any of this module's other
// tests. `redc` is private, so this can't be pinned through the public API either; the
// QUALITY_AND_STYLE.md "private function, known-answer, can't be reached cleanly from outside the
// crate" exception applies. `T_LIMBS` is the exact 18-limb product that triggered the panic in the
// wycheproof run (captured by printing it, not hand-derived); `EXPECTED` was computed independently
// in Python two ways -- `(t * pow(R, -1, n)) % n` directly, and a line-by-line simulation of this
// same SOS algorithm -- which agreed with each other before either was compared to this crate's
// own output.
#[cfg(test)]
mod tests {
    use super::*;

    const T_LIMBS: [u64; 18] = [
        0x316b3dda1d070851, 0x69303a5b0ee10995, 0x3238669d5bd66d1a, 0x9828b88f2d9faf39,
        0xd229922b690684d0, 0x10ee65adb877b80b, 0x7fd5e3973e0f3364, 0xde220c48e8776f64,
        0x3a7e5d51b462c5ca, 0x4e0e624d9721269a, 0xa770b74d39cfd04c, 0x19b6118eac6cf99f,
        0xa30d0f077e5f161d, 0xfffffffffffffff4, 0xffffffffffffffff, 0xffffffffffffffff,
        0x000000000003ffff, 0x0000000000000000,
    ];
    // Coincidentally equal to R_LIMBS (this input happened to arise from a step of Fermat
    // inversion computing a value's final `a * a^(n-2) = a^(n-1) == 1`, i.e. `1`'s own Montgomery
    // form) -- written out literally rather than as `R_LIMBS` so this stays a KAT against an
    // independently computed value, not a reference to another constant in this file.
    const EXPECTED: [u64; 9] = [
        0xfb80000000000000, 0x28a2482470b763cd, 0x17e2251b23bb31dc, 0xca4019ff5b847b2d,
        0x02d73cbc3e206834, 0, 0, 0, 0,
    ];

    #[test]
    fn redc_handles_the_rare_carry_propagation_case() {
        assert_eq!(redc(&T_LIMBS), EXPECTED);
    }
}
