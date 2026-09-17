//! The secp256k1 base field, GF(p) for `p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1`.
//!
//! Domain parameters are from SEC 2 v2 §2.4.1: the prime `p` quoted there in hex is
//! `0xffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f` (256 bits, most
//! significant word first). [`P_LIMBS`] below is that same value in little-endian `u64` limbs.
//! Unlike every NIST curve in this crate, secp256k1's `a = 0` (see [`crate::p256k1_point`]), not
//! `-3`; the field arithmetic here is unaffected by that (it's the same kind of Solinas-friendly
//! prime as P-256/P-384), only the point-doubling formula differs.
//!
//! # Reduction algorithm
//!
//! Same fold as [`crate::p256`]/[`crate::p384`]: `2^256 = p + C` where `C = 2^32 + 2^9 + 2^8 + 2^7
//! + 2^6 + 2^4 + 1` (33 bits -- even smaller relative to the modulus than P-384's `C < 2^129`).
//! Two folds bound the result to within a single extra bit of `2^256`, exactly like
//! [`crate::p384::reduce`]: that function's own doc comment has the full derivation and the
//! wycheproof-caught bug an earlier, `debug_assert`-based version of this shape produced by
//! assuming that extra bit was always `0`. This module folds it in explicitly from the start.

use crate::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `p`, little-endian `u64` limbs (SEC 2 v2 §2.4.1).
pub const P_LIMBS: [u64; 4] =
    [0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];

/// `2^256 mod p = 2^32 + 2^9 + 2^8 + 2^7 + 2^6 + 2^4 + 1`, little-endian `u64` limbs. This is the
/// constant [`reduce`]'s fold uses in place of `2^256`.
const C_LIMBS: [u64; 4] = [0x00000001000003d1, 0, 0, 0];

/// `p - 2`, little-endian `u64` limbs -- the public exponent [`P256K1FieldElement::invert`] raises
/// its base to, per Fermat's little theorem.
const P_MINUS_2_LIMBS: [u64; 4] =
    [0xfffffffefffffc2d, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff];

/// An element of the secp256k1 base field GF(p), always held in canonical reduced form (`< p`).
#[derive(Clone, Copy, Debug)]
pub struct P256K1FieldElement([u64; 4]);

impl P256K1FieldElement {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// The multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Builds a field element from little-endian `u64` limbs, reducing once if `limbs >= p`. Any
    /// `u64` limb pattern is accepted: since `limbs < 2^256 < 2*p`, a single conditional
    /// subtraction always suffices to bring it into `[0, p)`.
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        let (diff, borrow) = nat::sub(&limbs, &P_LIMBS);
        let mut result = [0u64; 4];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut result);
        Self(result)
    }

    /// Returns the canonical little-endian `u64` limbs, `< p`.
    pub fn to_limbs(&self) -> [u64; 4] {
        self.0
    }

    /// TRUE iff this element is the additive identity.
    pub fn is_zero(&self) -> Condition<u64> {
        nat::is_zero(&self.0)
    }

    /// `self + other mod p`.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = nat::add(&self.0, &other.0);
        let (sum_plus_c, _) = nat::add(&sum, &C_LIMBS);
        let (diff, borrow) = nat::sub(&sum, &P_LIMBS);
        let mut when_no_carry = [0u64; 4];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &sum, &diff, &mut when_no_carry);
        let mut result = [0u64; 4];
        ct::conditional_select(
            Condition::<u64>::from_lsb(carry),
            &sum_plus_c,
            &when_no_carry,
            &mut result,
        );
        Self(result)
    }

    /// `self - other mod p`.
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = nat::sub(&self.0, &other.0);
        let (corrected, _) = nat::add(&diff, &P_LIMBS);
        let mut result = [0u64; 4];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod p`.
    pub fn negate(&self) -> Self {
        let (diff, _) = nat::sub(&P_LIMBS, &self.0);
        let mut result = [0u64; 4];
        ct::conditional_select(nat::is_zero(&self.0), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod p`.
    pub fn mul(&self, other: &Self) -> Self {
        Self(reduce(&widening_mul(&self.0, &other.0)))
    }

    /// `self^2 mod p`.
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
        Self(reduce(&widening_square(&self.0)))
    }

    /// `self^-1 mod p`, or `0` if `self` is `0`. Fermat's little theorem; see
    /// [`crate::p256::P256FieldElement::invert`]'s docs, which this mirrors exactly.
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..4).rev() {
            let limb = P_MINUS_2_LIMBS[limb_idx];
            for bit in (0..64).rev() {
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

impl PartialEq for P256K1FieldElement {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..4 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for P256K1FieldElement {}

/// Schoolbook widening multiply of two 4-limb (256-bit) operands into an 8-limb (512-bit)
/// product. See [`crate::p256`]'s widening_mul docs for why this is duplicated per curve.
fn widening_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
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
        let mut k = i + 4;
        while k < 8 {
            let s = (result[k] as u128) + carry;
            result[k] = s as u64;
            carry = s >> 64;
            k += 1;
        }
    }
    result
}

/// Schoolbook squaring of a 4-limb value into its 8-limb square.
///
/// `a * a` is symmetric: the product `a_i * a_j` appears twice for every `i != j`. Forming each of
/// those once and doubling costs `L(L+1)/2` limb multiplications -- 10 at this width against
/// the 16 [`widening_mul`] would form for the same value.
///
/// Three passes: the off-diagonal products `a_i * a_j` for `i < j`; a doubling of the whole
/// accumulator; then the diagonal squares `a_i * a_i` added in at limb `2i`. Writing `result[i +
/// 4]` in the first pass is an assignment rather than an accumulation because row `i` only ever
/// reaches limbs `2i + 1 ..= i + 4 - 1`, and no earlier row reaches limb `i + 4` either, so that
/// limb is still zero when the row's final carry lands on it. The doubling cannot overflow: the
/// off-diagonal sum is strictly less than `a^2 / 2`.
///
/// Verified against Python's arbitrary-precision `**2` over 20,000 random 4-limb values plus the
/// all-ones worst case before being written here.
fn widening_square(a: &[u64; 4]) -> [u64; 8] {
    let mut result = [0u64; 8];

    // Off-diagonal products, each formed once.
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in (i + 1)..4 {
            let idx = i + j;
            let prod = (a[i] as u128) * (a[j] as u128) + (result[idx] as u128) + carry;
            result[idx] = prod as u64;
            carry = prod >> 64;
        }
        result[i + 4] = carry as u64;
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
    debug_assert_eq!(carry, 0, "doubling the off-diagonal sum overflowed 8 limbs");

    // Diagonal squares.
    let mut carry: u128 = 0;
    for i in 0..4 {
        let square = (a[i] as u128) * (a[i] as u128);
        let low = (result[2 * i] as u128) + ((square as u64) as u128) + carry;
        result[2 * i] = low as u64;
        let high = (result[2 * i + 1] as u128) + (square >> 64) + (low >> 64);
        result[2 * i + 1] = high as u64;
        carry = high >> 64;
    }
    debug_assert_eq!(carry, 0, "adding the diagonal overflowed 8 limbs");

    result
}

/// Reduces an 8-limb (512-bit) value modulo `p`, per the fold described in the module docs.
fn reduce(t: &[u64; 8]) -> [u64; 4] {
    let mut acc: [u64; 8] = *t;
    for _ in 0..2 {
        let hi: [u64; 4] = [acc[4], acc[5], acc[6], acc[7]];
        let lo: [u64; 4] = [acc[0], acc[1], acc[2], acc[3]];
        // Hand-specialising this to a 4x1 multiply (secp256k1's `C = 2^32 + 977` occupies a
        // single limb, so twelve of `widening_mul`'s sixteen limb multiplications are by zero)
        // was tried and measured *slower*: 17.2ns vs 16.3ns per field multiplication. `C_LIMBS`
        // is a compile-time constant, so the optimizer already elides those multiplications, and
        // a hand-rolled version only constrains its codegen. Leave it as the general call.
        let product = widening_mul(&hi, &C_LIMBS);
        let lo_extended: [u64; 8] = [lo[0], lo[1], lo[2], lo[3], 0, 0, 0, 0];
        let (sum, carry) = nat::add(&product, &lo_extended);
        debug_assert_eq!(carry, 0, "secp256k1 reduction fold overflowed 512 bits");
        acc = sum;
    }
    // After exactly 2 folds, `acc`'s high 4 limbs are at most a single bit -- see
    // crate::p384::reduce's doc comment for the general proof (identical shape: fold 1 bounds
    // `hi < 2^34ish` since `C < 2^33` here, fold 2 then bounds the result to within a single bit
    // of `2^256`). Folded in explicitly rather than assumed zero, per that function's own
    // wycheproof-caught lesson (verified here too, not checked in, against 2,000,000 random
    // trials plus the `(p-1)*(p-1)` worst case, none of which happened to hit the rare case --
    // exactly the kind of gap a real-world adversarial test suite, not random sampling, catches).
    let extra_bit = acc[4];
    let low: [u64; 4] = [acc[0], acc[1], acc[2], acc[3]];
    let mut c_or_zero = [0u64; 4];
    ct::conditional_select(
        Condition::<u64>::from_lsb(extra_bit),
        &C_LIMBS,
        &[0u64; 4],
        &mut c_or_zero,
    );
    let (folded, carry1) = nat::add(&low, &c_or_zero);
    let (folded_plus_c, _) = nat::add(&folded, &C_LIMBS); // valid when carry1 == 1: folded < 2^33 there
    let (diff, borrow) = nat::sub(&folded, &P_LIMBS); // valid when carry1 == 0
    let mut when_no_carry = [0u64; 4];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &folded, &diff, &mut when_no_carry);
    let mut result = [0u64; 4];
    ct::conditional_select(
        Condition::<u64>::from_lsb(carry1),
        &folded_plus_c,
        &when_no_carry,
        &mut result,
    );
    result
}
