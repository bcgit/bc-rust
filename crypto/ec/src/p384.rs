//! The P-384 base field, GF(p) for `p = 2^384 - 2^128 - 2^96 + 2^32 - 1`.
//!
//! Domain parameters are from NIST SP 800-186 (Feb 2023) §3.2.1.4, "Curve P-384": the prime `p`
//! quoted there in hex is
//! `0xffffffff ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe ffffffff 00000000
//! 00000000 ffffffff` (384 bits, most significant word first). [`P_LIMBS`] below is that same
//! value in little-endian `u64` limbs.
//!
//! # Reduction algorithm
//!
//! Same shape as [`crate::p256`]'s (see that module's docs): `p` is a generalized Mersenne number,
//! so a 768-bit product reduces to a fixed sum and difference of 384-bit terms assembled from the
//! product's own 32-bit words, with no multiplication at all. SP 800-186 (Feb 2023) Appendix
//! G.1.3, "Curve P-384", gives the expression -- `B = (T + 2S1 + S2 + S3 + S4 + S5 + S6 - D1 - D2
//! - D3) mod p` -- and [`reduce`] transcribes it directly, so a reviewer with G.1.3 open can match
//! its ten terms to the document row by row.
//!
//! G.1's preamble states the precondition ("given an integer A less than m^2") and the shape of
//! the leftover work ("the integer sum or difference can be evaluated and the result reduced
//! modulo m. The latter reduction can be accomplished by adding or subtracting a few copies of
//! m."); [`reduce`] carries the exact bound on how many copies that is here.
//!
//! The identity `2^384 = p + C` with `C = 2^128 + 2^96 - 2^32 + 1` (i.e. `2^384 mod p = C`)
//! survives in two places: [`P384FieldElement::add`] uses it to correct a carry out of the top
//! limb, and [`reduce`]'s final fold uses it on the accumulator's top limb.

use crate::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `p`, little-endian `u64` limbs (SP 800-186 §3.2.1.4).
pub const P_LIMBS: [u64; 6] = [
    0x00000000ffffffff, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff,
];

/// `2^384 mod p = 2^128 + 2^96 - 2^32 + 1`, little-endian `u64` limbs. This is the constant
/// [`reduce`]'s fold uses in place of `2^384`.
const C_LIMBS: [u64; 6] = [0xffffffff00000001, 0x00000000ffffffff, 0x0000000000000001, 0, 0, 0];

/// `p - 2`, little-endian `u64` limbs -- the public exponent [`P384FieldElement::invert`] raises
/// its base to, per Fermat's little theorem.
const P_MINUS_2_LIMBS: [u64; 6] = [
    0x00000000fffffffd, 0xffffffff00000000, 0xfffffffffffffffe, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff,
];

/// `4p`, little-endian `u64` limbs -- the bias [`reduce`] starts its accumulator at so that
/// subtracting SP 800-186 §G.1.3's three `D` terms can never take it below zero. See [`reduce`]
/// for why `4` is the right multiple.
const FOUR_P_LIMBS: [u64; 7] = [
    0x00000003fffffffc, 0xfffffffc00000000, 0xfffffffffffffffb, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0x0000000000000003,
];

/// An element of the P-384 base field GF(p), always held in canonical reduced form (`< p`).
#[derive(Clone, Copy, Debug)]
pub struct P384FieldElement([u64; 6]);

impl P384FieldElement {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0]);

    /// Builds a field element from little-endian `u64` limbs, reducing once if `limbs >= p`. Any
    /// `u64` limb pattern is accepted: since `limbs < 2^384 < 2*p`, a single conditional
    /// subtraction of `p` always suffices to bring it into `[0, p)`.
    pub fn from_limbs(limbs: [u64; 6]) -> Self {
        let (diff, borrow) = nat::sub(&limbs, &P_LIMBS);
        let mut result = [0u64; 6];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut result);
        Self(result)
    }

    /// Returns the canonical little-endian `u64` limbs, `< p`.
    pub fn to_limbs(&self) -> [u64; 6] {
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
        let mut when_no_carry = [0u64; 6];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &sum, &diff, &mut when_no_carry);
        let mut result = [0u64; 6];
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
        let mut result = [0u64; 6];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod p`.
    pub fn negate(&self) -> Self {
        let (diff, _) = nat::sub(&P_LIMBS, &self.0);
        let mut result = [0u64; 6];
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
        for limb_idx in (0..6).rev() {
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

impl PartialEq for P384FieldElement {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..6 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for P384FieldElement {}

/// Schoolbook widening multiply of two 6-limb (384-bit) operands into a 12-limb (768-bit) product.
/// See [`crate::p256`]'s widening_mul docs for why this is duplicated per curve.
fn widening_mul(a: &[u64; 6], b: &[u64; 6]) -> [u64; 12] {
    let mut result = [0u64; 12];
    for i in 0..6 {
        let mut carry: u128 = 0;
        for j in 0..6 {
            let idx = i + j;
            let prod = (a[i] as u128) * (b[j] as u128) + (result[idx] as u128) + carry;
            result[idx] = prod as u64;
            carry = prod >> 64;
        }
        let mut k = i + 6;
        while k < 12 {
            let s = (result[k] as u128) + carry;
            result[k] = s as u64;
            carry = s >> 64;
            k += 1;
        }
    }
    result
}

/// The 32-bit word `A_i` of the 768-bit product, in SP 800-186 §G.1.3's numbering: that appendix
/// writes the product as `A = (A23 || A22 || ... || A0)` with each `A_i` a 32-bit integer, `A0`
/// least significant.
fn word(t: &[u64; 12], i: usize) -> u64 {
    (t[i / 2] >> (32 * (i % 2))) & 0xffff_ffff
}

/// Assembles one of §G.1.3's 384-bit terms from its twelve 32-bit words. The document prints each
/// term most significant word first; this takes them least significant first, so each call site
/// below reads its document row right to left.
fn term(w: [u64; 12]) -> [u64; 6] {
    [
        w[0] | (w[1] << 32),
        w[2] | (w[3] << 32),
        w[4] | (w[5] << 32),
        w[6] | (w[7] << 32),
        w[8] | (w[9] << 32),
        w[10] | (w[11] << 32),
    ]
}

/// Zero-extends a 6-limb value to 7 limbs, for arithmetic against the 7-limb accumulator.
fn widen(v: &[u64; 6]) -> [u64; 7] {
    [v[0], v[1], v[2], v[3], v[4], v[5], 0]
}

/// `small * v`, one limb times a 6-limb value, as 7 limbs. Only ever called with a `small` that is
/// a bounded, operand-independent count (see [`reduce`]), never a secret.
fn mul_small(small: u64, v: &[u64; 6]) -> [u64; 7] {
    let mut out = [0u64; 7];
    let mut carry: u128 = 0;
    for i in 0..6 {
        let prod = (small as u128) * (v[i] as u128) + carry;
        out[i] = prod as u64;
        carry = prod >> 64;
    }
    out[6] = carry as u64;
    out
}

/// Schoolbook squaring of a 6-limb value into its 12-limb square.
///
/// `a * a` is symmetric: the product `a_i * a_j` appears twice for every `i != j`. Forming each of
/// those once and doubling costs `L(L+1)/2` limb multiplications -- 21 at this width against
/// the 36 [`widening_mul`] would form for the same value.
///
/// Three passes: the off-diagonal products `a_i * a_j` for `i < j`; a doubling of the whole
/// accumulator; then the diagonal squares `a_i * a_i` added in at limb `2i`. Writing `result[i +
/// 6]` in the first pass is an assignment rather than an accumulation because row `i` only ever
/// reaches limbs `2i + 1 ..= i + 6 - 1`, and no earlier row reaches limb `i + 6` either, so that
/// limb is still zero when the row's final carry lands on it. The doubling cannot overflow: the
/// off-diagonal sum is strictly less than `a^2 / 2`.
///
/// Verified against Python's arbitrary-precision `**2` over 20,000 random 6-limb values plus the
/// all-ones worst case before being written here.
fn widening_square(a: &[u64; 6]) -> [u64; 12] {
    let mut result = [0u64; 12];

    // Off-diagonal products, each formed once.
    for i in 0..6 {
        let mut carry: u128 = 0;
        for j in (i + 1)..6 {
            let idx = i + j;
            let prod = (a[i] as u128) * (a[j] as u128) + (result[idx] as u128) + carry;
            result[idx] = prod as u64;
            carry = prod >> 64;
        }
        result[i + 6] = carry as u64;
    }

    // Every off-diagonal product appears twice in the square.
    let mut carry = 0u64;
    for limb in result.iter_mut() {
        let next_carry = *limb >> 63;
        *limb = (*limb << 1) | carry;
        carry = next_carry;
    }
    debug_assert_eq!(carry, 0, "doubling the off-diagonal sum overflowed 12 limbs");

    // Diagonal squares.
    let mut carry: u128 = 0;
    for i in 0..6 {
        let square = (a[i] as u128) * (a[i] as u128);
        let low = (result[2 * i] as u128) + ((square as u64) as u128) + carry;
        result[2 * i] = low as u64;
        let high = (result[2 * i + 1] as u128) + (square >> 64) + (low >> 64);
        result[2 * i + 1] = high as u64;
        carry = high >> 64;
    }
    debug_assert_eq!(carry, 0, "adding the diagonal overflowed 12 limbs");

    result
}

/// Reduces a 12-limb (768-bit) value modulo `p`, per SP 800-186 §G.1.3 (see the module docs).
///
/// **Precondition: `t < p^2`**, which is G.1's own stated precondition ("given an integer A less
/// than m^2") and holds for every call site, since `mul` is the only one and it passes the product
/// of two canonical (`< p`) field elements. The bounds below all rest on it; a raw 768-bit value
/// near `2^768` is *not* reduced correctly by this function.
///
/// Bounds. Each of the ten terms is a 384-bit value, so `T + 2*S1 + S2 + S3 + S4 + S5 + S6 <
/// 8*2^384` and `D1 + D2 + D3 < 3*2^384`. Starting the accumulator at `4p` therefore keeps it
/// non-negative throughout (`4p > 3*2^384`, since `4p - 3*2^384 = 2^384 - 4*2^128 - ... > 0`) and
/// bounded by `4p + 8*2^384 < 12*2^384`, so seven limbs are always enough and the top limb is at
/// most 11. Folding that top limb back in via `2^384 ≡ C` adds `u_hi*C < 12*2^129 < 2^133`,
/// leaving `V < 2^384 + 2^133`; since `p > 2^384 - 2^129`, `V - p < 2^133 + 2^129 < p`, so exactly
/// one conditional subtraction finishes the job.
fn reduce(t: &[u64; 12]) -> [u64; 6] {
    let a = |i: usize| word(t, i);

    // SP 800-186 §G.1.3's ten terms, each row read right to left from the document.
    let t_term = term([a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7), a(8), a(9), a(10), a(11)]);
    let s1 = term([0, 0, 0, 0, a(21), a(22), a(23), 0, 0, 0, 0, 0]);
    let s2 =
        term([a(12), a(13), a(14), a(15), a(16), a(17), a(18), a(19), a(20), a(21), a(22), a(23)]);
    let s3 =
        term([a(21), a(22), a(23), a(12), a(13), a(14), a(15), a(16), a(17), a(18), a(19), a(20)]);
    let s4 = term([0, a(23), 0, a(20), a(12), a(13), a(14), a(15), a(16), a(17), a(18), a(19)]);
    let s5 = term([0, 0, 0, 0, a(20), a(21), a(22), a(23), 0, 0, 0, 0]);
    let s6 = term([a(20), 0, 0, a(21), a(22), a(23), 0, 0, 0, 0, 0, 0]);
    let d1 =
        term([a(23), a(12), a(13), a(14), a(15), a(16), a(17), a(18), a(19), a(20), a(21), a(22)]);
    let d2 = term([0, a(20), a(21), a(22), a(23), 0, 0, 0, 0, 0, 0, 0]);
    let d3 = term([0, 0, 0, a(23), a(23), 0, 0, 0, 0, 0, 0, 0]);

    // B + 4p = 4p + T + 2*S1 + S2 + S3 + S4 + S5 + S6 - D1 - D2 - D3, over seven limbs. `S1`
    // appears twice rather than being doubled, so every step is the same 7-limb add.
    let mut acc = FOUR_P_LIMBS;
    for addend in [&t_term, &s1, &s1, &s2, &s3, &s4, &s5, &s6] {
        let (sum, carry) = nat::add(&acc, &widen(addend));
        debug_assert_eq!(carry, 0, "P-384 reduction accumulator overflowed 7 limbs");
        acc = sum;
    }
    for subtrahend in [&d1, &d2, &d3] {
        let (diff, borrow) = nat::sub(&acc, &widen(subtrahend));
        debug_assert_eq!(
            borrow, 0,
            "P-384 reduction accumulator went negative despite the 4p bias"
        );
        acc = diff;
    }

    // Fold the accumulator's top limb back in: `2^384 ≡ C (mod p)`.
    debug_assert!(acc[6] <= 11, "P-384 reduction top limb exceeded its proven bound");
    let low: [u64; 6] = [acc[0], acc[1], acc[2], acc[3], acc[4], acc[5]];
    let (v, carry) = nat::add(&mul_small(acc[6], &C_LIMBS), &widen(&low));
    debug_assert_eq!(carry, 0, "P-384 reduction fold overflowed 7 limbs");

    let (diff, borrow) = nat::sub(&v, &widen(&P_LIMBS));
    let mut selected = [0u64; 7];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &v, &diff, &mut selected);
    debug_assert_eq!(selected[6], 0, "P-384 reduction left a value >= 2^384");
    [selected[0], selected[1], selected[2], selected[3], selected[4], selected[5]]
}
