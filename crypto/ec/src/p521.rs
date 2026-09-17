//! The P-521 base field, GF(p) for `p = 2^521 - 1` (a Mersenne prime).
//!
//! Domain parameters are from NIST SP 800-186 (Feb 2023) §3.2.1.4, "Curve P-521". [`P_LIMBS`]
//! holds `p` in little-endian `u64` limbs, 9 limbs (576 bits of storage) for the 521-bit value;
//! the top limb only ever uses its low 9 bits (`0x1ff`).
//!
//! # Reduction algorithm
//!
//! Same fold shape as [`crate::p256`] and [`crate::p384`]: `2^521 = p + 1`, i.e. `C = 1`, the
//! simplest possible case (no widening multiply needed for the fold at all -- just an add). For a
//! product `t = a*b` with `a, b < p < 2^521` (so `t < 2^1042`): fold 1 splits `t` into `hi0 =
//! t >> 521 < 2^521` and `lo0 = t mod 2^521 < 2^521`, giving `acc1 = hi0 + lo0 < 2^522`; fold 2
//! splits `acc1` into `hi1 = acc1 >> 521 < 2` and `lo1 = acc1 mod 2^521 < 2^521`, giving `acc2 =
//! hi1 + lo1`. Unlike [`crate::p384::reduce`] (whose analogous two-fold bound leaves room for a
//! rare extra bit above `2^521`'s P-384 equivalent -- see that function's comment for the bug this
//! caused there), `acc2` here is *provably* always `< 2^521`: `acc1 <= 2*(2^521 - 1) = 2^522 - 2`
//! (both `hi0` and `lo0` are `<= 2^521 - 1`), which excludes `acc1 = 2^522 - 1`, the only value
//! that would let `hi1 = 1` and `lo1 = 2^521 - 1` hold simultaneously and push `acc2` to exactly
//! `2^521`. So two folds always leave a clean `< 2^521` result, needing only the usual single
//! conditional subtraction of `p` (verified, not checked in, against 500,000 random trials plus
//! the `(p-1)*(p-1)` worst case, in addition to the proof above).

use crate::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `p`, little-endian `u64` limbs (SP 800-186 §3.2.1.4); the top limb only uses its low 9 bits.
pub const P_LIMBS: [u64; 9] = [
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0x00000000000001ff,
];

/// `p - 2`, little-endian `u64` limbs -- the public exponent [`P521FieldElement::invert`] raises
/// its base to, per Fermat's little theorem.
const P_MINUS_2_LIMBS: [u64; 9] = [
    0xfffffffffffffffd, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    0x00000000000001ff,
];

/// An element of the P-521 base field GF(p), always held in canonical reduced form (`< p`).
#[derive(Clone, Copy, Debug)]
pub struct P521FieldElement([u64; 9]);

impl P521FieldElement {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// Builds a field element from little-endian `u64` limbs, accepting the type's *entire*
    /// 576-bit storage range (unlike [`crate::p256::P256FieldElement::from_limbs`] and
    /// [`crate::p384::P384FieldElement::from_limbs`], whose native limb width matches their
    /// curve's bit width exactly, this one has 55 spare bits above `p`'s 521). Simply masking
    /// those spare bits away would silently discard them -- `p + 1 = 2^521` sets only bit 521, so
    /// masking it off would wrongly produce `0` instead of correctly reducing to `1` -- so instead
    /// the top limb's bits 9-63 (`>> 9`, at most 55 bits) are folded back in via `2^521 ≡ 1 (mod
    /// p)`, the same identity [`reduce`] uses: the fold's sum is `< 2^521 + 2^55`, comfortably `<
    /// 2p`, so one conditional subtraction still suffices.
    pub fn from_limbs(limbs: [u64; 9]) -> Self {
        let hi_val = limbs[8] >> 9;
        let mut lo = limbs;
        lo[8] &= 0x1ff;
        let (folded, carry) = nat::add(&lo, &[hi_val, 0, 0, 0, 0, 0, 0, 0, 0]);
        debug_assert_eq!(carry, 0, "P-521 from_limbs fold overflowed 9 limbs");
        let (diff, borrow) = nat::sub(&folded, &P_LIMBS);
        let mut result = [0u64; 9];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &folded, &diff, &mut result);
        Self(result)
    }

    /// Returns the canonical little-endian `u64` limbs, `< p`.
    pub fn to_limbs(&self) -> [u64; 9] {
        self.0
    }

    /// TRUE iff this element is the additive identity.
    pub fn is_zero(&self) -> Condition<u64> {
        nat::is_zero(&self.0)
    }

    /// `self + other mod p`.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = nat::add(&self.0, &other.0);
        // true_sum = sum + carry*2^576; self,other < p < 2^521, so true_sum < 2p < 2^522, and the
        // carry out of the 9-limb (576-bit) add can only ever be 0 in practice (2p < 2^576 with
        // huge headroom) -- kept for structural symmetry with the other curves' `add`, and
        // debug-asserted rather than silently trusted.
        debug_assert_eq!(carry, 0, "P-521 add overflowed 576 bits, which should be unreachable");
        let (diff, borrow) = nat::sub(&sum, &P_LIMBS);
        let mut result = [0u64; 9];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &sum, &diff, &mut result);
        Self(result)
    }

    /// `self - other mod p`.
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = nat::sub(&self.0, &other.0);
        let (corrected, _) = nat::add(&diff, &P_LIMBS);
        let mut result = [0u64; 9];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod p`.
    pub fn negate(&self) -> Self {
        let (diff, _) = nat::sub(&P_LIMBS, &self.0);
        let mut result = [0u64; 9];
        ct::conditional_select(nat::is_zero(&self.0), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod p`.
    pub fn mul(&self, other: &Self) -> Self {
        Self(reduce(&widening_mul(&self.0, &other.0)))
    }

    /// `self^2 mod p`.
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// `self^-1 mod p`, or `0` if `self` is `0`. Fermat's little theorem.
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..9).rev() {
            let limb = P_MINUS_2_LIMBS[limb_idx];
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

impl PartialEq for P521FieldElement {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..9 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for P521FieldElement {}

/// Schoolbook widening multiply of two 9-limb operands (of which only the low 521 bits are ever
/// nonzero) into an 18-limb product.
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
        // Mutating `carry = s >> 64` here (e.g. to `<< 64`) is an accepted mutant, not a bug: this
        // loop's carry is always `0` or `1` at each step (`s` sums two u64-range values, so `s <
        // 2^65`), and a value produced by `<< 64` has all its bits at position 64 or above -- so it
        // contributes nothing to `result[k'] as u128 + carry`'s low 64 bits at the next iteration,
        // `result[k']` is written unchanged, and the "carry" that comes back out is again pure
        // high bits, propagating forever without ever affecting `result` (which is all this
        // function returns; `carry` itself is discarded once the loop ends). This holds for any
        // input, not just this crate's own `< p` values -- confirmed both by this argument and by
        // hand-mutating this exact line and finding no test (including a version instrumented to
        // panic whenever this loop's incoming carry is nonzero, which it regularly is) notices.
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

/// Reduces an 18-limb (1042-bit-capacity) value modulo `p`, per the fold described in the module
/// docs: `2^521 ≡ 1 (mod p)`, so each fold is a plain add of the high and low 521-bit halves.
fn reduce(t: &[u64; 18]) -> [u64; 9] {
    let mut acc: [u64; 18] = *t;
    for _ in 0..2 {
        // Split at bit 521: the low 8 limbs plus the low 9 bits of limb 8 are `lo`; the rest of
        // limb 8 (bits 9-63) plus limbs 9..18 form `hi`, shifted down by 521 bits.
        let mut hi = [0u64; 9];
        for i in 0..9 {
            // `acc[8+i] >> 9` fills bits 0-54 of the result; `acc[9+i] << 55` fills bits 55-63
            // (only its own low 9 bits survive the shift) -- disjoint, so `|` and `^` agree here.
            hi[i] = (acc[8 + i] >> 9) | (acc[9 + i] << 55);
        }
        let mut lo = [0u64; 9];
        lo[..8].copy_from_slice(&acc[..8]);
        lo[8] = acc[8] & 0x1ff;

        let (sum, carry) = nat::add(&hi, &lo);
        debug_assert_eq!(carry, 0, "P-521 reduction fold overflowed 9 limbs");
        acc = [
            sum[0], sum[1], sum[2], sum[3], sum[4], sum[5], sum[6], sum[7], sum[8], 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
    }
    let low: [u64; 9] = [acc[0], acc[1], acc[2], acc[3], acc[4], acc[5], acc[6], acc[7], acc[8]];
    let (diff, borrow) = nat::sub(&low, &P_LIMBS);
    let mut result = [0u64; 9];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &low, &diff, &mut result);
    result
}
