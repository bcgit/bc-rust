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
//! Same fold as [`crate::p256`]'s `reduce` (see that module's docs for the full derivation): `p`
//! has the identity `2^384 = p + C` where `C = 2^128 + 2^96 - 2^32 + 1`, so reducing a 768-bit
//! product means repeatedly splitting into high/low 384-bit halves and replacing `high * 2^384`
//! with `high * C`. Here `C < 2^129`, much smaller relative to the modulus than P-256's `C <
//! 2^224` is to *its* modulus, so this converges far faster: two folds bound the result to `<
//! 2^384 + 2^259` (proof in [`reduce`]'s own comment), leaving at most a single extra bit above
//! `2^384` rather than P-256's need for a full further limb of headroom -- but that single bit is
//! not *always* zero, unlike an earlier version of this module assumed (see [`reduce`]'s comment
//! for the wycheproof-caught bug that assumption produced).

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
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// `self^-1 mod p`, or `0` if `self` is `0`. Fermat's little theorem; see
    /// [`crate::p256::P256FieldElement::invert`]'s docs, which this mirrors exactly.
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..6).rev() {
            let limb = P_MINUS_2_LIMBS[limb_idx];
            for bit in (0..64).rev() {
                result = result.square();
                let multiplied = result.mul(self);
                let bit_is_set = Condition::<u64>::from_lsb((limb >> bit) & 1);
                let mut selected = [0u64; 6];
                ct::conditional_select(bit_is_set, &multiplied.0, &result.0, &mut selected);
                result = Self(selected);
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

/// Reduces a 12-limb (768-bit) value modulo `p`, per the fold described in the module docs.
fn reduce(t: &[u64; 12]) -> [u64; 6] {
    let mut acc: [u64; 12] = *t;
    for _ in 0..2 {
        let hi: [u64; 6] = [acc[6], acc[7], acc[8], acc[9], acc[10], acc[11]];
        let lo: [u64; 6] = [acc[0], acc[1], acc[2], acc[3], acc[4], acc[5]];
        let product = widening_mul(&hi, &C_LIMBS);
        let lo_extended: [u64; 12] = [lo[0], lo[1], lo[2], lo[3], lo[4], lo[5], 0, 0, 0, 0, 0, 0];
        let (sum, carry) = nat::add(&product, &lo_extended);
        debug_assert_eq!(carry, 0, "P-384 reduction fold overflowed 768 bits");
        acc = sum;
    }
    // After exactly 2 folds, `acc`'s high 6 limbs are not always zero: fold 1 leaves `hi < 2^130`
    // (`t < 2^768` splits into `hi0 < 2^384`, and `hi0*C < 2^384 * 2^129 = 2^513`, so fold 1's
    // result is `< 2^513 + 2^384`, whose own high half is `< 2^130`); fold 2 then bounds the
    // result to `< 2^384 + 2^259` (`hi1*C < 2^130*2^129 = 2^259`, plus `lo1 < 2^384`), so its high
    // half -- `acc[6..12]` here -- is at most a single bit: `acc[6] in {0, 1}`, `acc[7..12] ==
    // 0`. Dropping that bit (as an earlier version of this function did via `debug_assert_eq!`,
    // relying on it always being exactly zero) silently corrupts the rare product that actually
    // sets it -- caught by the wycheproof `ecdsa_secp384r1` suite, not by 200,000+ random trials,
    // which never happened to hit it. So the bit is folded in explicitly: `2^384 ≡ C (mod p)`
    // again, added only when the bit is set, mirroring [`P384FieldElement::add`]'s carry handling
    // -- with a tighter bound here (`low + C < 2^384 + 2^129`, so a carry out of *that* addition
    // leaves a remainder `< 2^129`, far short of `p`, needing no further reduction at all) since
    // `low` is an arbitrary 384-bit value here, not already `< p` the way `add`'s operands are.
    let extra_bit = acc[6];
    let low: [u64; 6] = [acc[0], acc[1], acc[2], acc[3], acc[4], acc[5]];
    let mut c_or_zero = [0u64; 6];
    ct::conditional_select(
        Condition::<u64>::from_lsb(extra_bit),
        &C_LIMBS,
        &[0u64; 6],
        &mut c_or_zero,
    );
    let (folded, carry1) = nat::add(&low, &c_or_zero);
    let (folded_plus_c, _) = nat::add(&folded, &C_LIMBS); // valid when carry1 == 1: folded < 2^129 there
    let (diff, borrow) = nat::sub(&folded, &P_LIMBS); // valid when carry1 == 0
    let mut when_no_carry = [0u64; 6];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &folded, &diff, &mut when_no_carry);
    let mut result = [0u64; 6];
    ct::conditional_select(
        Condition::<u64>::from_lsb(carry1),
        &folded_plus_c,
        &when_no_carry,
        &mut result,
    );
    result
}

// `reduce` is private and, from `mul`, only ever reached on operands that are already `< p` (an
// invariant `P384FieldElement` upholds everywhere else in this module), so no integration test
// through the public API can hand it a raw 12-limb value chosen to land in the astronomically
// narrow (~2^-125 of the input space) window that sets the "extra bit" this function's comment
// describes -- a systematic sweep over `hi0` in `t = hi0 * 2^384` (`lo0 = 0`) is what found
// [`T_LIMBS`] below, since 2,000,000-trial uniform random search over both realistic `a*b`
// products and raw 768-bit values found nothing. `EXPECTED` is `T_LIMBS`'s value reduced mod `p`
// via Python's arbitrary-precision `%`, independent of this module's own reduction code.
#[cfg(test)]
mod tests {
    use super::*;

    const T_LIMBS: [u64; 12] = [
        0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
        0x0000000000000000, 0x0000000000000000, 0xfffffffffffb5180, 0xffffffffffffffff,
        0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
    ];
    const EXPECTED: [u64; 6] = [
        0x0004ae7dfffb5181, 0xfffb518200000001, 0xfffffffdfffb517f, 0x0000000200000000,
        0x0000000000000001, 0x0000000000000000,
    ];

    #[test]
    fn reduce_handles_the_rare_post_two_fold_extra_bit() {
        assert_eq!(reduce(&T_LIMBS), EXPECTED);
    }
}
