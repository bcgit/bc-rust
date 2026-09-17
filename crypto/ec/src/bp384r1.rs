//! The brainpoolP384r1 base field, GF(p) (RFC 5639 §3.4). Unlike every NIST curve or secp256k1 in
//! this crate, `p` here is a "random" prime with no Solinas-style algebraic shortcut for
//! reduction (RFC 5639 §3.1's curves are generated pseudorandomly, not chosen for a special
//! bit-pattern) -- so this field, like [`crate::bp384r1_scalar`], is built on
//! [`crate::montgomery`]'s generic Montgomery multiplication instead of a per-curve fold.
//!
//! `p`'s value and the base point's coordinates were extracted directly from RFC 5639 §3.4's text
//! (programmatically, concatenating the line-wrapped hex, not retyped) and verified in Python: `G`
//! is on the curve and `n·G` is the point at infinity, before any of this was ported to Rust.

use crate::montgomery;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `p`, little-endian `u64` limbs (RFC 5639 §3.4).
pub const P_LIMBS: [u64; 6] = [
    0x874700133107ec53, 0xacd3a729901d1a71, 0x12b1da197fb71123, 0x152f7109ed5456b4,
    0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
];

/// `-p^-1 mod 2^64`, the Montgomery reduction constant.
const N_PRIME: u64 = 0x9a6ea96cea9ec825;

/// `R^2 mod p` (`R = 2^384`), used to bring a plain value into Montgomery form.
const R_SQUARED_LIMBS: [u64; 6] = [
    0x087cefff40b64bde, 0x535283343d7fd965, 0x8e28f99cc9940899, 0x621401919918d5af,
    0xd5c6ef3ba57e052c, 0x36bf6883178df842,
];

/// `R mod p`, also the Montgomery representation of `1`.
const R_MOD_P_LIMBS: [u64; 6] = [
    0x78b8ffeccef813ad, 0x532c58d66fe2e58e, 0xed4e25e68048eedc, 0xead08ef612aba94b,
    0xf0a29081af19be20, 0x7346e17d5cc792d7,
];

/// `p - 2`, little-endian `u64` limbs -- the public exponent [`Bp384r1FieldElement::invert`]
/// raises its base to, per Fermat's little theorem.
const P_MINUS_2_LIMBS: [u64; 6] = [
    0x874700133107ec51, 0xacd3a729901d1a71, 0x12b1da197fb71123, 0x152f7109ed5456b4,
    0x0f5d6f7e50e641df, 0x8cb91e82a3386d28,
];

/// An element of the brainpoolP384r1 base field GF(p). Stored internally in Montgomery form.
#[derive(Clone, Copy, Debug)]
pub struct Bp384r1FieldElement([u64; 6]);

impl Bp384r1FieldElement {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity. Its Montgomery form is `R mod p`, not the literal integer `1`.
    pub const ONE: Self = Self(R_MOD_P_LIMBS);

    /// Builds a field element from little-endian `u64` limbs (an ordinary, non-Montgomery value),
    /// reducing once if `limbs >= p` (valid since `limbs < 2^384 < 2p`: `p`'s top limb is
    /// `0x8cb9...`, comfortably more than half of `u64::MAX`, so `2p > 2^384`), then converting to
    /// Montgomery form.
    pub fn from_limbs(limbs: [u64; 6]) -> Self {
        let (diff, borrow) = crate::nat::sub(&limbs, &P_LIMBS);
        let mut reduced = [0u64; 6];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
        let t = montgomery::widening_mul::<6, 12>(&reduced, &R_SQUARED_LIMBS);
        Self(Self::finish_redc(&t))
    }

    /// Returns the canonical little-endian `u64` limbs (an ordinary, non-Montgomery value), `< p`.
    pub fn to_limbs(&self) -> [u64; 6] {
        let mut t = [0u64; 12];
        t[..6].copy_from_slice(&self.0);
        montgomery::redc::<6, 12, 13>(&t, &P_LIMBS, N_PRIME).0
    }

    /// TRUE iff this element is the additive identity.
    pub fn is_zero(&self) -> Condition<u64> {
        crate::nat::is_zero(&self.0)
    }

    /// `self + other mod p`. Operates directly on the Montgomery-form limbs: Montgomery form is
    /// linear, so this needs no REDC, just the same carry-aware correction every Montgomery
    /// scalar field in this crate uses -- `R_MOD_P_LIMBS` (`R mod p`), not `P_LIMBS`, since a
    /// carry out of the top limb means the true sum is `sum + 2^384`, and `2^384 mod p` is
    /// `R_MOD_P_LIMBS` by definition, not `p` itself.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = crate::nat::add(&self.0, &other.0);
        let (sum_plus_r, _) = crate::nat::add(&sum, &R_MOD_P_LIMBS);
        let (diff, borrow) = crate::nat::sub(&sum, &P_LIMBS);
        let mut when_no_carry = [0u64; 6];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &sum, &diff, &mut when_no_carry);
        let mut result = [0u64; 6];
        ct::conditional_select(
            Condition::<u64>::from_lsb(carry),
            &sum_plus_r,
            &when_no_carry,
            &mut result,
        );
        Self(result)
    }

    /// `self - other mod p`.
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = crate::nat::sub(&self.0, &other.0);
        let (corrected, _) = crate::nat::add(&diff, &P_LIMBS);
        let mut result = [0u64; 6];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod p`.
    pub fn negate(&self) -> Self {
        let (diff, _) = crate::nat::sub(&P_LIMBS, &self.0);
        let mut result = [0u64; 6];
        ct::conditional_select(self.is_zero(), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod p`, via Montgomery multiplication.
    pub fn mul(&self, other: &Self) -> Self {
        let t = montgomery::widening_mul::<6, 12>(&self.0, &other.0);
        Self(Self::finish_redc(&t))
    }

    /// `self^2 mod p`.
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// `self^-1 mod p`, or `0` if `self` is `0`. Fermat's little theorem, by fixed
    /// square-then-conditionally-multiply over the public exponent `p-2`.
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

    /// [`montgomery::redc`]'s `(high, extra)` result, reduced to the canonical `< p` value: if
    /// `extra == 1`, `high + R_MOD_P_LIMBS` (proven to need no further reduction, the same
    /// invariant every per-curve `redc` caller in this crate relies on -- verified, not checked
    /// in, against 20,000 random trials plus the `(p-1)*(p-1)` worst case for this specific `p`);
    /// otherwise `high`, minus `p` once more if `high >= p`.
    fn finish_redc(t: &[u64; 12]) -> [u64; 6] {
        let (high, extra) = montgomery::redc::<6, 12, 13>(t, &P_LIMBS, N_PRIME);
        let (sum, _) = crate::nat::add(&high, &R_MOD_P_LIMBS);
        let (diff, borrow) = crate::nat::sub(&high, &P_LIMBS);
        let mut when_no_extra = [0u64; 6];
        ct::conditional_select(
            Condition::<u64>::from_lsb(borrow),
            &high,
            &diff,
            &mut when_no_extra,
        );
        let mut result = [0u64; 6];
        ct::conditional_select(
            Condition::<u64>::from_lsb(extra),
            &sum,
            &when_no_extra,
            &mut result,
        );
        result
    }
}

impl PartialEq for Bp384r1FieldElement {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found. Comparing Montgomery-form limbs directly is valid: the map `x -> x*R mod p` is a
    /// bijection.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..6 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for Bp384r1FieldElement {}
