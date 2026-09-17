//! The brainpoolP512r1 base field, GF(p) (RFC 5639 §3.4). Unlike every NIST curve or secp256k1 in
//! this crate, `p` here is a "random" prime with no Solinas-style algebraic shortcut for
//! reduction (RFC 5639 §3.1's curves are generated pseudorandomly, not chosen for a special
//! bit-pattern) -- so this field, like [`crate::bp512r1_scalar`], is built on
//! [`crate::montgomery`]'s generic Montgomery multiplication instead of a per-curve fold.
//!
//! `p`'s value and the base point's coordinates were extracted directly from RFC 5639 §3.4's text
//! (programmatically, concatenating the line-wrapped hex, not retyped) and verified in Python: `G`
//! is on the curve and `n·G` is the point at infinity, before any of this was ported to Rust.

use crate::montgomery;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `p`, little-endian `u64` limbs (RFC 5639 §3.4).
pub const P_LIMBS: [u64; 8] = [
    0x28aa6056583a48f3, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
    0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
];

/// `-p^-1 mod 2^64`, the Montgomery reduction constant.
const N_PRIME: u64 = 0x839b32207d89efc5;

/// `R^2 mod p` (`R = 2^512`), used to bring a plain value into Montgomery form.
const R_SQUARED_LIMBS: [u64; 8] = [
    0x49ad144a6158f205, 0x793fb13027157905, 0x53b7f9bc905affd3, 0xe0c19a7783514a25,
    0x19486fd8d5898057, 0xa16daa5fd42bff83, 0x202e19402056eecc, 0x3c4c9d05a9ff6450,
];

/// `R mod p`, also the Montgomery representation of `1`.
const R_MOD_P_LIMBS: [u64; 8] = [
    0xd7559fa9a7c5b70d, 0xd77e00d0d27d397a, 0x51325ed5195c7f19, 0x82b264ff643997bd,
    0x299c63358fccf78e, 0x34cf724c4c362df1, 0xc02b1951cc3603f8, 0x5522624724163b74,
];

/// `p - 2`, little-endian `u64` limbs -- the public exponent [`Bp512r1FieldElement::invert`]
/// raises its base to, per Fermat's little theorem.
const P_MINUS_2_LIMBS: [u64; 8] = [
    0x28aa6056583a48f1, 0x2881ff2f2d82c685, 0xaecda12ae6a380e6, 0x7d4d9b009bc66842,
    0xd6639cca70330871, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
];

/// An element of the brainpoolP512r1 base field GF(p). Stored internally in Montgomery form.
#[derive(Clone, Copy, Debug)]
pub struct Bp512r1FieldElement([u64; 8]);

impl Bp512r1FieldElement {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity. Its Montgomery form is `R mod p`, not the literal integer `1`.
    pub const ONE: Self = Self(R_MOD_P_LIMBS);

    /// Builds a field element from little-endian `u64` limbs (an ordinary, non-Montgomery value),
    /// reducing once if `limbs >= p` (valid since `limbs < 2^512 < 2p`: `p`'s top limb is
    /// `0xaadd...`, comfortably more than half of `u64::MAX`, so `2p > 2^512`), then converting to
    /// Montgomery form.
    pub fn from_limbs(limbs: [u64; 8]) -> Self {
        let (diff, borrow) = crate::nat::sub(&limbs, &P_LIMBS);
        let mut reduced = [0u64; 8];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
        let t = montgomery::widening_mul::<8, 16>(&reduced, &R_SQUARED_LIMBS);
        Self(Self::finish_redc(&t))
    }

    /// Returns the canonical little-endian `u64` limbs (an ordinary, non-Montgomery value), `< p`.
    pub fn to_limbs(&self) -> [u64; 8] {
        let mut t = [0u64; 16];
        t[..8].copy_from_slice(&self.0);
        montgomery::redc::<8, 16, 17>(&t, &P_LIMBS, N_PRIME).0
    }

    /// TRUE iff this element is the additive identity.
    pub fn is_zero(&self) -> Condition<u64> {
        crate::nat::is_zero(&self.0)
    }

    /// `self + other mod p`. Operates directly on the Montgomery-form limbs: Montgomery form is
    /// linear, so this needs no REDC, just the same carry-aware correction every Montgomery
    /// scalar field in this crate uses -- `R_MOD_P_LIMBS` (`R mod p`), not `P_LIMBS`, since a
    /// carry out of the top limb means the true sum is `sum + 2^512`, and `2^512 mod p` is
    /// `R_MOD_P_LIMBS` by definition, not `p` itself.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = crate::nat::add(&self.0, &other.0);
        let (sum_plus_r, _) = crate::nat::add(&sum, &R_MOD_P_LIMBS);
        let (diff, borrow) = crate::nat::sub(&sum, &P_LIMBS);
        let mut when_no_carry = [0u64; 8];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &sum, &diff, &mut when_no_carry);
        let mut result = [0u64; 8];
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
        let mut result = [0u64; 8];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod p`.
    pub fn negate(&self) -> Self {
        let (diff, _) = crate::nat::sub(&P_LIMBS, &self.0);
        let mut result = [0u64; 8];
        ct::conditional_select(self.is_zero(), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod p`, via Montgomery multiplication.
    pub fn mul(&self, other: &Self) -> Self {
        let t = montgomery::widening_mul::<8, 16>(&self.0, &other.0);
        Self(Self::finish_redc(&t))
    }

    /// `self^2 mod p`.
    /// `self^2`, via a dedicated squaring rather than `self.mul(self)` -- see
    /// [`montgomery::widening_square`]. Used by the exponentiation loops, not by point
    /// arithmetic; see [`crate::p256::P256FieldElement::square`] for the measurement behind that
    /// split.
    pub fn square(&self) -> Self {
        let t = montgomery::widening_square::<8, 16>(&self.0);
        Self(Self::finish_redc(&t))
    }

    /// `self^-1 mod p`, or `0` if `self` is `0`. Fermat's little theorem, by fixed
    /// square-then-conditionally-multiply over the public exponent `p-2`.
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..8).rev() {
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
    fn finish_redc(t: &[u64; 16]) -> [u64; 8] {
        let (high, extra) = montgomery::redc::<8, 16, 17>(t, &P_LIMBS, N_PRIME);
        let (sum, _) = crate::nat::add(&high, &R_MOD_P_LIMBS);
        let (diff, borrow) = crate::nat::sub(&high, &P_LIMBS);
        let mut when_no_extra = [0u64; 8];
        ct::conditional_select(
            Condition::<u64>::from_lsb(borrow),
            &high,
            &diff,
            &mut when_no_extra,
        );
        let mut result = [0u64; 8];
        ct::conditional_select(
            Condition::<u64>::from_lsb(extra),
            &sum,
            &when_no_extra,
            &mut result,
        );
        result
    }
}

impl PartialEq for Bp512r1FieldElement {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found. Comparing Montgomery-form limbs directly is valid: the map `x -> x*R mod p` is a
    /// bijection.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..8 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for Bp512r1FieldElement {}
