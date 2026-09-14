//! The P-256 base field, GF(p) for `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`.
//!
//! Domain parameters are from NIST SP 800-186 (Feb 2023) §3.2.1.3, "Curve P-256": the prime `p`
//! quoted there in hex is
//! `0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff` (256 bits, most
//! significant word first). [`P_LIMBS`] below is that same value in little-endian `u64` limbs.
//!
//! # Reduction algorithm
//!
//! `p` has the Solinas-friendly identity `2^256 = p + C` where `C = 2^224 - 2^192 - 2^96 + 1`
//! (i.e. `2^256 mod p = C`); this is what makes P-256 a "custom curve" candidate at all (see the
//! crate's design notes). bc-java's `SecP256R1Field.reduce` exploits this identity in a single
//! pass over 32-bit words, because `p`'s special exponents (96, 192, 224) are all 32-bit-word
//! boundaries. They are not 64-bit-limb boundaries (`96 = 64 + 32`, `224 = 3*64 + 32`), so a
//! direct port to `u64` limbs would need to split limbs at 32-bit offsets. Instead, [`reduce`]
//! applies the same `2^256 ≡ C` identity iteratively at 64-bit-limb granularity: split the
//! 512-bit product into its high and low 256-bit halves and replace `high * 2^256` with
//! `high * C`, folding the high half back into the low one. Worked out below (and confirmed
//! against 40,000+ random trials plus the `(p-1)*(p-1)` worst case in
//! `p256_reduce_explore2.py`, not checked in): each fold cannot grow the value's bit length by
//! more than `224 - 256 = -32` bits net (since `C < 2^224`), so starting from a 512-bit product,
//! 9 folds are enough to guarantee the high half is exactly zero, leaving a value less than `2p`
//! that a single conditional subtraction reduces into `[0, p)`. This is slower than bc-java's
//! single-pass, word-granular reduction (a later optimization, replaceable behind the same
//! signature per CLAUDE.md's spec-deviation rule), but every step is a fixed, public-length loop
//! over fixed-size arrays, so it stays trivially constant-time in the operands.

use crate::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;

/// `p`, little-endian `u64` limbs (SP 800-186 §3.2.1.3).
pub const P_LIMBS: [u64; 4] =
    [0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001];

/// `2^256 mod p = 2^224 - 2^192 - 2^96 + 1`, little-endian `u64` limbs. This is the constant
/// [`reduce`]'s fold uses in place of `2^256`.
const C_LIMBS: [u64; 4] =
    [0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe];

/// `p - 2`, little-endian `u64` limbs -- the public exponent [`P256FieldElement::invert`] raises
/// its base to, per Fermat's little theorem.
const P_MINUS_2_LIMBS: [u64; 4] =
    [0xfffffffffffffffd, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001];

/// An element of the P-256 base field GF(p), always held in canonical reduced form (`< p`).
#[derive(Clone, Copy, Debug)]
pub struct P256FieldElement([u64; 4]);

impl P256FieldElement {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// The multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Builds a field element from little-endian `u64` limbs, reducing once if `limbs >= p`. Any
    /// `u64` limb pattern is accepted: since `limbs < 2^256 < 2*p`, a single conditional
    /// subtraction of `p` always suffices to bring it into `[0, p)`.
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        let (diff, borrow) = nat::sub(&limbs, &P_LIMBS);
        let mut result = [0u64; 4];
        // borrow == 1 means limbs < p already; otherwise take the (single) reduced difference.
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut result);
        Self(result)
    }

    /// Returns the canonical little-endian `u64` limbs, `< p`.
    pub fn to_limbs(&self) -> [u64; 4] {
        self.0
    }

    /// `self + other mod p`.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = nat::add(&self.0, &other.0);
        // true_sum = sum + carry*2^256, and self,other < p so true_sum < 2p.
        let (sum_plus_c, _) = nat::add(&sum, &C_LIMBS); // used when carry == 1: true_sum - p == sum + C
        let (diff, borrow) = nat::sub(&sum, &P_LIMBS); // used when carry == 0: is sum >= p?
        let mut when_no_carry = [0u64; 4];
        // borrow == 1 means sum < p already; otherwise take sum - p.
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
        let (corrected, _) = nat::add(&diff, &P_LIMBS); // used when borrow == 1: (self - other) + p
        let mut result = [0u64; 4];
        // borrow == 1 means self < other, so the wrapped diff needs +p added back.
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod p`.
    pub fn negate(&self) -> Self {
        let (diff, _) = nat::sub(&P_LIMBS, &self.0); // p - self; never borrows since self < p
        let mut result = [0u64; 4];
        // p - 0 == p, which is not canonical: 0 must negate to 0, not p.
        ct::conditional_select(nat::is_zero(&self.0), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod p`.
    pub fn mul(&self, other: &Self) -> Self {
        Self(reduce(&widening_mul(&self.0, &other.0)))
    }

    /// `self^2 mod p`. Not (yet) a dedicated squaring routine -- see the crate's design notes on
    /// why correctness comes before that optimization.
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// `self^-1 mod p`, or `0` if `self` is `0`.
    ///
    /// Computed as `self^(p-2) mod p` (Fermat's little theorem: `self^(p-1) = 1` for `self != 0`,
    /// FIPS 186-5 Appendix B.1, whose reference algorithm this deliberately does not use --
    /// its own text sanctions the substitution: *"The algorithm given below is for reference
    /// purposes. Other (constant time) algorithms that produce an equivalent result may be
    /// used."* The exponent `p-2` is a compile-time public constant, so the fixed
    /// square-then-conditionally-multiply sequence below takes the same path on every call
    /// regardless of `self`; the "conditionally" is itself branch-free, selecting between the
    /// multiplied and un-multiplied candidates by a mask rather than a data-dependent branch, so
    /// no step of the computation branches on `self`.
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..4).rev() {
            let limb = P_MINUS_2_LIMBS[limb_idx];
            for bit in (0..64).rev() {
                result = result.square();
                let multiplied = result.mul(self);
                let bit_is_set = Condition::<u64>::from_lsb((limb >> bit) & 1);
                let mut selected = [0u64; 4];
                ct::conditional_select(bit_is_set, &multiplied.0, &result.0, &mut selected);
                result = Self(selected);
            }
        }
        result
    }
}

impl PartialEq for P256FieldElement {
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

impl Eq for P256FieldElement {}

/// Schoolbook widening multiply of two 4-limb (256-bit) operands into an 8-limb (512-bit)
/// product. Not expressed generically over `Nat<L>`: stable Rust has no way to bound an output
/// array's length to `2*L` for a generic `L`, so each curve's field module writes its own
/// fixed-width widening multiply (the "field arithmetic is per curve" rule the crate's design
/// notes describe for the reduction, applied here too).
///
/// Carry propagation always walks every remaining output limb for a given row, whether or not the
/// carry is actually still nonzero: the loop bound depends only on the (public) row index `i`, not
/// on the (potentially secret) operand values, so this does not leak timing through an
/// early-exit carry chain.
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

/// Reduces an 8-limb (512-bit) value modulo `p`, per the fold described in the module docs.
fn reduce(t: &[u64; 8]) -> [u64; 4] {
    let mut acc: [u64; 8] = *t;
    for _ in 0..9 {
        let hi: [u64; 4] = [acc[4], acc[5], acc[6], acc[7]];
        let lo: [u64; 4] = [acc[0], acc[1], acc[2], acc[3]];
        let product = widening_mul(&hi, &C_LIMBS);
        let lo_extended: [u64; 8] = [lo[0], lo[1], lo[2], lo[3], 0, 0, 0, 0];
        let (sum, carry) = nat::add(&product, &lo_extended);
        debug_assert_eq!(carry, 0, "P-256 reduction fold overflowed 512 bits");
        acc = sum;
    }
    debug_assert_eq!([acc[4], acc[5], acc[6], acc[7]], [0, 0, 0, 0]);
    let low: [u64; 4] = [acc[0], acc[1], acc[2], acc[3]];
    let (diff, borrow) = nat::sub(&low, &P_LIMBS);
    let mut result = [0u64; 4];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &low, &diff, &mut result);
    result
}
