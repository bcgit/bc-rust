//! The P-256 base field, GF(p) for `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`.
//!
//! Domain parameters are from NIST SP 800-186 (Feb 2023) §3.2.1.3, "Curve P-256": the prime `p`
//! quoted there in hex is
//! `0xffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff` (256 bits, most
//! significant word first). [`P_LIMBS`] below is that same value in little-endian `u64` limbs.
//!
//! # Reduction algorithm
//!
//! `p` is a generalized Mersenne number, so a 512-bit product reduces without any multiplication
//! at all: SP 800-186 (Feb 2023) Appendix G.1.2, "Curve P-256", gives `B = (T + 2S1 + 2S2 + S3 +
//! S4 - D1 - D2 - D3 - D4) mod p`, where each of the nine terms is a 256-bit value assembled by
//! concatenating 32-bit words of the product itself. [`reduce`] transcribes that expression
//! directly, so a reviewer with G.1.2 open can match its nine terms to the document row by row.
//!
//! G.1's own preamble states both the precondition -- "given an integer A less than m^2" -- and
//! the shape of the leftover work: "the integer sum or difference can be evaluated and the result
//! reduced modulo m. The latter reduction can be accomplished by adding or subtracting a few
//! copies of m." [`reduce`] carries the exact bound on how many copies that is here, and why,
//! after biasing the accumulator by `5p` so it never goes negative, a single fold of the top limb
//! plus a single conditional subtraction always lands in `[0, p)`.
//!
//! The one identity that outlives the reduction is `2^256 = p + C` where `C = 2^224 - 2^192 -
//! 2^96 + 1` (i.e. `2^256 mod p = C`): [`P256FieldElement::add`] uses it to correct a carry out
//! of the top limb, and [`reduce`]'s final fold uses it on the accumulator's top limb.
//!
//! Every step is a fixed, public-length loop over fixed-size arrays with a single masked select,
//! so the whole routine is trivially constant-time in the operands.

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

/// `5p`, little-endian `u64` limbs -- the bias [`reduce`] starts its accumulator at so that
/// subtracting SP 800-186 §G.1.2's four `D` terms can never take it below zero. See [`reduce`]
/// for why `5` is the right multiple.
const FIVE_P_LIMBS: [u64; 5] = [
    0xfffffffffffffffb, 0x00000004ffffffff, 0x0000000000000000, 0xfffffffb00000005,
    0x0000000000000004,
];

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

    /// TRUE iff this element is the additive identity.
    pub fn is_zero(&self) -> Condition<u64> {
        nat::is_zero(&self.0)
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

    /// `self^2 mod p`, via a dedicated squaring rather than `self.mul(self)` -- see
    /// [`widening_square`].
    ///
    /// Worth using in the exponentiation loops ([`Self::invert`],
    /// [`crate::p256_sec1`]'s square-and-multiply), which call it hundreds of times in a row with
    /// nothing else competing for registers: inversion measured ~25% faster. It is deliberately
    /// *not* used by [`crate::p256_point`], whose `double`/`generic_add` square by calling `mul`
    /// with equal arguments. That was tried and measured: despite `square` being ~9% cheaper than
    /// `mul` in isolation, routing the point arithmetic through it made the constant-time comb
    /// multiplier consistently slower (42.0us -> 42.3us over three interleaved rounds), since
    /// inlining a third wide-multiply routine into that loop costs more than the four saved
    /// partial products return. Left as it is on purpose.
    pub fn square(&self) -> Self {
        Self(reduce(&widening_square(&self.0)))
    }

    /// `self^-1 mod p`, or `0` if `self` is `0`.
    ///
    /// Computed as `self^(p-2) mod p` (Fermat's little theorem: `self^(p-1) = 1` for `self != 0`,
    /// FIPS 186-5 Appendix B.1, whose reference algorithm this deliberately does not use --
    /// its own text sanctions the substitution: *"The algorithm given below is for reference
    /// purposes. Other (constant time) algorithms that produce an equivalent result may be
    /// used."* The exponent `p-2` is a compile-time public constant, so the fixed
    /// square-then-conditionally-multiply sequence below takes the same path on every call
    /// regardless of `self`. The "conditionally" is an ordinary `if` on a bit of that constant,
    /// not a mask: the condition is known at compile time, so which operations run -- and in what
    /// order -- is fixed before `self` exists, and no step of the computation branches on `self`.
    /// (An earlier version masked instead, multiplying on every bit and selecting the result.
    /// That bought no additional secret-independence, since the bit was never secret, and cost a
    /// full field multiplication per exponent bit.)
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

/// The 32-bit word `A_i` of the 512-bit product, in SP 800-186 §G.1.2's numbering: that appendix
/// writes the product as `A = (A15 || A14 || ... || A0)` with each `A_i` a 32-bit integer, `A0`
/// least significant.
fn word(t: &[u64; 8], i: usize) -> u64 {
    (t[i / 2] >> (32 * (i % 2))) & 0xffff_ffff
}

/// Assembles one of §G.1.2's 256-bit terms from its eight 32-bit words. The document prints each
/// term most significant word first (`( A15 || A14 || ... )`); this takes them least significant
/// first, so each call site below reads its document row right to left.
fn term(w: [u64; 8]) -> [u64; 4] {
    [w[0] | (w[1] << 32), w[2] | (w[3] << 32), w[4] | (w[5] << 32), w[6] | (w[7] << 32)]
}

/// Zero-extends a 4-limb value to 5 limbs, for arithmetic against the 5-limb accumulator.
fn widen(v: &[u64; 4]) -> [u64; 5] {
    [v[0], v[1], v[2], v[3], 0]
}

/// `small * v`, one limb times a 4-limb value, as 5 limbs. Only ever called with a `small` that
/// is a bounded, operand-independent count (see [`reduce`]), never a secret.
fn mul_small(small: u64, v: &[u64; 4]) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let prod = (small as u128) * (v[i] as u128) + carry;
        out[i] = prod as u64;
        carry = prod >> 64;
    }
    out[4] = carry as u64;
    out
}

/// Schoolbook squaring of a 4-limb value into its 8-limb square.
///
/// `a * a` is symmetric: the product `a_i * a_j` appears twice for every `i != j`. Forming each of
/// those once and doubling the result costs `L(L+1)/2` limb multiplications -- ten at this width
/// against the sixteen [`widening_mul`] would form for the same value.
///
/// Three passes: the off-diagonal products `a_i * a_j` for `i < j`; a doubling of the whole
/// accumulator; then the diagonal squares `a_i * a_i` added in at limb `2i`. Writing `result[i +
/// L]` in the first pass is an assignment rather than an accumulation because row `i` only ever
/// reaches limbs `2i + 1 ..= i + L - 1`, and no earlier row reaches limb `i + L` either, so that
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

/// Reduces an 8-limb (512-bit) value modulo `p`, per SP 800-186 §G.1.2 (see the module docs).
///
/// **Precondition: `t < p^2`**, which is G.1's own stated precondition ("given an integer A less
/// than m^2") and holds for every call site, since `mul` is the only one and it passes the product
/// of two canonical (`< p`) field elements. The bounds below all rest on it; a raw 512-bit value
/// near `2^512` is *not* reduced correctly by this function.
///
/// Bounds. Each of the nine terms is a 256-bit value, so `T + 2*S1 + 2*S2 + S3 + S4 < 6*2^256`
/// and `D1 + D2 + D3 + D4 < 4*2^256`. Starting the accumulator at `5p` therefore keeps it
/// non-negative throughout (`5p > 4*2^256`, since `5p - 4*2^256 = 2^256 - 5*2^224 + ... > 0`) and
/// bounded by `5p + 6*2^256 < 11*2^256`, so five limbs are always enough and the top limb `u_hi`
/// is at most 10. Folding that top limb back in via `2^256 ≡ C` adds `u_hi*C < 11*2^224 < 2^228`,
/// leaving `V < 2^256 + 2^228`; since `p > 2^256 - 2^224`, `V - p < 2^228 + 2^224 < p`, so exactly
/// one conditional subtraction finishes the job.
fn reduce(t: &[u64; 8]) -> [u64; 4] {
    let a = |i: usize| word(t, i);

    // SP 800-186 §G.1.2's nine terms, each row read right to left from the document.
    let t_term = term([a(0), a(1), a(2), a(3), a(4), a(5), a(6), a(7)]);
    let s1 = term([0, 0, 0, a(11), a(12), a(13), a(14), a(15)]);
    let s2 = term([0, 0, 0, a(12), a(13), a(14), a(15), 0]);
    let s3 = term([a(8), a(9), a(10), 0, 0, 0, a(14), a(15)]);
    let s4 = term([a(9), a(10), a(11), a(13), a(14), a(15), a(13), a(8)]);
    let d1 = term([a(11), a(12), a(13), 0, 0, 0, a(8), a(10)]);
    let d2 = term([a(12), a(13), a(14), a(15), 0, 0, a(9), a(11)]);
    let d3 = term([a(13), a(14), a(15), a(8), a(9), a(10), 0, a(12)]);
    let d4 = term([a(14), a(15), 0, a(9), a(10), a(11), 0, a(13)]);

    // B + 5p = 5p + T + 2*S1 + 2*S2 + S3 + S4 - D1 - D2 - D3 - D4, over five limbs. `S1` and `S2`
    // appear twice rather than being doubled, so every step is the same 5-limb add.
    let mut acc = FIVE_P_LIMBS;
    for addend in [&t_term, &s1, &s1, &s2, &s2, &s3, &s4] {
        let (sum, carry) = nat::add(&acc, &widen(addend));
        debug_assert_eq!(carry, 0, "P-256 reduction accumulator overflowed 5 limbs");
        acc = sum;
    }
    for subtrahend in [&d1, &d2, &d3, &d4] {
        let (diff, borrow) = nat::sub(&acc, &widen(subtrahend));
        debug_assert_eq!(
            borrow, 0,
            "P-256 reduction accumulator went negative despite the 5p bias"
        );
        acc = diff;
    }

    // Fold the accumulator's top limb back in: `2^256 ≡ C (mod p)`.
    debug_assert!(acc[4] <= 10, "P-256 reduction top limb exceeded its proven bound");
    let low: [u64; 4] = [acc[0], acc[1], acc[2], acc[3]];
    let (v, carry) = nat::add(&mul_small(acc[4], &C_LIMBS), &widen(&low));
    debug_assert_eq!(carry, 0, "P-256 reduction fold overflowed 5 limbs");

    let (diff, borrow) = nat::sub(&v, &widen(&P_LIMBS));
    let mut selected = [0u64; 5];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &v, &diff, &mut selected);
    debug_assert_eq!(selected[4], 0, "P-256 reduction left a value >= 2^256");
    [selected[0], selected[1], selected[2], selected[3]]
}
