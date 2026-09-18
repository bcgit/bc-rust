//! The P-256 scalar field, arithmetic mod the curve order `n` (SP 800-186 §3.2.1.3), needed for
//! `k⁻¹` and `s = k⁻¹(e + rd) mod n` in ECDSA.
//!
//! Unlike `p`, `n` is not a Solinas prime -- there is no special shape to exploit for reduction --
//! so this uses Montgomery arithmetic instead: [`P256ScalarField`] holds its value as `x*R mod n`
//! internally (`R = 2^256`), which turns multiplication mod `n` into one wide multiply plus one
//! *fixed-length* reduction pass (REDC) with no data-dependent trial subtraction. Addition and
//! subtraction don't need REDC at all -- Montgomery form is linear, so `(a*R mod n) + (b*R mod n)
//! mod n == (a+b)*R mod n` -- and reuse the same "modulus close to `2^256`" trick
//! [`crate::p256::P256FieldElement`] uses for `p` (this one isn't Solinas-specific either: it only
//! needs `n < 2^256`, true of the curve order for every curve in NIST SP 800-186's recommended
//! set).
//!
//! # REDC
//!
//! [`redc`] is the textbook "Separated Operand Scanning" (SOS) Montgomery reduction (Koç, Acar &
//! Kaliski, *Analyzing and Comparing Montgomery Multiplication Algorithms*, 1996, Algorithm 2): for
//! `i` in `0..4`, compute `m = T[i] * n' mod 2^64` (`n' = -n⁻¹ mod 2^64`) and add `m*n` into `T`
//! at limb offset `i`, which zeroes `T[i]` by construction; after all 4 rounds `T`'s low 4 limbs
//! are zero and the result is `T`'s remaining limbs, reduced by at most one final subtraction of
//! `n`. Verified (not checked in) against 30,000 random trials plus the `(n-1)*(n-1)` worst case:
//! the reduction never touches beyond a 9-limb accumulator, which is what [`redc`] uses.

use crate::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// `n`, the order of the P-256 base point `G`, little-endian `u64` limbs (SP 800-186 §3.2.1.3).
pub const N_LIMBS: [u64; 4] =
    [0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000];

/// `2^256 mod n` -- both the correction constant [`P256ScalarField::add`] uses (mirroring
/// [`crate::p256::P256FieldElement::add`]) and, not by coincidence, the Montgomery representation
/// of `1` (`R mod n` where `R = 2^256`), since `2^256 mod n` *is* `R mod n`.
const R_LIMBS: [u64; 4] =
    [0x0c46353d039cdaaf, 0x4319055258e8617b, 0x0000000000000000, 0x00000000ffffffff];

/// `R^2 mod n`, used to bring a plain value into Montgomery form: `REDC(x * R^2) = x*R mod n`.
const R_SQUARED_LIMBS: [u64; 4] =
    [0x83244c95be79eea2, 0x4699799c49bd6fa6, 0x2845b2392b6bec59, 0x66e12d94f3d95620];

/// `-n^-1 mod 2^64`, the Montgomery reduction constant.
const N_PRIME: u64 = 0xccd1c8aaee00bc4f;

/// `n - 2`, little-endian `u64` limbs -- the public exponent [`P256ScalarField::invert`] raises
/// its base to, per Fermat's little theorem (`n` is prime).
const N_MINUS_2_LIMBS: [u64; 4] =
    [0xf3b9cac2fc63254f, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000];

/// An element of the P-256 scalar field, i.e. an integer mod `n`. Stored internally in Montgomery
/// form; see the module docs.
#[derive(Clone, Copy, Debug)]
pub struct P256ScalarField([u64; 4]);

impl P256ScalarField {
    /// The additive identity. `0`'s Montgomery form is `0` itself (`0 * R mod n == 0`).
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// The multiplicative identity. Its Montgomery form is `R mod n`, i.e. [`R_LIMBS`], not the
    /// literal integer `1`.
    pub const ONE: Self = Self(R_LIMBS);

    /// Builds a scalar-field element from little-endian `u64` limbs (an ordinary, non-Montgomery
    /// value), reducing once if `limbs >= n` (the same single-conditional-subtraction argument as
    /// [`crate::p256::P256FieldElement::from_limbs`] applies: `limbs < 2^256 < 2n`), then
    /// converting to Montgomery form.
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
        let mut reduced = [0u64; 4];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
        Self(redc(&widening_mul(&reduced, &R_SQUARED_LIMBS)))
    }

    /// Returns the canonical little-endian `u64` limbs (an ordinary, non-Montgomery value), `< n`.
    pub fn to_limbs(&self) -> [u64; 4] {
        let mut wide = [0u64; 8];
        wide[..4].copy_from_slice(&self.0);
        redc(&wide)
    }

    /// TRUE iff this element is the additive identity.
    pub fn is_zero(&self) -> Condition<u64> {
        nat::is_zero(&self.0)
    }

    /// `self + other mod n`. Operates directly on the Montgomery-form limbs: no REDC needed, since
    /// Montgomery form is linear (see the module docs).
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = nat::add(&self.0, &other.0);
        let (sum_plus_r, _) = nat::add(&sum, &R_LIMBS);
        let (diff, borrow) = nat::sub(&sum, &N_LIMBS);
        let mut when_no_carry = [0u64; 4];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &sum, &diff, &mut when_no_carry);
        let mut result = [0u64; 4];
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
        let mut result = [0u64; 4];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod n`.
    pub fn negate(&self) -> Self {
        let (diff, _) = nat::sub(&N_LIMBS, &self.0);
        let mut result = [0u64; 4];
        ct::conditional_select(self.is_zero(), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod n`, via Montgomery multiplication (widening multiply + [`redc`]).
    pub fn mul(&self, other: &Self) -> Self {
        Self(redc(&widening_mul(&self.0, &other.0)))
    }

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

    /// Converts a secret scalar (`d` or `k`) into Montgomery form for field arithmetic (`k⁻¹`, `r*d`,
    /// ...). Reads the secret's limbs once into a plain value, the same "protects storage, not
    /// every derived computation" boundary [`crate::p256_comb::comb_multiply_base_point`] already
    /// crosses to read `k`'s bits.
    pub fn from_secret(secret: &P256Scalar) -> Self {
        Self::from_limbs(*secret.limbs())
    }

    /// `self^-1 mod n`, or `0` if `self` is `0`. Fermat's little theorem (`n` is prime) over the
    /// public exponent `n-2`, by the same fixed 4-bit-window exponentiation as
    /// [`crate::p256::P256FieldElement::invert`] -- see its docs for the constant-time argument.
    pub fn invert(&self) -> Self {
        // self^0 .. self^15, indexed by nibble value.
        let mut table = [Self::ONE; 16];
        table[1] = *self;
        for i in 2..16 {
            table[i] = table[i - 1].mul(self);
        }

        let mut result = Self::ONE;
        for limb_idx in (0..4).rev() {
            let limb = N_MINUS_2_LIMBS[limb_idx];
            for nibble_idx in (0..16).rev() {
                for _ in 0..4 {
                    result = result.square();
                }
                // `limb` is one word of a compile-time constant exponent and `nibble_idx` a loop
                // index, so both the index into `table` and this branch depend on public data
                // only: the sequence of operations is fixed at compile time and identical on every
                // call.
                let nibble = ((limb >> (4 * nibble_idx)) & 0xf) as usize;
                if nibble != 0 {
                    result = result.mul(&table[nibble]);
                }
            }
        }
        result
    }
}

impl PartialEq for P256ScalarField {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found. Comparing the Montgomery-form limbs directly is valid: the map `x -> x*R mod n` is a
    /// bijection, so two elements are equal iff their Montgomery forms are.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..4 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for P256ScalarField {}

/// Schoolbook widening multiply, identical in shape to
/// [`crate::p256`]'s private helper of the same name; see that module's docs for why this isn't
/// expressed generically over `Nat<L>`.
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

/// `m * n`, one limb times the 4-limb modulus `n`, as the 5 limbs such a product can occupy.
///
/// This is exactly what each round of [`redc`]'s SOS reduction needs, and the shape
/// [`crate::montgomery::redc`] has always used for the brainpool curves. Every hand-written scalar
/// REDC in this crate previously formed it with the general 4x4 [`widening_mul`] against a
/// zero-padded `[m, 0, ..., 0]` instead, asking for 16 limb multiplications where 4 are needed.
///
/// Whether that padding costs anything turns out to depend entirely on the width, measured rather
/// than assumed: at four limbs the optimizer eliminates it completely (P-256 and secp256k1 time
/// identically either way), but it stops doing so by six, where the padded form measured 3.2x
/// slower per scalar multiplication for P-384 and 5.2x slower for P-521. All four are written this
/// way regardless, so the four modules read alike and none of them asks for work it does not want.
fn modulus_times_limb(m: u64) -> [u64; 5] {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for j in 0..4 {
        let prod = (m as u128) * (N_LIMBS[j] as u128) + carry;
        out[j] = prod as u64;
        carry = prod >> 64;
    }
    out[4] = carry as u64;
    out
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

/// Montgomery reduction (SOS method): given an 8-limb value `t < n*R`, returns `t * R^-1 mod n` as
/// 4 limbs. See the module docs for the algorithm.
///
/// After the 4 reduction rounds, the low 4 limbs of the 9-limb accumulator are zero and the
/// result -- `t * R^-1`, an integer, not yet reduced mod `n` -- occupies the remaining 5 limbs
/// (`acc[4..9]`): unlike [`crate::p256::reduce`], whose modulus is small enough that the analogous
/// step needs only one limb of headroom, `n` is close enough to `2^256` that `2n` can exceed it,
/// so a 9th limb (`acc[8]`, verified to always be `0` or `1`) is needed. The final step folds that
/// bit in exactly like [`crate::p256::P256FieldElement::add`]'s carry-aware correction: if
/// `acc[8] == 1`, the true value is `high + 2^256`, `>= 2^256 > n`, so `high + (2^256 mod n)` (i.e.
/// `+ R_LIMBS`) is the reduced result; otherwise it's `high`, conditionally reduced once more if
/// `high >= n`.
fn redc(t: &[u64; 8]) -> [u64; 4] {
    let mut acc = [0u64; 9];
    acc[..8].copy_from_slice(t);

    for i in 0..4 {
        let m = acc[i].wrapping_mul(N_PRIME);
        let mn = modulus_times_limb(m);

        let mut carry: u128 = 0;
        for j in 0..5 {
            let idx = i + j;
            let s = (acc[idx] as u128) + (mn[j] as u128) + carry;
            acc[idx] = s as u64;
            carry = s >> 64;
        }
        let mut idx = i + 5;
        while carry != 0 {
            debug_assert!(idx < 9, "REDC overflowed its verified 9-limb bound");
            let s = (acc[idx] as u128) + carry;
            acc[idx] = s as u64;
            carry = s >> 64;
            idx += 1;
        }
    }
    debug_assert_eq!(&acc[..4], &[0u64; 4], "REDC's low limbs must be cleared after 4 rounds");
    debug_assert!(acc[8] == 0 || acc[8] == 1, "REDC's top limb must be a single bit");

    let high: [u64; 4] = [acc[4], acc[5], acc[6], acc[7]];
    let (high_plus_r, _) = nat::add(&high, &R_LIMBS); // used when acc[8] == 1
    let (diff, borrow) = nat::sub(&high, &N_LIMBS); // used when acc[8] == 0: is high >= n?
    let mut when_no_extra_bit = [0u64; 4];
    ct::conditional_select(
        Condition::<u64>::from_lsb(borrow),
        &high,
        &diff,
        &mut when_no_extra_bit,
    );
    let mut result = [0u64; 4];
    ct::conditional_select(
        Condition::<u64>::from_lsb(acc[8]),
        &high_plus_r,
        &when_no_extra_bit,
        &mut result,
    );
    result
}

fn reduce_once(limbs: [u64; 4]) -> [u64; 4] {
    let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
    let mut result = [0u64; 4];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut result);
    result
}

/// A scalar mod `n`, `< n`, held in `Secret` -- for a value that must never be handled in
/// non-constant time: a private key `d`, or the per-signature secret `k`. There is deliberately no
/// conversion from `P256Scalar` to [`P256PublicScalar`]: the crate's constant-time and
/// variable-time scalar multipliers take `&P256Scalar` and `&P256PublicScalar` respectively, so a
/// caller cannot pass a secret scalar to the variable-time multiplier by accident -- the type
/// system forbids it, rather than relying on a reviewer to notice (the design plan's §5, §7 rule
/// 4). `Clone`/`Debug`/`PartialEq`/`Eq` forward to [`Secret`]'s own impls (`Debug` redacting,
/// `PartialEq` constant-time), which is what `core::traits::SignaturePrivateKey`'s bound needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256Scalar(Secret<[u64; 4]>);

impl P256Scalar {
    /// Builds a secret scalar from little-endian `u64` limbs, reducing once if `limbs >= n` (see
    /// [`P256ScalarField::from_limbs`]'s doc for why one conditional subtraction always suffices).
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        let mut secret = Secret::<[u64; 4]>::new();
        *secret = reduce_once(limbs);
        Self(secret)
    }

    /// Builds a secret scalar from SEC 1 §2.3.7 big-endian octets, reducing once if `>= n`.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_limbs(crate::p256_sec1::limbs_from_be_bytes(bytes))
    }

    /// Encodes to SEC 1 §2.3.7 big-endian octets -- the wire form of an ECDSA private key.
    /// Momentarily holds the plain value in the returned array, same as any other `encode()` on a
    /// `SignaturePrivateKey`: the caller asked for the bytes.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        crate::p256_sec1::be_bytes_from_limbs(&self.0)
    }

    /// The scalar's limbs, for the crate's own multiplier and field-arithmetic implementations to
    /// read (see [`P256ScalarField::from_secret`]). Not exposed outside the crate: nothing outside
    /// `bouncycastle-ec` should ever hold a bare, unprotected copy of a secret scalar's value.
    pub(crate) fn limbs(&self) -> &[u64; 4] {
        &self.0
    }
}

/// A scalar mod `n`, `< n`, held as a plain (non-secret) value -- for a value that is public by
/// construction: the `u`, `v` scalars ECDSA verification computes from a signature and public
/// data, or a message-derived value. See [`P256Scalar`]'s docs for why there is no conversion the
/// other way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256PublicScalar([u64; 4]);

impl P256PublicScalar {
    /// Builds a public scalar from little-endian `u64` limbs, reducing once if `limbs >= n`.
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(reduce_once(limbs))
    }

    /// Returns the scalar's little-endian `u64` limbs, `< n`.
    pub fn to_limbs(&self) -> [u64; 4] {
        self.0
    }

    /// `self^-1 mod n` in **variable time**, as a [`P256ScalarField`] ready for the arithmetic
    /// that follows, or `0` for `0`. For ECDSA verification's `s` (FIPS 186-5 §6.4.2 step 4),
    /// which is part of the signature and so already public; nothing derived from a private key
    /// or a per-message secret may reach this, which is why it lives on the public scalar type
    /// and not on [`P256ScalarField`], whose `invert` is the constant-time one. See
    /// [`crate::inverse_vartime`].
    pub fn invert_vartime(&self) -> P256ScalarField {
        P256ScalarField::from_limbs(crate::inverse_vartime::mod_inverse(&self.0, &N_LIMBS))
    }
}

#[cfg(test)]
mod tests {
    // `P256Scalar::limbs` is `pub(crate)`, deliberately not reachable from an integration test
    // (nothing outside the crate should get a bare copy of a secret scalar) -- exercised here
    // instead, per QUALITY_AND_STYLE's carve-out for code unreachable through the public API.
    use super::*;

    #[test]
    fn secret_scalar_reduces_and_round_trips() {
        let limbs: [u64; 4] = [1, 2, 3, 4];
        let scalar = P256Scalar::from_limbs(limbs);
        assert_eq!(*scalar.limbs(), limbs);
    }

    #[test]
    fn secret_scalar_reduces_out_of_range_input() {
        let scalar = P256Scalar::from_limbs(N_LIMBS);
        assert_eq!(*scalar.limbs(), [0, 0, 0, 0]);
    }
}
