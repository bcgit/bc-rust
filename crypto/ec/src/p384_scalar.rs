//! The P-384 scalar field, arithmetic mod the curve order `n` (SP 800-186 §3.2.1.4). Identical in
//! shape to [`crate::p256_scalar`] -- Montgomery form (`R = 2^384`), the same SOS reduction, the
//! same `Secret`/plain scalar split -- with `n` swapped for P-384's; see that module's docs for
//! the full derivation.
//!
//! REDC's accumulator, like [`crate::p256_scalar::redc`]'s, needs one bit of headroom beyond the
//! 12-limb product (`n` is close enough to `2^384` that `2n` can exceed it): verified (not checked
//! in) against 30,000 random trials plus the `(n-1)*(n-1)` worst case.

use crate::nat;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// `n`, the order of the P-384 base point `G`, little-endian `u64` limbs (SP 800-186 §3.2.1.4).
pub const N_LIMBS: [u64; 6] = [
    0xecec196accc52973, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff,
];

/// `2^384 mod n`, also the Montgomery representation of `1`.
const R_LIMBS: [u64; 6] = [
    0x1313e695333ad68d, 0xa7e5f24db74f5885, 0x389cb27e0bc8d220, 0x0000000000000000,
    0x0000000000000000, 0x0000000000000000,
];

/// `R^2 mod n`, used to bring a plain value into Montgomery form.
const R_SQUARED_LIMBS: [u64; 6] = [
    0x2d319b2419b409a9, 0xff3d81e5df1aa419, 0xbc3e483afcb82947, 0xd40d49174aab1cc5,
    0x3fb05b7a28266895, 0x0c84ee012b39bf21,
];

/// `-n^-1 mod 2^64`, the Montgomery reduction constant.
const N_PRIME: u64 = 0x6ed46089e88fdc45;

/// `n - 2`, little-endian `u64` limbs -- the public exponent [`P384ScalarField::invert`] raises
/// its base to.
const N_MINUS_2_LIMBS: [u64; 6] = [
    0xecec196accc52971, 0x581a0db248b0a77a, 0xc7634d81f4372ddf, 0xffffffffffffffff,
    0xffffffffffffffff, 0xffffffffffffffff,
];

/// An element of the P-384 scalar field, i.e. an integer mod `n`. Stored internally in Montgomery
/// form; see the module docs.
#[derive(Clone, Copy, Debug)]
pub struct P384ScalarField([u64; 6]);

impl P384ScalarField {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity. Its Montgomery form is `R mod n`, not the literal integer `1`.
    pub const ONE: Self = Self(R_LIMBS);

    /// Builds a scalar-field element from little-endian `u64` limbs (an ordinary, non-Montgomery
    /// value), reducing once if `limbs >= n`, then converting to Montgomery form.
    pub fn from_limbs(limbs: [u64; 6]) -> Self {
        let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
        let mut reduced = [0u64; 6];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
        Self(redc(&widening_mul(&reduced, &R_SQUARED_LIMBS)))
    }

    /// Returns the canonical little-endian `u64` limbs (an ordinary, non-Montgomery value), `< n`.
    pub fn to_limbs(&self) -> [u64; 6] {
        let mut wide = [0u64; 12];
        wide[..6].copy_from_slice(&self.0);
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

    /// `self - other mod n`.
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = nat::sub(&self.0, &other.0);
        let (corrected, _) = nat::add(&diff, &N_LIMBS);
        let mut result = [0u64; 6];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod n`.
    pub fn negate(&self) -> Self {
        let (diff, _) = nat::sub(&N_LIMBS, &self.0);
        let mut result = [0u64; 6];
        ct::conditional_select(self.is_zero(), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod n`, via Montgomery multiplication.
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

    /// Converts a secret scalar (`d` or `k`) into Montgomery form for field arithmetic. See
    /// [`crate::p256_scalar::P256ScalarField::from_secret`]'s docs.
    pub fn from_secret(secret: &P384Scalar) -> Self {
        Self::from_limbs(*secret.limbs())
    }

    /// `self^-1 mod n`, or `0` if `self` is `0`. Fermat's little theorem, by fixed
    /// square-then-conditionally-multiply over the public exponent `n-2`.
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..6).rev() {
            let limb = N_MINUS_2_LIMBS[limb_idx];
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

impl PartialEq for P384ScalarField {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found. Comparing Montgomery-form limbs directly is valid: the map `x -> x*R mod n` is a
    /// bijection.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..6 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for P384ScalarField {}

/// Schoolbook widening multiply, identical in shape to [`crate::p256_scalar`]'s.
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
        // `*limb << 1` always leaves bit 0 clear and `carry` is only ever 0 or 1, so the two
        // operands are disjoint: mutating this `|` to `^` is an accepted equivalent, not a bug.
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

/// `m * n`, one limb times the 6-limb modulus `n`, as the 7 limbs such a product can occupy.
///
/// This is exactly what each round of [`redc`]'s SOS reduction needs, and the shape
/// [`crate::montgomery::redc`] has always used for the brainpool curves. Every hand-written scalar
/// REDC in this crate previously formed it with the general 6x6 [`widening_mul`] against a
/// zero-padded `[m, 0, ..., 0]` instead, asking for 36 limb multiplications where 6 are needed.
///
/// Whether that padding costs anything turns out to depend entirely on the width, measured rather
/// than assumed: at four limbs the optimizer eliminates it completely (P-256 and secp256k1 time
/// identically either way), but it stops doing so by six, where the padded form measured 3.2x
/// slower per scalar multiplication for P-384 and 5.2x slower for P-521. All four are written this
/// way regardless, so the four modules read alike and none of them asks for work it does not want.
fn modulus_times_limb(m: u64) -> [u64; 7] {
    let mut out = [0u64; 7];
    let mut carry: u128 = 0;
    for j in 0..6 {
        let prod = (m as u128) * (N_LIMBS[j] as u128) + carry;
        out[j] = prod as u64;
        carry = prod >> 64;
    }
    out[6] = carry as u64;
    out
}

/// Montgomery reduction (SOS method): given a 12-limb value `t < n*R`, returns `t * R^-1 mod n` as
/// 6 limbs. See [`crate::p256_scalar::redc`]'s docs for the algorithm; the 13th accumulator limb
/// plays the same role as that function's 9th.
fn redc(t: &[u64; 12]) -> [u64; 6] {
    let mut acc = [0u64; 13];
    acc[..12].copy_from_slice(t);

    for i in 0..6 {
        let m = acc[i].wrapping_mul(N_PRIME);
        let mn = modulus_times_limb(m);

        let mut carry: u128 = 0;
        for j in 0..7 {
            let idx = i + j;
            let s = (acc[idx] as u128) + (mn[j] as u128) + carry;
            acc[idx] = s as u64;
            carry = s >> 64;
        }
        let mut idx = i + 7;
        while carry != 0 {
            debug_assert!(idx < 13, "REDC overflowed its verified 13-limb bound");
            let s = (acc[idx] as u128) + carry;
            acc[idx] = s as u64;
            carry = s >> 64;
            idx += 1;
        }
    }
    debug_assert_eq!(&acc[..6], &[0u64; 6], "REDC's low limbs must be cleared after 6 rounds");
    debug_assert!(acc[12] == 0 || acc[12] == 1, "REDC's top limb must be a single bit");

    let high: [u64; 6] = [acc[6], acc[7], acc[8], acc[9], acc[10], acc[11]];
    let (high_plus_r, _) = nat::add(&high, &R_LIMBS);
    let (diff, borrow) = nat::sub(&high, &N_LIMBS);
    let mut when_no_extra_bit = [0u64; 6];
    ct::conditional_select(
        Condition::<u64>::from_lsb(borrow),
        &high,
        &diff,
        &mut when_no_extra_bit,
    );
    let mut result = [0u64; 6];
    ct::conditional_select(
        Condition::<u64>::from_lsb(acc[12]),
        &high_plus_r,
        &when_no_extra_bit,
        &mut result,
    );
    result
}

fn reduce_once(limbs: [u64; 6]) -> [u64; 6] {
    let (diff, borrow) = nat::sub(&limbs, &N_LIMBS);
    let mut result = [0u64; 6];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut result);
    result
}

/// A scalar mod `n`, `< n`, held in `Secret`. See [`crate::p256_scalar::P256Scalar`]'s docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P384Scalar(Secret<[u64; 6]>);

impl P384Scalar {
    /// Builds a secret scalar from little-endian `u64` limbs, reducing once if `limbs >= n`.
    pub fn from_limbs(limbs: [u64; 6]) -> Self {
        let mut secret = Secret::<[u64; 6]>::new();
        *secret = reduce_once(limbs);
        Self(secret)
    }

    /// Builds a secret scalar from SEC 1 §2.3.7 big-endian octets, reducing once if `>= n`.
    pub fn from_be_bytes(bytes: &[u8; 48]) -> Self {
        Self::from_limbs(crate::p384_sec1::limbs_from_be_bytes(bytes))
    }

    /// Encodes to SEC 1 §2.3.7 big-endian octets.
    pub fn to_be_bytes(&self) -> [u8; 48] {
        crate::p384_sec1::be_bytes_from_limbs(&self.0)
    }

    /// The scalar's limbs, for the crate's own multiplier and field-arithmetic implementations to
    /// read. Not exposed outside the crate.
    pub(crate) fn limbs(&self) -> &[u64; 6] {
        &self.0
    }
}

/// A scalar mod `n`, `< n`, held as a plain (non-secret) value. See
/// [`crate::p256_scalar::P256PublicScalar`]'s docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P384PublicScalar([u64; 6]);

impl P384PublicScalar {
    /// Builds a public scalar from little-endian `u64` limbs, reducing once if `limbs >= n`.
    pub fn from_limbs(limbs: [u64; 6]) -> Self {
        Self(reduce_once(limbs))
    }

    /// Returns the scalar's little-endian `u64` limbs, `< n`.
    pub fn to_limbs(&self) -> [u64; 6] {
        self.0
    }

    /// `self^-1 mod n` in **variable time**, as a [`P384ScalarField`] ready for the arithmetic
    /// that follows, or `0` for `0`. For ECDSA verification's `s` (FIPS 186-5 §6.4.2 step 4),
    /// which is part of the signature and so already public; nothing derived from a private key
    /// or a per-message secret may reach this, which is why it lives on the public scalar type
    /// and not on [`P384ScalarField`], whose `invert` is the constant-time one. See
    /// [`crate::inverse_vartime`].
    pub fn invert_vartime(&self) -> P384ScalarField {
        P384ScalarField::from_limbs(crate::inverse_vartime::mod_inverse(&self.0, &N_LIMBS))
    }
}
