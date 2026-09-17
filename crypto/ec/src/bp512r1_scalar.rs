//! The brainpoolP512r1 scalar field, arithmetic mod the curve order `n` (RFC 5639 §3.4). Like
//! [`crate::bp512r1`], `n` here has no special algebraic structure, so this is built on
//! [`crate::montgomery`]'s generic Montgomery multiplication rather than a per-curve fold --
//! identical in shape to every other curve's own scalar field in this crate (e.g.
//! [`crate::p256_scalar`]), just delegating the widening-multiply/REDC work to the shared module
//! instead of hand-writing it again.

use crate::montgomery;
use bouncycastle_utils::ct;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// `n`, the order of the brainpoolP512r1 base point `G`, little-endian `u64` limbs (RFC 5639
/// §3.4).
pub const N_LIMBS: [u64; 8] = [
    0xb58796829ca90069, 0x1db1d381085ddadd, 0x418661197fac1047, 0x553e5c414ca92619,
    0xd6639cca70330870, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
];

/// `-n^-1 mod 2^64`, the Montgomery reduction constant.
const N_PRIME: u64 = 0xad49541f0f1b7027;

/// `R^2 mod n` (`R = 2^512`), used to bring a plain value into Montgomery form.
const R_SQUARED_LIMBS: [u64; 8] = [
    0xd2a3681ecda81671, 0x0886b75895283ddd, 0x3ec64bd033b7627f, 0xa6f230c72f0207e8,
    0xd7f9cc263b790de3, 0x723c37a22f16bbdf, 0x95df1b4c194b2e56, 0xa794586a718407b0,
];

/// `R mod n`, also the Montgomery representation of `1`.
const R_MOD_N_LIMBS: [u64; 8] = [
    0x4a78697d6356ff97, 0xe24e2c7ef7a22522, 0xbe799ee68053efb8, 0xaac1a3beb356d9e6,
    0x299c63358fccf78f, 0x34cf724c4c362df1, 0xc02b1951cc3603f8, 0x5522624724163b74,
];

/// `n - 2`, little-endian `u64` limbs -- the public exponent [`Bp512r1ScalarField::invert`]
/// raises its base to.
const N_MINUS_2_LIMBS: [u64; 8] = [
    0xb58796829ca90067, 0x1db1d381085ddadd, 0x418661197fac1047, 0x553e5c414ca92619,
    0xd6639cca70330870, 0xcb308db3b3c9d20e, 0x3fd4e6ae33c9fc07, 0xaadd9db8dbe9c48b,
];

/// An element of the brainpoolP512r1 scalar field, i.e. an integer mod `n`. Stored internally in
/// Montgomery form; see the module docs.
#[derive(Clone, Copy, Debug)]
pub struct Bp512r1ScalarField([u64; 8]);

impl Bp512r1ScalarField {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0, 0, 0, 0, 0]);

    /// The multiplicative identity. Its Montgomery form is `R mod n`, not the literal integer `1`.
    pub const ONE: Self = Self(R_MOD_N_LIMBS);

    /// Builds a scalar-field element from little-endian `u64` limbs (an ordinary, non-Montgomery
    /// value), reducing once if `limbs >= n` (valid since `limbs < 2^512 < 2n`), then converting
    /// to Montgomery form.
    pub fn from_limbs(limbs: [u64; 8]) -> Self {
        let (diff, borrow) = crate::nat::sub(&limbs, &N_LIMBS);
        let mut reduced = [0u64; 8];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut reduced);
        let t = montgomery::widening_mul::<8, 16>(&reduced, &R_SQUARED_LIMBS);
        Self(Self::finish_redc(&t))
    }

    /// Returns the canonical little-endian `u64` limbs (an ordinary, non-Montgomery value), `< n`.
    pub fn to_limbs(&self) -> [u64; 8] {
        let mut t = [0u64; 16];
        t[..8].copy_from_slice(&self.0);
        montgomery::redc::<8, 16, 17>(&t, &N_LIMBS, N_PRIME).0
    }

    /// TRUE iff this element is the additive identity.
    pub fn is_zero(&self) -> Condition<u64> {
        crate::nat::is_zero(&self.0)
    }

    /// `self + other mod n`. Operates directly on the Montgomery-form limbs: no REDC needed.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = crate::nat::add(&self.0, &other.0);
        let (sum_plus_r, _) = crate::nat::add(&sum, &R_MOD_N_LIMBS);
        let (diff, borrow) = crate::nat::sub(&sum, &N_LIMBS);
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

    /// `self - other mod n`.
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = crate::nat::sub(&self.0, &other.0);
        let (corrected, _) = crate::nat::add(&diff, &N_LIMBS);
        let mut result = [0u64; 8];
        ct::conditional_select(Condition::<u64>::from_lsb(borrow), &corrected, &diff, &mut result);
        Self(result)
    }

    /// `-self mod n`.
    pub fn negate(&self) -> Self {
        let (diff, _) = crate::nat::sub(&N_LIMBS, &self.0);
        let mut result = [0u64; 8];
        ct::conditional_select(self.is_zero(), &Self::ZERO.0, &diff, &mut result);
        Self(result)
    }

    /// `self * other mod n`, via Montgomery multiplication.
    pub fn mul(&self, other: &Self) -> Self {
        let t = montgomery::widening_mul::<8, 16>(&self.0, &other.0);
        Self(Self::finish_redc(&t))
    }

    /// `self^2 mod n`.
    /// `self^2`, via a dedicated squaring rather than `self.mul(self)` -- see
    /// [`montgomery::widening_square`]. Used by the exponentiation loops, not by point
    /// arithmetic; see [`crate::p256::P256FieldElement::square`] for the measurement behind that
    /// split.
    pub fn square(&self) -> Self {
        let t = montgomery::widening_square::<8, 16>(&self.0);
        Self(Self::finish_redc(&t))
    }

    /// Converts a secret scalar (`d` or `k`) into Montgomery form for field arithmetic. See
    /// [`crate::p256_scalar::P256ScalarField::from_secret`]'s docs.
    pub fn from_secret(secret: &Bp512r1Scalar) -> Self {
        Self::from_limbs(*secret.limbs())
    }

    /// `self^-1 mod n`, or `0` if `self` is `0`. Fermat's little theorem, by fixed
    /// square-then-conditionally-multiply over the public exponent `n-2`.
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..8).rev() {
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

    /// [`montgomery::redc`]'s `(high, extra)` result, reduced to the canonical `< n` value. See
    /// [`crate::bp512r1::Bp512r1FieldElement`]'s identical `finish_redc` for the invariant this
    /// relies on and how it was verified for this specific `n`.
    fn finish_redc(t: &[u64; 16]) -> [u64; 8] {
        let (high, extra) = montgomery::redc::<8, 16, 17>(t, &N_LIMBS, N_PRIME);
        let (sum, _) = crate::nat::add(&high, &R_MOD_N_LIMBS);
        let (diff, borrow) = crate::nat::sub(&high, &N_LIMBS);
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

impl PartialEq for Bp512r1ScalarField {
    /// Constant-time: every limb is compared regardless of where (or whether) a difference is
    /// found. Comparing Montgomery-form limbs directly is valid: the map `x -> x*R mod n` is a
    /// bijection.
    fn eq(&self, other: &Self) -> bool {
        let mut acc = Condition::<u64>::TRUE;
        for i in 0..8 {
            acc &= Condition::<u64>::is_equal(self.0[i], other.0[i]);
        }
        acc.to_bool()
    }
}

impl Eq for Bp512r1ScalarField {}

fn reduce_once(limbs: [u64; 8]) -> [u64; 8] {
    let (diff, borrow) = crate::nat::sub(&limbs, &N_LIMBS);
    let mut result = [0u64; 8];
    ct::conditional_select(Condition::<u64>::from_lsb(borrow), &limbs, &diff, &mut result);
    result
}

/// A scalar mod `n`, `< n`, held in `Secret`. See [`crate::p256_scalar::P256Scalar`]'s docs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bp512r1Scalar(Secret<[u64; 8]>);

impl Bp512r1Scalar {
    /// Builds a secret scalar from little-endian `u64` limbs, reducing once if `limbs >= n`.
    pub fn from_limbs(limbs: [u64; 8]) -> Self {
        let mut secret = Secret::<[u64; 8]>::new();
        *secret = reduce_once(limbs);
        Self(secret)
    }

    /// Builds a secret scalar from SEC 1 §2.3.7 big-endian octets, reducing once if `>= n`.
    pub fn from_be_bytes(bytes: &[u8; 64]) -> Self {
        Self::from_limbs(crate::bp512r1_sec1::limbs_from_be_bytes(bytes))
    }

    /// Encodes to SEC 1 §2.3.7 big-endian octets.
    pub fn to_be_bytes(&self) -> [u8; 64] {
        crate::bp512r1_sec1::be_bytes_from_limbs(&self.0)
    }

    /// The scalar's limbs, for the crate's own multiplier and field-arithmetic implementations to
    /// read. Not exposed outside the crate.
    pub(crate) fn limbs(&self) -> &[u64; 8] {
        &self.0
    }
}

/// A scalar mod `n`, `< n`, held as a plain (non-secret) value. See
/// [`crate::p256_scalar::P256PublicScalar`]'s docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bp512r1PublicScalar([u64; 8]);

impl Bp512r1PublicScalar {
    /// Builds a public scalar from little-endian `u64` limbs, reducing once if `limbs >= n`.
    pub fn from_limbs(limbs: [u64; 8]) -> Self {
        Self(reduce_once(limbs))
    }

    /// Returns the scalar's little-endian `u64` limbs, `< n`.
    pub fn to_limbs(&self) -> [u64; 8] {
        self.0
    }
}
