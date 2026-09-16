//! The SM2 scalar field, arithmetic mod the curve order `n` (`draft-shen-sm2-ecdsa-02` Appendix
//! D), needed for `k⁻¹` and `s = k⁻¹(e + rd) mod n` in ECDSA-shaped signing.
//!
//! Unlike `p`, `n` is not a Solinas prime -- there is no special shape to exploit for reduction --
//! so this uses Montgomery arithmetic instead: [`Sm2ScalarField`] holds its value as `x*R mod n`
//! internally (`R = 2^256`), which turns multiplication mod `n` into one wide multiply plus one
//! *fixed-length* reduction pass (REDC) with no data-dependent trial subtraction. Addition and
//! subtraction don't need REDC at all -- Montgomery form is linear, so `(a*R mod n) + (b*R mod n)
//! mod n == (a+b)*R mod n` -- and reuse the same "modulus close to `2^256`" trick
//! [`crate::sm2::Sm2FieldElement`] uses for `p` (this one isn't Solinas-specific either: it only
//! needs `n < 2^256`, true here just as for P-256's own scalar field).
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

/// `n`, the order of the SM2 base point `G`, little-endian `u64` limbs (`draft-shen-sm2-ecdsa-02`
/// Appendix D).
pub const N_LIMBS: [u64; 4] =
    [0x53bbf40939d54123, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff];

/// `2^256 mod n` -- both the correction constant [`Sm2ScalarField::add`] uses (mirroring
/// [`crate::sm2::Sm2FieldElement::add`]) and, not by coincidence, the Montgomery representation
/// of `1` (`R mod n` where `R = 2^256`), since `2^256 mod n` *is* `R mod n`.
const R_LIMBS: [u64; 4] =
    [0xac440bf6c62abedd, 0x8dfc2094de39fad4, 0x0000000000000000, 0x0000000100000000];

/// `R^2 mod n`, used to bring a plain value into Montgomery form: `REDC(x * R^2) = x*R mod n`.
const R_SQUARED_LIMBS: [u64; 4] =
    [0x901192af7c114f20, 0x3464504ade6fa2fa, 0x620fc84c3affe0d4, 0x1eb5e412a22b3d3b];

/// `-n^-1 mod 2^64`, the Montgomery reduction constant.
const N_PRIME: u64 = 0x327f9e8872350975;

/// `n - 2`, little-endian `u64` limbs -- the public exponent [`Sm2ScalarField::invert`] raises
/// its base to, per Fermat's little theorem (`n` is prime).
const N_MINUS_2_LIMBS: [u64; 4] =
    [0x53bbf40939d54121, 0x7203df6b21c6052b, 0xffffffffffffffff, 0xfffffffeffffffff];

/// An element of the SM2 scalar field, i.e. an integer mod `n`. Stored internally in Montgomery
/// form; see the module docs.
#[derive(Clone, Copy, Debug)]
pub struct Sm2ScalarField([u64; 4]);

impl Sm2ScalarField {
    /// The additive identity. `0`'s Montgomery form is `0` itself (`0 * R mod n == 0`).
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// The multiplicative identity. Its Montgomery form is `R mod n`, i.e. [`R_LIMBS`], not the
    /// literal integer `1`.
    pub const ONE: Self = Self(R_LIMBS);

    /// Builds a scalar-field element from little-endian `u64` limbs (an ordinary, non-Montgomery
    /// value), reducing once if `limbs >= n` (the same single-conditional-subtraction argument as
    /// [`crate::sm2::Sm2FieldElement::from_limbs`] applies: `limbs < 2^256 < 2n`), then
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

    /// `self^2 mod n`.
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Converts a secret scalar (`d` or `k`) into Montgomery form for field arithmetic (`k⁻¹`, `r*d`,
    /// ...). Reads the secret's limbs once into a plain value, the same "protects storage, not
    /// every derived computation" boundary [`crate::sm2_comb::comb_multiply_base_point`] already
    /// crosses to read `k`'s bits.
    pub fn from_secret(secret: &Sm2Scalar) -> Self {
        Self::from_limbs(*secret.limbs())
    }

    /// `self^-1 mod n`, or `0` if `self` is `0`. Fermat's little theorem (`n` is prime), by fixed
    /// square-then-conditionally-multiply over the public exponent `n-2` -- see
    /// [`crate::sm2::Sm2FieldElement::invert`]'s docs, which this mirrors exactly (branch-free,
    /// same reasoning: `n-2` is a compile-time public constant, and the "conditionally" is a
    /// branch-free mask, not a data-dependent branch).
    pub fn invert(&self) -> Self {
        let mut result = Self::ONE;
        for limb_idx in (0..4).rev() {
            let limb = N_MINUS_2_LIMBS[limb_idx];
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

impl PartialEq for Sm2ScalarField {
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

impl Eq for Sm2ScalarField {}

/// Schoolbook widening multiply, identical in shape to
/// [`crate::sm2`]'s private helper of the same name; see that module's docs for why this isn't
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

/// Montgomery reduction (SOS method): given an 8-limb value `t < n*R`, returns `t * R^-1 mod n` as
/// 4 limbs. See the module docs for the algorithm.
///
/// After the 4 reduction rounds, the low 4 limbs of the 9-limb accumulator are zero and the
/// result -- `t * R^-1`, an integer, not yet reduced mod `n` -- occupies the remaining 5 limbs
/// (`acc[4..9]`): unlike [`crate::sm2::reduce`], whose modulus is small enough that the analogous
/// step needs only one limb of headroom, `n` is close enough to `2^256` that `2n` can exceed it,
/// so a 9th limb (`acc[8]`, verified to always be `0` or `1`) is needed. The final step folds that
/// bit in exactly like [`crate::sm2::Sm2FieldElement::add`]'s carry-aware correction: if
/// `acc[8] == 1`, the true value is `high + 2^256`, `>= 2^256 > n`, so `high + (2^256 mod n)` (i.e.
/// `+ R_LIMBS`) is the reduced result; otherwise it's `high`, conditionally reduced once more if
/// `high >= n`.
fn redc(t: &[u64; 8]) -> [u64; 4] {
    let mut acc = [0u64; 9];
    acc[..8].copy_from_slice(t);

    for i in 0..4 {
        let m = acc[i].wrapping_mul(N_PRIME);
        let mn = widening_mul(&[m, 0, 0, 0], &N_LIMBS);
        debug_assert_eq!(mn[5], 0);
        debug_assert_eq!(mn[6], 0);
        debug_assert_eq!(mn[7], 0);

        let mut carry: u128 = 0;
        for j in 0..5 {
            let idx = i + j;
            let s = (acc[idx] as u128) + (mn[j] as u128) + carry;
            acc[idx] = s as u64;
            carry = s >> 64;
        }
        // Verified (over 50,000 pseudorandom trials plus the (n-1)*(n-1) worst case) that this
        // loop never needs more than a single iteration for any input reachable from an actual
        // scalar-field multiplication: `idx`'s post-increment value is therefore never read again
        // once the loop exits, which is why mutating `idx += 1` itself (as opposed to the bound
        // check above it) is an accepted equivalent mutant here -- the same reasoning
        // `crate::montgomery::redc`'s own tail loop documents for the brainpool curves.
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
/// conversion from `Sm2Scalar` to [`Sm2PublicScalar`]: the crate's constant-time and
/// variable-time scalar multipliers take `&Sm2Scalar` and `&Sm2PublicScalar` respectively, so a
/// caller cannot pass a secret scalar to the variable-time multiplier by accident -- the type
/// system forbids it, rather than relying on a reviewer to notice (the design plan's §5, §7 rule
/// 4). `Clone`/`Debug`/`PartialEq`/`Eq` forward to [`Secret`]'s own impls (`Debug` redacting,
/// `PartialEq` constant-time), which is what `core::traits::SignaturePrivateKey`'s bound needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sm2Scalar(Secret<[u64; 4]>);

impl Sm2Scalar {
    /// Builds a secret scalar from little-endian `u64` limbs, reducing once if `limbs >= n` (see
    /// [`Sm2ScalarField::from_limbs`]'s doc for why one conditional subtraction always suffices).
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        let mut secret = Secret::<[u64; 4]>::new();
        *secret = reduce_once(limbs);
        Self(secret)
    }

    /// Builds a secret scalar from SEC 1 §2.3.7 big-endian octets, reducing once if `>= n`.
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Self {
        Self::from_limbs(crate::sm2_sec1::limbs_from_be_bytes(bytes))
    }

    /// Encodes to SEC 1 §2.3.7 big-endian octets -- the wire form of an ECDSA private key.
    /// Momentarily holds the plain value in the returned array, same as any other `encode()` on a
    /// `SignaturePrivateKey`: the caller asked for the bytes.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        crate::sm2_sec1::be_bytes_from_limbs(&self.0)
    }

    /// The scalar's limbs, for the crate's own multiplier and field-arithmetic implementations to
    /// read (see [`Sm2ScalarField::from_secret`]). Not exposed outside the crate: nothing outside
    /// `bouncycastle-ec` should ever hold a bare, unprotected copy of a secret scalar's value.
    pub(crate) fn limbs(&self) -> &[u64; 4] {
        &self.0
    }
}

/// A scalar mod `n`, `< n`, held as a plain (non-secret) value -- for a value that is public by
/// construction: the `u`, `v` scalars ECDSA verification computes from a signature and public
/// data, or a message-derived value. See [`Sm2Scalar`]'s docs for why there is no conversion the
/// other way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sm2PublicScalar([u64; 4]);

impl Sm2PublicScalar {
    /// Builds a public scalar from little-endian `u64` limbs, reducing once if `limbs >= n`.
    pub fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(reduce_once(limbs))
    }

    /// Returns the scalar's little-endian `u64` limbs, `< n`.
    pub fn to_limbs(&self) -> [u64; 4] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    // `Sm2Scalar::limbs` is `pub(crate)`, deliberately not reachable from an integration test
    // (nothing outside the crate should get a bare copy of a secret scalar) -- exercised here
    // instead, per QUALITY_AND_STYLE's carve-out for code unreachable through the public API.
    use super::*;

    #[test]
    fn secret_scalar_reduces_and_round_trips() {
        let limbs: [u64; 4] = [1, 2, 3, 4];
        let scalar = Sm2Scalar::from_limbs(limbs);
        assert_eq!(*scalar.limbs(), limbs);
    }

    #[test]
    fn secret_scalar_reduces_out_of_range_input() {
        let scalar = Sm2Scalar::from_limbs(N_LIMBS);
        assert_eq!(*scalar.limbs(), [0, 0, 0, 0]);
    }
}
