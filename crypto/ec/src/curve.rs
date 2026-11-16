//! The curve as a type parameter: [`Curve`], implemented by the seven markers at the crate root,
//! names a curve's arithmetic types and routes to its [`hazmat`](crate::hazmat) functions, so that
//! a signature or key-agreement crate is written once over `C: Curve` and instantiated per curve.
//! The constant-time arithmetic stays in the per-curve hazmat modules; nothing here computes, it
//! only names and forwards, and monomorphisation produces the same code as a direct call.
//!
//! Lengths reach generic code as array types rather than as constants, because stable Rust cannot
//! write `[u8; C::SCALAR_LEN]`: `C::Signature` is the `[u8; N]` a signature is, and where a `core`
//! trait needs the `N` itself an impl is generic over it and bound `C: Curve<Signature = [u8; N]>`,
//! which the solver resolves from `C` so that no call site names `N`. The `*_LEN` constants are the
//! same numbers for documentation and arithmetic, and [`check_lengths`] pins the two together.

use crate::nat;
use bouncycastle_core::errors::RNGError;
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::traits::RNG;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::{Secret, ZeroizablePrimitive};
use core::fmt::Debug;

/// A fixed-size array a curve's values are held or encoded in: `[u64; L]` limbs or `[u8; N]`
/// bytes. `ZEROED` (from [`ZeroizablePrimitive`]) stands in for `Default`, which arrays over 32
/// elements lack.
pub trait Array<T: Copy>:
    ZeroizablePrimitive + AsRef<[T]> + AsMut<[T]> + PartialEq + Eq + Debug + 'static
{
    /// The number of elements.
    const LEN: usize;
}

impl<T: ZeroizablePrimitive + PartialEq + Eq + Debug + 'static, const N: usize> Array<T>
    for [T; N]
{
    const LEN: usize = N;
}

/// An element of a curve's base field, in the curve's own reduced representation. Every
/// operation is constant time in the element's value; see the hazmat module of each curve.
pub trait FieldElement: Copy + Clone + Debug + PartialEq + Eq + 'static {
    /// The limb array behind the element.
    type Limbs: Array<u64>;
    /// `0`.
    const ZERO: Self;
    /// `1`.
    const ONE: Self;
    /// From canonical limbs (little-endian words of the value in `[0, p)`).
    fn from_limbs(limbs: Self::Limbs) -> Self;
    /// The canonical limbs.
    fn to_limbs(&self) -> Self::Limbs;
    /// The canonical limbs into `out`, for a caller keeping them in a [`Secret`].
    fn to_limbs_into(&self, out: &mut Self::Limbs);
    /// Whether the element is `0`, as a mask.
    fn is_zero(&self) -> Condition<u64>;
    /// Overwrites the limbs with zero through a volatile store.
    fn zeroize(&mut self);
    /// `self + other`.
    fn add(&self, other: &Self) -> Self;
    /// `self - other`.
    fn sub(&self, other: &Self) -> Self;
    /// `-self`.
    fn negate(&self) -> Self;
    /// `self * other`.
    fn mul(&self, other: &Self) -> Self;
    /// `self^2`.
    fn square(&self) -> Self;
    /// `self^-1` by exponentiation, constant time; `0` maps to `0`.
    fn invert(&self) -> Self;
}

/// A point in Jacobian coordinates, `(X, Y, Z)` for the affine `(X / Z^2, Y / Z^3)`, with
/// `Z == 0` the point at infinity.
pub trait JacobianPoint: Copy + Clone + Debug + 'static {
    /// The coordinate type.
    type Fe: FieldElement;
    /// The point at infinity, the group's identity.
    const INFINITY: Self;
    /// `(x, y, 1)`.
    fn from_affine(x: Self::Fe, y: Self::Fe) -> Self;
    /// `X`.
    fn x(&self) -> &Self::Fe;
    /// `Y`.
    fn y(&self) -> &Self::Fe;
    /// `Z`.
    fn z(&self) -> &Self::Fe;
    /// Whether the point is the identity, as a mask.
    fn is_infinity(&self) -> Condition<u64>;
    /// The affine coordinates, or `None` for the identity. Branches on the identity, so not for
    /// a point computed from a secret; see [`JacobianPoint::affine_x_of_nonidentity`].
    fn to_affine(&self) -> Option<(Self::Fe, Self::Fe)>;
    /// `-self`.
    fn negate(&self) -> Self;
    /// Overwrites the coordinates with zero through volatile stores.
    fn zeroize(&mut self);
    /// `2 * self`.
    fn double(&self) -> Self;
    /// `self + other`.
    fn add(&self, other: &Self) -> Self;

    /// The affine `x`, `X * Z^-2`, computed without the identity branch of
    /// [`to_affine`](JacobianPoint::to_affine): for a point the caller knows is not the identity
    /// (`[k]G` for `k` in `[1, n-1]`, `[d]Q` for a validated `Q`), whose coordinates came from a
    /// secret. The inverse and its square are zeroized here; the inversion's own intermediates
    /// are the field's.
    fn affine_x_of_nonidentity(&self) -> Self::Fe {
        let mut z_inv = self.z().invert();
        let mut z_inv_sq = z_inv.square();
        let x = self.x().mul(&z_inv_sq);
        z_inv.zeroize();
        z_inv_sq.zeroize();
        x
    }
}

/// A secret scalar in `[0, n)`, held in a [`Secret`]: a private key or a per-message secret.
pub trait SecretScalar: Clone + Debug + PartialEq + Eq + 'static {
    /// The limb array behind the scalar.
    type Limbs: Array<u64>;
    /// The big-endian encoding, `ceil(log2 n / 8)` bytes.
    type Bytes: Array<u8>;
    /// From limbs, reduced mod `n`; the argument is zeroized.
    fn from_limbs(limbs: Self::Limbs) -> Self;
    /// From borrowed limbs, reduced mod `n`, leaving the caller's copy to the caller.
    fn from_borrowed_limbs(limbs: &Self::Limbs) -> Self;
    /// From the big-endian encoding, reduced mod `n`.
    fn from_be_bytes(bytes: &Self::Bytes) -> Self;
    /// The big-endian encoding, as a plain array the caller asked for.
    fn to_be_bytes(&self) -> Self::Bytes;
}

/// An element of the scalar field `Z_n` in the curve's Montgomery representation, for the
/// signature arithmetic (`k^-1`, `e + r * d`); constant time in its value.
pub trait ScalarFieldElement: Copy + Clone + Debug + PartialEq + Eq + 'static {
    /// The limb array behind the element.
    type Limbs: Array<u64>;
    /// The secret scalar type an element is loaded from.
    type Secret: SecretScalar<Limbs = Self::Limbs>;
    /// `0`.
    const ZERO: Self;
    /// `1`.
    const ONE: Self;
    /// From canonical limbs of a value below `2n`, reduced by one conditional subtraction.
    fn from_limbs(limbs: Self::Limbs) -> Self;
    /// The canonical limbs.
    fn to_limbs(&self) -> Self::Limbs;
    /// Whether the element is `0`, as a mask.
    fn is_zero(&self) -> Condition<u64>;
    /// Overwrites the limbs with zero through a volatile store.
    fn zeroize(&mut self);
    /// `self + other`.
    fn add(&self, other: &Self) -> Self;
    /// `self - other`.
    fn sub(&self, other: &Self) -> Self;
    /// `-self`.
    fn negate(&self) -> Self;
    /// `self * other`.
    fn mul(&self, other: &Self) -> Self;
    /// `self^2`.
    fn square(&self) -> Self;
    /// Into the field from a secret scalar.
    fn from_secret(secret: &Self::Secret) -> Self;
    /// `self^-1` by exponentiation, constant time.
    fn invert(&self) -> Self;
}

/// A public scalar (a signature's `s`, verification's `u` and `v`), on which variable-time
/// arithmetic is allowed. A separate type from the secret scalars so that a secret cannot reach
/// the variable-time paths by accident.
pub trait PublicScalar: Copy + Clone + Debug + 'static {
    /// The limb array behind the scalar.
    type Limbs: Array<u64>;
    /// The scalar field an inverse lands in.
    type Field: ScalarFieldElement<Limbs = Self::Limbs>;
    /// From canonical limbs.
    fn from_limbs(limbs: Self::Limbs) -> Self;
    /// The canonical limbs.
    fn to_limbs(&self) -> Self::Limbs;
    /// `self^-1` in variable time.
    fn invert_vartime(&self) -> Self::Field;
}

/// What [`Curve::keygen`] produces: the private scalar and `[d]G` in affine form.
pub type GeneratedKeyPair<C> = (<C as Curve>::Scalar, (<C as Curve>::Fe, <C as Curve>::Fe));

/// A curve: the marker's view of one of the crate's `hazmat` implementations. Sealed, since an
/// impl is a routing table into this crate's arithmetic and every length below must agree with
/// it ([`check_lengths`]).
pub trait Curve:
    sealed::Sealed + Copy + Clone + Debug + Default + PartialEq + Eq + 'static
{
    /// The curve's name as it appears in algorithm names: `P256`, `secp256k1`,
    /// `brainpoolP256r1`.
    const NAME: &'static str;
    /// The strength SP 800-57 Part 1 Rev. 5 Table 2 gives the order's bit length.
    const STRENGTH: SecurityStrength;
    /// The bit length of the order `n` (`qlen` in RFC 6979).
    const ORDER_BITS: usize;
    /// The byte length of a field element, `ceil(log2 p / 8)`.
    const FE_LEN: usize;
    /// The byte length of a scalar, `ceil(log2 n / 8)`.
    const SCALAR_LEN: usize;
    /// `1 + 2 * FE_LEN`, SEC 1 Section 2.3.3's uncompressed point.
    const PK_UNCOMPRESSED_LEN: usize;
    /// `1 + FE_LEN`, SEC 1 Section 2.3.3's compressed point.
    const PK_COMPRESSED_LEN: usize;
    /// `2 * SCALAR_LEN`, a raw `r || s` signature.
    const SIG_LEN: usize;
    /// The DRBG output key generation with extra random bits reduces, in bytes: at least the
    /// `N + 64` bits of FIPS 186-5 Appendix A.2.1 step 4 and SP 800-56A Rev. 3 Section 5.6.1.2.1
    /// step 3, and not less than FIPS 186-5 Table A.2's recommended length, which for P-256 is
    /// 352 bits (`N + 96`); `SCALAR_LEN + 8` for every other curve here.
    const EXTRA_BITS_DRAW_LEN: usize;

    /// The limb array of a field element and a scalar.
    type Limbs: Array<u64>;
    /// `[u8; FE_LEN]`.
    type FeBytes: Array<u8>;
    /// `[u8; SCALAR_LEN]`.
    type ScalarBytes: Array<u8>;
    /// `[u8; PK_UNCOMPRESSED_LEN]`.
    type PkUncompressed: Array<u8>;
    /// `[u8; PK_COMPRESSED_LEN]`.
    type PkCompressed: Array<u8>;
    /// `[u8; SIG_LEN]`.
    type Signature: Array<u8>;
    /// `[u8; EXTRA_BITS_DRAW_LEN]`.
    type ExtraBitsDraw: Array<u8>;

    /// The base field element.
    type Fe: FieldElement<Limbs = Self::Limbs>;
    /// The Jacobian point.
    type Point: JacobianPoint<Fe = Self::Fe>;
    /// The secret scalar.
    type Scalar: SecretScalar<Limbs = Self::Limbs, Bytes = Self::ScalarBytes>;
    /// The scalar field element.
    type ScalarField: ScalarFieldElement<Limbs = Self::Limbs, Secret = Self::Scalar>;
    /// The public scalar.
    type PublicScalar: PublicScalar<Limbs = Self::Limbs, Field = Self::ScalarField>;

    /// The order `n`, as canonical limbs.
    const N: Self::Limbs;
    /// The RNG strength key generation requires, which is [`STRENGTH`](Curve::STRENGTH).
    const RNG_STRENGTH: SecurityStrength;
    /// The most bytes [`keygen`](Curve::keygen) can reduce in one draw.
    const MAX_DRBG_OUTPUT_LEN: usize;

    /// The base point `G`.
    fn base_point() -> Self::Point;
    /// `[k]G`, constant time in `k`, by the fixed-base comb.
    fn multiply_base_point(k: &Self::Scalar) -> Self::Point;
    /// `[k]Q`, constant time in `k`.
    fn multiply_point(k: &Self::Scalar, q: &Self::Point) -> Self::Point;
    /// `[u]G + [v]Q` in variable time, for public `u` and `v`.
    fn shamir_multiply(
        u: &Self::PublicScalar,
        v: &Self::PublicScalar,
        q: &Self::Point,
    ) -> Self::Point;
    /// `(bytes mod (n - 1)) + 1`, big-endian, into `[1, n-1]`: FIPS 186-5 Appendix A.2.1 and
    /// A.3.1, SP 800-56A Rev. 3 Section 5.6.1.2.1.
    fn reduce_wide_bits_mod_n_minus_1(bytes: &[u8]) -> Self::Scalar;
    /// A key pair from `DRBG_LEN` bytes of `rng`, which must offer
    /// [`RNG_STRENGTH`](Curve::RNG_STRENGTH): the private scalar and `[d]G` in affine form.
    ///
    /// # Errors
    /// [`RNGError::SecurityStrengthInsufficientForAlgorithm`] below the strength, or the RNG's
    /// own error.
    fn keygen<const DRBG_LEN: usize>(rng: &mut dyn RNG)
    -> Result<GeneratedKeyPair<Self>, RNGError>;
    /// [`keygen`](Curve::keygen) at the curve's extra-bits draw,
    /// [`EXTRA_BITS_DRAW_LEN`](Curve::EXTRA_BITS_DRAW_LEN) bytes.
    ///
    /// # Errors
    /// As [`keygen`](Curve::keygen).
    fn keygen_extra_bits(rng: &mut dyn RNG) -> Result<GeneratedKeyPair<Self>, RNGError>;
    /// `[d]G` in affine form.
    fn public_point(d: &Self::Scalar) -> (Self::Fe, Self::Fe);

    /// SEC 1 Section 2.3.3, `04 || X || Y`.
    fn encode_uncompressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkUncompressed;
    /// SEC 1 Section 2.3.3, `02 || X` or `03 || X`.
    fn encode_compressed(x: &Self::Fe, y: &Self::Fe) -> Self::PkCompressed;
    /// SEC 1 Section 2.3.4 on either encoding, with the point validated to be on the curve and
    /// in range; `None` for anything else.
    fn decode(bytes: &[u8]) -> Option<(Self::Fe, Self::Fe)>;
    /// Big-endian bytes to limbs, unreduced.
    fn limbs_from_be_bytes(bytes: &Self::ScalarBytes) -> Self::Limbs;
    /// As [`limbs_from_be_bytes`](Curve::limbs_from_be_bytes), into `out`.
    fn limbs_from_be_bytes_into(bytes: &Self::ScalarBytes, out: &mut Self::Limbs);
    /// Limbs to big-endian bytes.
    fn be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::ScalarBytes;
    /// As [`be_bytes_from_limbs`](Curve::be_bytes_from_limbs), into `out`.
    fn be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::ScalarBytes);
    /// A field element's limbs to big-endian bytes, SEC 1 Section 2.3.5 (`FE_LEN` bytes).
    fn fe_be_bytes_from_limbs(limbs: &Self::Limbs) -> Self::FeBytes;
    /// As [`fe_be_bytes_from_limbs`](Curve::fe_be_bytes_from_limbs), into `out`.
    fn fe_be_bytes_from_limbs_into(limbs: &Self::Limbs, out: &mut Self::FeBytes);
    /// Whether `limbs`, read as an unreduced integer, is in `[1, n-1]`, as a mask: the range
    /// test of a private key on load (SP 800-56A Rev. 3 Section 5.6.2.1.2), of a signature's `r`
    /// and `s` (FIPS 186-5 Section 6.4.2 step 1) and of an RFC 6979 candidate (Section 3.2 step
    /// h.3); [`limbs_in_range`] against the curve's order.
    fn scalar_in_range(limbs: &Self::Limbs) -> Condition<u64>;
}

/// Whether `limbs`, read as an unreduced integer, is in `[1, n-1]`, as a mask: the body of
/// [`Curve::scalar_in_range`], generic over the limb count. The value is taken as a secret: the
/// difference `limbs - n` lives in a [`Secret`], and the two bounds combine under masks without
/// a branch on the value.
pub fn limbs_in_range<const L: usize>(limbs: &[u64; L], n: &[u64; L]) -> Condition<u64> {
    let mut diff = Secret::<[u64; L]>::new();
    diff.copy_from_slice(limbs);
    let borrow = nat::sub_assign(&mut diff, n);
    !nat::is_zero(limbs) & Condition::<u64>::from_lsb(borrow)
}

/// A private scalar from its big-endian encoding, or `None` when the encoding is not in
/// `[1, n-1]`: the check is on the raw value before any reduction, so that `d = n + 1` is refused
/// rather than loaded as `d = 1`. The candidate is a secret from the moment it arrives, so the
/// limbs are staged in a [`Secret`] and the scalar is reduced from that borrowed copy straight into
/// its own; nothing plain is left in this frame.
pub fn private_scalar_from_be_bytes<C: Curve>(bytes: &C::ScalarBytes) -> Option<C::Scalar> {
    let mut limbs = Secret::<C::Limbs>::new();
    C::limbs_from_be_bytes_into(bytes, &mut limbs);
    if !C::scalar_in_range(&limbs).to_bool() {
        return None;
    }
    Some(C::Scalar::from_borrowed_limbs(&limbs))
}

/// The lengths a [`Curve`] impl states, checked against the array types it names and each
/// other; evaluated as a `const` beside every impl, so a curve whose table disagrees with its
/// arithmetic does not compile.
pub const fn check_lengths<C: Curve>() {
    assert!(
        C::FE_LEN == <C::FeBytes as Array<u8>>::LEN,
        "FE_LEN is the field element's byte length"
    );
    assert!(
        C::SCALAR_LEN == <C::ScalarBytes as Array<u8>>::LEN,
        "SCALAR_LEN is the scalar's byte length"
    );
    assert!(C::SCALAR_LEN == C::ORDER_BITS.div_ceil(8), "SCALAR_LEN is ceil(ORDER_BITS / 8)");
    assert!(C::PK_UNCOMPRESSED_LEN == 1 + 2 * C::FE_LEN, "PK_UNCOMPRESSED_LEN is 1 + 2 * FE_LEN");
    assert!(
        C::PK_UNCOMPRESSED_LEN == <C::PkUncompressed as Array<u8>>::LEN,
        "PK_UNCOMPRESSED_LEN is the uncompressed point's byte length"
    );
    assert!(C::PK_COMPRESSED_LEN == 1 + C::FE_LEN, "PK_COMPRESSED_LEN is 1 + FE_LEN");
    assert!(
        C::PK_COMPRESSED_LEN == <C::PkCompressed as Array<u8>>::LEN,
        "PK_COMPRESSED_LEN is the compressed point's byte length"
    );
    assert!(C::SIG_LEN == 2 * C::SCALAR_LEN, "SIG_LEN is 2 * SCALAR_LEN");
    assert!(
        C::SIG_LEN == <C::Signature as Array<u8>>::LEN,
        "SIG_LEN is the signature's byte length"
    );
    assert!(
        <C::Limbs as Array<u64>>::LEN * 64 >= C::ORDER_BITS
            && (<C::Limbs as Array<u64>>::LEN - 1) * 64 < C::ORDER_BITS,
        "the limb count is the least that holds the order"
    );
    assert!(
        C::EXTRA_BITS_DRAW_LEN >= C::SCALAR_LEN + 8,
        "EXTRA_BITS_DRAW_LEN is at least N + 64 bits"
    );
    assert!(
        C::EXTRA_BITS_DRAW_LEN == <C::ExtraBitsDraw as Array<u8>>::LEN,
        "EXTRA_BITS_DRAW_LEN is the draw's byte length"
    );
    assert!(C::MAX_DRBG_OUTPUT_LEN >= C::EXTRA_BITS_DRAW_LEN, "the N + 64 bit draw fits");
}

pub(crate) mod sealed {
    pub trait Sealed {}
}
