use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// Mask for one limb: `2^56 - 1`. A [`FieldElement448`] holds the value
/// `x0 + x1*2^56 + ... + x7*2^392`, so `& M56` extracts a limb's own 56 bits and leaves the
/// overflow to be carried into the next limb (or, out of `x7`, folded back into `x0` and `x4`,
/// since `2^448 == 2^224 + 1 mod p`).
const M56: i64 = (1 << 56) - 1;

/// An element of GF(p), p = 2^448 - 2^224 - 1: the field that curve448's point coordinates live
/// in (RFC 7748 Section 4.2). The u-coordinate of X448 is one of these, and so are the x and y
/// coordinates of Ed448 (RFC 8032 Section 5.2).
///
/// # Representation
/// Eight signed 64-bit limbs in radix 2^56 (see [`M56`]); limb 4 has weight `2^224`, which is
/// what makes the reduction cheap. Arithmetic is lazily reduced, as in
/// [`FieldElement25519`](crate::curve25519::FieldElement25519): limbs may exceed 56 bits or go
/// negative between operations, and [`Self::normalize`] produces the canonical representation as
/// a [`NormalizedFieldElement448`], the only type that encodes, compares and tests parity.
///
/// # Mathematical operations implemented
/// Addition and subtraction (lazily reduced), multiplication, squaring and multiplication by a
/// small constant, inversion, a constant-time swap, decoding from 56 bytes and, through
/// [`Self::normalize`], the canonical form that encodes; for Ed448, negation, a carry pass, a
/// constant-time move and negation, and the square root of a ratio. Everything is constant time
/// except what is named `_var`, which takes public input only. The limbs are wiped with volatile
/// stores when a value is dropped; what the compiler kept in registers or spilled itself is not
/// reached.
///
/// # Operand bounds
/// A value is *reduced* when every limb lies in `[-2^8, 2^56 + 2^8]`, which is what
/// [`Self::mul`], [`Self::sqr`], [`Self::mul_u32`], [`Self::carry`] and [`Self::decode_448`]
/// return. The three multiplications accept the sum or difference of two reduced values (limbs
/// of magnitude at most `2^57 + 2^9`) and little more: their last carries are `i64`, which
/// operands of `2^58` can overflow. A longer run of additions takes a [`Self::carry`] first.
#[derive(Clone, Default)]
#[must_use] // x.sqr() returns its result and leaves x alone, so dropping the result is a bug.
pub(crate) struct FieldElement448([i64; 8]);

impl FieldElement448 {
    /// Wipes the limbs with volatile stores (`zeroize_in_place`); [`Drop`] calls it, so an
    /// explicit call is only for a value that must be cleared before it goes out of scope.
    pub(crate) fn zeroize(&mut self) {
        bouncycastle_utils::secret::zeroize_in_place(&mut self.0);
    }
}

impl Drop for FieldElement448 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl FieldElement448 {
    /// In a debug build, panics unless the value is inside the multiplications' operand bound
    /// (the type's "Operand bounds"): a caller that chains additions past it without a
    /// [`Self::carry`] is caught where it multiplies. The limbs are not printed, an operand
    /// being secret as often as not.
    #[inline(always)]
    fn debug_check_operand(&self) {
        #[cfg(debug_assertions)]
        for limb in &self.0 {
            debug_assert!(
                limb.unsigned_abs() <= (1 << 57) + (1 << 9),
                "a Curve448 multiplication operand is outside its bound"
            );
        }
    }

    /// `self + rhs`, limb by limb. Lazily reduced: no carry propagation, so limb magnitudes grow
    /// by up to one bit and the result is congruent mod p but not normalized.
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;
        let [y0, y1, y2, y3, y4, y5, y6, y7] = rhs.0;
        Self([x0 + y0, x1 + y1, x2 + y2, x3 + y3, x4 + y4, x5 + y5, x6 + y6, x7 + y7])
    }

    /// Returns `(self + rhs, self - rhs)` in one pass over the limbs, each half lazily reduced
    /// as [`Self::add`] and [`Self::sub`] are. The X448 ladder always wants both
    /// of the same pair: RFC 7748 Section 5's `A = x_2 + z_2` / `B = x_2 - z_2`, and its `C` and
    /// `D`.
    pub(crate) fn sum_and_difference(&self, rhs: &Self) -> (Self, Self) {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;
        let [y0, y1, y2, y3, y4, y5, y6, y7] = rhs.0;
        (
            Self([x0 + y0, x1 + y1, x2 + y2, x3 + y3, x4 + y4, x5 + y5, x6 + y6, x7 + y7]),
            Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4, x5 - y5, x6 - y6, x7 - y7]),
        )
    }

    /// Swaps `lhs` and `rhs` if `cond` is true.
    ///
    /// Constant time: both limb arrays are rewritten unconditionally with a masked exchange, so
    /// nothing about `cond`, and hence nothing about the scalar bit driving it, shows in memory
    /// access patterns or timing.
    pub(crate) fn cswap(cond: Condition<i64>, lhs: &mut Self, rhs: &mut Self) {
        (lhs.0[0], rhs.0[0]) = cond.swap(lhs.0[0], rhs.0[0]);
        (lhs.0[1], rhs.0[1]) = cond.swap(lhs.0[1], rhs.0[1]);
        (lhs.0[2], rhs.0[2]) = cond.swap(lhs.0[2], rhs.0[2]);
        (lhs.0[3], rhs.0[3]) = cond.swap(lhs.0[3], rhs.0[3]);
        (lhs.0[4], rhs.0[4]) = cond.swap(lhs.0[4], rhs.0[4]);
        (lhs.0[5], rhs.0[5]) = cond.swap(lhs.0[5], rhs.0[5]);
        (lhs.0[6], rhs.0[6]) = cond.swap(lhs.0[6], rhs.0[6]);
        (lhs.0[7], rhs.0[7]) = cond.swap(lhs.0[7], rhs.0[7]);
    }

    /// Decodes 56 little-endian bytes as a field element; the inverse of
    /// [`NormalizedFieldElement448::encode_448`]. All 448 bits are read: there is no unused bit,
    /// as there is in the 255-bit field.
    ///
    /// The result is reduced but NOT normalized: the value is in `[0, 2^448)`, so the encodings
    /// of `p .. 2^448 - 1` decode to values `>= p`. The caller owns the policy on those: X448
    /// accepts them (RFC 7748 Section 5), Ed448 rejects them (RFC 8032 Section 5.2.3).
    pub(crate) fn decode_448(bytes: &[u8; 56]) -> Self {
        // Wiped, so that decoding a secret value leaves no copy of it here.
        let mut x: Secret<[u64; 7]> = Secret::new();
        let (chunks, _) = bytes.as_chunks::<8>(); // 56 bytes: exactly 7 chunks, no remainder
        for (x_i, chunk) in x.iter_mut().zip(chunks) {
            *x_i = u64::from_le_bytes(*chunk);
        }

        // Each limb is a 56-bit window of the 448-bit integer, straddling word boundaries.
        let [x0, x1, x2, x3, x4, x5, x6] = *x;
        let z0 = x0 as i64 & M56;
        let z1 = (x0 >> 56 | x1 << 8) as i64 & M56;
        let z2 = (x1 >> 48 | x2 << 16) as i64 & M56;
        let z3 = (x2 >> 40 | x3 << 24) as i64 & M56;
        let z4 = (x3 >> 32 | x4 << 32) as i64 & M56;
        let z5 = (x4 >> 24 | x5 << 40) as i64 & M56;
        let z6 = (x5 >> 16 | x6 << 48) as i64 & M56;
        let z7 = (x6 >> 8) as i64 & M56;
        Self([z0, z1, z2, z3, z4, z5, z6, z7])
    }

    /// Multiplicative inverse in GF(p), by Fermat's little theorem: `x^(p-2) == x^-1`, with
    /// `p - 2 == 4 * ((p - 3) / 4) + 1`, so two squarings and a multiplication after
    /// [`Self::pow_p_sub3_div4`]. Costs 447 squarings and 13 multiplications.
    ///
    /// Constant time: a fixed addition chain, with no data-dependent branch or index.
    ///
    /// `inv(0) == 0`, and X448 depends on it: a small-order input point drives the ladder's
    /// `z_2` to zero, and the all-zero output RFC 7748 Section 6.2 lets a caller check for is
    /// what comes of the final `x_2 * z_2^-1`.
    pub(crate) fn inv(&self) -> Self {
        self.pow_p_sub3_div4().sqr_n(2).mul(self)
    }

    /// `self * rhs` in GF(p), for operands inside the type's operand bound.
    ///
    /// Write `phi = 2^224`, so that an element is `a + b*phi` with four-limb halves and
    /// `phi^2 == phi + 1 mod p`. Then
    ///
    /// ```text
    /// (a + b*phi)(c + d*phi) = (ac + bd) + (ad + bc + bd)*phi
    ///                        = (ac + bd) + ((a + b)(c + d) - ac)*phi
    /// ```
    ///
    /// which is three half-size products, `t = ac`, `u = bd` and `v = (a + b)(c + d)`, in place
    /// of four (Karatsuba; `m4` uses the same step once more inside each). Each has seven
    /// coefficients; coefficients 4 to 6 of the low part `t + u` carry a factor `phi` and move
    /// to the high part, and those of the high part `v - t` carry `phi^2` and so are added to
    /// both. The eight `i128` sums go to [`Self::reduce_products`].
    pub(crate) fn mul(&self, rhs: &Self) -> Self {
        #[inline(always)]
        fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        self.debug_check_operand();
        rhs.debug_check_operand();

        /// The three coefficients of a two-limb by two-limb product.
        #[inline(always)]
        fn m2(x: [i64; 2], y: [i64; 2]) -> [i128; 3] {
            [m(x[0], y[0]), m(x[0], y[1]) + m(x[1], y[0]), m(x[1], y[1])]
        }

        /// The seven coefficients of a four-limb by four-limb product, by Karatsuba over
        /// two-limb halves: `t + (v - t - u) X^2 + u X^4` for `t = lo*lo`, `u = hi*hi` and
        /// `v = (lo + hi)(lo + hi)`.
        #[inline(always)]
        fn m4(x: [i64; 4], y: [i64; 4]) -> [i128; 7] {
            let t = m2([x[0], x[1]], [y[0], y[1]]);
            let u = m2([x[2], x[3]], [y[2], y[3]]);
            let v = m2([x[0] + x[2], x[1] + x[3]], [y[0] + y[2], y[1] + y[3]]);

            [
                t[0],
                t[1],
                t[2] + v[0] - t[0] - u[0],
                v[1] - t[1] - u[1],
                u[0] + v[2] - t[2] - u[2],
                u[1],
                u[2],
            ]
        }

        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;
        let [y0, y1, y2, y3, y4, y5, y6, y7] = rhs.0;

        let t = m4([x0, x1, x2, x3], [y0, y1, y2, y3]);
        let u = m4([x4, x5, x6, x7], [y4, y5, y6, y7]);
        let v = m4([x0 + x4, x1 + x5, x2 + x6, x3 + x7], [y0 + y4, y1 + y5, y2 + y6, y3 + y7]);

        Self::reduce_products([
            t[0] + u[0] + v[4] - t[4],
            t[1] + u[1] + v[5] - t[5],
            t[2] + u[2] + v[6] - t[6],
            t[3] + u[3],
            u[4] + v[0] - t[0] + v[4],
            u[5] + v[1] - t[1] + v[5],
            u[6] + v[2] - t[2] + v[6],
            v[3] - t[3],
        ])
    }

    /// `self * rhs` in GF(p) for a small unsigned constant: one product a limb, with no
    /// wrap-around terms. X448 uses it for the ladder's `a24 * E` (RFC 7748 Section 5).
    pub(crate) fn mul_u32(&self, rhs: u32) -> Self {
        #[inline(always)]
        fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        self.debug_check_operand();

        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;
        let y0 = rhs as i64;

        Self::reduce_products([
            m(x0, y0),
            m(x1, y0),
            m(x2, y0),
            m(x3, y0),
            m(x4, y0),
            m(x5, y0),
            m(x6, y0),
            m(x7, y0),
        ])
    }

    /// The canonical representation of the value: every limb in `[0, 2^56)` and the value in
    /// `[0, p)`, as a [`NormalizedFieldElement448`]. Idempotent.
    ///
    /// Total on every input whose limbs lie in `[-2^58, 2^58]`, which covers a reduced value
    /// and the sum or difference of two.
    ///
    /// Four carry passes of [`Self::reduce`]. With `V` the value and `t8 = x7 >> 56` the top
    /// limb's overflow, each pass computes `V - p * t8` with limbs 0 to 6 in `[0, 2^56)`:
    /// 1. `reduce(0)`: `t8` is in `[-4, 4]` and every carry in `[-5, 4]`, so limb 7 comes out
    ///    in `[-5, 2^56 + 3]`.
    /// 2. `reduce(0)` again: `t8` is now `-1`, `0` or `1`. A negative limb 7 means `V < 0`, and
    ///    adding `p` leaves limb 7 in `[2^56 - 6, 2^56 - 1]`; a limb 7 of `2^56` or more loses
    ///    one `p` and comes out in `[0, 4]`; otherwise nothing moves. So every limb is in
    ///    `[0, 2^56)` and `V` is in `[0, 2^448)`: canonical limbs, value possibly `>= p`.
    /// 3. `reduce(1)` adds `2^224 + 1`: the sum is `2^448 + (V - p)` when `V >= p`, which
    ///    leaves limb 7 at exactly `2^56` since `V - p <= 2^224`, and stays below `2^448` with
    ///    canonical limbs otherwise.
    /// 4. `reduce(-1)`: when limb 7 is `2^56`, `t8 = 1 - 1 = 0` drops the `2^448` and the result
    ///    is `V - p`; otherwise `t8 = -1` takes the `2^224 + 1` back, and the borrow resolves
    ///    inside the limbs, since the result `V` is at least `0`.
    ///
    /// Pass 3 is what implements RFC 7748 Section 5's "Implementations MUST accept
    /// non-canonical values and process them as if they had been reduced modulo the field
    /// prime": `V >= p` if and only if `V + 2^224 + 1 >= 2^448`.
    pub(crate) fn normalize(&self) -> NormalizedFieldElement448 {
        NormalizedFieldElement448(self.reduce(0).reduce(0).reduce(1).reduce(-1))
    }

    /// The multiplicative identity, 1, in canonical form.
    pub(crate) fn one() -> Self {
        Self([1, 0, 0, 0, 0, 0, 0, 0])
    }

    /// `x^((p-3)/4)` for `x = self`, by a fixed addition chain.
    ///
    /// `(p - 3) / 4 == 2^446 - 2^222 - 1`, which in binary is 223 ones, a zero, then 222 ones.
    /// The locals count *consecutive 1-bits*, not exponents: `x2` is `x^3` (`0b11`), `x3` is
    /// `x^7`, and `x222` is `x^(2^222 - 1)`.
    ///
    /// [`Self::inv`] finishes it to `x^(p-2)`, and the `p == 3 mod 4` square root of
    /// [`Self::sqrt_ratio_var`] uses it as it is.
    fn pow_p_sub3_div4(&self) -> Self {
        // Addition chain: 1 2 3 6 9 18 19 37 74 111 [222] [223]
        let x = self;
        let x2 = x.sqr().mul(x);
        let x3 = x2.sqr().mul(x);
        let x6 = x3.sqr_n(3).mul(&x3);
        let x9 = x6.sqr_n(3).mul(&x3);
        let x18 = x9.sqr_n(9).mul(&x9);
        let x19 = x18.sqr().mul(x);
        let x37 = x19.sqr_n(18).mul(&x18);
        let x74 = x37.sqr_n(37).mul(&x37);
        let x111 = x74.sqr_n(37).mul(&x37);
        let x222 = x111.sqr_n(111).mul(&x111);
        let x223 = x222.sqr().mul(x);

        x223.sqr_n(223).mul(&x222)
    }

    /// One carry pass that also subtracts `x7 >> 56` multiples of p and adds `(2^224 + 1) * y`.
    /// Not a standalone reduction: it serves the four calls of [`Self::normalize`].
    ///
    /// Bits at or above `2^448` (the `x7 >> 56` carry) are removed from the top and re-added at
    /// limbs 0 and 4, which subtracts a multiple of p since `2^448 == 2^224 + 1 mod p`. `y`
    /// joins that fold with no matching removal at the top:
    ///
    /// ```text
    /// value(reduce(x, y)) == value(x) - (x7 >> 56) * p + (2^224 + 1) * y
    /// ```
    fn reduce(&self, y: i64) -> Self {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;

        let t7 = x7 & M56;
        let t8 = (x7 >> 56) + y;

        let mut c = t8;

        c += x0;
        let z0 = c & M56;
        c >>= 56;
        c += x1;
        let z1 = c & M56;
        c >>= 56;
        c += x2;
        let z2 = c & M56;
        c >>= 56;
        c += x3;
        let z3 = c & M56;
        c >>= 56;

        c += t8;

        c += x4;
        let z4 = c & M56;
        c >>= 56;
        c += x5;
        let z5 = c & M56;
        c >>= 56;
        c += x6;
        let z6 = c & M56;
        c >>= 56;
        c += t7;
        let z7 = c;

        Self([z0, z1, z2, z3, z4, z5, z6, z7])
    }

    /// Carries the eight `i128` product sums of [`Self::mul`], [`Self::sqr`] and
    /// [`Self::mul_u32`] down into eight `i64` limbs, reduced but not normalized.
    ///
    /// The two halves are carried separately, each keeping its running carry in `i128`. The
    /// carry out of the low half (`c4`, at weight `2^224`) goes to limb 4, and the carry out of
    /// the high half (`c8`, at weight `2^448 == 2^224 + 1`) to limbs 0 and 4; both are `i64`,
    /// which is where the type's operand bound comes from. One more step moves what limbs 0 and
    /// 4 then hold above 56 bits into limbs 1 and 5, which may therefore end slightly outside
    /// `[0, 2^56)`.
    fn reduce_products(p: [i128; 8]) -> Self {
        #[inline(always)]
        fn split(x: i128) -> (i64, i64) {
            (x as i64 & M56, (x >> 56) as i64)
        }

        /// The low 56 bits of `lo`, and `hi` plus what `lo` holds above them.
        #[inline(always)]
        fn carry(lo: i128, hi: i128) -> (i64, i128) {
            (lo as i64 & M56, hi + (lo >> 56))
        }

        let [p0, p1, p2, p3, p4, p5, p6, p7] = p;

        let (z0, c1) = carry(p0, p1);
        let (z1, c2) = carry(c1, p2);
        let (z2, c3) = carry(c2, p3);
        let (z3, c4) = split(c3);

        let (z4, c5) = carry(p4, p5);
        let (z5, c6) = carry(c5, p6);
        let (z6, c7) = carry(c6, p7);
        let (z7, c8) = split(c7);

        let w0 = z0 + c8;
        let w4 = z4 + c8 + c4;

        Self([w0 & M56, z1 + (w0 >> 56), z2, z3, w4 & M56, z5 + (w4 >> 56), z6, z7])
    }

    /// `self^2` in GF(p): the shape of [`Self::mul`], with each half-size product a squaring,
    /// whose cross terms come in equal pairs.
    pub(crate) fn sqr(&self) -> Self {
        #[inline(always)]
        fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        self.debug_check_operand();

        /// The seven coefficients of the square of four limbs.
        #[inline(always)]
        fn s4(x: [i64; 4]) -> [i128; 7] {
            [
                m(x[0], x[0]),
                m(x[0], 2 * x[1]),
                m(x[0], 2 * x[2]) + m(x[1], x[1]),
                m(x[0], 2 * x[3]) + m(x[1], 2 * x[2]),
                m(x[1], 2 * x[3]) + m(x[2], x[2]),
                m(x[2], 2 * x[3]),
                m(x[3], x[3]),
            ]
        }

        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;

        let t = s4([x0, x1, x2, x3]);
        let u = s4([x4, x5, x6, x7]);
        let v = s4([x0 + x4, x1 + x5, x2 + x6, x3 + x7]);

        Self::reduce_products([
            t[0] + u[0] + v[4] - t[4],
            t[1] + u[1] + v[5] - t[5],
            t[2] + u[2] + v[6] - t[6],
            t[3] + u[3],
            u[4] + v[0] - t[0] + v[4],
            u[5] + v[1] - t[1] + v[5],
            u[6] + v[2] - t[2] + v[6],
            v[3] - t[3],
        ])
    }

    /// Squares `self` `n` times, i.e. raises it to the `2^n`.
    pub(crate) fn sqr_n(&self, mut n: usize) -> Self {
        let mut z = Self(self.0);
        while n > 0 {
            z = z.sqr();
            n -= 1;
        }
        z
    }

    /// `self - rhs`, limb by limb. Lazily reduced, as [`Self::add`]: limbs may go negative,
    /// which the arithmetic shifts of the reductions carry correctly.
    pub(crate) fn sub(&self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;
        let [y0, y1, y2, y3, y4, y5, y6, y7] = rhs.0;
        Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4, x5 - y5, x6 - y6, x7 - y7])
    }

    /// The additive identity, 0, in canonical form.
    pub(crate) fn zero() -> Self {
        Self([0; 8])
    }
}

// The operations Ed448 needs and X448 does not.
impl FieldElement448 {
    /// The element with the given limbs, least significant first; `const`, for curve constants.
    ///
    /// The limbs are taken as they are, so they must already be inside the bound of whatever
    /// consumes the value; a constant written with every limb in `[0, 2^56)` always is.
    pub(crate) const fn new(limbs: [i64; 8]) -> Self {
        Self(limbs)
    }

    /// One carry pass: the bits of each limb above the low 56 move into the next limb, and those
    /// of the top limb into limbs 0 and 4. The value mod p is unchanged; the result is reduced
    /// but not normalized.
    ///
    /// This brings limbs widened by a run of lazy [`Self::add`] / [`Self::sub`] back near 56
    /// bits ahead of a [`Self::mul`] or [`Self::sqr`]: for input limbs of magnitude below
    /// `2^62` each carry is in `[-64, 64)`. Constant time.
    pub(crate) fn carry(&self) -> Self {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;
        let c7 = x7 >> 56;
        Self([
            (x0 & M56) + c7,
            (x1 & M56) + (x0 >> 56),
            (x2 & M56) + (x1 >> 56),
            (x3 & M56) + (x2 >> 56),
            (x4 & M56) + (x3 >> 56) + c7,
            (x5 & M56) + (x4 >> 56),
            (x6 & M56) + (x5 >> 56),
            (x7 & M56) + (x6 >> 56),
        ])
    }

    /// Sets `self` to `x` if `cond` is true and leaves it unchanged otherwise.
    ///
    /// Constant time, as [`Self::cswap`]: every limb is rewritten through a masked select
    /// whichever way `cond` goes. This is the step of a table lookup that passes over every
    /// entry.
    pub(crate) fn cmov(&mut self, cond: Condition<i64>, x: &Self) {
        cond.mov(x.0[0], &mut self.0[0]);
        cond.mov(x.0[1], &mut self.0[1]);
        cond.mov(x.0[2], &mut self.0[2]);
        cond.mov(x.0[3], &mut self.0[3]);
        cond.mov(x.0[4], &mut self.0[4]);
        cond.mov(x.0[5], &mut self.0[5]);
        cond.mov(x.0[6], &mut self.0[6]);
        cond.mov(x.0[7], &mut self.0[7]);
    }

    /// Replaces `self` with its negation ([`Self::negate`]) if `cond` is true and leaves it
    /// unchanged otherwise. Constant time: every limb goes through a masked negation whichever
    /// way `cond` goes.
    pub(crate) fn cnegate(&mut self, cond: Condition<i64>) {
        self.0[0] = cond.negate(self.0[0]);
        self.0[1] = cond.negate(self.0[1]);
        self.0[2] = cond.negate(self.0[2]);
        self.0[3] = cond.negate(self.0[3]);
        self.0[4] = cond.negate(self.0[4]);
        self.0[5] = cond.negate(self.0[5]);
        self.0[6] = cond.negate(self.0[6]);
        self.0[7] = cond.negate(self.0[7]);
    }

    /// The additive inverse, limb by limb. Lazily reduced like [`Self::sub`]: limb magnitudes
    /// are unchanged and the result is congruent to `-self` mod p but not normalized. Constant
    /// time.
    pub(crate) fn negate(&self) -> Self {
        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0;
        Self([-x0, -x1, -x2, -x3, -x4, -x5, -x6, -x7])
    }

    /// A square root of `u / v`, or `None` when `u / v` is not a square: the x-coordinate
    /// recovery of RFC 8032 Section 5.2.3, steps 2 and 3. The result is not normalized and
    /// either root may come back, so the caller chooses between `x` and `-x` (step 4).
    ///
    /// `u` and `v` may be lazily reduced, up to one [`Self::add`] or [`Self::sub`] of reduced
    /// values. The RFC's `v` is never zero; for `v == 0` this returns `Some(0)` when `u` is zero
    /// too and `None` otherwise.
    ///
    /// Variable time: which outcome occurs is branched on, so `u` and `v` must be public, as
    /// the coordinates of a point being decoded are.
    pub(crate) fn sqrt_ratio_var(u: &Self, v: &Self) -> Option<Self> {
        // Step 2: the candidate root x = (u/v)^((p+1)/4) = u^3 v (u^5 v^3)^((p-3)/4), "to use a
        // single modular powering for both the inversion of v and the square root".
        let u2v = u.sqr().mul(v);
        let u3v = u2v.mul(u);
        let u5v3 = u2v.sqr().mul(&u.mul(v));
        let x = u5v3.pow_p_sub3_div4().mul(&u3v);

        // Step 3: "If v * x^2 = u, the recovered x-coordinate is x. Otherwise, no square root
        // exists, and the decoding fails."
        if x.sqr().mul(v).sub(u).normalize().is_zero_var() {
            return Some(x);
        }
        None
    }
}

/// A [`FieldElement448`] in canonical form: every limb in `[0, 2^56)` and the value in `[0, p)`.
/// The only constructor is [`FieldElement448::normalize`].
///
/// It dereferences to [`FieldElement448`], so arithmetic continues on a normalized value without
/// a conversion; the result of any such operation is a [`FieldElement448`] again.
#[derive(Clone)]
#[must_use]
pub(crate) struct NormalizedFieldElement448(FieldElement448);

impl core::ops::Deref for NormalizedFieldElement448 {
    type Target = FieldElement448;

    fn deref(&self) -> &FieldElement448 {
        &self.0
    }
}

impl NormalizedFieldElement448 {
    /// Debug-only check of the invariant this type carries: every limb in `[0, 2^56)` and the
    /// value below p. Every method calls it first; it compiles to nothing in release builds.
    ///
    /// p's limbs are `2^56 - 1` throughout except limb 4, which is `2^56 - 2`. So a value with
    /// every limb in range is `>= p` exactly when limbs 5 to 7 are all `2^56 - 1` and either
    /// limb 4 is too, or limb 4 is `2^56 - 2` and limbs 0 to 3 are all `2^56 - 1`.
    ///
    /// Branches on the limbs, so it is not constant time. That is acceptable only because it is
    /// compiled out of release builds.
    fn debug_check_range(&self) {
        let x = &self.0.0;
        for (i, limb) in x.iter().enumerate() {
            debug_assert!((0..=M56).contains(limb), "limb {i} out of [0, 2^56)");
        }
        debug_assert!(
            !(x[5] == M56
                && x[6] == M56
                && x[7] == M56
                && (x[4] == M56
                    || (x[4] == M56 - 1
                        && x[0] == M56
                        && x[1] == M56
                        && x[2] == M56
                        && x[3] == M56))),
            "value >= p"
        );
    }

    /// Encodes the field element as 56 little-endian bytes; the inverse of
    /// [`FieldElement448::decode_448`].
    pub(crate) fn encode_448(&self, bytes: &mut [u8; 56]) {
        self.debug_check_range();
        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0.0;
        // Each word takes a whole limb's remaining bits plus the low bits of the next. The
        // splices are `|`, not `+`, which is why the limbs must be canonical: a limb with bits
        // at or above 56 would collide with the next limb's. The words are as secret as the
        // value, so they are wiped.
        let mut z: Secret<[u64; 7]> = Secret::new();
        *z = [
            (x0 | x1 << 56) as u64,
            (x1 >> 8 | x2 << 48) as u64,
            (x2 >> 16 | x3 << 40) as u64,
            (x3 >> 24 | x4 << 32) as u64,
            (x4 >> 32 | x5 << 24) as u64,
            (x5 >> 40 | x6 << 16) as u64,
            (x6 >> 48 | x7 << 8) as u64,
        ];
        let (chunks, _) = bytes.as_chunks_mut::<8>(); // 56 bytes: exactly 7 chunks, no remainder
        for (chunk, z_i) in chunks.iter_mut().zip(z.iter()) {
            *chunk = z_i.to_le_bytes();
        }
    }
}

// The tests Ed448 needs on a canonical value.
impl NormalizedFieldElement448 {
    /// Whether two values are equal. Variable time: both must be public.
    pub(crate) fn are_equal_var(lhs: &Self, rhs: &Self) -> bool {
        lhs.debug_check_range();
        rhs.debug_check_range();
        lhs.0.0 == rhs.0.0
    }

    /// TRUE iff the value is zero, as a mask. Constant time.
    pub(crate) fn is_zero(&self) -> Condition<i64> {
        self.debug_check_range();
        let [x0, x1, x2, x3, x4, x5, x6, x7] = self.0.0;
        Condition::<i64>::is_zero(x0 | x1 | x2 | x3 | x4 | x5 | x6 | x7)
    }

    /// Whether the value is zero. Variable time: the value must be public.
    pub(crate) fn is_zero_var(&self) -> bool {
        self.debug_check_range();
        self.0.0 == [0; 8]
    }

    /// The least significant bit of the value, which is what an Ed448 point encoding keeps of
    /// the x-coordinate (RFC 8032 Section 5.2.2). Constant time.
    pub(crate) fn parity(&self) -> u8 {
        self.debug_check_range();
        (self.0.0[0] & 1) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Alice's public key from the X448 test vector in Section 6.2 of RFC 7748, used here purely
    /// as a fixed value for the byte <-> limb codec. It is less than p, so its encoding is
    /// canonical and it round-trips exactly.
    const KNOWN_VALUE: [u8; 56] = [
        0x9B, 0x08, 0xF7, 0xCC, 0x31, 0xB7, 0xE3, 0xE6, //
        0x7D, 0x22, 0xD5, 0xAE, 0xA1, 0x21, 0x07, 0x4A, //
        0x27, 0x3B, 0xD2, 0xB8, 0x3D, 0xE0, 0x9C, 0x63, //
        0xFA, 0xA7, 0x3D, 0x2C, 0x22, 0xC5, 0xD9, 0xBB, //
        0xC8, 0x36, 0x64, 0x72, 0x41, 0xD9, 0x53, 0xD4, //
        0x0C, 0x5B, 0x12, 0xDA, 0x88, 0x12, 0x0D, 0x53, //
        0x17, 0x7F, 0x80, 0xE5, 0x32, 0xC4, 0x1F, 0xA0, //
    ];

    /// The same value as eight 56-bit limbs: `KNOWN_LIMBS[i] == (v >> (56 * i)) & (2^56 - 1)`,
    /// where v is `KNOWN_VALUE` read as a little-endian integer. Computed independently of this
    /// crate.
    const KNOWN_LIMBS: [i64; 8] = [
        0xE3B731CCF7089B, 0x21A1AED5227DE6, 0x3DB8D23B274A07, 0x2C3DA7FA639CE0, 0x6436C8BBD9C522,
        0x5B0CD453D94172, 0x17530D1288DA12, 0xA01FC432E5807F,
    ];

    /// p as limbs.
    const P_LIMBS: [i64; 8] = [M56, M56, M56, M56, M56 - 1, M56, M56, M56];

    /// A normalized value straight from limbs, without the checks `normalize` would apply.
    fn n(limbs: [i64; 8]) -> NormalizedFieldElement448 {
        NormalizedFieldElement448(FieldElement448(limbs))
    }

    fn small(v: i64) -> [i64; 8] {
        [v, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn decode_448_known_value() {
        assert_eq!(FieldElement448::decode_448(&KNOWN_VALUE).0, KNOWN_LIMBS);
        // Every bit is part of the value: all ones is 2^448 - 1, every limb full.
        assert_eq!(FieldElement448::decode_448(&[0xFF; 56]).0, [M56; 8]);
    }

    #[test]
    fn encode_448_known_value() {
        // Start from a non-zero buffer so a partial write cannot pass by accident.
        let mut bytes = [0xFF_u8; 56];
        FieldElement448(KNOWN_LIMBS).normalize().encode_448(&mut bytes);
        assert_eq!(bytes, KNOWN_VALUE);
    }

    /// p - 1, the largest canonical value, passes the range check, and so does the largest
    /// value whose limb 4 is full: `2^448 - 2^224 - 1 - 2^392`.
    #[test]
    fn debug_check_range_accepts_values_below_p() {
        n([M56 - 1, M56, M56, M56, M56 - 1, M56, M56, M56]).debug_check_range();
        n([M56, M56, M56, M56, M56, M56, M56, M56 - 1]).debug_check_range();
        n([M56, M56, M56, M56, M56, M56, M56 - 1, M56]).debug_check_range();
        n([M56, M56, M56, M56, M56, M56 - 1, M56, M56]).debug_check_range();
        for limb in 0..4 {
            let mut limbs = P_LIMBS;
            limbs[limb] -= 1;
            n(limbs).debug_check_range();
        }
    }

    /// p itself is not canonical; the range check must reject it.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "value >= p")]
    fn debug_check_range_rejects_p() {
        n(P_LIMBS).debug_check_range();
    }

    /// Nor is p + 1 = 2^448 - 2^224, whose low limbs are zero under a full limb 4.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "value >= p")]
    fn debug_check_range_rejects_p_plus_1() {
        n([0, 0, 0, 0, M56, M56, M56, M56]).debug_check_range();
    }

    /// A limb at 2^56 is out of range even though the value is below p.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "limb 0 out of [0, 2^56)")]
    fn debug_check_range_rejects_wide_limb() {
        n(small(M56 + 1)).debug_check_range();
    }

    /// And so is a negative one.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "limb 7 out of [0, 2^56)")]
    fn debug_check_range_rejects_negative_limb() {
        n([0, 0, 0, 0, 0, 0, 0, -1]).debug_check_range();
    }

    /// The multiplications take an operand at their bound and, in a debug build, refuse one
    /// past it.
    #[test]
    fn the_multiplications_take_operands_at_their_bound() {
        const BOUND: i64 = (1 << 57) + (1 << 9);
        let one = FieldElement448::one();
        for limb in [BOUND, -BOUND] {
            let x = FieldElement448([limb; 8]);
            let expected = x.normalize().0.0;
            assert_eq!(x.mul(&one).normalize().0.0, expected);
            assert_eq!(one.mul(&x).normalize().0.0, expected);
            assert_eq!(x.mul_u32(1).normalize().0.0, expected);
            assert_eq!(x.sqr().normalize().0.0, x.mul(&x).normalize().0.0);
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "outside its bound")]
    fn mul_rejects_an_operand_past_its_bound() {
        let _ = FieldElement448::one().mul(&FieldElement448([0, 0, 0, 0, 0, 0, 0, 1 << 58]));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "outside its bound")]
    fn sqr_rejects_an_operand_past_its_bound() {
        let _ = FieldElement448([0, 0, 0, -(1 << 58), 0, 0, 0, 0]).sqr();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "outside its bound")]
    fn mul_u32_rejects_an_operand_past_its_bound() {
        let _ = FieldElement448([(1 << 57) + (1 << 9) + 1, 0, 0, 0, 0, 0, 0, 0]).mul_u32(3);
    }

    /// The values either side of p, where normalize's third and fourth passes decide the answer.
    #[test]
    fn normalize_edge_values() {
        // p - 1: already canonical, unchanged.
        let p_minus_1 = [M56 - 1, M56, M56, M56, M56 - 1, M56, M56, M56];
        assert_eq!(FieldElement448(p_minus_1).normalize().0.0, p_minus_1);
        // p reduces to 0, p + 1 to 1.
        assert_eq!(FieldElement448(P_LIMBS).normalize().0.0, [0; 8]);
        assert_eq!(FieldElement448([0, 0, 0, 0, M56, M56, M56, M56]).normalize().0.0, small(1));
        // 2^448 - 1, the largest non-canonical encoding: reduces to 2^224.
        assert_eq!(FieldElement448([M56; 8]).normalize().0.0, [0, 0, 0, 0, 1, 0, 0, 0]);
        // 2^448 itself, a top limb of 2^56, folds to 2^224 + 1 in the first pass.
        let two_448 = FieldElement448([0, 0, 0, 0, 0, 0, 0, M56 + 1]).normalize();
        assert_eq!(two_448.0.0, [1, 0, 0, 0, 1, 0, 0, 0]);
    }

    /// Representations with negative and over-wide limbs: -1, -2^224, -2^392, and p - 3 held
    /// with a top limb of 2^56 over a negative limb.
    #[test]
    fn normalize_is_total_on_wide_and_negative_representations() {
        let minus_1 = FieldElement448(small(-1)).normalize();
        assert_eq!(minus_1.0.0, [M56 - 1, M56, M56, M56, M56 - 1, M56, M56, M56]);
        let minus_2_224 = FieldElement448([0, 0, 0, 0, -1, 0, 0, 0]).normalize();
        assert_eq!(minus_2_224.0.0, [M56, M56, M56, M56, M56 - 2, M56, M56, M56]);
        let minus_2_392 = FieldElement448([0, 0, 0, 0, 0, 0, 0, -1]).normalize();
        assert_eq!(minus_2_392.0.0, [M56, M56, M56, M56, M56 - 1, M56, M56, M56 - 1]);
        let p_minus_3 =
            FieldElement448([M56 - 3, M56, M56, M56, M56 - 1, M56, -1, M56 + 1]).normalize();
        assert_eq!(p_minus_3.0.0, [M56 - 3, M56, M56, M56, M56 - 1, M56, M56, M56]);
        // 4 * 2^448 = 4 * (2^224 + 1), and its negation.
        let top = FieldElement448([0, 0, 0, 0, 0, 0, 0, 1 << 58]).normalize();
        assert_eq!(top.0.0, [4, 0, 0, 0, 4, 0, 0, 0]);
        let top_negative = FieldElement448([0, 0, 0, 0, 0, 0, 0, -(1 << 58)]).normalize();
        assert_eq!(top_negative.0.0, [M56 - 4, M56, M56, M56, M56 - 5, M56, M56, M56]);
    }

    /// Every limb pattern over the edges of normalize's domain: the canonical form has
    /// canonical limbs (which `debug_check_range` asserts in debug builds), and is the same
    /// whether the value is normalized as given, after a reducing multiply by one where the
    /// value is inside the multiplications' operand bound (normalize's domain is wider), or
    /// with a representation of p added limb-wise where that stays inside the domain.
    #[test]
    fn normalize_agrees_with_itself_across_representations_of_the_domain_edges() {
        const EDGES: [i64; 5] = [0, -1, M56, 1 << 58, -(1 << 58)];
        let one = FieldElement448::one();
        // p = 2^448 - 2^224 - 1 as a top limb of 2^56 over two limbs of -1.
        let p = FieldElement448([-1, 0, 0, 0, -1, 0, 0, M56 + 1]);
        for pattern in 0..5_usize.pow(8) {
            let limbs: [i64; 8] =
                core::array::from_fn(|i| EDGES[pattern / 5_usize.pow(i as u32) % 5]);
            let x = FieldElement448(limbs);
            let direct = x.normalize();
            direct.debug_check_range();
            if limbs.iter().all(|limb| limb.unsigned_abs() <= (1 << 57) + (1 << 9)) {
                assert_eq!(direct.0.0, x.mul(&one).normalize().0.0, "{limbs:?} * 1");
            }
            if limbs[0] != -(1 << 58) && limbs[4] != -(1 << 58) && limbs[7] != 1 << 58 {
                assert_eq!(direct.0.0, x.add(&p).normalize().0.0, "{limbs:?} + p");
            }
        }
    }

    fn patterned_values() -> [FieldElement448; 10] {
        [
            FieldElement448::one(),
            FieldElement448(small(2)),
            FieldElement448(small(3)),
            FieldElement448([1, 0, 0, 0, 1, 0, 0, 0]),
            FieldElement448([M56 - 1, M56, M56, M56, M56 - 1, M56, M56, M56]),
            FieldElement448(KNOWN_LIMBS),
            FieldElement448([M56, 0, M56, 0, M56, 0, M56, 0]),
            FieldElement448([1 << 55; 8]),
            FieldElement448([
                0x1234567, 0x89abcde, 0xf0f0f0f, 0x5a5a5a5, 0x7777777, 0x1357924, 0xfedcba9,
                0x2468ace,
            ]),
            FieldElement448([0, 0, 0, 0, 0, 0, 0, 1]),
        ]
    }

    /// `x^e` by plain square-and-multiply over the low `bits` bits of an exponent given by
    /// `is_set`, sharing nothing with `pow_p_sub3_div4`.
    fn pow_bits(
        x: &FieldElement448,
        bits: usize,
        is_set: impl Fn(usize) -> bool,
    ) -> FieldElement448 {
        let mut acc = FieldElement448::one();
        for bit in (0..bits).rev() {
            acc = acc.sqr();
            if is_set(bit) {
                acc = acc.mul(x);
            }
        }
        acc
    }

    /// `x * inv(x) = 1` for the patterned values, and both exponents agree with
    /// square-and-multiply over their bits: `(p - 3) / 4 = 2^446 - 2^222 - 1` is 446 ones with
    /// bit 222 clear, and `p - 2 = 2^448 - 2^224 - 3` is 448 ones with bits 224 and 1 clear.
    #[test]
    fn inv_is_the_multiplicative_inverse() {
        for x in patterned_values() {
            let product = x.mul(&x.inv()).normalize();
            assert_eq!(product.0.0, small(1), "{:?}", x.0);
            let chain = x.pow_p_sub3_div4().normalize();
            assert_eq!(chain.0.0, pow_bits(&x, 446, |bit| bit != 222).normalize().0.0);
            let inverse = pow_bits(&x, 448, |bit| bit != 224 && bit != 1).normalize();
            assert_eq!(x.inv().normalize().0.0, inverse.0.0, "{:?}", x.0);
        }
        assert_eq!(FieldElement448::zero().inv().normalize().0.0, [0; 8]);
    }

    /// `sqr` is `mul` of a value by itself, `sqr_n` is `sqr` repeated, and `mul_u32` is `mul`
    /// by the constant as an element.
    #[test]
    fn sqr_and_mul_u32_agree_with_mul() {
        for x in patterned_values() {
            assert_eq!(x.sqr().normalize().0.0, x.mul(&x).normalize().0.0, "{:?}", x.0);
            assert_eq!(x.sqr_n(0).0, x.0);
            assert_eq!(x.sqr_n(3).normalize().0.0, x.sqr().sqr().sqr().normalize().0.0);
            for c in [39_082_u32, 1, u32::MAX] {
                let by_const = x.mul(&FieldElement448(small(c as i64)));
                assert_eq!(x.mul_u32(c).normalize().0.0, by_const.normalize().0.0, "{:?}", x.0);
            }
        }
    }

    /// `cswap` exchanges both values when told to and neither when not.
    #[test]
    fn cswap_swaps_on_the_condition_only() {
        let other = [11, 12, 13, 14, 15, 16, 17, 18];
        let (mut a, mut b) = (FieldElement448(KNOWN_LIMBS), FieldElement448(other));
        FieldElement448::cswap(Condition::<i64>::from_bool_const::<false>(), &mut a, &mut b);
        assert_eq!((a.0, b.0), (KNOWN_LIMBS, other));
        FieldElement448::cswap(Condition::<i64>::from_bool_const::<true>(), &mut a, &mut b);
        assert_eq!((a.0, b.0), (other, KNOWN_LIMBS));
    }

    /// The outputs of the three multiplications are reduced, limbs in `[-2^8, 2^56 + 2^8]`,
    /// for the widest operands they accept (and in a debug build no step of them overflows).
    #[test]
    fn products_of_the_widest_operands_are_reduced() {
        const WIDEST: i64 = (1 << 57) + (1 << 9);
        let wide = FieldElement448([WIDEST; 8]);
        let wide_negative = FieldElement448([-WIDEST; 8]);
        let alternating =
            FieldElement448([WIDEST, -WIDEST, WIDEST, -WIDEST, WIDEST, -WIDEST, WIDEST, -WIDEST]);
        let halves =
            FieldElement448([WIDEST, WIDEST, WIDEST, WIDEST, -WIDEST, -WIDEST, -WIDEST, -WIDEST]);
        let operands = [wide, wide_negative, alternating, halves];
        for x in &operands {
            for y in &operands {
                for z in [x.mul(y), x.sqr(), x.mul_u32(u32::MAX)] {
                    for limb in z.0 {
                        assert!((-(1 << 8)..=(1 << 56) + (1 << 8)).contains(&limb), "{:?}", z.0);
                    }
                }
            }
        }
    }

    // Known answers for every field operation, computed by a second implementation of this
    // field and each recomputed with arbitrary-precision integers (scratch programs, not in
    // this repository): the operations on the values around p and around 2^224, and on
    // pseudo-random values (splitmix64, fixed seed), with the results encoded canonically as 56
    // little-endian bytes in hexadecimal.

    /// One row: `a` as given to `decode_448`, and the answers for it, with `b` the next row's
    /// `a`. `mul_u32` is by 39082.
    struct FieldKat {
        a: &'static str,
        canonical: &'static str,
        mul: &'static str,
        sqr: &'static str,
        mul_u32: &'static str,
        add: &'static str,
        sub: &'static str,
        negate: &'static str,
        inv: &'static str,
        sqrt_ratio: Option<&'static str>,
        is_zero: bool,
        parity: u8,
        equals_b: bool,
    }

    /// One row: a representation with limbs outside `[0, 2^56)`, the limbs `carry` makes of
    /// it, its canonical encoding, and its square and its product with the next row.
    struct WideKat {
        limbs: [i64; 8],
        carry: [i64; 8],
        canonical: Option<&'static str>,
        sqr: Option<&'static str>,
        mul: Option<&'static str>,
    }

    // 25 cases; b is the next case's a, cyclically.
    const FIELD_KATS: [FieldKat; 25] = [
        FieldKat {
            a: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            canonical: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul_u32: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sub: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            negate: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            inv: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some(
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            is_zero: true,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            canonical: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul: "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul_u32: "aa98000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            add: "0300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sub: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            negate: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some(
                "caa2a9af351c0ce3ca5afdb8c524ea0276e6a4a81d4b4e023dba91743dfb69569503a34f8c42bb43bb119a7775325995a006657b3d4b346b",
            ),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            canonical: "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul: "fdfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            sqr: "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul_u32: "5431010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sub: "0300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            negate: "fdfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "00000000000000000000000000000000000000000000000000000080ffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            canonical: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            mul: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul_u32: "5567fffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            add: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            sub: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            negate: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            inv: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            canonical: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul_u32: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sub: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            negate: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            inv: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some(
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            is_zero: true,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "00000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            canonical: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul_u32: "aa98000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            add: "0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sub: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            negate: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some(
                "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            is_zero: false,
            parity: 1,
            equals_b: true,
        },
        FieldKat {
            a: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            canonical: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul: "0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul_u32: "aa98000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            sub: "00000000000000000000000000000000000000000000000000000000feffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            negate: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some(
                "0000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000",
            ),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            canonical: "0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            mul: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            mul_u32: "00000000000000000000000000000000000000000000000000000000aa980000000000000000000000000000000000000000000000000000",
            add: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff01000000000000000000000000000000000000000000000000000000",
            sub: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            negate: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some(
                "0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            ),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",
            canonical: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",
            mul: "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqr: "01000000000000000000000000000000000000000000000000000000feffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            mul_u32: "5667ffffffffffffffffffffffffffffffffffffffffffffffffffffa9980000000000000000000000000000000000000000000000000000",
            add: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff01000000000000000000000000000000000000000000000000000000",
            sub: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            negate: "00000000000000000000000000000000000000000000000000000000feffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",
            ),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            canonical: "0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            mul: "0100000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            mul_u32: "00000000000000000000000000000000000000000000000000000000aa980000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000",
            sub: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            negate: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some(
                "0000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000",
            ),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            canonical: "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            mul: "0100000000000000000000000000000000000000000000000000008001000000000000000000000000000000000000000000000000000000",
            sqr: "0200000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000",
            mul_u32: "aa980000000000000000000000000000000000000000000000000000aa980000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000080",
            sub: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
            negate: "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "01000000000000000000000000000000000000000000000000000000feffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            sqrt_ratio: Some(
                "9445535f6b3818c695b5fa718b49d405eccc49513b969c047a7423e97af6d3ac2a07469f18857687762334efea64b22a410dcaf67a9668d6",
            ),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
            canonical: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
            mul: "0200000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000",
            sqr: "0000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000080",
            mul_u32: "554c0000000000000000000000000000000000000000000000000000554c0000000000000000000000000000000000000000000000000000",
            add: "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080",
            sub: "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            negate: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            inv: "03000000000000000000000000000000000000000000000000000000fdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            sqrt_ratio: Some(
                "9efd34abca81d12746a1dda1dd08cdbb3a99ac4a5083b2bd9e259a3503cf0983e58f5799ab4e5c7e401b42bd750cff1edfa8d93ebd02e3ef",
            ),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            canonical: "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul: "6bbfabe167deee50c8783d41dea6850a8144e03676f79f31719bc13bef2b4ac631c2db74112dcc9ae2175f9e4b372c1ec1f0d3ab493a3da8",
            sqr: "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            mul_u32: "a862020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            add: "deef6af899b73b14325e4f90b769a1422011b88dddfd674cdc66f00efb8a92718cf0365d440bb3a6f8c597e7d20d8b4730fcf46a924e0fea",
            sub: "291095076648c4ebcda1b06f48965ebddfee4772220298b323990ff103756d8e730fc9a2bbf44c59073a68182df274b8cf030b956db1f015",
            negate: "fbfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            inv: "000000000000000000000000000000000000000000000000000000c0ffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
            sqrt_ratio: Some(
                "33f32155d73e9697e5e99b34e196d044929d5bf50c18564cf59a84b4890fb2759aa0c637b5b14363b1e6202733611d9ec466191fcec3a3c3",
            ),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "daef6af899b73b14325e4f90b769a1422011b88dddfd674cdc66f00efb8a92718cf0365d440bb3a6f8c597e7d20d8b4730fcf46a924e0fea",
            canonical: "daef6af899b73b14325e4f90b769a1422011b88dddfd674cdc66f00efb8a92718cf0365d440bb3a6f8c597e7d20d8b4730fcf46a924e0fea",
            mul: "3e5ff2685b73f1c6ae272106f7b6e45068a0c1d1d9f98804e45882036053831d48325ffaf0dc304431be6647e62961f7d73a7d959dac0f87",
            sqr: "92fe4f2ee2bb6234dbf888fbfbb8536ace484544028b64c8fb1c4b7904cf310e631abc30ed9f2b23b4370ebc76489d5cbe2d6a6100301376",
            mul_u32: "58426d75be57abe44449a2f49431f515fc8666664521ca7ba81bb7a82ae7d56db2204f85be129601191a55e88f678c128a226c7cbc1cd184",
            add: "166d0636e7ee041dc09dea25d965bbf55613dea4f94424d0d72b433a47a5a4b97499eedb19735048975f4d882dbcc7245b79afbe26d629e6",
            sub: "9e72cfba4c80720ba41eb4fa956d878fe90e9276c1b6abc8e0a19de3ae708029a4477fde6ea315055a2ce246785f4e6a057f3a17fec6f4ed",
            negate: "251095076648c4ebcda1b06f48965ebddfee4772220298b323990ff103756d8e730fc9a2bbf44c59073a68182df274b8cf030b956db1f015",
            inv: "a2732c69495b30e48fdaff430e9b04d76b7f8ccc7a3219353323c923f7a958df3a41bfbe0284ceb74433222f4e7126ff26a4c06f53e516f7",
            sqrt_ratio: Some(
                "7ab4c93bd168feca613352f970ca15791ff76d74cdd2f7b75511bda1f664ebe4e2bcf46293df116f7f5d9d4377f089df3bd0774fb63def2c",
            ),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "3b7d9b3d4d37c9088e3f9b9521fc19b3360226171c47bc83fbc4522b4b1a1248e8a8b77ed5679da19e99b5a05aae3cdd2a7dba5394871afc",
            canonical: "3b7d9b3d4d37c9088e3f9b9521fc19b3360226171c47bc83fbc4522b4b1a1248e8a8b77ed5679da19e99b5a05aae3cdd2a7dba5394871afc",
            mul: "4efeb1dc028026780479ffa840b262549e02e66e3ac8ebdc78cfce9fc450b1054229b0bffa2220622ce4b97b856a377244aac08bf6e748ad",
            sqr: "e079ff7496c6de6cbb888158e53b5d60d213c8d1ba31e630f925275c07b3439889b952adb397a0ccd8594c64c2c1cdcec2af60fdb70f003e",
            mul_u32: "85c79c3bdf95744e8989d486215ff55caaf28df065e63f453d25ece9faada29b0a15403203b72dc84c33ce8b9a97d1f1d2912854361a1e2a",
            add: "f78306c911d89d85f31cf54f87a0f32f58b164d0e96813ca8d316749958d92c2ef6d0795419b49666f984a8d1976469154443782ba14301d",
            sub: "807630b28896f48b286241dbbb5740361553e75d4e25653d69583e0d02a791cde0e367686934f1dccd9a20b49be6322901b63d256efa04db",
            negate: "c48264c2b2c836f771c0646ade03e64cc9fdd9e8e3b8437c043badd4b3e5edb7175748812a98625e61664a5fa551c322d58245ac6b78e503",
            inv: "e1bb4f52f7e2275b7986f95985b5717e022338b44be36082e02ba877dc04409145c21a9e0832c147865d396b361fc1451c94d54f1408a185",
            sqrt_ratio: None,
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "bb066b8bc4a0d47c65dd59ba65a4d97c21af3eb9cd215746926c141e4973807a07c54f166c33acc4d0fe94ecbec709b429c77c2e268d1521",
            canonical: "bb066b8bc4a0d47c65dd59ba65a4d97c21af3eb9cd215746926c141e4973807a07c54f166c33acc4d0fe94ecbec709b429c77c2e268d1521",
            mul: "eb0269b4cfb4330bbd52d4d36283e2f6b772a465524da564d4a8f6535b08ee7e754442e86a41eca46b28bb5b6f097ef2d8ee6bb645021aaa",
            sqr: "de202c898ad2a4d376b42656d33d9c67cbd116682b224235fe0b415ff86284fbde9963a3c3470ab51649285259a56320949dc61636ce074f",
            mul_u32: "e89311214c75a7248347211b339223225e2e9c3b9a98ee71e6f2061a240cc09db347f52d0653e2d8682b3d924101185d97041df5f4661ec4",
            add: "0a8d7fc49cdd37652599f4373d2cbaea4e6773d9ce556f13a156ff08ced1df1748e810ca33b06378b1e250a7bda13bcbb6e47eb567a5bea7",
            sub: "6b805652ec637194a521bf3c8e1cf90ef4f60999cced3e7983822933c31421ddc6a18e62a4b6f410f01ad931c0edd79c9ca97aa7e4746c9a",
            negate: "44f994743b5f2b839a22a6459a5b2683de50c14632dea8b96d93ebe1b58c7f85f83ab0e993cc533b2f016b134138f64bd63883d1d972eade",
            inv: "f7d735d4a16d4eb29d85c5a726005047cf0c39d2e15055b8ef43a306491fd29d8697c36960d1e0bc444aa35aa5952465b16d91f88c125e85",
            sqrt_ratio: Some(
                "120ec886e149617ca65f1581005e200cfcf9c46eaa80dd14e658d334843fdbff27af09d48e1655ed4bbeba5444f85ea902e33126acb6d9c6",
            ),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "4f861439d83c63e8bfbb9a7dd787e06d2db83420013418cd0eeaeaea845e5f9d4023c1b3c77cb7b3e0e3bbbafed931178d1d02874118a986",
            canonical: "4f861439d83c63e8bfbb9a7dd787e06d2db83420013418cd0eeaeaea845e5f9d4023c1b3c77cb7b3e0e3bbbafed931178d1d02874118a986",
            mul: "ecb9043d8798589b65f335ea160ae69730f8bed301cc686929e7922ec7ce4b89396abde59b192428363cde12cf2b741a54831397a00eb9a3",
            sqr: "93af39bba774be423e5537f0a498a54d108c9b7feb1cb84281c4f4f4c2ac1036fad479846c3faf4d4a0753ae0a4824d4417d886bbe8a464a",
            mul_u32: "c36860177ac9063e6b9f3a48ad27c24768475db0de33f3909a37f87a0c00742159c62f0b586fef49ecbd129007028a007765f3e8ac03b1d2",
            add: "5784555b296405a24eeae12b9657a18d09a19c080a54f82c077350e36cac002b4ce59d9223261c52c441ed71da27774d7f17a8a60bd688bf",
            sub: "4788d3168715c12e318d53cf18b81f4e51cfcc37f813386d166185f29c10be0f3561e4d46bd35215fd858a03238cece09a235c67775ac94d",
            negate: "b079ebc627c39c174044658228781f92d247cbdffecbe732f11515157aa1a062bfdc3e4c3883484c1f1c44450126cee872e2fd78bee75679",
            inv: "f0278686e135e248b25f199efcccce89811f7c42c3b2eb1935e3c7f3184fe894cfc8dc29ee27d95dc46aa85e1bbff1d57f709bac82b7210a",
            sqrt_ratio: None,
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "08fe40225127a2b98e2e47aebecfc01fdce867e80820e05ff88865f8e74da18d0bc2dcde5ba9649ee35d31b7db4d4536f2f9a51fcabddf38",
            canonical: "08fe40225127a2b98e2e47aebecfc01fdce867e80820e05ff88865f8e74da18d0bc2dcde5ba9649ee35d31b7db4d4536f2f9a51fcabddf38",
            mul: "0d2f287d1ef1cd9cf090cd01f88787b4a3eab0c36f79def59851846b6f92eee2ff0079a247c843777875a130d0ed2e9ae7024f36cfb999eb",
            sqr: "feec8d59d326105005e0ad4188223e47096773ec8a47d9647e751e7bc6ec857de3d91336cbbf36d95b10ec52143dd9a1137d6e795c035f30",
            mul_u32: "3a93fd553748068dffa8e9fe192c639107554307e88fdabddc6dc03c71995fd3c3b7cf11550367f3327f87f6ac28403011cb9f90030b449d",
            add: "225f585d0bc3e1c18399c27b96b6bc9c6624d04cb2074a92617f58670d50b9a6ea1a3b7537df7044f0ad8817d17bfbc9303e15256c5cb9c0",
            sub: "ed9c29e7968b62b199c3cbe0e6e8c4a251adff835f38762d8f927289c14b89742c697e48807358f8d60dda56e61f8fa2b3b5361a281f06b1",
            negate: "f701bfddaed85d4671d1b85141303fe023179817f7df1fa007779a0717b25e72f43d2321a4569b611ca2ce4824b2bac90d065ae0354220c7",
            inv: "3a8f13606d6b4cb467b706ffbbc9ca4fc836d3d1506a52780756e64fa7cc1e8d8ce153e464b85aebc997d7190033ca270abeedf670c8adfc",
            sqrt_ratio: Some(
                "91bd87beb69aa6cfe8560e8a117a6d8e023ed47b1ea83d3f2d7e24075063ecf9c69eda631d6e033e792167ba0a681b76fe7c9586127134a7",
            ),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "1a61173bba9b3f08f56a7bcdd7e6fb7c8a3b6864a9e7693269f6f26e25021819df585e96db350ca60c505760f52db6933e446f05a29ed987",
            canonical: "1a61173bba9b3f08f56a7bcdd7e6fb7c8a3b6864a9e7693269f6f26e25021819df585e96db350ca60c505760f52db6933e446f05a29ed987",
            mul: "eb1a0f773fb7d4966f5b8bfc9632efd1ffc06fc96301ddde21708ada0f1f85f22526948077c4cd0ba7368b960e1605da88b30ef2d31f3978",
            sqr: "9c6a726c570e48a543a3dbcdc95a0897834792a4b52007da3eb475360b595550b7c1a677dabd257336d9f920fdf91804bf154debd08c56c7",
            mul_u32: "473c2e1fc1fcb33e9d8376bb4f6d57902cc491901a6ae05bca17a6efbef737eb0c7b6bdf19251684fdaa82d125364442427968acd18ab36c",
            add: "000f7f2cd2ea2b280eab4fa490cb7255726090b016381a5e62d11610cd276cfc0b72ea354fea39baba6298c9f8ec9c83455aed4b2556f9f9",
            sub: "34b3af49a24c53e8db2aa7f61e0285a4a21640183c97b906701bcfcd7ddcc335b23fd2f66781de915e3d16f7f16ecfa3372ef1be1ee7b915",
            negate: "e59ee8c44564c0f70a9584322819048375c4979b561896cd96090d91d9fde7e620a7a16924caf359f3afa89f0ad2496cc1bb90fa5d612678",
            inv: "5f6bb9d7b799d1c264d2b127450aad1d6a77f12efec19ee72643991c518028699cee663d145bb97dbc6155c596b08dd962ae0a9e2480806f",
            sqrt_ratio: Some(
                "cbc2046ebd0b8bf23e3ddccf9cbd060ef00e618d173884eaca7a19e0cf1f5346553d608b5b853926879ce6fa0a2d5719d43edcb6124b06fd",
            ),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "e6ad67f1174fec1f1940d4d6b8e476d8e724284c6d50b02bf9da23a1a72554e32c198c9f73b42d14ae12416903bfe6ef06167e4683b71f72",
            canonical: "e6ad67f1174fec1f1940d4d6b8e476d8e724284c6d50b02bf9da23a1a72554e32c198c9f73b42d14ae12416903bfe6ef06167e4683b71f72",
            mul: "4c81a5fe6d2ab61cd35ad97f2e4213756e06d352d1a189579cec113b9f113cb449b4a7106231f5332ee917874853c639b106c9fd245a03e7",
            sqr: "31819f290a080ca0191bde161c8280ebedbebcf840deb3e258ec3f2f58c6e3d406092801c5a5567f8ec637bfd008361230d865336ff7bd85",
            mul_u32: "ca4e1ade3bbde281a37b01af4ca2c1567c2a9268cc4dd6b2675bd34b0ccd3cecc85efb21837b7e8994c34d88c2dea4500cbfceac07cf059e",
            add: "518c2eb73ab4b1ad6eee3e9ac1a122060b4202074f2ea917512195772c74b20e7f18c9d2bbf82e3ce6c9cc00b7003220da66131810ba6ffc",
            sub: "7acfa02bf5e92692c3916913b027cbaac4074e918b72b73fa194b2ca21d7f5b7da194f6c2b702cec755bb5d14f7d9bbf33c5e874f6b4cfe7",
            negate: "1952980ee8b013e0e6bf2b29471b892718dbd7b392af4fd40625dc5e57daab1cd3e673608c4bd2eb51edbe96fc401910f9e981b97c48e08d",
            inv: "aec5cdc30dd411a819cc91f20252ff59a588f67acd25199bd35e43906bf6414d204c6c9626e8f9a4d0e812055fe543c423fe604f1c5f33ad",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "6bdec6c52265c58d55ae6ac308bdab2d231ddabae1ddf8eb574671d6844e5e2b52ff3c334844012838b78b97b3414b30d35095d18c02508a",
            canonical: "6bdec6c52265c58d55ae6ac308bdab2d231ddabae1ddf8eb574671d6844e5e2b52ff3c334844012838b78b97b3414b30d35095d18c02508a",
            mul: "ef02e7ecebe6a24903187d2fa89406c5c75b496e0f15913e8a24ffd8651e40ed43d95d2a7f3e63959055d1006688803f58c6d0930440fd63",
            sqr: "acc5c92dbeb3edf9f5c37c3db35070940f77dccd120919e0c827e816d509c96962a03745d39b0675bea79cd1605c5cb30e192d507ad4d27f",
            mul_u32: "898d1f6a85ce2159fd905a1cd9bb484c7a3c2496d75e01777eeafca804563fcb50561a3e5e3662510b0391973d43fcc0ea1025d5f34da55a",
            add: "dfe9445f2fead25e3f5333bdb6f7c5064e97553bf1af17d94aad039d9d9f28ee4c6d424a83a18c2079f67d91db8ec9003f59310de0efdcc3",
            sub: "f7d2482c16e0b7bc6b09a2c95a829154f8a25e3ad20bdafe64dfde0f6cfd93685791371c0de7752ff777999d8bf4cc5f6748f9953915c350",
            negate: "9421393add9a3a72aa51953cf74254d2dce225451e220714a8b98e297ab1a1d4ad00c3ccb7bbfed7c74874684cbeb4cf2caf6a2e73fdaf75",
            inv: "f3ed8a2441cfa44a7d2decf1d7320a35b9ea18a795be80a763ca58614762dc9e65599fcfabad168c1c7fd4228e1d9671bbae521134f38234",
            sqrt_ratio: Some(
                "b44f00a67894b95930fd8a68df5eae5dc9cd3abb717c5ee264824e0671815b69554b6b328d01d9de30db1f76a1978307b20d143aceaca61f",
            ),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "740b7e990c850dd1e9a4c8f9ad3a1ad92a7a7b800fd21eedf26692c61851cac2fa6d05173b5d8bf8403ff2f9274d7ed06b089c3b53ed8c39",
            canonical: "740b7e990c850dd1e9a4c8f9ad3a1ad92a7a7b800fd21eedf26692c61851cac2fa6d05173b5d8bf8403ff2f9274d7ed06b089c3b53ed8c39",
            mul: "be9fb4e232f96a22d3423314288d1b0e97fb8be35937a925249d7208415d227f6ea7213d40c3fcbff47a1b09d404a9acb005be2594961b74",
            sqr: "d881df1b774720580a0ce74a0c21f3a066591c567d560c6e6ded7908b048ed2cf8f72da736c72005a111e0d49b875179a59fda601cbc350d",
            mul_u32: "599d80c480d5f9d964572801d74342be5b9188a294b230c31b9a58caabb2807a2dece782e8fee6cbb7946cd0f3f8ae71639b9d3aaa047fe4",
            add: "4b1cdb3d608476113b5ebe479e1120175f98bd044b91eecc1481484e19e5502927f24e1eecf5b8b54c4d18ed4dad1fb27addde9905d5f012",
            sub: "9dfa20f5b885a49098ebd2abbd63149bf65b39fcd3124f0dd14cdc3e18bd435ccee9bb0f8ac45d3b3531cc0602eddcee5c3359dda0052960",
            negate: "8bf48166f37af22e165b370652c5e526d585847ff02de1120d996d39e6ae353d0592fae8c4a27407bfc00d06d8b2812f94f763c4ac1273c6",
            inv: "739e30b9720dd0c3af63a593d829eaaf3c4cf687cc5480850abb123fe97a1dea155231e76ab5d248235592866aa8724c5f28ed3a8a41598a",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "d6105da453ff684051b9f54df0d6053e341e42843bbfcfdf211ab687ff9386662c844907b1982dbd0b0e26f32560a1e10ed5425eb2e763d9",
            canonical: "d6105da453ff684051b9f54df0d6053e341e42843bbfcfdf211ab687ff9386662c844907b1982dbd0b0e26f32560a1e10ed5425eb2e763d9",
            mul: "65c0436aac01b1cd5b9266071210778ec62438b4694107eb477d0193ea9cff0ecdaa354ce22ca17ae9c6fee6afde25849a14644575debb1d",
            sqr: "6ec4e942ee334f038cbcdfe9f6fcf0bd9089566b2da50e55784c31559fc43244ea1f26ef660e2fbd330357008f581978ea38f68ed91cccb9",
            mul_u32: "bfbfcc672237531d334e35abdd697fa78413d7150d5480f96177713ee7813efd5b224c7de281f0b21e4c9c0f926140a6d951e2466ac4e9ad",
            add: "e70a22c71cb354f947680c3de102d198d3a695f128798797b2034753914b3abc36a461f2f75e378cb08eac54cb1e1934916917d102ff5823",
            sub: "c61698818a4b7d875a0adf5effaa3ae39495ee164e051828913025bc6edcd2102264311c6ad223ee668d9f9180a1298f8c406eeb61d06e8f",
            negate: "29efa25bac0097bfae460ab20f29fac1cbe1bd7bc4403020dee54978ff6b7999d37bb6f84e67d242f4f1d90cda9f5e1ef12abda14d189c26",
            inv: "845a93549f70b9a1b92d5565726563000b03af35fae51a0a8dee7a74d03c32608b94c1b0d35bb34b657de54bf7bfa144eb69191da0d74da1",
            sqrt_ratio: Some(
                "72c909c9e7d2892137e788dbb5f5bd1bd2da3ab61c1263bb57d483619d6f7fce5343b77e5377171012c53001ffec9636e80b447d8faaaa88",
            ),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "10fac422c9b3ebb8f6ae16eff02bcb5a9f88536dedb9b7b790e990cb90b7b3550a2018eb46c609cfa4808661a5be77528294d4725017f549",
            canonical: "10fac422c9b3ebb8f6ae16eff02bcb5a9f88536dedb9b7b790e990cb90b7b3550a2018eb46c609cfa4808661a5be77528294d4725017f549",
            mul: "77f26b8c21be2185a95d4729944e14edf6740289a757229d9e8688cdb2d672e6531c3c053046f7285830c619dedf1153025b767058f057ac",
            sqr: "85894ead4f3fe5b05c4651cbc656004591048b6f976f5fae0de40e9675c2d40f1e421b04a576f3d119ed337a499d4eb6a737a645438d9f98",
            mul_u32: "baba470b36d044bfa2adf23cf43b02edba579732947066162f07e9381f0b569ebf690b71aec6374a5f48b39fbacbb6dc81ff57799a3f99a2",
            add: "3ca2e74f3f8a9dad8009bed3594497136dacad89fef5ed82b830c63f6e18afb2e476b6870b16d61dc8d9636803a98a814a86388d20dcb782",
            sub: "e451a2f552dd39c46c546f0a8813ffa1d164f950dc7d81ec68a25b57b356b8f82fc9794e82763d808127a95a47d46423baa2705880523211",
            negate: "ef053bdd364c14470951e9100fd434a56077ac92124648486f166f346e484caaf5dfe714b939f6305b7f799e5a4188ad7d6b2b8dafe80ab6",
            inv: "0c78f7c0e0d7c3d4f475de9dbebe5421b3c6dddde6bb93b94548d2840b37bb905ed2e64e06fa4b0d470c03576ac4c3e002699c3e78401196",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "2ca8222d76d6b1f4895aa7e46818ccb8cd235a1c113c36cb27473574dd60fb5cda569e9cc44fcc4e2359dd065eea122fc8f1631ad0c4c238",
            canonical: "2ca8222d76d6b1f4895aa7e46818ccb8cd235a1c113c36cb27473574dd60fb5cda569e9cc44fcc4e2359dd065eea122fc8f1631ad0c4c238",
            mul: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            sqr: "9e6ea232b224aaa5db5d1c5ef6f0ee8111ae8323a4d3914e79f5745625e72d02bad1b72734b33dfac2b4a1f8bf7c889514d2861a85631df0",
            mul_u32: "11efdd8c46956e15e608e4346b7d06e655ec1d59320cae2515e1a0cde7f171003754b7048eb509a33b28eafb8376b77de26aeddddc413256",
            add: "2ca8222d76d6b1f4895aa7e46818ccb8cd235a1c113c36cb27473574dd60fb5cda569e9cc44fcc4e2359dd065eea122fc8f1631ad0c4c238",
            sub: "2ca8222d76d6b1f4895aa7e46818ccb8cd235a1c113c36cb27473574dd60fb5cda569e9cc44fcc4e2359dd065eea122fc8f1631ad0c4c238",
            negate: "d357ddd289294e0b76a5581b97e7334732dca5e3eec3c934d8b8ca8b219f04a325a961633bb033b1dca622f9a115edd0370e9ce52f3b3dc7",
            inv: "5ebb8ae0052ef8788bb9f588d0e0217629a81be22fe9c1926181bc51c16485018488d9f6f1d9453b95c992f46ae7237ad4904da9f911d8dd",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
    ];

    // 12 cases; the multiplier is the next case's limbs, cyclically. The last case is
    // outside the magnitude mul and sqr accept, so it has a carry answer only.
    const WIDE_KATS: [WideKat; 12] = [
        WideKat {
            limbs: [
                72057594037927935, 72057594037927935, 72057594037927935, 72057594037927935,
                72057594037927935, 72057594037927935, 72057594037927935, 72057594037927935,
            ],
            carry: [
                72057594037927935, 72057594037927935, 72057594037927935, 72057594037927935,
                72057594037927935, 72057594037927935, 72057594037927935, 72057594037927935,
            ],
            canonical: Some(
                "0000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            ),
            sqr: Some(
                "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            ),
            mul: Some(
                "0201000000000001010000000000010100000000000101000000000003020000000000020200000000000202000000000002020000000000",
            ),
        },
        WideKat {
            limbs: [
                72057594037928192, 72057594037928192, 72057594037928192, 72057594037928192,
                72057594037928192, 72057594037928192, 72057594037928192, 72057594037928192,
            ],
            carry: [257, 257, 257, 257, 258, 257, 257, 257],
            canonical: Some(
                "0101000000000001010000000000010100000000000101000000000002010000000000010100000000000101000000000001010000000000",
            ),
            sqr: Some(
                "0e180b000000000c160a000000000b1409000000000a120800000000172812000000001424100000000012200e00000000101c0c00000000",
            ),
            mul: Some(
                "fff3f4fffffffffff4f5fffffffffff5f6fffffffffff6f7fffffffffeebedffffffffffedefffffffffffeff1fffffffffff1f3ffffffff",
            ),
        },
        WideKat {
            limbs: [-256, -256, -256, -256, -256, -256, -256, -256],
            carry: [
                72057594037927679, 72057594037927679, 72057594037927679, 72057594037927679,
                72057594037927678, 72057594037927679, 72057594037927679, 72057594037927679,
            ],
            canonical: Some(
                "fffefffffffffffffefffffffffffffefffffffffffffefffffffffffefefffffffffffffefffffffffffffefffffffffffffeffffffffff",
            ),
            sqr: Some(
                "00000b0000000000000a000000000000090000000000000800000000000012000000000000100000000000000e0000000000000c00000000",
            ),
            mul: Some(
                "ffe7e9ffffffffffe9ebffffffffffebedffffffffffedeffffffffffed7dbffffffffffdbdfffffffffffdfe3ffffffffffe3e7ffffffff",
            ),
        },
        WideKat {
            limbs: [
                144115188075856384, 144115188075856384, 144115188075856384, 144115188075856384,
                144115188075856384, 144115188075856384, 144115188075856384, 144115188075856384,
            ],
            carry: [514, 514, 514, 514, 516, 514, 514, 514],
            canonical: Some(
                "0202000000000002020000000000020200000000000202000000000004020000000000020200000000000202000000000002020000000000",
            ),
            sqr: Some(
                "38602c00000000305828000000002c502400000000284820000000005ca04800000000509040000000004880380000000040703000000000",
            ),
            mul: Some(
                "c79fd3ffffffffcfa7d7ffffffffd3afdbffffffffd7b7dfffffffffa25fb7ffffffffaf6fbfffffffffb77fc7ffffffffbf8fcfffffffff",
            ),
        },
        WideKat {
            limbs: [
                -144115188075856384, -144115188075856384, -144115188075856384, -144115188075856384,
                -144115188075856384, -144115188075856384, -144115188075856384, -144115188075856384,
            ],
            carry: [
                72057594037927421, 72057594037927421, 72057594037927421, 72057594037927421,
                72057594037927418, 72057594037927421, 72057594037927421, 72057594037927421,
            ],
            canonical: Some(
                "fdfdfffffffffffdfdfffffffffffdfdfffffffffffdfdfffffffffffafdfffffffffffdfdfffffffffffdfdfffffffffffdfdffffffffff",
            ),
            sqr: Some(
                "38602c00000000305828000000002c502400000000284820000000005ca04800000000509040000000004880380000000040703000000000",
            ),
            mul: Some(
                "0202000000000002020000000000020200000000000202000000000004020000000000020200000000000202000000000002020000000000",
            ),
        },
        WideKat {
            limbs: [-1, 0, 0, 0, 0, 0, 0, 0],
            carry: [72057594037927935, -1, 0, 0, 0, 0, 0, 0],
            canonical: Some(
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            sqr: Some(
                "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            mul: Some(
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
        },
        WideKat {
            limbs: [0, 0, 0, 0, 0, 0, 0, 72057594037927936],
            carry: [1, 0, 0, 0, 1, 0, 0, 0],
            canonical: Some(
                "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            ),
            sqr: Some(
                "0200000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000",
            ),
            mul: Some(
                "fffffffffffffffffffffffffffffffffffffffffffefffffffffffffefffffffffffffffffffffffffffffffffffffffffdffffffffffff",
            ),
        },
        WideKat {
            limbs: [0, 0, 0, 0, 0, 0, 0, -1],
            carry: [-1, 0, 0, 0, -1, 0, 0, 72057594037927935],
            canonical: Some(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffeffffffffffff",
            ),
            sqr: Some(
                "0000000000000000000000000000010000000000000000000000000000000000000000000000000000000200000000000000000000000000",
            ),
            mul: Some(
                "0000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000001000000000000",
            ),
        },
        WideKat {
            limbs: [0, 0, 0, 0, -1, 0, 0, 0],
            carry: [0, 0, 0, 0, 72057594037927935, -1, 0, 0],
            canonical: Some(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffdffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            sqr: Some(
                "0100000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000",
            ),
            mul: Some(
                "0000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000",
            ),
        },
        WideKat {
            limbs: [
                72057594037927932, 72057594037927935, 72057594037927935, 72057594037927935,
                72057594037927934, 72057594037927935, -1, 72057594037927936,
            ],
            carry: [
                72057594037927933, 72057594037927935, 72057594037927935, 72057594037927935,
                72057594037927935, 72057594037927935, 72057594037927935, -1,
            ],
            canonical: Some(
                "fcfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            ),
            sqr: Some(
                "0900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            ),
            mul: Some(
                "f3ffffffffffff0e000000000000e2ffffffffffff0b00000000000005000000000000f1ffffffffffff05000000000080feffffffffffff",
            ),
        },
        WideKat {
            limbs: [
                144115188075855877, -72057594037927943, 72057594037927947, -5, 144115188075855871,
                -144115188075855869, 36028797018963968, -72057594037927936,
            ],
            carry: [
                4, 72057594037927931, 9, 72057594037927932, 72057594037927933, 4,
                36028797018963966, 0,
            ],
            canonical: Some(
                "04000000000000fbffffffffffff09000000000000fcfffffffffffffdffffffffffff04000000000000feffffffffff7f00000000000000",
            ),
            sqr: Some(
                "c8ffffffffffffdbffffffffff3f8600000000000066ffffffffffff3c000000000000eeffffffffff7fc3ffffffffffff75000000000000",
            ),
            mul: None,
        },
        WideKat {
            limbs: [
                2305843009213693957, -2305843009213693943, 1152921504606846975,
                -1152921504606846976, 2305843009213693875, -576460752303423491,
                2305843009213693953, -2305843009213681607,
            ],
            carry: [
                -27, 41, 72057594037927903, 15, 72057594037927811, 72057594037927964, -8, 12377,
            ],
            canonical: None,
            sqr: None,
            mul: None,
        },
    ];

    fn bytes56(hex: &str) -> [u8; 56] {
        bouncycastle_core::hex::decode(hex).unwrap().try_into().unwrap()
    }

    /// The canonical encoding of a value.
    fn canonical(x: &FieldElement448) -> [u8; 56] {
        let mut bytes = [0xFF_u8; 56];
        x.normalize().encode_448(&mut bytes);
        bytes
    }

    fn kat_inputs() -> [FieldElement448; FIELD_KATS.len()] {
        core::array::from_fn(|i| FieldElement448::decode_448(&bytes56(FIELD_KATS[i].a)))
    }

    #[test]
    fn field_operations_match_the_known_answers() {
        let inputs = kat_inputs();
        for (i, kat) in FIELD_KATS.iter().enumerate() {
            let (a, b) = (&inputs[i], &inputs[(i + 1) % inputs.len()]);
            assert_eq!(canonical(a), bytes56(kat.canonical), "canonical {i}");
            assert_eq!(canonical(&a.mul(b)), bytes56(kat.mul), "mul {i}");
            assert_eq!(canonical(&a.sqr()), bytes56(kat.sqr), "sqr {i}");
            assert_eq!(canonical(&a.mul_u32(39_082)), bytes56(kat.mul_u32), "mul_u32 {i}");
            assert_eq!(canonical(&a.add(b)), bytes56(kat.add), "add {i}");
            assert_eq!(canonical(&a.sub(b)), bytes56(kat.sub), "sub {i}");
            let (sum, difference) = a.sum_and_difference(b);
            assert_eq!(canonical(&sum), bytes56(kat.add), "sum {i}");
            assert_eq!(canonical(&difference), bytes56(kat.sub), "difference {i}");
            assert_eq!(canonical(&a.negate()), bytes56(kat.negate), "negate {i}");
            assert_eq!(canonical(&a.inv()), bytes56(kat.inv), "inv {i}");
            // Either root is a correct answer; the known one fixes which this code returns.
            let root = FieldElement448::sqrt_ratio_var(a, b);
            assert_eq!(root.as_ref().map(canonical), kat.sqrt_ratio.map(bytes56), "sqrt {i}");

            let (a_n, b_n) = (a.normalize(), b.normalize());
            assert_eq!(a_n.is_zero().to_bool(), kat.is_zero, "is_zero {i}");
            assert_eq!(a_n.is_zero_var(), kat.is_zero, "is_zero_var {i}");
            assert_eq!(a_n.parity(), kat.parity, "parity {i}");
            let equal = NormalizedFieldElement448::are_equal_var(&a_n, &b_n);
            assert_eq!(equal, kat.equals_b, "are_equal_var {i}");
        }
    }

    #[test]
    fn wide_representations_match_the_known_answers() {
        for (i, kat) in WIDE_KATS.iter().enumerate() {
            let a = FieldElement448::new(kat.limbs);
            let b = FieldElement448::new(WIDE_KATS[(i + 1) % WIDE_KATS.len()].limbs);
            assert_eq!(a.carry().0, kat.carry, "carry {i}");
            if let Some(expected) = kat.canonical {
                assert_eq!(canonical(&a), bytes56(expected), "canonical {i}");
                // The carry pass changes the representation, not the value.
                assert_eq!(canonical(&a.carry()), bytes56(expected), "carry value {i}");
            }
            if let Some(sqr) = kat.sqr {
                assert_eq!(canonical(&a.sqr()), bytes56(sqr), "sqr {i}");
            }
            if let Some(mul) = kat.mul {
                assert_eq!(canonical(&a.mul(&b)), bytes56(mul), "mul {i}");
            }
        }
    }

    /// `new` is usable in a constant and keeps the limbs as given.
    #[test]
    fn new_keeps_the_limbs() {
        const KNOWN: FieldElement448 = FieldElement448::new(KNOWN_LIMBS);
        assert_eq!(KNOWN.0, KNOWN_LIMBS);
    }

    /// `zeroize` clears every limb.
    #[test]
    fn zeroize_clears_the_limbs() {
        let mut x = FieldElement448(KNOWN_LIMBS);
        x.zeroize();
        assert_eq!(x.0, [0; 8]);
    }

    /// `-(-x) = x` limb for limb, `x + (-x) = 0`, and `x * inv(x) = 1` unless `x` is zero, when
    /// the inverse is zero too.
    #[test]
    fn negate_and_inv_are_the_inverses() {
        for (i, x) in kat_inputs().iter().enumerate() {
            assert_eq!(x.negate().negate().0, x.0, "{i}");
            assert_eq!(x.add(&x.negate()).normalize().0.0, [0; 8], "{i}");
            let expected = if x.normalize().is_zero_var() { [0; 8] } else { small(1) };
            assert_eq!(x.mul(&x.inv()).normalize().0.0, expected, "{i}");
        }
    }

    /// Normalizing a normalized value changes nothing.
    #[test]
    fn normalize_is_idempotent() {
        for (i, x) in kat_inputs().iter().enumerate() {
            let n = x.normalize();
            assert_eq!(n.normalize().0.0, n.0.0, "{i}");
        }
    }

    /// A normalized value dereferences to its own limbs, and arithmetic goes on from there.
    #[test]
    fn a_normalized_value_dereferences_to_the_field_element() {
        let x = FieldElement448(KNOWN_LIMBS);
        let n = x.normalize();
        let as_field: &FieldElement448 = &n;
        assert_eq!(as_field.0, KNOWN_LIMBS);
        assert_eq!(n.sqr().normalize().0.0, x.sqr().normalize().0.0);
    }

    /// `cmov` copies every limb when told to and none when not.
    #[test]
    fn cmov_moves_on_the_condition_only() {
        let source = FieldElement448([11, 12, 13, 14, 15, 16, 17, 18]);
        let mut a = FieldElement448(KNOWN_LIMBS);
        a.cmov(Condition::<i64>::from_bool_const::<false>(), &source);
        assert_eq!(a.0, KNOWN_LIMBS);
        a.cmov(Condition::<i64>::from_bool_const::<true>(), &source);
        assert_eq!(a.0, [11, 12, 13, 14, 15, 16, 17, 18]);
    }

    /// `cnegate` negates every limb when told to and none when not.
    #[test]
    fn cnegate_negates_on_the_condition_only() {
        let mut a = FieldElement448([11, -12, 13, -14, 15, -16, 17, -18]);
        a.cnegate(Condition::<i64>::from_bool_const::<false>());
        assert_eq!(a.0, [11, -12, 13, -14, 15, -16, 17, -18]);
        a.cnegate(Condition::<i64>::from_bool_const::<true>());
        assert_eq!(a.0, [-11, 12, -13, 14, -15, 16, -17, 18]);
        // And as a field operation it agrees with negate.
        let mut x = FieldElement448(KNOWN_LIMBS);
        x.cnegate(Condition::<i64>::from_bool_const::<true>());
        assert_eq!(x.0, FieldElement448(KNOWN_LIMBS).negate().0);
    }

    /// The zero test, the equality test and the parity each look at every limb they should: a
    /// value that is non-zero in one limb only, and one that is non-zero in two.
    #[test]
    fn zero_equality_and_parity_tests_see_every_limb() {
        let zero = n([0; 8]);
        assert!(zero.is_zero().to_bool());
        assert!(zero.is_zero_var());
        assert!(NormalizedFieldElement448::are_equal_var(&zero, &n([0; 8])));
        for limb in 0..8 {
            let mut limbs = [0; 8];
            limbs[limb] = 7;
            assert!(!n(limbs).is_zero().to_bool(), "limb {limb}");
            assert!(!n(limbs).is_zero_var(), "limb {limb}");
            assert!(!NormalizedFieldElement448::are_equal_var(&zero, &n(limbs)), "limb {limb}");
            assert!(NormalizedFieldElement448::are_equal_var(&n(limbs), &n(limbs)));
            for other in 0..limb {
                limbs[other] = 7;
                assert!(!n(limbs).is_zero().to_bool(), "limbs {other} and {limb}");
                assert!(!n(limbs).is_zero_var(), "limbs {other} and {limb}");
                limbs[other] = 0;
            }
        }
        assert_eq!(n([2, 1, 1, 1, 1, 1, 1, 1]).parity(), 0);
        assert_eq!(n(small(3)).parity(), 1);
        // p - 1 is even.
        assert_eq!(n([M56 - 1, M56, M56, M56, M56 - 1, M56, M56, M56]).parity(), 0);
    }

    /// Over every ordered pair of the known-answer inputs: a reported root satisfies
    /// `v * x^2 = u`, and a root is reported exactly when Euler's criterion says `u / v` is a
    /// square. `u / v` is a square iff `u * v` is (they differ by `v^2`), and
    /// `(u * v)^((p-1)/2)` is 0 or 1 for a square and -1 otherwise;
    /// `(p - 1) / 2 = 2^447 - 2^223 - 1` is 447 ones with bit 223 clear.
    #[test]
    fn sqrt_ratio_var_agrees_with_eulers_criterion() {
        let inputs = kat_inputs();
        let minus_one = canonical(&FieldElement448::one().negate());
        let (mut roots, mut non_squares) = (0, 0);
        for u in &inputs {
            for v in &inputs {
                let root = FieldElement448::sqrt_ratio_var(u, v);
                if let Some(x) = &root {
                    assert_eq!(canonical(&x.sqr().mul(v)), canonical(u));
                    roots += 1;
                }
                let has_root = if v.normalize().is_zero_var() {
                    u.normalize().is_zero_var()
                } else {
                    let euler = canonical(&pow_bits(&u.mul(v), 447, |bit| bit != 223));
                    non_squares += usize::from(euler == minus_one);
                    euler != minus_one
                };
                assert_eq!(root.is_some(), has_root);
            }
        }
        // Both outcomes occur, many times over.
        assert!(roots > 100 && non_squares > 100, "{roots} roots, {non_squares} non-squares");
    }

    /// -1 is not a square, since p == 3 mod 4: the step RFC 8032 Section 5.2.3 has no second
    /// candidate for.
    #[test]
    fn minus_one_has_no_square_root() {
        let one = FieldElement448::one();
        assert!(FieldElement448::sqrt_ratio_var(&one.negate(), &one).is_none());
        let two = FieldElement448(small(2)).sqr();
        let root = FieldElement448::sqrt_ratio_var(&two, &one).unwrap();
        assert_eq!(canonical(&root.sqr()), canonical(&two));
    }
}
