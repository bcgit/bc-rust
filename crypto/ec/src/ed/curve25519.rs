use bouncycastle_utils::ct::Condition;

/// Mask for one limb: `2^51 - 1`. A [`FieldElement25519`] holds the value
/// `x0 + x1*2^51 + x2*2^102 + x3*2^153 + x4*2^204`, so `& M51` extracts a limb's own 51 bits and
/// leaves the overflow to be carried into the next limb (or, out of `x4`, folded back into `x0`
/// scaled by 19, since `2^255 == 19 mod p`).
const M51: i64 = (1 << 51) - 1;

/// An element of GF(p), p = 2^255 - 19: the field that curve25519's point coordinates live in.
///
/// This is the base field, as opposed to the scalar field of integers mod the group order that
/// private keys live in. Every curve25519 coordinate here is one of these: the u-coordinate of
/// X25519 (RFC7748), and the x and y coordinates of Ed25519 (RFC8032).
///
/// # Representation
/// Five signed 64-bit limbs in radix 2^51, holding the value
/// `x0 + x1*2^51 + x2*2^102 + x3*2^153 + x4*2^204` (see [`M51`]). Arithmetic is lazily reduced:
/// limbs may exceed 51 bits or go negative between operations, so the same residue mod p has many
/// representations. [`Self::normalize`] produces the canonical representation as a
/// [`NormalizedFieldElement25519`], the only type that encodes, compares and tests parity.
///
/// # Mathematical operations implemented
/// Addition and subtraction (lazily reduced), multiplication, squaring and multiplication by a
/// small constant, inversion, a constant-time swap, decoding from 32 bytes and, through
/// [`Self::normalize`], the canonical form that encodes; for Ed25519, negation, a carry pass, a
/// constant-time move and negation, and the square root of a ratio. Everything is constant time
/// except what is named `_var`, which takes public input only. The limbs
/// are wiped with volatile stores when a value is dropped, so every intermediate of the ladder
/// and the inversion is cleared at the end of its lifetime (QUALITY_AND_STYLE.md's rule for a
/// local computed from a secret); what the compiler kept in registers or spilled itself is not
/// reached.
///
/// # Math Background
/// The group law on elliptic curve points is point addition, where A + B yields a new point C on
/// the curve. The special case of adding a point to itself, A + A, is called "point doubling" and
/// is often implemented separately because it can be done more efficiently than the general case.
/// Repeated addition, A + A + ... + A, is written k * A for a scalar k and called "scalar
/// multiplication", again implemented separately. All three are built out of the field operations
/// on this type.
///
/// X25519 represents a point in Montgomery form by its u-coordinate alone, which identifies a
/// point on the curve or its quadratic twist up to sign; ie it names the pair {P, -P}. Point
/// doubling and scalar multiplication are well-defined on u-coordinates, since they commute with
/// negation (k*(-A) = -(k*A)), but general point addition is not. XDH (RFC7748) only needs scalar
/// multiplication, which the Montgomery ladder in [`crate::ed::x25519`] computes. Ed25519 uses the full
/// (x, y) coordinates on the equivalent twisted Edwards curve, where general addition is defined.
#[derive(Clone, Default)]
#[must_use] // to help catch bugs that x.sqr() actually returns a result rather than mutates x, so not using the return is a bug.
pub(in crate::ed) struct FieldElement25519([i64; 5]);

impl FieldElement25519 {
    /// Wipes the limbs with volatile stores (`zeroize_in_place`); [`Drop`] calls it, so an
    /// explicit call is only for a value that must be cleared before it goes out of scope.
    pub(in crate::ed) fn zeroize(&mut self) {
        bouncycastle_utils::secret::zeroize_in_place(&mut self.0);
    }
}

impl Drop for FieldElement25519 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl FieldElement25519 {
    /// Add another [`FieldElement25519`] to this one, component-wise.
    ///
    /// Lazily reduced: no carry propagation, so limb magnitudes grow by up to one bit and the result
    /// is congruent mod p but not normalized. That is deliberate -- every consumer here funnels into
    /// a [`Self::mul`], [`Self::sqr`] or [`Self::mul_u32`], each of which reduces through
    /// [`Self::reduce_products`], so magnitudes never run away and an explicit carry pass is not
    /// needed.
    pub(in crate::ed) fn add(&self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        Self([x0 + y0, x1 + y1, x2 + y2, x3 + y3, x4 + y4])
    }

    /// Returns `(self + rhs, self - rhs)` in one pass over the limbs.
    ///
    /// Each half is the plain limb-wise [`Self::add`] / [`Self::sub`], with the same lazy-reduction
    /// caveat: no carry propagation, so limbs may go negative and both results are congruent mod p
    /// but not normalized. Fusing them avoids reading the limbs twice, and matches the fact that
    /// the ladder always wants the sum and the difference of the same pair.
    ///
    /// This is Section 5 of RFC7748's `A = x_2 + z_2` / `B = x_2 - z_2` pair, and equally its
    /// `C = x_3 + z_3` / `D = x_3 - z_3`. It is the workhorse of the ladder in [`crate::ed::x25519`].
    ///
    /// Note on the name: RFC7748 does not name this operation -- it writes the two assignments out
    /// separately, so there is no spec name to match.
    pub(in crate::ed) fn sum_and_difference(&self, rhs: &Self) -> (Self, Self) {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        (
            Self([x0 + y0, x1 + y1, x2 + y2, x3 + y3, x4 + y4]),
            Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4]),
        )
    }

    /// Conditionally Swap the values of lhs and rhs if `cond` is true.
    ///
    /// Constant time: both limb arrays are rewritten unconditionally with a masked exchange, so
    /// nothing about `cond` -- and hence nothing about the scalar bit driving it -- leaks through
    /// memory access patterns or timing.
    pub(in crate::ed) fn cswap(cond: Condition<i64>, lhs: &mut Self, rhs: &mut Self) {
        (lhs.0[0], rhs.0[0]) = cond.swap(lhs.0[0], rhs.0[0]);
        (lhs.0[1], rhs.0[1]) = cond.swap(lhs.0[1], rhs.0[1]);
        (lhs.0[2], rhs.0[2]) = cond.swap(lhs.0[2], rhs.0[2]);
        (lhs.0[3], rhs.0[3]) = cond.swap(lhs.0[3], rhs.0[3]);
        (lhs.0[4], rhs.0[4]) = cond.swap(lhs.0[4], rhs.0[4]);
    }

    /// Decodes 32 little-endian bytes as a field element, ignoring bit 255 (the most significant
    /// bit of the final byte); the inverse of [`NormalizedFieldElement25519::encode_255`].
    ///
    /// This is the RFC-neutral byte layout shared by both protocols. Callers own the meaning of
    /// bit 255 and the policy on non-canonical input: X25519 ignores the bit and accepts values
    /// `>= p` (`decode_u_coordinate` in `x25519.rs`, RFC7748 Section 5), while Ed25519 reads the bit
    /// as the sign of x and rejects a y-coordinate `>= p` (RFC8032 Section 5.1.3).
    ///
    /// Note: Result is NOT normalized -- the value is in `[0, 2^255)`, so the 19 encodings of
    /// `2^255 - 19 .. 2^255 - 1` decode to values `>= p`. Call [`Self::normalize`] before comparing
    /// or encoding.
    ///
    /// Input: 32 bytes, read as a little-endian integer.
    /// Output: The low 255 bits of that integer as a [`FieldElement25519`].
    pub(in crate::ed) fn decode_255(bytes: &[u8; 32]) -> Self {
        /// Unpacks a 256-bit little-endian integer held as four 64-bit words into the five 51-bit limbs
        /// of a [`FieldElement25519`], where the represented value is
        /// `z0 + z1*2^51 + z2*2^102 + z3*2^153 + z4*2^204`. Each limb is a 51-bit window of the input,
        /// straddling word boundaries; the `& M51` masks make every limb non-negative and leave headroom
        /// for lazily-carried arithmetic. Bit 255 of the input is dropped -- see [`Self::decode_255`].
        /// Inverse of [`NormalizedFieldElement25519::encode64_255`].
        /// Input: A 256-bit integer as four little-endian 64-bit words, least significant word first.
        /// Output: Bits 0..254 of that integer as a [`FieldElement25519`].
        ///
        /// Note: Result is NOT normalized.
        fn decode64_255(x: &[u64; 4]) -> FieldElement25519 {
            let [x0, x1, x2, x3] = *x;
            let z0 = x0 as i64 & M51;
            let z1 = (x0 >> 51 | x1 << 13) as i64 & M51;
            let z2 = (x1 >> 38 | x2 << 26) as i64 & M51;
            let z3 = (x2 >> 25 | x3 << 39) as i64 & M51;
            let z4 = (x3 >> 12) as i64 & M51;
            FieldElement25519([z0, z1, z2, z3, z4])
        }

        let b = bytes;
        let x0 = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let x1 = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
        let x2 = u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]);
        let x3 = u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]);
        decode64_255(&[x0, x1, x2, x3])
    }

    /// Multiplicative inverse in GF(p), by Fermat's little theorem: `x^(p-2) == x^-1`.
    ///
    /// [`Self::pow_p_sub5_div8`] writes `x^3` and `x^((p-5)/8)` into this frame's two buffers.
    /// Raising the second to the 8th and multiplying by the first gives exponent
    /// `8 * (2^252 - 3) + 3 == 2^255 - 21 == p - 2`. Costs 254 squarings and 12 multiplies. The
    /// two buffers, which together give `x^-1`, are wiped when this frame drops them.
    ///
    /// Constant time: a fixed addition chain, with no data-dependent branch or index.
    ///
    /// `inv(0) == 0`, since `0^(p-2) == 0`. That is not a case to guard against -- X25519 depends
    /// on it. A small-order input point drives the ladder's `z_2` to zero, and Section 6.1 of
    /// RFC7748 requires the resulting all-zero output to be detectable: "the X25519 function
    /// produces that value if it operates on an input corresponding to a point with small order".
    /// Returning zero here is what carries that through the final `x_2 * z_2^-1`.
    ///
    /// `x * inv(x) = 1` is checked in the test module over the edge cases and patterned values.
    ///
    /// Scope: both x25519 and ed25519.
    // TODO -- a safegcd-style `mod_odd_inverse` would be asymptotically cheaper. Only worth
    //          revisiting if this shows up in a profile -- it is one call per scalar_mult_into.
    pub(in crate::ed) fn inv(&self) -> Self {
        let mut x_cubed = Self::zero();
        let mut t = Self::zero();
        self.pow_p_sub5_div8(&mut x_cubed, &mut t);
        t.sqr_n(3).mul(&x_cubed)
    }

    /// Multiply self by rhs in GF(p), `p = 2^255 - 19`.
    ///
    /// Schoolbook 5x5: output limb `k` collects every `x[i] * y[j]` with `i + j == k`, plus every
    /// pair with `i + j == k + 5`. The second set lands at weight `2^255` or above, and
    /// `2^255 == 19 mod p`, so those terms are pre-scaled by 19 -- that is what `t1..t4` are. The 25
    /// products accumulate in `i128` (a 51-bit by 56-bit product would overflow `i64`) and
    /// [`Self::reduce_products`] carries them back down to five `i64` limbs.
    pub(in crate::ed) fn mul(&self, rhs: &Self) -> Self {
        #[inline(always)]
        fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        let [t1, t2, t3, t4] = [y1 * 19, y2 * 19, y3 * 19, y4 * 19];

        Self::reduce_products(
            m(x0, y0) + m(x1, t4) + m(x2, t3) + m(x3, t2) + m(x4, t1),
            m(x0, y1) + m(x1, y0) + m(x2, t4) + m(x3, t3) + m(x4, t2),
            m(x0, y2) + m(x1, y1) + m(x2, y0) + m(x3, t4) + m(x4, t3),
            m(x0, y3) + m(x1, y2) + m(x2, y1) + m(x3, y0) + m(x4, t4),
            m(x0, y4) + m(x1, y3) + m(x2, y2) + m(x3, y1) + m(x4, y0),
        )
    }

    /// Multiply self by a small unsigned scalar in GF(p).
    ///
    /// A single-limb multiply, so unlike [`Self::mul`] there are no wrap-around terms to pre-scale by
    /// 19 -- each output limb takes exactly one product. The `19` fold still happens, but only for
    /// whatever carries out of the top limb inside [`Self::reduce_products`].
    ///
    /// Scope: X25519. This is the `a24 * E` of the Section 5 ladder, with
    /// `a24 = (486662 - 2) / 4 = 121665`; both callers here pass `121666`, the `(A + 2) / 4`
    /// form, see `C_A24` in `x25519.rs`.
    pub(in crate::ed) fn mul_u32(&self, rhs: u32) -> Self {
        #[inline(always)]
        fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        let [x0, x1, x2, x3, x4] = self.0;
        let y0 = rhs as i64;

        Self::reduce_products(m(x0, y0), m(x1, y0), m(x2, y0), m(x3, y0), m(x4, y0))
    }

    /// The canonical representation of the value: every limb in `[0, 2^51)` and the value in
    /// `[0, p)`, as a [`NormalizedFieldElement25519`]. Idempotent.
    ///
    /// Total on every input whose limbs lie in `[-2^53, 2^53]`, which covers everything the
    /// arithmetic here produces: [`Self::reduce_products`] leaves limb 0 in `[0, 2^51)` and the
    /// others in `(-2^9, 2^51 + 2^9)` for reduced operands (lazily reduced ones widen that
    /// slightly, still far inside the bound), [`Self::decode_255`] leaves all five in `[0, 2^51)`, and
    /// one lazy [`Self::add`] or [`Self::sub`] of two such values stays well inside the bound.
    ///
    /// Four carry passes of [`Self::reduce`]. With `V` the value and `x4 >> 51` the top limb's
    /// overflow `t5`, each pass computes `V - p * t5` with limbs 0 to 3 in `[0, 2^51)`:
    /// 1. `reduce(0)`: `t5` is in `[-4, 4]` and the carries in `[-5, 4]`, so limb 4 comes out in
    ///    `[-5, 2^51 + 4]`.
    /// 2. `reduce(0)` again: `t5` is now `-1`, `0` or `1`. A negative limb 4 means `V < 0`, and
    ///    adding `p` leaves limb 4 in `[2^51 - 6, 2^51 - 1]`; a limb 4 of `2^51` or `2^51 + 1`
    ///    loses one `p` and comes out in `[0, 2]`; otherwise nothing moves. So every limb is in
    ///    `[0, 2^51)` and `V` is in `[0, 2^255)`: canonical limbs, value possibly in `[p, 2^255)`.
    /// 3. `reduce(1)` adds `19`: `V + 19` is `2^255 + (V - p)` when `V >= p`, which leaves limb 4
    ///    at exactly `2^51` since `V - p < 19`, and stays below `2^255` with canonical limbs
    ///    otherwise.
    /// 4. `reduce(-1)`: when limb 4 is `2^51`, `t5 = 1 - 1 = 0` drops the `2^255` and the result
    ///    is `V - p`, in `[0, 19)`; otherwise `t5 = -1` takes the `19` back and the borrow it may
    ///    cause resolves inside the limbs, since the result `V` is at least `0`.
    ///
    /// Pass 3's `+19` is what implements Section 5 of RFC7748's "Implementations MUST accept
    /// non-canonical values and process them as if they had been reduced modulo the field
    /// prime. The non-canonical values are 2^255 - 19 through 2^255 - 1": `v >= p` if and only
    /// if `v + 19 >= 2^255`. The `normalize_edge_values` unit test pins `p - 1`, `p` and
    /// `2^255 - 1`.
    pub(in crate::ed) fn normalize(&self) -> NormalizedFieldElement25519 {
        NormalizedFieldElement25519(self.reduce(0).reduce(0).reduce(1).reduce(-1))
    }

    /// The multiplicative identity, 1, in canonical form.
    pub(in crate::ed) fn one() -> Self {
        Self([1, 0, 0, 0, 0])
    }

    /// Writes `x^3` to `x_cubed` and `x^((p-5)/8)` to `z`, for `x = self`, by a fixed addition
    /// chain. Both are the caller's buffers so that they are wiped in the caller's frame; the
    /// chain's intermediates are this frame's temporaries, wiped as they drop.
    ///
    /// `(p - 5) / 8 == 2^252 - 3` for `p = 2^255 - 19`, which in binary is 250 ones, a zero, then a
    /// one -- the `FFFF..FD` of the comment below. The chain reaches it in 10 steps by doubling runs
    /// of 1-bits. Both outputs are checked through the inversion test in the test module.
    ///
    /// Beware the naming: the locals count *consecutive 1-bits*, not exponents. `x_cubed` is `x^3`
    /// (`0b11`, two ones), `x3` is `x^7`, `x5` is `x^31`, and `x250` is `x^(2^250 - 1)`. It reads
    /// like an off-by-one bug and is not one.
    ///
    /// Inversion takes both, as `z.sqr_n(3).mul(&x_cubed)` -- exponent
    /// `8 * (2^252 - 3) + 3 == 2^255 - 21 == p - 2`, i.e. Fermat. The `p == 5 mod 8` square root
    /// Ed25519 will need takes `z` alone, as its candidate.
    fn pow_p_sub5_div8(&self, x_cubed: &mut Self, z: &mut Self) {
        // z = x^((p-5)/8) = x^FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
        // (250 1s) (1 0s) (1 1s)
        // Addition chain: [1] 2 3 5 10 15 25 50 75 125 [250]

        let x = self;
        *x_cubed = x.sqr().mul(x);
        let x3 = x_cubed.sqr().mul(x);
        let x5 = x3.sqr_n(2).mul(x_cubed);
        let x10 = x5.sqr_n(5).mul(&x5);
        let x15 = x10.sqr_n(5).mul(&x5);
        let x25 = x15.sqr_n(10).mul(&x10);
        let x50 = x25.sqr_n(25).mul(&x25);
        let x75 = x50.sqr_n(25).mul(&x25);
        let x125 = x75.sqr_n(50).mul(&x50);
        let x250 = x125.sqr_n(125).mul(&x125);

        *z = x250.sqr_n(2).mul(x);
    }

    /// One carry pass that additionally subtracts `(x4 >> 51)` multiples of p and adds `19 * y` at
    /// the bottom. Not a standalone reduction -- see the warning below.
    ///
    /// Bits at or above `2^255` (the `x4 >> 51` carry) are removed from the top and re-added at the
    /// bottom scaled by 19, which subtracts a multiple of `p = 2^255 - 19`. The `y` argument is added
    /// into that same fold, so it contributes `19 * y` at the bottom with *no* matching removal at
    /// the top. The verified identity is:
    ///
    /// ```text
    /// value(reduce(x, y)) == value(x) - (x4 >> 51) * p + 19 * y
    /// ```
    ///
    /// Warning: a single `reduce` is therefore **not** congruent to its input mod p unless `y == 0`.
    /// The `19 * y` is a deliberate offset that only cancels across the pair of calls in
    /// [`Self::normalize`], and this function exists to serve that pair -- it is not a general-purpose
    /// reduction.
    ///
    /// Requires limbs inside the magnitude bound the carry chain assumes: `t5 * 19 + x0` must not
    /// overflow `i64`.
    fn reduce(&self, y: i64) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;

        let t4 = x4 & M51;
        let t5 = (x4 >> 51) + y;

        let mut c = t5 * 19;

        c += x0;
        let z0 = c & M51;
        c >>= 51;
        c += x1;
        let z1 = c & M51;
        c >>= 51;
        c += x2;
        let z2 = c & M51;
        c >>= 51;
        c += x3;
        let z3 = c & M51;
        c >>= 51;
        c += t4;
        let z4 = c;

        Self([z0, z1, z2, z3, z4])
    }

    /// Carry the five `i128` product accumulators produced by [`Self::mul`], [`Self::sqr`] and
    /// [`Self::mul_u32`] back down into five `i64` limbs.
    ///
    /// One pass: `split` peels each accumulator into its own 51 bits and the carry above them, the
    /// carries move up one limb each, and the carry out of the top (`c5`, at weight `2^255`) folds
    /// into limb 0 scaled by 19 because `2^255 == 19 mod p`. A second short carry chain over
    /// `u0..u3` absorbs the fold.
    ///
    /// The result is congruent mod p with limbs near 51 bits, but is *not* normalized -- it may still
    /// exceed p. Call [`Self::normalize`] before encoding or comparing.
    fn reduce_products(p0: i128, p1: i128, p2: i128, p3: i128, p4: i128) -> Self {
        #[inline(always)]
        fn split(x: i128) -> (i64, i64) {
            (x as i64 & M51, (x >> 51) as i64)
        }

        let (t0, c1) = split(p0);
        let (t1, c2) = split(p1);
        let (t2, c3) = split(p2);
        let (t3, c4) = split(p3);
        let (t4, c5) = split(p4 + c4 as i128);

        let u0 = t0 + c5 * 19;
        let u1 = t1 + c1;
        let u2 = t2 + c2;
        let u3 = t3 + c3;

        Self([
            u0 & M51,
            (u1 & M51) + (u0 >> 51),
            (u2 & M51) + (u1 >> 51),
            (u3 & M51) + (u2 >> 51),
            t4 + (u3 >> 51),
        ])
    }

    /// Square self in GF(p).
    ///
    /// Same shape as [`Self::mul`], but a squaring's cross terms come in equal pairs, so pre-doubling
    /// `x0..x3` into `y0..y3` lets one product stand for two and drops the count from 25 to 15. The
    /// `19` fold for the `i + j >= 5` terms is folded into `t3`, `t4` as before.
    pub(in crate::ed) fn sqr(&self) -> Self {
        #[inline(always)]
        fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3] = [x0 * 2, x1 * 2, x2 * 2, x3 * 2];
        let [t3, t4] = [x3 * 19, x4 * 19];

        Self::reduce_products(
            m(x0, x0) + m(y1, t4) + m(y2, t3),
            m(y0, x1) + m(y2, t4) + m(x3, t3),
            m(y0, x2) + m(x1, x1) + m(y3, t4),
            m(y0, x3) + m(y1, x2) + m(x4, t4),
            m(y0, x4) + m(y1, x3) + m(x2, x2),
        )
    }

    /// Square self `n` times, i.e. raise to the `2^n`.
    pub(in crate::ed) fn sqr_n(&self, mut n: usize) -> Self {
        let mut z = Self(self.0);
        while n > 0 {
            z = z.sqr();
            n -= 1;
        }
        z
    }

    /// Subtract rhs from self, component-wise.
    ///
    /// Lazily reduced, exactly as [`Self::add`]: no borrow propagation, so limbs may go negative and
    /// the result is congruent mod p but not normalized. Negative limbs are fine here --
    /// [`Self::reduce_products`] and [`Self::reduce`] both use arithmetic (sign-propagating) shifts,
    /// so a negative limb borrows correctly on the next reduction.
    pub(in crate::ed) fn sub(&self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4])
    }

    /// The additive identity, 0, in canonical form.
    pub(in crate::ed) fn zero() -> Self {
        Self([0; 5])
    }
}

// The operations Ed25519 needs and X25519 does not.
impl FieldElement25519 {
    /// The element with the given limbs, least significant first; `const`, for curve constants.
    ///
    /// The limbs are taken as they are, so they must already be inside the bound of whatever
    /// consumes the value; a constant written with every limb in `[0, 2^51)` always is.
    pub(in crate::ed) const fn new(limbs: [i64; 5]) -> Self {
        Self(limbs)
    }

    /// One carry pass: the bits of each limb above the low 51 move into the next limb, and those
    /// of the top limb into limb 0 scaled by 19. The value mod p is unchanged; the result is not
    /// normalized.
    ///
    /// This brings limbs widened by a run of lazy [`Self::add`] / [`Self::sub`] back near 51
    /// bits ahead of a [`Self::mul`] or [`Self::sqr`]. For input limbs of magnitude below `2^57`
    /// each carry is in `[-64, 64)`, so limb 0 comes out in `(-2^11, 2^51 + 2^11)` and the
    /// others in `[-64, 2^51 + 64)`. Constant time.
    pub(in crate::ed) fn carry(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        Self([
            (x0 & M51) + (x4 >> 51) * 19,
            (x1 & M51) + (x0 >> 51),
            (x2 & M51) + (x1 >> 51),
            (x3 & M51) + (x2 >> 51),
            (x4 & M51) + (x3 >> 51),
        ])
    }

    /// Sets `self` to `x` if `cond` is true and leaves it unchanged otherwise.
    ///
    /// Constant time, as [`Self::cswap`]: every limb is rewritten through a masked select
    /// whichever way `cond` goes. This is the step of a table lookup that passes over every
    /// entry.
    pub(in crate::ed) fn cmov(&mut self, cond: Condition<i64>, x: &Self) {
        cond.mov(x.0[0], &mut self.0[0]);
        cond.mov(x.0[1], &mut self.0[1]);
        cond.mov(x.0[2], &mut self.0[2]);
        cond.mov(x.0[3], &mut self.0[3]);
        cond.mov(x.0[4], &mut self.0[4]);
    }

    /// Replaces `self` with its negation ([`Self::negate`]) if `cond` is true and leaves it
    /// unchanged otherwise. Constant time: every limb goes through a masked negation whichever
    /// way `cond` goes.
    pub(in crate::ed) fn cnegate(&mut self, cond: Condition<i64>) {
        self.0[0] = cond.negate(self.0[0]);
        self.0[1] = cond.negate(self.0[1]);
        self.0[2] = cond.negate(self.0[2]);
        self.0[3] = cond.negate(self.0[3]);
        self.0[4] = cond.negate(self.0[4]);
    }

    /// The additive inverse, limb by limb. Lazily reduced like [`Self::sub`]: limb magnitudes
    /// are unchanged and the result is congruent to `-self` mod p but not normalized. Constant
    /// time.
    pub(in crate::ed) fn negate(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        Self([-x0, -x1, -x2, -x3, -x4])
    }

    /// A square root of `u / v`, or `None` when `u / v` is not a square: the x-coordinate
    /// recovery of RFC 8032 Section 5.1.3, steps 2 and 3. The result is not normalized and
    /// either root may come back, so the caller chooses between `x` and `-x` (step 4).
    ///
    /// `u` and `v` may be lazily reduced, up to one [`Self::add`] or [`Self::sub`] of reduced
    /// values. The RFC's `v` is never zero; for `v == 0` this returns `Some(0)` when `u` is zero
    /// too and `None` otherwise.
    ///
    /// Variable time: which of the three outcomes occurs is branched on, so `u` and `v` must be
    /// public, as the coordinates of a point being decoded are.
    pub(in crate::ed) fn sqrt_ratio_var(u: &Self, v: &Self) -> Option<Self> {
        /// `2^((p-1)/4)`, a square root of -1 (RFC 8032 Section 5.1.3, step 3.2), in canonical
        /// limbs. The `sqrt_m1_is_two_to_the_p_minus_1_over_4` unit test recomputes it.
        const SQRT_M1: FieldElement25519 = FieldElement25519::new([
            0x61B274A0EA0B0, 0x0D5A5FC8F189D, 0x7EF5E9CBD0C60, 0x78595A6804C9E, 0x2B8324804FC1D,
        ]);

        // Step 2: the candidate root x = (u/v)^((p+3)/8) = u v^3 (u v^7)^((p-5)/8), "using a
        // single modular powering for both the inversion of v and the square root".
        let uv = u.mul(v);
        let v2 = v.sqr();
        let uv3 = v2.mul(&uv);
        let uv7 = v2.sqr().mul(&uv3);
        let mut uv7_cubed = Self::zero(); // the chain's other output, not needed here
        let mut w = Self::zero();
        uv7.pow_p_sub5_div8(&mut uv7_cubed, &mut w);
        let x = w.mul(&uv3);

        let vx2 = x.sqr().mul(v);
        // Step 3.1: "If v x^2 = u (mod p), x is a square root."
        if vx2.sub(u).normalize().is_zero_var() {
            return Some(x);
        }
        // Step 3.2: "If v x^2 = -u (mod p), set x <-- x * 2^((p-1)/4), which is a square root."
        if vx2.add(u).normalize().is_zero_var() {
            return Some(x.mul(&SQRT_M1));
        }
        // Step 3.3: "Otherwise, no square root exists for modulo p".
        None
    }
}

/// A [`FieldElement25519`] in canonical form: every limb in `[0, 2^51)` and the value in `[0, p)`.
/// The only constructor is [`FieldElement25519::normalize`].
///
/// It dereferences to [`FieldElement25519`], so arithmetic continues on a normalized value (the
/// x-coordinate of a decoded Ed25519 point, a table entry) without a conversion; the result of
/// any such operation is a [`FieldElement25519`] again.
#[derive(Clone)]
#[must_use]
pub(in crate::ed) struct NormalizedFieldElement25519(FieldElement25519);

impl core::ops::Deref for NormalizedFieldElement25519 {
    type Target = FieldElement25519;

    fn deref(&self) -> &FieldElement25519 {
        &self.0
    }
}

impl NormalizedFieldElement25519 {
    /// Debug-only check of the invariant this type carries: every limb in `[0, 2^51)` and the
    /// value below p. Every method calls it first; it compiles to nothing in release builds.
    ///
    /// p's limbs are `[2^51 - 19, 2^51 - 1, 2^51 - 1, 2^51 - 1, 2^51 - 1]`, so a value with every
    /// limb in range is `>= p` exactly when limbs 1..4 are all `2^51 - 1` and limb 0 is at least
    /// `2^51 - 19`.
    ///
    /// Branches on the limbs, so it is not constant time. That is acceptable only because it is
    /// compiled out of release builds.
    fn debug_check_range(&self) {
        let [x0, x1, x2, x3, x4] = self.0.0;
        debug_assert!((0..=M51).contains(&x0), "limb 0 out of [0, 2^51)");
        debug_assert!((0..=M51).contains(&x1), "limb 1 out of [0, 2^51)");
        debug_assert!((0..=M51).contains(&x2), "limb 2 out of [0, 2^51)");
        debug_assert!((0..=M51).contains(&x3), "limb 3 out of [0, 2^51)");
        debug_assert!((0..=M51).contains(&x4), "limb 4 out of [0, 2^51)");
        debug_assert!(
            !(x1 == M51 && x2 == M51 && x3 == M51 && x4 == M51 && x0 >= M51 - 18),
            "value >= p"
        );
    }

    /// Encodes the field element as a 255-bit value in 32 little-endian bytes; the inverse of
    /// [`FieldElement25519::decode_255`]. Bit 255 (the most significant bit of the last byte) is
    /// always written as zero.
    ///
    /// Callers that need that bit to carry something else -- the
    /// sign of x in an Ed25519 point encoding (Section 5.1.3 of RFC 8032) -- must OR it in after.
    ///
    /// Input: self; a 32-byte output buffer.
    /// Output: The value written to `bytes` as a 255-bit little-endian integer.
    pub(in crate::ed) fn encode_255(&self, bytes: &mut [u8; 32]) {
        self.debug_check_range();
        let [w0, w1, w2, w3] = self.encode64_255();
        let (a, b, c, d) = (w0.to_le_bytes(), w1.to_le_bytes(), w2.to_le_bytes(), w3.to_le_bytes());
        // Each word fills a fixed 8-byte window, least significant word first. Every index is a
        // constant into a fixed-size array, so an out-of-bounds index would be a compile error (the
        // deny-by-default `unconditional_panic` lint) and no runtime bounds check survives.
        *bytes = [
            a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], //
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], //
            c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], //
            d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
        ];
    }

    /// Packs the five 51-bit limbs into a 255-bit little-endian integer held as four 64-bit words,
    /// each word taking a whole limb plus the low bits of the next. Inverse of the `decode64_255`
    /// step inside [`FieldElement25519::decode_255`]. Bit 255 of the result is always zero, since
    /// limb `x4` lands in bits 204..254.
    ///
    /// Relies on the normalized form: every limb in [0, 2^51) and the value reduced mod p. The
    /// splices below are `|`, not `+`, so a limb with bits at or above 51 collides with the next
    /// limb's bits instead of carrying into them, and the result is garbage. (The `x1 << 51` etc.
    /// deliberately shift bits off the top of the i64 -- those are the bits the previous word
    /// already carried.)
    ///
    /// Input: self.
    /// Output: The value as four little-endian 64-bit words, least significant word first.
    fn encode64_255(&self) -> [u64; 4] {
        self.debug_check_range();
        let [x0, x1, x2, x3, x4] = self.0.0;
        let z0 = (x0 | x1 << 51) as u64;
        let z1 = (x1 >> 13 | x2 << 38) as u64;
        let z2 = (x2 >> 26 | x3 << 25) as u64;
        let z3 = (x3 >> 39 | x4 << 12) as u64;
        [z0, z1, z2, z3]
    }
}

// The tests Ed25519 needs on a canonical value.
impl NormalizedFieldElement25519 {
    /// Whether two values are equal. Variable time: both must be public.
    pub(in crate::ed) fn are_equal_var(lhs: &Self, rhs: &Self) -> bool {
        lhs.debug_check_range();
        rhs.debug_check_range();
        lhs.0.0 == rhs.0.0
    }

    /// TRUE iff the value is zero, as a mask. Constant time.
    pub(in crate::ed) fn is_zero(&self) -> Condition<i64> {
        self.debug_check_range();
        let [x0, x1, x2, x3, x4] = self.0.0;
        Condition::<i64>::is_zero(x0 | x1 | x2 | x3 | x4)
    }

    /// Whether the value is zero. Variable time: the value must be public.
    pub(in crate::ed) fn is_zero_var(&self) -> bool {
        self.debug_check_range();
        self.0.0 == [0; 5]
    }

    /// The least significant bit of the value, which is what an Ed25519 point encoding keeps of
    /// the x-coordinate (RFC 8032 Section 5.1.2). Constant time.
    pub(in crate::ed) fn parity(&self) -> u8 {
        self.debug_check_range();
        (self.0.0[0] & 1) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Alice's public key from the X25519 test vector in Section 6.1 of RFC 7748, used here purely
    /// as a fixed value for the byte <-> limb codec. It is less than p (its top byte is 0x6A), so
    /// its encoding is canonical and it needs no normalization to round-trip exactly.
    const KNOWN_VALUE: [u8; 32] = [
        0x85, 0x20, 0xF0, 0x09, 0x89, 0x30, 0xA7, 0x54, //
        0x74, 0x8B, 0x7D, 0xDC, 0xB4, 0x3E, 0xF7, 0x5A, //
        0x0D, 0xBF, 0x3A, 0x0D, 0x26, 0x38, 0x1A, 0xF4, //
        0xEB, 0xA4, 0xA9, 0x8E, 0xAA, 0x9B, 0x4E, 0x6A,
    ];

    /// The same value as five 51-bit limbs: `KNOWN_LIMBS[i] == (v >> (51 * i)) & (2^51 - 1)`, where
    /// v is `KNOWN_VALUE` read as a little-endian integer. Computed independently of this crate.
    const KNOWN_LIMBS: [i64; 5] =
        [0x7308909F02085, 0x69B8FB16E8A94, 0x4EAFC356BDCFA, 0x275FA0D1C1306, 0x6A4E9BAA8EA9A];

    #[test]
    fn decode_255_known_value() {
        assert_eq!(FieldElement25519::decode_255(&KNOWN_VALUE).0, KNOWN_LIMBS);

        // Bit 255 is not part of the field element, so setting it must not change the result.
        let mut bit_255_set = KNOWN_VALUE;
        bit_255_set[31] |= 0x80;
        assert_eq!(FieldElement25519::decode_255(&bit_255_set).0, KNOWN_LIMBS);
    }

    /// p - 1 = 2^255 - 20, the largest canonical value, passes the range check.
    #[test]
    fn debug_check_range_accepts_p_minus_1() {
        NormalizedFieldElement25519(FieldElement25519([M51 - 19, M51, M51, M51, M51]))
            .debug_check_range();
    }

    /// p itself is not canonical; the range check must reject it.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "value >= p")]
    fn debug_check_range_rejects_p() {
        NormalizedFieldElement25519(FieldElement25519([M51 - 18, M51, M51, M51, M51]))
            .debug_check_range();
    }

    /// A limb at 2^51 is out of range even though the value is below p.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "limb 0 out of [0, 2^51)")]
    fn debug_check_range_rejects_wide_limb() {
        NormalizedFieldElement25519(FieldElement25519([M51 + 1, 0, 0, 0, 0])).debug_check_range();
    }

    /// A value of `2^255` or more is outside the domain normalize is verified on.
    /// `2^255` is `19` mod p: the top limb's overflow folds in the first pass.
    #[test]
    fn normalize_folds_2_pow_255_to_19() {
        let n = FieldElement25519([0, 0, 0, 0, M51 + 1]).normalize();
        assert_eq!(n.0.0, [19, 0, 0, 0, 0]);
    }

    /// A limb of exactly `2^51` under saturated limbs above it: the value is
    /// `2^51 * 2^51 + (2^51 - 1) * (2^102 + 2^153) = 2^204`, well inside the domain.
    #[test]
    fn normalize_accepts_limb_of_2_pow_51() {
        let n = FieldElement25519([0, 1 << 51, M51, M51, 0]).normalize();
        assert_eq!(n.0.0, [0, 0, 0, 0, 1]);
    }

    /// The values either side of p, where normalize's `+19` / `-19` passes decide the answer. The
    /// last multiply of a scalar multiplication returns the representation `r + p` for many valid
    /// results (every `r` in about `[19, 2^207)`), so `[p, 2^255)` is reached routinely through
    /// the public API, which is why `normalize` has to be total; see the regression in
    /// `tests/ed_x25519_tests.rs`.
    #[test]
    fn normalize_edge_values() {
        // p - 1 = 2^255 - 20: already canonical, unchanged.
        let n = FieldElement25519([M51 - 19, M51, M51, M51, M51]).normalize();
        assert_eq!(n.0.0, [M51 - 19, M51, M51, M51, M51]);

        // p = 2^255 - 19: reduces to 0.
        let n = FieldElement25519([M51 - 18, M51, M51, M51, M51]).normalize();
        assert_eq!(n.0.0, [0, 0, 0, 0, 0]);

        // 2^255 - 1, the largest non-canonical value: reduces to 18.
        let n = FieldElement25519([M51, M51, M51, M51, M51]).normalize();
        assert_eq!(n.0.0, [18, 0, 0, 0, 0]);
    }

    #[test]
    fn encode_255_known_value() {
        // Start from a non-zero buffer so a partial write cannot pass by accident.
        let mut bytes = [0xFF_u8; 32];
        FieldElement25519(KNOWN_LIMBS).normalize().encode_255(&mut bytes);
        assert_eq!(bytes, KNOWN_VALUE);
    }
    /// p as limbs, the canonical representation of 0 plus one modulus.
    const P_LIMBS: [i64; 5] = [M51 - 18, M51, M51, M51, M51];

    /// The case the two-pass normalize got wrong: `p - 3` held with limb 4 at `2^51` and limb 1
    /// negative. Its single fold gave `-3`, which the `-19` pass then left with a negative top
    /// limb, and `encode_255` wrote garbage in release. Also `p + 1`, `-1` and `2^255 + 2^255`.
    #[test]
    fn normalize_is_total_on_wide_and_negative_representations() {
        let p_minus_3 = FieldElement25519([M51 - 21, -1, 0, 0, 1 << 51]).normalize();
        assert_eq!(p_minus_3.0.0, [M51 - 21, M51, M51, M51, M51]);
        let p_plus_1 = FieldElement25519([M51 - 17, M51, M51, M51, M51]).normalize();
        assert_eq!(p_plus_1.0.0, [1, 0, 0, 0, 0]);
        let minus_1 = FieldElement25519([-1, 0, 0, 0, 0]).normalize();
        assert_eq!(minus_1.0.0, [M51 - 19, M51, M51, M51, M51]);
        let two_to_256 = FieldElement25519([0, 0, 0, 0, 1 << 52]).normalize();
        assert_eq!(two_to_256.0.0, [38, 0, 0, 0, 0]);
        let top_negative = FieldElement25519([5, 0, 0, 0, -(1 << 53)]).normalize();
        // -2^257 = -4 * 2^255 = -4 * 19 mod p, plus 5: p - 71.
        assert_eq!(top_negative.0.0, [M51 - 18 - 71, M51, M51, M51, M51]);
    }

    /// Every limb pattern over the domain's edges: the canonical form is the same whether a
    /// value is normalized as given, with `p` added limb-wise, or after a reducing multiply by
    /// one; and its limbs are canonical, which `debug_check_range` asserts in debug builds.
    #[test]
    fn normalize_agrees_with_itself_across_representations_of_the_domain_edges() {
        let edges: [i64; 7] = [0, 1, -1, M51, 1 << 51, -(1 << 51), 1 << 53];
        let one = FieldElement25519::one();
        let p = FieldElement25519(P_LIMBS);
        for &a in &edges {
            for &b in &edges {
                for &c in &edges {
                    for &d in &edges {
                        for &e in &edges {
                            // Limb-wise p is only in the domain when the sum is.
                            if a.saturating_add(M51).abs() > (1 << 53)
                                || e.saturating_add(M51).abs() > (1 << 53)
                            {
                                continue;
                            }
                            let x = FieldElement25519([a, b, c, d, e]);
                            let direct = x.normalize();
                            direct.debug_check_range();
                            assert_eq!(direct.0.0, x.add(&p).normalize().0.0, "{:?} + p", x.0);
                            assert_eq!(direct.0.0, x.mul(&one).normalize().0.0, "{:?} * 1", x.0);
                        }
                    }
                }
            }
        }
    }

    fn patterned_values() -> [FieldElement25519; 10] {
        [
            FieldElement25519::one(),
            FieldElement25519([2, 0, 0, 0, 0]),
            FieldElement25519([3, 0, 0, 0, 0]),
            FieldElement25519([19, 0, 0, 0, 0]),
            FieldElement25519([M51 - 19, M51, M51, M51, M51]),
            FieldElement25519(KNOWN_LIMBS),
            FieldElement25519([M51, 0, M51, 0, M51]),
            FieldElement25519([1 << 50, 1 << 50, 1 << 50, 1 << 50, 1 << 50]),
            FieldElement25519([0x1234567, 0x89abcde, 0xf0f0f0f, 0x5a5a5a5, 0x7777777]),
            FieldElement25519([0, 0, 0, 0, 1]),
        ]
    }

    /// `x * inv(x) = 1` for the patterned values, and `inv` through the two exponents it is built
    /// from agrees with `x^(p-2)` computed by square-and-multiply over the exponent's bits.
    #[test]
    fn inv_is_the_multiplicative_inverse() {
        for x in patterned_values() {
            let product = x.mul(&x.inv()).normalize();
            assert_eq!(product.0.0, [1, 0, 0, 0, 0], "{:?}", x.0);
        }
        // x^(p-2) by square-and-multiply, p - 2 = 2^255 - 21, from the top bit down.
        let x = FieldElement25519(KNOWN_LIMBS);
        let mut acc = FieldElement25519::one();
        for bit in (0..255).rev() {
            acc = acc.sqr();
            let exponent_bit = if bit >= 5 { 1 } else { ((0b01011_i64 >> bit) & 1) as u8 };
            // 2^255 - 21 = 0b111...1101011: every bit from 254 down to 5 set, then 01011.
            if exponent_bit == 1 {
                acc = acc.mul(&x);
            }
        }
        assert_eq!(acc.normalize().0.0, x.inv().normalize().0.0);
    }

    /// `sqr` is `mul` of a value by itself, and `mul_u32` is `mul` by the constant as an element.
    #[test]
    fn sqr_and_mul_u32_agree_with_mul() {
        for x in patterned_values() {
            assert_eq!(x.sqr().normalize().0.0, x.mul(&x).normalize().0.0, "{:?}", x.0);
            let by_const = x.mul(&FieldElement25519([121_666, 0, 0, 0, 0]));
            assert_eq!(x.mul_u32(121_666).normalize().0.0, by_const.normalize().0.0, "{:?}", x.0);
        }
    }

    /// `cswap` exchanges both values when told to and neither when not.
    #[test]
    fn cswap_swaps_on_the_condition_only() {
        let (mut a, mut b) = (FieldElement25519(KNOWN_LIMBS), FieldElement25519::one());
        FieldElement25519::cswap(Condition::<i64>::from_bool_const::<false>(), &mut a, &mut b);
        assert_eq!((a.0, b.0), (KNOWN_LIMBS, [1, 0, 0, 0, 0]));
        FieldElement25519::cswap(Condition::<i64>::from_bool_const::<true>(), &mut a, &mut b);
        assert_eq!((a.0, b.0), ([1, 0, 0, 0, 0], KNOWN_LIMBS));
    }

    /// `reduce_products`' output limbs lie in the bound `normalize`'s domain argument relies on,
    /// for the largest inputs the arithmetic feeds it.
    #[test]
    fn products_of_the_widest_operands_stay_inside_the_normalize_domain() {
        let wide = FieldElement25519([(1 << 51) + (1 << 9); 5]);
        let wide_negative = FieldElement25519([-(1 << 9); 5]);
        for x in [wide.mul(&wide), wide.sqr(), wide.mul(&wide_negative), wide_negative.sqr()] {
            let [x0, x1, x2, x3, x4] = x.0;
            assert!((0..1 << 51).contains(&x0), "{:?}", x.0);
            for limb in [x1, x2, x3, x4] {
                assert!(limb > -(1 << 9) && limb < (1 << 51) + (1 << 9), "{:?}", x.0);
            }
        }
    }

    // Known answers for the operations Ed25519 needs, from the prototype this module's field was
    // ported from: each operation run there on the values around p and on pseudo-random values
    // (splitmix64, fixed seed), and the results encoded canonically, as 32 little-endian bytes
    // in hexadecimal. Regenerate with the scratch program that printed the two tables (`kat-gen
    // field`, not in this repository), which depends on the prototype's crates by path.

    /// One row: `a` as given to `decode_255`, and the prototype's answers for it, with `b` the
    /// next row's `a`.
    struct FieldKat {
        a: &'static str,
        canonical: &'static str,
        mul: &'static str,
        sqr: &'static str,
        add: &'static str,
        sub: &'static str,
        negate: &'static str,
        inv: &'static str,
        sqrt_ratio: Option<&'static str>,
        is_zero: bool,
        parity: u8,
        equals_b: bool,
    }

    /// One row: a representation with limbs outside `[0, 2^51)`, the limbs the prototype's
    /// `carry` makes of it, and its square and its product with the next row.
    struct WideKat {
        limbs: [i64; 5],
        carry: [i64; 5],
        sqr: Option<&'static str>,
        mul: Option<&'static str>,
    }

    // 23 cases; b is the next case's a, cyclically.
    const FIELD_KATS: [FieldKat; 23] = [
        FieldKat {
            a: "0000000000000000000000000000000000000000000000000000000000000000",
            canonical: "0000000000000000000000000000000000000000000000000000000000000000",
            mul: "0000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0000000000000000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000000000000",
            sub: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            negate: "0000000000000000000000000000000000000000000000000000000000000000",
            inv: "0000000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some("0000000000000000000000000000000000000000000000000000000000000000"),
            is_zero: true,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "0100000000000000000000000000000000000000000000000000000000000000",
            canonical: "0100000000000000000000000000000000000000000000000000000000000000",
            mul: "0200000000000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000000000000",
            add: "0300000000000000000000000000000000000000000000000000000000000000",
            sub: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            negate: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            inv: "0100000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: None,
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "0200000000000000000000000000000000000000000000000000000000000000",
            canonical: "0200000000000000000000000000000000000000000000000000000000000000",
            mul: "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            sqr: "0400000000000000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000000000000",
            sub: "0300000000000000000000000000000000000000000000000000000000000000",
            negate: "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            inv: "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            canonical: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            mul: "0000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000000000000",
            add: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            sub: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            negate: "0100000000000000000000000000000000000000000000000000000000000000",
            inv: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            canonical: "0000000000000000000000000000000000000000000000000000000000000000",
            mul: "0000000000000000000000000000000000000000000000000000000000000000",
            sqr: "0000000000000000000000000000000000000000000000000000000000000000",
            add: "0100000000000000000000000000000000000000000000000000000000000000",
            sub: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            negate: "0000000000000000000000000000000000000000000000000000000000000000",
            inv: "0000000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some("0000000000000000000000000000000000000000000000000000000000000000"),
            is_zero: true,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            canonical: "0100000000000000000000000000000000000000000000000000000000000000",
            mul: "0100000000000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000000000000",
            add: "0200000000000000000000000000000000000000000000000000000000000000",
            sub: "0000000000000000000000000000000000000000000000000000000000000000",
            negate: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            inv: "0100000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: Some("0100000000000000000000000000000000000000000000000000000000000000"),
            is_zero: false,
            parity: 1,
            equals_b: true,
        },
        FieldKat {
            a: "0100000000000000000000000000000000000000000000000000000000000000",
            canonical: "0100000000000000000000000000000000000000000000000000000000000000",
            mul: "1200000000000000000000000000000000000000000000000000000000000000",
            sqr: "0100000000000000000000000000000000000000000000000000000000000000",
            add: "1300000000000000000000000000000000000000000000000000000000000000",
            sub: "dcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            negate: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            inv: "0100000000000000000000000000000000000000000000000000000000000000",
            sqrt_ratio: None,
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            canonical: "1200000000000000000000000000000000000000000000000000000000000000",
            mul: "5601000000000000000000000000000000000000000000000000000000000000",
            sqr: "4401000000000000000000000000000000000000000000000000000000000000",
            add: "2500000000000000000000000000000000000000000000000000000000000000",
            sub: "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            negate: "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            inv: "89e3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388e23",
            sqrt_ratio: Some("f5ffffffffffffffffffffffffffffffaea1bc86f21aca6b28afa1bc86f21a4a"),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "1300000000000000000000000000000000000000000000000000000000000000",
            canonical: "1300000000000000000000000000000000000000000000000000000000000000",
            mul: "ab00000000000000000000000000000000000000000000000000000000000040",
            sqr: "6901000000000000000000000000000000000000000000000000000000000000",
            add: "1300000000000000000000000000000000000000000000000000000000000040",
            sub: "0000000000000000000000000000000000000000000000000000000000000040",
            negate: "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            inv: "14ca6b28afa1bc86f21aca6b28afa1bc86f21aca6b28afa1bc86f21aca6b282f",
            sqrt_ratio: None,
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "0000000000000000000000000000000000000000000000000000000000000040",
            canonical: "0000000000000000000000000000000000000000000000000000000000000040",
            mul: "2600000000000000000000000000000000000000000000000000000000000000",
            sqr: "4c00000000000000000000000000000000000000000000000000000000000060",
            add: "0400000000000000000000000000000000000000000000000000000000000040",
            sub: "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
            negate: "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f",
            inv: "2894d7505e43790de53594d7505e43790de53594d7505e43790de53594d7505e",
            sqrt_ratio: Some("edffffffffffffffffffffffffffffbfffffffffffffffffffffffffffffff7f"),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "0400000000000000000000000000000000000000000000000000000000000000",
            canonical: "0400000000000000000000000000000000000000000000000000000000000000",
            mul: "16a2615d2fae86d31c2784aa993f7298d11c76b61ac84de7de8a4f958340cb78",
            sqr: "1000000000000000000000000000000000000000000000000000000000000000",
            add: "806858d78babe134c709a16ae68f1c6634879dad0672d3b9b7e253e520d0325e",
            sub: "7597a72874541ecb38f65e951970e399cb786252f98d2c46481dac1adf2fcd21",
            negate: "e9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            inv: "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "7c6858d78babe134c709a16ae68f1c6634879dad0672d3b9b7e253e520d0325e",
            canonical: "7c6858d78babe134c709a16ae68f1c6634879dad0672d3b9b7e253e520d0325e",
            mul: "09b9c7283af0bcc8a08aeb655e41a8ae6660a3eda1baf0c22ce1e6727a5a8e15",
            sqr: "349a7b1dc72d70a596d35bf0546ed1f2774d69a4824c543fe5721f42cafdd624",
            add: "e1be821c5aaf8322496dc3e677681e7c946f8f8d6901e17095e75d1e81e8033f",
            sub: "17122e92bda73f4745a67eee54b71a50d49eabcda3e2c502dadd49acc0b7617d",
            negate: "7197a72874541ecb38f65e951970e399cb786252f98d2c46481dac1adf2fcd21",
            inv: "5451f75d4862b2e230ffb18bf827c832cae912b94c14daba66ad8115b89bce7e",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "52562a45ce03a2ed8163227c91d8011660e8f1df628f0db7dd040a396018d160",
            canonical: "52562a45ce03a2ed8163227c91d8011660e8f1df628f0db7dd040a396018d160",
            mul: "9dc4d2c384d8d6fc12f85f5644d25abca441b11e0fd2d05722e4fcbdea73895e",
            sqr: "cde2a13b3056807c4565b49356c3e50a2f882c0a51be4358ef9eeeec5e206518",
            add: "f18c6bd1633c569d0c26887dabb73918ace236a62824a8c52368e81572834271",
            sub: "b31fe9b838cbed3df7a0bc7a77f9c91314eeac199dfa72a897a12b5c4ead5f50",
            negate: "9ba9d5ba31fc5d127e9cdd836e27fee99f170e209d70f24822fbf5c69fe72e1f",
            inv: "83032cdd3cbe1441c603737df9221f32d7c5b4bfe1f2dd32b0c2fad644e4052a",
            sqrt_ratio: Some("e180f996c6eaead7cf2faf82b1e384b42add957038b6efca1b05eb9ae1165f5b"),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "9f36418c9538b4af8ac265011adf37024cfa44c6c5949a0e4663dedc116b7110",
            canonical: "9f36418c9538b4af8ac265011adf37024cfa44c6c5949a0e4663dedc116b7110",
            mul: "0f58211d0a819bedb7ad8fe5777b44198841d39a51a67f22c370bcf4791c123f",
            sqr: "e9f6e8d3e936fca4c0c3b6e87a5a7170997f8d86fc5b54c5b523433bdd841f46",
            add: "059d715a6d35503ce6cca51e05ddbb0907cc8feed6f0096c2bc7d25c7510b72a",
            sub: "26d010bebd3b18232fb825e42ee1b3fa9028fa9db4382bb160ffe95caec52b76",
            negate: "4ec9be736ac74b50753d9afee520c8fdb305bb393a6b65f1b99c2123ee948e6f",
            inv: "f57ad23ecf74dc5b0275ad2bed133c1ba18c54a635e8c09284408330a2574e57",
            sqrt_ratio: Some("91c0027476947a07899d9da306629d80ac431fdaed3793bb5e95e83bd0817b7c"),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "666630ced7fc9b8c5b0a401debfd8307bbd14a28115c6f5de563f47f63a5451a",
            canonical: "666630ced7fc9b8c5b0a401debfd8307bbd14a28115c6f5de563f47f63a5451a",
            mul: "2ba9db8063637acb5545b7fc423a43bfbeb98abc260e070e9937d084976da60f",
            sqr: "79e174c889425c2a97ac46231a65527c5435276f2db32ee5b18828ef8f1eae2b",
            add: "a8daa8f925d4213cc84df21decc4c6e09461793b800906022a2df51b117a6008",
            sub: "24f2b7a2892516ddeec68d1cea36412ee1411c15a2aed8b8a09af3e3b5d02a2c",
            negate: "8799cf3128036473a4f5bfe214027cf8442eb5d7eea390a21a9c0b809c5aba65",
            inv: "920570459df2841c82eb0e5d7f3fe1fe4ef8fcab3bcd9e70bfd228573e42af7b",
            sqrt_ratio: Some("61018289aaa5809683207995a0de15cdfd2aa32f7bd7931cc477ec0c977a363f"),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "2f74782b4ed785af6c43b20001c742d9d98f2e136fad96a444c9009cadd41a6e",
            canonical: "2f74782b4ed785af6c43b20001c742d9d98f2e136fad96a444c9009cadd41a6e",
            mul: "b1dc62d4343952c292a890c4d2ab89c428e683eaba0a9c59b094e99ef3b99020",
            sqr: "a1a35fd1f740eceff79d50ffb0d04e10015515bf941e44155bce7efa9170d314",
            add: "7d63299893a5e037c964577b4efff6804c605e6599ffc4bf4832f64cc700bc05",
            sub: "f484c7be08092b2710220d86b38e8e3167bffec0445b688940600beb93a87956",
            negate: "be8b87d4b1287a5093bc4dfffe38bd262670d1ec9052695bbb36ff63522be511",
            inv: "c935db0266cb26cf3d47c07113ef3f91ee2716a7eb978e4eb5f30ef3423d6e4f",
            sqrt_ratio: None,
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "3befb06c45ce5a885c21a57a4d38b4a772d02f522a522e1b0469f5b0192ca117",
            canonical: "3befb06c45ce5a885c21a57a4d38b4a772d02f522a522e1b0469f5b0192ca117",
            mul: "0e852e86285d18cc32261d8fdf346c1141236c5b150ac01d8967e805ef13ba58",
            sqr: "33fa435fba411cc38bb25b0e46b795ad720dd9d0f4c3ac35065f6c11f72bb766",
            add: "7c6178cadc4c3f842e5798d17d99c1932fa475d5f4d985d6b925bbdc791d7e73",
            sub: "e77ce90eae4f768c8aebb1231dd7a6bbb5fce9ce5fcad65f4eac2f85b93ac43b",
            negate: "b2104f93ba31a577a3de5a85b2c74b588d2fd0add5add1e4fb960a4fe6d35e68",
            inv: "6af2a661816f852d1dc3d8e2f42ae1d95b86d98ecac4d2c35d0914df850a624c",
            sqrt_ratio: Some("ffd6098380ca6b39bb3ce348e2574e9c51be8e6a0932e359ab47b630ecf29617"),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "4172c75d977ee4fbd135f35630610decbcd34583ca8757bbb5bcc52b60f1dc5b",
            canonical: "4172c75d977ee4fbd135f35630610decbcd34583ca8757bbb5bcc52b60f1dc5b",
            mul: "06347133f7a919180681401297c4bfa6a8bf24242415bb7905496971ba5dfe4e",
            sqr: "9b161552151e99c31dedebde9b3f97062d1f9044b16a9936fb4aec5894426e5c",
            add: "c2c0da36e0a028059879f4a7d3adff88fe7881dbace8745eb0392f1b84b55458",
            sub: "c023b4844e5ca0f20bf2f1058d141b4f7b2e0a2be8263a18bb3f5c3c3c2d655f",
            negate: "ac8d38a268811b042eca0ca9cf9ef213432cba7c3578a8444a433ad49f0e2324",
            inv: "57a66663a862efcd819b83df5c18bb0d25647259f9d5cbd02cfd53634a97e152",
            sqrt_ratio: Some("60b288bb52e2a509059dcc11bdca59f2e0d50d361e11d6e7ffe21033aa7b4279"),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "6e4e13d948224409c6430151a34cf29c41a53b58e2601da3fa7c69ef23c4777c",
            canonical: "6e4e13d948224409c6430151a34cf29c41a53b58e2601da3fa7c69ef23c4777c",
            mul: "6e00b1fa04fedc04de1278e50bbb93daae995bb8b6cfd01db2f5a7c2e306c27b",
            sqr: "34f77585d816f70908c417283ae0489ed4ef606c6ba24d583f8d64067fa56329",
            add: "948ead4a19671bbddf976abfb17959b32d7e86cc92a1e7edb8832e228494cb1a",
            sub: "5b0e796778dd6c55acef97e2941f8b8655ccf0e3312053583c76a4bcc3f3235e",
            negate: "7fb1ec26b7ddbbf639bcfeae5cb30d63be5ac4a71d9fe25c05839610dc3b8803",
            inv: "943015461e9d42b9b6ea46c13e3c22cc527dffa256290233419d424a40889054",
            sqrt_ratio: Some("25e60ef0540c474d962c5b2f4477e5365086fb5d6e59c5553efde5ac73d91122"),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "13409a71d044d7b31954696e0e2d6716ecd84a74b040ca4abe06c53260d0531e",
            canonical: "13409a71d044d7b31954696e0e2d6716ecd84a74b040ca4abe06c53260d0531e",
            mul: "e676247df0134884cb840503275ad072f378a06be360127e193f309b45a44179",
            sqr: "3346dae1a822ddfb18c7dff86e7cae8ba3583cf4d15b2c1a34307f5c21d8a360",
            add: "3170cc9b62aded35572e9fed44f79bfa1a18a1c8ce60de39df8fecfb61ac653a",
            sub: "f50f68473edcc031dc7933efd7623232bd99f41f9220b65b9d7d9d695ef44102",
            negate: "dabf658e2fbb284ce6ab9691f1d298e91327b58b4fbf35b541f93acd9f2fac61",
            inv: "336ccd1e2eb0fc974e6f637bb6896f9d831560f350d43b2a34a987e9a8fc642e",
            sqrt_ratio: Some("dd9d94c0da63e87ad1b56d0819f260ceb8015a380fd181cffd78233d80b7e21e"),
            is_zero: false,
            parity: 1,
            equals_b: false,
        },
        FieldKat {
            a: "1e30322a926816823dda357f36ca34e42e3f56541e2014ef208927c901dc111c",
            canonical: "1e30322a926816823dda357f36ca34e42e3f56541e2014ef208927c901dc111c",
            mul: "c100875983af8d7ad0df81b5338d2c637aa5c45ef11fddcc4b3437d5782fb755",
            sqr: "433a97a527554c7098eddceef432200a9b66288affa1b13c906e12b44fe71108",
            add: "3cd286d59801b309f3b5760027666c09213fabcb57d821880f47ae2ca4cb7b45",
            sub: "ed8ddd7e8bcf79fa87fef4fd452efdbe3c3f01dde467065632cba0655feca772",
            negate: "cfcfcdd56d97e97dc225ca80c935cb1bd1c0a9abe1dfeb10df76d836fe23ee63",
            inv: "560ed06f414990e69620eb914e4c94dd07a7211fa40a68b7ae447041c5b8cb21",
            sqrt_ratio: None,
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "1ea254ab06999c87b5db4081f09b3725f2ff547739b80d99eebd8663a2ef6929",
            canonical: "1ea254ab06999c87b5db4081f09b3725f2ff547739b80d99eebd8663a2ef6929",
            mul: "51bfd3d436e344b34d71accc9b37e0f996dbcb736f03aded6c6992eb2cfc3057",
            sqr: "b44bd13d5758f7653a8eb084229ddc4a4367c1956539d7b5aacfe69dbf481662",
            add: "385b415da7cde52579e31061a13321a42f52a16c3945ec24c1c66315e84c3745",
            sub: "04e967f9656453e9f1d370a13f044ea6b4ad0882392b2f0d1cb5a9b15c929c0d",
            negate: "cf5dab54f96663784a24bf7e0f64c8da0d00ab88c647f2661142799c5d109656",
            inv: "9cc5881946f5fd59d390e4e7a9907f2765ae53fdd02a27e51736572e00828726",
            sqrt_ratio: Some("269fcd80d3d7f677aca069b896de96beabb1644a307d03c502cb01922bb33f53"),
            is_zero: false,
            parity: 0,
            equals_b: false,
        },
        FieldKat {
            a: "1ab9ecb1a034499ec307d0dfb097e97e3d524cf5ff8cde8bd208ddb1455dcd1b",
            canonical: "1ab9ecb1a034499ec307d0dfb097e97e3d524cf5ff8cde8bd208ddb1455dcd1b",
            mul: "0000000000000000000000000000000000000000000000000000000000000000",
            sqr: "af76921367a475a35fd55eec6deacf04cb2b95675cb59064cd702e2ad612456c",
            add: "1ab9ecb1a034499ec307d0dfb097e97e3d524cf5ff8cde8bd208ddb1455dcd1b",
            sub: "1ab9ecb1a034499ec307d0dfb097e97e3d524cf5ff8cde8bd208ddb1455dcd1b",
            negate: "d346134e5fcbb6613cf82f204f681681c2adb30a007321742df7224ebaa23264",
            inv: "e44e41b21345c026287c20d40d159218cd07afd031e811dfc0ef0364251aa858",
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
                2251799813685247, 2251799813685247, 2251799813685247, 2251799813685247,
                2251799813685247,
            ],
            carry: [
                2251799813685247, 2251799813685247, 2251799813685247, 2251799813685247,
                2251799813685247,
            ],
            sqr: Some("4401000000000000000000000000000000000000000000000000000000000000"),
            mul: Some("5625000000009020010000008004090000000024480000000020410200000000"),
        },
        WideKat {
            limbs: [
                2251799813685760, 2251799813685760, 2251799813685760, 2251799813685760,
                2251799813685760,
            ],
            carry: [531, 513, 513, 513, 513],
            sqr: Some("b57d35010000f8a26907000040133b290000007648b900000090c24501000000"),
            mul: Some("ed41cbfeffffff2f9bf8ffffff7fe2d6ffffffff5b47ffffffff1fbdfeffff7f"),
        },
        WideKat {
            limbs: [-512, -512, -512, -512, -512],
            carry: [
                2251799813684717, 2251799813684735, 2251799813684735, 2251799813684735,
                2251799813684735,
            ],
            sqr: Some("000034010000000060070000000000290000000000b800000000004001000000"),
            mul: Some("ed83feffffffff5ff6ffffffffffc4ffffffffffb7feffffffff3ffaffffff7f"),
        },
        WideKat {
            limbs: [
                4503599627370496, 4503599627370496, 4503599627370496, 4503599627370496,
                4503599627370496,
            ],
            carry: [38, 2, 2, 2, 2],
            sqr: Some("d40600000000e00b00000000004d0000000000d80100000000400a0000000000"),
            mul: Some("19f9ffffffff1ff4ffffffffffb2ffffffffff27feffffffffbff5ffffffff7f"),
        },
        WideKat {
            limbs: [
                -4503599627370496, -4503599627370496, -4503599627370496, -4503599627370496,
                -4503599627370496,
            ],
            carry: [-38, -2, -2, -2, -2],
            sqr: Some("d40600000000e00b00000000004d0000000000d80100000000400a0000000000"),
            mul: Some("2600000000001000000000008000000000000004000000000020000000000000"),
        },
        WideKat {
            limbs: [-1, 0, 0, 0, 0],
            carry: [2251799813685247, -1, 0, 0, 0],
            sqr: Some("0100000000000000000000000000000000000000000000000000000000000000"),
            mul: Some("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        },
        WideKat {
            limbs: [0, 0, 0, 0, 2251799813685248],
            carry: [19, 0, 0, 0, 0],
            sqr: Some("6901000000000000000000000000000000000000000000000000000000000000"),
            mul: Some("edffffffffffffffffffffffffffffffffffffffffffffffffcffeffffffff7f"),
        },
        WideKat {
            limbs: [0, 0, 0, 0, -1],
            carry: [-19, 0, 0, 0, 2251799813685247],
            sqr: Some("0000000000000000000000000000000000000026000000000000000000000000"),
            mul: Some("0000000000000000000000000000000000000000000000000030000000000000"),
        },
        WideKat {
            limbs: [2251799813685226, -1, 0, 0, 2251799813685248],
            carry: [2251799813685245, 2251799813685247, -1, 0, 0],
            sqr: Some("0900000000000000000000000000000000000000000000000000000000000000"),
            mul: Some("97ffffffffff77000000000080f8ffffffffff17000000000030000000000000"),
        },
        WideKat {
            limbs: [4503599627370493, -2251799813685255, 2251799813685259, -5, 4503599627370495],
            carry: [2251799813685264, 2251799813685242, 9, 2251799813685244, 2251799813685246],
            sqr: Some("97ffffffffffaff2ffffffff3fdb00000000002efdffffffff5f040000000000"),
            mul: None,
        },
        WideKat {
            limbs: [
                6071069917077903, -1859891319704212, 2768537711524340, -1385333551277580,
                1870173626231450,
            ],
            carry: [
                1567470289707407, 391908493981038, 516737897839091, 866466262407669,
                1870173626231449,
            ],
            sqr: None,
            mul: None,
        },
        WideKat {
            limbs: [
                72057594037927941, -72057594037927927, 36028797018963967, -36028797018963968,
                72057594037927859,
            ],
            carry: [594, 41, 2251799813685215, 15, 2251799813685155],
            sqr: None,
            mul: None,
        },
    ];

    fn bytes32(hex: &str) -> [u8; 32] {
        bouncycastle_core::hex::decode(hex).unwrap().try_into().unwrap()
    }

    /// The canonical encoding of a value.
    fn canonical(x: &FieldElement25519) -> [u8; 32] {
        let mut bytes = [0xFF_u8; 32];
        x.normalize().encode_255(&mut bytes);
        bytes
    }

    fn kat_inputs() -> impl Iterator<Item = FieldElement25519> {
        FIELD_KATS.iter().map(|kat| FieldElement25519::decode_255(&bytes32(kat.a)))
    }

    /// `x^e` for the exponent whose bits, from bit `top` down to bit `low.len()`, are all ones
    /// and whose remaining low bits are `low`, most significant first: plain square-and-multiply,
    /// sharing nothing with `pow_p_sub5_div8`.
    fn pow_ones_then(x: &FieldElement25519, top: usize, low: &[u8]) -> FieldElement25519 {
        let mut acc = FieldElement25519::one();
        for bit in (0..=top).rev() {
            acc = acc.sqr();
            if bit >= low.len() || low[low.len() - 1 - bit] == 1 {
                acc = acc.mul(x);
            }
        }
        acc
    }

    #[test]
    fn field_operations_match_the_prototype() {
        let inputs: [FieldElement25519; FIELD_KATS.len()] =
            core::array::from_fn(|i| FieldElement25519::decode_255(&bytes32(FIELD_KATS[i].a)));
        for (i, kat) in FIELD_KATS.iter().enumerate() {
            let (a, b) = (&inputs[i], &inputs[(i + 1) % inputs.len()]);
            assert_eq!(canonical(a), bytes32(kat.canonical), "canonical {i}");
            assert_eq!(canonical(&a.mul(b)), bytes32(kat.mul), "mul {i}");
            assert_eq!(canonical(&a.sqr()), bytes32(kat.sqr), "sqr {i}");
            assert_eq!(canonical(&a.add(b)), bytes32(kat.add), "add {i}");
            assert_eq!(canonical(&a.sub(b)), bytes32(kat.sub), "sub {i}");
            let (sum, difference) = a.sum_and_difference(b);
            assert_eq!(canonical(&sum), bytes32(kat.add), "sum {i}");
            assert_eq!(canonical(&difference), bytes32(kat.sub), "difference {i}");
            assert_eq!(canonical(&a.negate()), bytes32(kat.negate), "negate {i}");
            assert_eq!(canonical(&a.inv()), bytes32(kat.inv), "inv {i}");
            let root = FieldElement25519::sqrt_ratio_var(a, b);
            assert_eq!(root.as_ref().map(canonical), kat.sqrt_ratio.map(bytes32), "sqrt {i}");

            let (a_n, b_n) = (a.normalize(), b.normalize());
            assert_eq!(a_n.is_zero().to_bool(), kat.is_zero, "is_zero {i}");
            assert_eq!(a_n.is_zero_var(), kat.is_zero, "is_zero_var {i}");
            assert_eq!(a_n.parity(), kat.parity, "parity {i}");
            let equal = NormalizedFieldElement25519::are_equal_var(&a_n, &b_n);
            assert_eq!(equal, kat.equals_b, "are_equal_var {i}");
        }
    }

    #[test]
    fn wide_representations_match_the_prototype() {
        for (i, kat) in WIDE_KATS.iter().enumerate() {
            let a = FieldElement25519::new(kat.limbs);
            let b = FieldElement25519::new(WIDE_KATS[(i + 1) % WIDE_KATS.len()].limbs);
            assert_eq!(a.carry().0, kat.carry, "carry {i}");
            if let Some(sqr) = kat.sqr {
                assert_eq!(canonical(&a.sqr()), bytes32(sqr), "sqr {i}");
                // The carry pass changes the representation, not the value.
                assert_eq!(canonical(&a.carry()), canonical(&a), "carry value {i}");
            }
            if let Some(mul) = kat.mul {
                assert_eq!(canonical(&a.mul(&b)), bytes32(mul), "mul {i}");
            }
        }
    }

    /// `new` is usable in a constant and keeps the limbs as given.
    #[test]
    fn new_keeps_the_limbs() {
        const KNOWN: FieldElement25519 = FieldElement25519::new(KNOWN_LIMBS);
        assert_eq!(KNOWN.0, KNOWN_LIMBS);
    }

    /// `-(-x) = x` limb for limb, `x + (-x) = 0`, and `x * inv(x) = 1` unless `x` is zero, when
    /// the inverse is zero too.
    #[test]
    fn negate_and_inv_are_the_inverses() {
        for (i, x) in kat_inputs().enumerate() {
            assert_eq!(x.negate().negate().0, x.0, "{i}");
            assert_eq!(x.add(&x.negate()).normalize().0.0, [0; 5], "{i}");
            let expected = if x.normalize().is_zero_var() { [0; 5] } else { [1, 0, 0, 0, 0] };
            assert_eq!(x.mul(&x.inv()).normalize().0.0, expected, "{i}");
        }
    }

    /// Normalizing a normalized value changes nothing.
    #[test]
    fn normalize_is_idempotent() {
        for (i, x) in kat_inputs().enumerate() {
            let n = x.normalize();
            assert_eq!(n.normalize().0.0, n.0.0, "{i}");
        }
    }

    /// A normalized value dereferences to its own limbs, and arithmetic goes on from there.
    #[test]
    fn a_normalized_value_dereferences_to_the_field_element() {
        let x = FieldElement25519(KNOWN_LIMBS);
        let n = x.normalize();
        let as_field: &FieldElement25519 = &n;
        assert_eq!(as_field.0, KNOWN_LIMBS);
        assert_eq!(n.sqr().normalize().0.0, x.sqr().normalize().0.0);
    }

    /// `cmov` copies every limb when told to and none when not.
    #[test]
    fn cmov_moves_on_the_condition_only() {
        let source = FieldElement25519([11, 12, 13, 14, 15]);
        let mut a = FieldElement25519(KNOWN_LIMBS);
        a.cmov(Condition::<i64>::from_bool_const::<false>(), &source);
        assert_eq!(a.0, KNOWN_LIMBS);
        a.cmov(Condition::<i64>::from_bool_const::<true>(), &source);
        assert_eq!(a.0, [11, 12, 13, 14, 15]);
    }

    /// `cnegate` negates every limb when told to and none when not.
    #[test]
    fn cnegate_negates_on_the_condition_only() {
        let mut a = FieldElement25519([11, -12, 13, -14, 15]);
        a.cnegate(Condition::<i64>::from_bool_const::<false>());
        assert_eq!(a.0, [11, -12, 13, -14, 15]);
        a.cnegate(Condition::<i64>::from_bool_const::<true>());
        assert_eq!(a.0, [-11, 12, -13, 14, -15]);
        // And as a field operation it agrees with negate.
        let mut x = FieldElement25519(KNOWN_LIMBS);
        x.cnegate(Condition::<i64>::from_bool_const::<true>());
        assert_eq!(x.0, FieldElement25519(KNOWN_LIMBS).negate().0);
    }

    /// The zero test, the equality test and the parity each look at every limb they should: a
    /// value that is non-zero in one limb only, and one whose limbs cancel under XOR.
    #[test]
    fn zero_equality_and_parity_tests_see_every_limb() {
        let n = |limbs: [i64; 5]| NormalizedFieldElement25519(FieldElement25519(limbs));
        let zero = n([0; 5]);
        assert!(zero.is_zero().to_bool());
        assert!(zero.is_zero_var());
        assert!(NormalizedFieldElement25519::are_equal_var(&zero, &n([0; 5])));
        for limb in 0..5 {
            let mut limbs = [0; 5];
            limbs[limb] = 7;
            assert!(!n(limbs).is_zero().to_bool(), "limb {limb}");
            assert!(!n(limbs).is_zero_var(), "limb {limb}");
            assert!(!NormalizedFieldElement25519::are_equal_var(&zero, &n(limbs)), "limb {limb}");
            assert!(NormalizedFieldElement25519::are_equal_var(&n(limbs), &n(limbs)));
            for other in 0..limb {
                limbs[other] = 7;
                assert!(!n(limbs).is_zero().to_bool(), "limbs {other} and {limb}");
                assert!(!n(limbs).is_zero_var(), "limbs {other} and {limb}");
                limbs[other] = 0;
            }
        }
        assert_eq!(n([2, 1, 1, 1, 1]).parity(), 0);
        assert_eq!(n([3, 0, 0, 0, 0]).parity(), 1);
        // p - 1 is even.
        assert_eq!(n([M51 - 19, M51, M51, M51, M51]).parity(), 0);
    }

    /// The constant behind step 3.2 of RFC 8032 Section 5.1.3: `sqrt_ratio_var(-1, 1)` takes
    /// that step with the candidate root 1, so it returns the constant itself, which must be
    /// `2^((p-1)/4)` and square to -1.
    #[test]
    fn sqrt_m1_is_two_to_the_p_minus_1_over_4() {
        let one = FieldElement25519::one();
        let sqrt_m1 = FieldElement25519::sqrt_ratio_var(&one.negate(), &one).unwrap();
        // (p - 1) / 4 = 2^253 - 5: bits 252 down to 3 set, then 011.
        let two = FieldElement25519([2, 0, 0, 0, 0]);
        assert_eq!(canonical(&sqrt_m1), canonical(&pow_ones_then(&two, 252, &[0, 1, 1])));
        assert_eq!(canonical(&sqrt_m1.sqr()), canonical(&one.negate()));
    }

    /// Over every ordered pair of the known-answer inputs: a reported root satisfies
    /// `v * x^2 = u`, and a root is reported exactly when Euler's criterion says `u / v` is a
    /// square. `u / v` is a square iff `u * v` is (they differ by `v^2`), and
    /// `(u * v)^((p-1)/2)` is 0 or 1 for a square and -1 otherwise.
    #[test]
    fn sqrt_ratio_var_agrees_with_eulers_criterion() {
        let inputs: [FieldElement25519; FIELD_KATS.len()] =
            core::array::from_fn(|i| FieldElement25519::decode_255(&bytes32(FIELD_KATS[i].a)));
        let minus_one = canonical(&FieldElement25519::one().negate());
        let (mut roots, mut non_squares) = (0, 0);
        for u in &inputs {
            for v in &inputs {
                let root = FieldElement25519::sqrt_ratio_var(u, v);
                if let Some(x) = &root {
                    assert_eq!(canonical(&x.sqr().mul(v)), canonical(u));
                    roots += 1;
                }
                let has_root = if v.normalize().is_zero_var() {
                    u.normalize().is_zero_var()
                } else {
                    // (p - 1) / 2 = 2^254 - 10: bits 253 down to 4 set, then 0110.
                    let euler = canonical(&pow_ones_then(&u.mul(v), 253, &[0, 1, 1, 0]));
                    non_squares += usize::from(euler == minus_one);
                    euler != minus_one
                };
                assert_eq!(root.is_some(), has_root);
            }
        }
        // Both outcomes occur, many times over.
        assert!(roots > 100 && non_squares > 100, "{roots} roots, {non_squares} non-squares");
    }
}
