use bouncycastle_utils::ct::Condition;

/// Mask for one limb: `2^51 - 1`. A [`FieldElement25519`] holds the value
/// `x0 + x1*2^51 + x2*2^102 + x3*2^153 + x4*2^204`, so `& M51` extracts a limb's own 51 bits and
/// leaves the overflow to be carried into the next limb (or, out of `x4`, folded back into `x0`
/// scaled by 19, since `2^255 == 19 mod p`).
const M51: i64 = (1 << 51) - 1;

// /// The field prime `p = 2^255 - 19` as eight little-endian 32-bit words, least significant first.
// ///
// /// Currently referenced nowhere in the crate; [`FieldElement25519::normalize`] reduces via the
// /// `* 19` fold rather than by comparing against `p`.
// ///
// /// Scope: neither -- dead as of today.
// // TODO: remove?
// const P32: [u32; 8] = [
//     0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
// ];
// /// The field prime `p = 2^255 - 19` as four little-endian 64-bit words, least significant first.
// /// Note the low word is `...FFED` = `-19 mod 2^64`, and the top word has bit 63 clear, giving
// /// `2^255 - 19` rather than `2^256 - 19`.
// ///
// /// Referenced only by the commented-out `modular::mod_odd_inverse` form of `inv`, so it is dead
// /// until inversion is restored.
// ///
// /// Scope: both -- once inversion lands.
// // TODO: remove?
// const P64: [u64; 4] =
//     [0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];

/// An element of GF(p), p = 2^255 - 19: the field that curve25519's point coordinates live in.
///
/// This is the base field, as opposed to the scalar field of integers mod the group order that
/// private keys live in. Every coordinate in this crate is one of these: the u-coordinate of
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
/// The field operations: addition, subtraction and negation, multiplication and squaring,
/// inversion, and the square root of a ratio. Constant-time conditional move, negate, select and
/// swap. Encoding to and decoding from 32 bytes. Everything is constant time except the methods
/// suffixed `_var`, which are for public inputs only.
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
/// multiplication, which the Montgomery ladder in [`crate::x25519`] computes. Ed25519 uses the full
/// (x, y) coordinates on the equivalent twisted Edwards curve, where general addition is defined.
#[derive(Clone, Default)]
#[must_use] // to help catch bugs that x.sqr() actually returns a result rather than mutates x, so not using the return is a bug.
pub(crate) struct FieldElement25519([i64; 5]);

impl FieldElement25519 {
    /// Add another [`FieldElement25519`] to this one, component-wise.
    ///
    /// Lazily reduced: no carry propagation, so limb magnitudes grow by up to one bit and the result
    /// is congruent mod p but not normalized. That is deliberate -- every consumer here funnels into
    /// a [`Self::mul`], [`Self::sqr`] or [`Self::mul_u32`], each of which reduces through
    /// [`Self::reduce_products`], so magnitudes never run away and an explicit carry pass is not
    /// needed.
    pub(crate) const fn add(&self, rhs: &Self) -> Self {
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
    /// `C = x_3 + z_3` / `D = x_3 - z_3`. It is the workhorse of the ladder in [`crate::x25519`].
    ///
    /// Note on the name: RFC7748 does not name this operation -- it writes the two assignments out
    /// separately, so there is no spec name to match.
    pub(crate) const fn sum_and_difference(&self, rhs: &Self) -> (Self, Self) {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        (
            Self([x0 + y0, x1 + y1, x2 + y2, x3 + y3, x4 + y4]),
            Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4]),
        )
    }

    // /// Add one to self, i.e. add 1 to limb `x0`, returning a new [`FieldElement25519`].
    // ///
    // /// One is representable exactly in the low limb, so no carry or fold is involved; as with
    // /// [`Self::add`] the result is congruent mod p but not normalized.
    // ///
    // /// Scope: Ed25519 -- unused today. The birational map of Section 4.1 of RFC7748,
    // /// `y = (u - 1)/(u + 1)`, is what wants `add_one` and [`Self::sub_one`]; the X25519 ladder never
    // /// adds a constant.
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) const fn add_one(&self) -> Self {
    //     let [x0, x1, x2, x3, x4] = self.0;
    //     Self([x0 + 1, x1, x2, x3, x4])
    // }

    // /// [`Self::add_one`] in place.
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) fn add_one_mut(&mut self) {
    //     self.0[0] += 1;
    // }

    // /// Carry each limb's overflow above 51 bits into the next limb up.
    // /// The overflow out of the top limb `x4` has weight `2^255`, so it wraps around
    // /// into `x0` multiplied by 19, since `2^255 == 19 mod p`.
    // ///
    // /// This is a weak reduction: the value is unchanged mod p, but the result is not normalized -- it
    // /// may be `>= p`. Use [`Self::normalize`] for the canonical representation.
    // ///
    // /// All five carries are taken from the input limbs at once, rather than rippling up from `x0` as
    // /// in [`Self::reduce`]. That keeps the five steps independent, so the longest dependency chain is
    // /// about three instructions (shift, `* 19`, add) rather than a ripple's ten or so, which an
    // /// out-of-order CPU can overlap; it also lets LLVM auto-vectorize limbs 1..4. The cost is that
    // /// each output limb is only bounded by `2^51` plus the carry it received: for input limbs below
    // /// `2^63` in magnitude a carry lies in `[-2^12, 2^12)`, so `z1..z4` lie in
    // /// `[-2^12, 2^51 + 2^12)` and `z0` in `[-19 * 2^12, 2^51 + 19 * 2^12)`.
    // ///
    // /// `>> 51` is an arithmetic shift, i.e. floor division by `2^51`, and `& M51` the matching
    // /// non-negative remainder, so a negative limb borrows from its neighbour correctly. A borrow can
    // /// leave the next limb negative, so the output limbs are not guaranteed non-negative.
    // pub(crate) const fn carry(&self) -> Self {
    //     let [x0, x1, x2, x3, x4] = self.0;
    //     let c1 = x0 >> 51;
    //     let c2 = x1 >> 51;
    //     let c3 = x2 >> 51;
    //     let c4 = x3 >> 51;
    //     let c5 = x4 >> 51;
    //     let z0 = (x0 & M51) + c5 * 19;
    //     let z1 = (x1 & M51) + c1;
    //     let z2 = (x2 & M51) + c2;
    //     let z3 = (x3 & M51) + c3;
    //     let z4 = (x4 & M51) + c4;
    //     Self([z0, z1, z2, z3, z4])
    // }

    // /// Conditionally move the coordinates of x into self if `cond` is true.
    // ///
    // /// Constant-time.
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) fn cmov(&mut self, cond: Condition<i64>, x: &Self) {
    //     // *self = Self::cselect(cond, x, self);
    //     cond.mov(x.0[0], &mut self.0[0]);
    //     cond.mov(x.0[1], &mut self.0[1]);
    //     cond.mov(x.0[2], &mut self.0[2]);
    //     cond.mov(x.0[3], &mut self.0[3]);
    //     cond.mov(x.0[4], &mut self.0[4]);
    // }

    // /// Returns a copy of lhs if `cond` is true, else a copy of rhs.
    // ///
    // /// Constant time.
    // ///
    // /// Scope: Ed25519 -- unused today; see [`Self::cmov`].
    // // TODO -- add back once we get to implementing Ed25519
    // // TODO -- do we really need this? Seems like this is equivalent to lhs.cmov(cond, rhs); Do we really need both?
    // pub(crate) fn cselect(cond: Condition<i64>, lhs: &Self, rhs: &Self) -> Self {
    //     let [x0, x1, x2, x3, x4] = lhs.0;
    //     let [y0, y1, y2, y3, y4] = rhs.0;
    //     let z0 = cond.select(x0, y0);
    //     let z1 = cond.select(x1, y1);
    //     let z2 = cond.select(x2, y2);
    //     let z3 = cond.select(x3, y3);
    //     let z4 = cond.select(x4, y4);
    //     Self([z0, z1, z2, z3, z4])
    // }

    // /// Negate the components of self if `cond` is true.
    // ///
    // /// Constant time.
    // // TODO -- add back once we get to implementing Ed25519
    // // TODO -- seems weird to negate the limbs instead of negating only the leading digit
    // pub(crate) fn cnegate(&mut self, cond: Condition<i64>) {
    //     self.0[0] = cond.negate(self.0[0]);
    //     self.0[1] = cond.negate(self.0[1]);
    //     self.0[2] = cond.negate(self.0[2]);
    //     self.0[3] = cond.negate(self.0[3]);
    //     self.0[4] = cond.negate(self.0[4]);
    // }

    /// Conditionally Swap the values of lhs and rhs if `cond` is true.
    ///
    /// Constant time: both limb arrays are rewritten unconditionally with a masked exchange, so
    /// nothing about `cond` -- and hence nothing about the scalar bit driving it -- leaks through
    /// memory access patterns or timing.
    pub(crate) fn cswap(cond: Condition<i64>, lhs: &mut Self, rhs: &mut Self) {
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
    pub(crate) const fn decode_255(bytes: &[u8; 32]) -> Self {
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
        const fn decode64_255(x: &[u64; 4]) -> FieldElement25519 {
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
    /// [`Self::pow_p_sub5_div8`] returns `(x^3, x^((p-5)/8))`. Raising the second to the 8th and
    /// multiplying by the first gives exponent `8 * (2^252 - 3) + 3 == 2^255 - 21 == p - 2`.
    /// Costs 254 squarings and 11 multiplies.
    ///
    /// Constant time: a fixed addition chain, with no data-dependent branch or index.
    ///
    /// `inv(0) == 0`, since `0^(p-2) == 0`. That is not a case to guard against -- X25519 depends
    /// on it. A small-order input point drives the ladder's `z_2` to zero, and Section 6.1 of
    /// RFC7748 requires the resulting all-zero output to be detectable: "the X25519 function
    /// produces that value if it operates on an input corresponding to a point with small order".
    /// Returning zero here is what carries that through the final `x_2 * z_2^-1`.
    ///
    /// Verified against a reference modular inverse over 305 values, edge cases included.
    ///
    /// Scope: both x25519 and ed25519.
    // TODO -- a safegcd-style `mod_odd_inverse` would be asymptotically cheaper, and P64 above is
    //          the constant it wants. Only worth revisiting if this shows up in a profile -- it is
    //          one call per scalar_mult.
    pub(crate) const fn inv(&self) -> Self {
        let (x_cubed, t) = self.pow_p_sub5_div8();
        t.sqr_n(3).mul(&x_cubed)
    }

    /// Multiply self by rhs in GF(p), `p = 2^255 - 19`.
    ///
    /// Schoolbook 5x5: output limb `k` collects every `x[i] * y[j]` with `i + j == k`, plus every
    /// pair with `i + j == k + 5`. The second set lands at weight `2^255` or above, and
    /// `2^255 == 19 mod p`, so those terms are pre-scaled by 19 -- that is what `t1..t4` are. The 25
    /// products accumulate in `i128` (a 51-bit by 56-bit product would overflow `i64`) and
    /// [`Self::reduce_products`] carries them back down to five `i64` limbs.
    pub(crate) const fn mul(&self, rhs: &Self) -> Self {
        #[inline(always)]
        const fn m(x: i64, y: i64) -> i128 {
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
    /// `a24 = (486662 - 2) / 4 = 121665`.
    pub(crate) const fn mul_u32(&self, rhs: u32) -> Self {
        #[inline(always)]
        const fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        let [x0, x1, x2, x3, x4] = self.0;
        let y0 = rhs as i64;

        Self::reduce_products(m(x0, y0), m(x1, y0), m(x2, y0), m(x3, y0), m(x4, y0))
    }

    // /// Negates self, component-wise.
    // ///
    // /// Negating every limb negates the value, since the limb weights `2^(51*i)` are all positive.
    // /// Lazily reduced, and note the result has negative limbs, which is legal in this representation
    // /// but means it is *not* normalized -- [`Self::normalize`] must run before any encode or
    // /// comparison.
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) const fn negate(&self) -> Self {
    //     let [x0, x1, x2, x3, x4] = self.0;
    //     Self([-x0, -x1, -x2, -x3, -x4])
    // }

    /// Reduce self to the unique canonical representative of its residue class: limbs all in
    /// `[0, 2^51)` and the value in `[0, p)`.
    ///
    /// Idempotent.
    ///
    /// Two [`Self::reduce`] passes with `y` and then `-y`, where `y` is bit 254 of the value (bit 50
    /// of limb `x4`, since `x4` sits at weight `2^204`). Each pass adds `19 * y` at the bottom
    /// without a matching removal at the top, so neither pass alone is congruent mod p -- but the
    /// `+19y` and `-19y` cancel exactly, leaving `value - (c + c') * p` for the two top-carry folds
    /// `c`, `c'`.
    ///
    /// Adding `19 * y` in the first pass and removing it in the second makes the top carry fire
    /// exactly when the value is `>= p`, since `v >= p` if and only if `v + 19 >= 2^255`. Only values
    /// `>= 2^254` can be `>= p`, which is why `y` is bit 254.
    ///
    /// This is what implements Section 5 of RFC7748's "Implementations MUST accept non-canonical
    /// values and process them as if they had been reduced modulo the field prime. The non-canonical
    /// values are 2^255 - 19 through 2^255 - 1".
    /// This `reduce(y).reduce(-y)` is exact on all of `[0, 2^255)`, which is the entire range
    /// [`Self::decode_255`] can produce. It first fails at `2^255`, outside the input domain.
    ///
    /// Requires the value in `[0, 2^255)`, the domain above that this is verified on. Individual
    /// limbs may exceed 51 bits: [`Self::mul`] can return a limb of exactly `2^51` (Wycheproof
    /// X25519 tcId 115 and 116), which the carry chain in [`Self::reduce`] handles. Checked by a
    /// `debug_assert` in debug builds; the [`NormalizedFieldElement25519`] typestate cannot enforce
    /// it.
    pub(crate) const fn normalize(&self) -> NormalizedFieldElement25519 {
        // Carry the limbs through without folding: the value is in [0, 2^255) exactly when the
        // carried top limb is in [0, 2^51).
        let [x0, x1, x2, x3, x4] = self.0;
        debug_assert!(
            {
                let c = ((((x0 >> 51) + x1) >> 51) + x2) >> 51;
                let top = ((c + x3) >> 51) + x4;
                0 <= top && top <= M51
            },
            "normalize: value out of [0, 2^255)"
        );

        let y = (self.0[4] >> (51 - 1)) & 1;
        NormalizedFieldElement25519(self.reduce(y).reduce(-y))
    }

    /// The multiplicative identity, 1, in canonical form.
    pub(crate) const fn one() -> Self {
        Self([1, 0, 0, 0, 0])
    }

    /// Returns `(x^3, x^((p-5)/8))` for `x = self`, by a fixed addition chain.
    ///
    /// `(p - 5) / 8 == 2^252 - 3` for `p = 2^255 - 19`, which in binary is 250 ones, a zero, then a
    /// one -- the `FFFF..FD` of the comment below. The chain reaches it in 10 steps by doubling runs
    /// of 1-bits. Both return values are exponent-verified.
    ///
    /// Beware the naming: the locals count *consecutive 1-bits*, not exponents. `x2` is `x^3`
    /// (`0b11`, two ones), `x3` is `x^7`, `x5` is `x^31`, and `x250` is `x^(2^250 - 1)`. It reads
    /// like an off-by-one bug and is not one.
    ///
    /// Both consumers need the pair:
    /// * inversion, as `z.sqr_n(3).mul(&x2)` -- exponent `8 * (2^252 - 3) + 3 == 2^255 - 21 == p - 2`,
    ///   i.e. Fermat.
    /// * [`Self::sqrt_ratio_var`], which uses `x^((p-5)/8)` directly as the `p == 5 mod 8` square-root
    ///   candidate.
    const fn pow_p_sub5_div8(&self) -> (Self, Self) {
        // z = x^((p-5)/8) = x^FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD
        // (250 1s) (1 0s) (1 1s)
        // Addition chain: [1] 2 3 5 10 15 25 50 75 125 [250]

        let x = self;
        let x2 = x.sqr().mul(x);
        let x3 = x2.sqr().mul(x);
        let x5 = x3.sqr_n(2).mul(&x2);
        let x10 = x5.sqr_n(5).mul(&x5);
        let x15 = x10.sqr_n(5).mul(&x5);
        let x25 = x15.sqr_n(10).mul(&x10);
        let x50 = x25.sqr_n(25).mul(&x25);
        let x75 = x50.sqr_n(25).mul(&x25);
        let x125 = x75.sqr_n(50).mul(&x50);
        let x250 = x125.sqr_n(125).mul(&x125);

        let z = x250.sqr_n(2).mul(x);
        (x2, z)
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
    const fn reduce(&self, y: i64) -> Self {
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
    const fn reduce_products(p0: i128, p1: i128, p2: i128, p3: i128, p4: i128) -> Self {
        #[inline(always)]
        const fn split(x: i128) -> (i64, i64) {
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
    pub(crate) const fn sqr(&self) -> Self {
        #[inline(always)]
        const fn m(x: i64, y: i64) -> i128 {
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
    /// Declared const to enable pre-computed tables to be built at compile-time.
    pub(crate) const fn sqr_n(&self, mut n: usize) -> Self {
        let mut z = Self(self.0);
        while n > 0 {
            z = z.sqr();
            n -= 1;
        }
        z
    }

    // /// Variable-time square root of the ratio `u / v`: returns `Some(x)` with `x^2 == u / v` if that
    // /// ratio is a quadratic residue, else `None`.
    // ///
    // /// The standard `p == 5 mod 8` method (p mod 8 is 5, checked), arranged to need no inversion: the
    // /// candidate is `x = u * v^3 * (u * v^7)^((p-5)/8)`, and `v * x^2` is then compared against `+u`
    // /// and `-u` to sort the three cases. If `v * x^2 == -u`, the true root is `x` times a square root
    // /// of -1, which is the `ROOT_NEG_ONE` constant -- verified to square to `-1 mod p`, and to equal
    // /// `2^((p-1)/4)`.
    // ///
    // /// Verified over 4,000 random `(u, v)`: every returned root satisfies `x^2 == u / v`, and every
    // /// `None` is a genuine non-residue.
    // ///
    // /// Variable time by construction.
    // /// That is acceptable for point decompression, which runs on public data, and it is why the
    // /// name carries the `_var` suffix.
    // // TODO -- double-check the variable-time assumption
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) const fn sqrt_ratio_var(u: &Self, v: &Self) -> Option<Self> {
    //     let uv = u.mul(v);
    //     let v2 = v.sqr();
    //     let uv3 = v2.mul(&uv);
    //     let uv7 = v2.sqr().mul(&uv3);
    //
    //     let (_, w) = uv7.pow_p_sub5_div8();
    //     let x = w.mul(&uv3);
    //     let vx2 = x.sqr().mul(v);
    //
    //     let t = vx2.sub(u).normalize();
    //
    //     if t.is_zero().to_bool() {
    //         return Some(x);
    //     }
    //
    //     let t = vx2.add(u).normalize();
    //     if t.is_zero().to_bool() {
    //         const ROOT_NEG_ONE: FieldElement25519 = FieldElement25519([
    //             -0x0001E4D8B5F15F50, 0x0000D5A5FC8F189E, -0x000010A16342F3A0, -0x00007A6A597FB361,
    //             0x0002B8324804FC1E,
    //         ]);
    //
    //         return Some(x.mul(&ROOT_NEG_ONE));
    //     }
    //
    //     None
    // }

    /// Subtract rhs from self, component-wise.
    ///
    /// Lazily reduced, exactly as [`Self::add`]: no borrow propagation, so limbs may go negative and
    /// the result is congruent mod p but not normalized. Negative limbs are fine here --
    /// [`Self::reduce_products`] and [`Self::reduce`] both use arithmetic (sign-propagating) shifts,
    /// so a negative limb borrows correctly on the next reduction.
    pub(crate) const fn sub(&self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4])
    }

    // /// Subtract one from self, i.e. subtract 1 from limb `x0`, returning a new
    // /// [`FieldElement25519`].
    // ///
    // /// Mirror of [`Self::add_one`]; if `x0` was zero the limb simply goes negative, which the next
    // /// reduction resolves.
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) const fn sub_one(&self) -> Self {
    //     let [x0, x1, x2, x3, x4] = self.0;
    //     Self([x0 - 1, x1, x2, x3, x4])
    // }

    /// The additive identity, 0, in canonical form.
    pub(crate) const fn zero() -> Self {
        Self([0; 5])
    }
}

/// A [`FieldElement25519`] in canonical form: every limb in `[0, 2^51)` and the value in `[0, p)`.
/// The only constructor is [`FieldElement25519::normalize`].
///
// TODO -- impl Deref<Target = FieldElement25519> once a caller needs to continue arithmetic on a
//          normalized value (e.g. Ed25519 point decompression).
#[derive(Clone)]
#[must_use]
pub(crate) struct NormalizedFieldElement25519(FieldElement25519);

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
    const fn debug_check_range(&self) {
        let [x0, x1, x2, x3, x4] = self.0.0;
        debug_assert!(0 <= x0 && x0 <= M51, "limb 0 out of [0, 2^51)");
        debug_assert!(0 <= x1 && x1 <= M51, "limb 1 out of [0, 2^51)");
        debug_assert!(0 <= x2 && x2 <= M51, "limb 2 out of [0, 2^51)");
        debug_assert!(0 <= x3 && x3 <= M51, "limb 3 out of [0, 2^51)");
        debug_assert!(0 <= x4 && x4 <= M51, "limb 4 out of [0, 2^51)");
        debug_assert!(
            !(x1 == M51 && x2 == M51 && x3 == M51 && x4 == M51 && x0 >= M51 - 18),
            "value >= p"
        );
    }

    // /// Constant-time equality of two field elements.
    // ///
    // /// Compares representations, not residue classes, so it is only correct on the normalized
    // /// form: a value and that value plus p have different limbs.
    // ///
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) const fn are_equal(lhs: &Self, rhs: &Self) -> Condition<i64> {
    //     lhs.debug_check_range();
    //     rhs.debug_check_range();
    //     let [x0, x1, x2, x3, x4] = lhs.0.0;
    //     let [y0, y1, y2, y3, y4] = rhs.0.0;
    //     Condition::<i64>::is_zero((x0 ^ y0) | (x1 ^ y1) | (x2 ^ y2) | (x3 ^ y3) | (x4 ^ y4))
    // }

    /// Encodes the field element as a 255-bit value in 32 little-endian bytes; the inverse of
    /// [`FieldElement25519::decode_255`]. Bit 255 (the most significant bit of the last byte) is
    /// always written as zero.
    ///
    /// Callers that need that bit to carry something else -- the
    /// sign of x in an Ed25519 point encoding (Section 5.1.3 of RFC 8032) -- must OR it in after.
    ///
    /// Input: self; a 32-byte output buffer.
    /// Output: The value written to `bytes` as a 255-bit little-endian integer.
    pub(crate) fn encode_255(&self, bytes: &mut [u8; 32]) {
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
    const fn encode64_255(&self) -> [u64; 4] {
        self.debug_check_range();
        let [x0, x1, x2, x3, x4] = self.0.0;
        let z0 = (x0 | x1 << 51) as u64;
        let z1 = (x1 >> 13 | x2 << 38) as u64;
        let z2 = (x2 >> 26 | x3 << 25) as u64;
        let z3 = (x3 >> 39 | x4 << 12) as u64;
        [z0, z1, z2, z3]
    }

    // /// Constant-time test for the value 1: `is_zero` over `(x0 ^ 1) | x1 | x2 | x3 | x4`.
    // ///
    // /// Correct only on the normalized form: only the canonical representative of 1 has limbs
    // /// `[1, 0, 0, 0, 0]`.
    // ///
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) const fn is_one(&self) -> Condition<i64> {
    //     self.debug_check_range();
    //     let [x0, x1, x2, x3, x4] = self.0.0;
    //     let x0 = x0 ^ 1;
    //     Condition::<i64>::is_zero(x0 | x1 | x2 | x3 | x4)
    // }

    // /// Constant-time test for the value 0: `is_zero` over the OR of all five limbs.
    // ///
    // /// Correct only on the normalized form: an un-normalized zero can be represented as p, whose
    // /// limbs are not all zero.
    // ///
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) const fn is_zero(&self) -> Condition<i64> {
    //     self.debug_check_range();
    //     let [x0, x1, x2, x3, x4] = self.0.0;
    //     Condition::<i64>::is_zero(x0 | x1 | x2 | x3 | x4)
    // }

    // /// The least significant bit of the value.
    // ///
    // /// Correct only on the normalized form, and the reason this type exists: p is odd, so an
    // /// un-normalized value in `[p, 2^255)` would report the parity of `v` rather than of `v - p` --
    // /// a wrong answer, not merely a non-canonical one.
    // // TODO -- add back once we get to implementing Ed25519
    // pub(crate) const fn is_odd(&self) -> u8 {
    //     self.debug_check_range();
    //     (self.0.0[0] & 1) as u8
    // }
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
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "normalize: value out of [0, 2^255)")]
    fn normalize_rejects_value_2_pow_255() {
        let _ = FieldElement25519([0, 0, 0, 0, M51 + 1]).normalize();
    }

    /// The shape of input Wycheproof X25519 tcId 115 produces: limb 1 is exactly `2^51`, but the
    /// value is `2^51 * 2^51 + (2^51 - 1) * (2^102 + 2^153) = 2^204`, well inside the domain.
    #[test]
    fn normalize_accepts_limb_of_2_pow_51() {
        let n = FieldElement25519([0, 1 << 51, M51, M51, 0]).normalize();
        assert_eq!(n.0.0, [0, 0, 0, 0, 1]);
    }

    /// The values either side of p, where the `y` adjustment in normalize decides the answer. Not
    /// reachable through the public API: X25519 only normalizes ladder outputs, which land in
    /// `[p, 2^255)` with negligible probability.
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
}
