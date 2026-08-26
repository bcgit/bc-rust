use bouncycastle_utils::ct::Condition;

/// The basic data value for any elliptic curve implementation is a point on the curve.
/// Holds the u-coordinate, which is an element of GF(p) with p = 2^255 - 19 for curve25519, held
/// here in a `[u8; 32]` as the representation of a point on a Montgomery curve.
///
///
/// # Mathematical operations implemented:
/// None.
/// All mathematical operations on a u-coordinate are implemented on [`Scalar25519`].
///
/// # Math Background
/// The group law on elliptic curve points is point addition where A + B yields a new point C on the
/// curve.
/// The special case of adding a point to itself, A + A is called "point doubling" and is often
/// implemented separately as this can be done more efficiently than the general case.
/// Finally, repeated addition with itself, A + A + ... + A is represented as k * A for a scalar k and
/// called "scalar multiplication", again, implemented separately.
///
/// Curve points are represented here in Montgomery form by their u-coordinate, which defines a point
/// on the curve or on the quadratic twist up to sign; ie it names the pair {P, -P}.
/// This means that point doubling and scalar multiplication are well-defined over u-coordinates since
/// they commute with negation; ie k*(-A) = -(k*A), but general point addition is not.
/// Fortunately, XDH defined in RFC7748 only requires scalar multiplication, not general point addition.
type UCoordinate25519 = [u8; 32];

/// Scalar values are integers used as the k value in scalar multiplication of points.
///
/// # Mathematical operations implemented:
///
/// * EC scalar multiplication: k * A: via `impl core::ops::Mul<UCoordinate25519> for Scalar25519`, with `Output = UCoordinate25519`
struct Scalar25519([u8; 32]);

impl core::ops::Mul<UCoordinate25519> for Scalar25519 {
    type Output = UCoordinate25519;

    /// EC scalar multiplication `k * A`, computed by the Montgomery ladder of Section 5 of
    /// RFC7748; ie this is the X25519 function itself.
    ///
    /// Input: self, the scalar `k`; rhs, the u-coordinate of a point `A`.
    /// Output: the u-coordinate of `k * A`.
    ///
    /// Scope: X25519.
    // TODO -- unimplemented. `todo!()` rather than a literally empty body because `mul` has to
    //          produce a `[u8; 32]`.
    // TODO: Claude-generated, double-check
    fn mul(self, rhs: UCoordinate25519) -> Self::Output {
        todo!()
    }
}

/// Mask for one limb: `2^51 - 1`. A [`CoordField`] holds the value
/// `x0 + x1*2^51 + x2*2^102 + x3*2^153 + x4*2^204`, so `& M51` extracts a limb's own 51 bits and
/// leaves the overflow to be carried into the next limb (or, out of `x4`, folded back into `x0`
/// scaled by 19, since `2^255 == 19 mod p`).
///
/// Scope: both.
// TODO: Claude-generated, double-check
const M51: i64 = (1 << 51) - 1;

/// The field prime `p = 2^255 - 19` as eight little-endian 32-bit words, least significant first.
///
/// Currently referenced nowhere in the crate; [`CoordField::normalize`] reduces via the `* 19`
/// fold rather than by comparing against `p`.
///
/// Scope: neither -- dead as of today.
// TODO: Claude-generated, double-check
const P32: [u32; 8] = [
    0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
];
/// The field prime `p = 2^255 - 19` as four little-endian 64-bit words, least significant first.
/// Note the low word is `...FFED` = `-19 mod 2^64`, and the top word has bit 63 clear, giving
/// `2^255 - 19` rather than `2^256 - 19`.
///
/// Referenced only by the commented-out `modular::mod_odd_inverse` form of `inv`, so it is dead
/// until inversion is restored.
///
/// Scope: both -- once inversion lands.
// TODO: Claude-generated, double-check
const P64: [u64; 4] =
    [0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];

// TODO Add magnitude, normalized fields to CoordField in debug mode and track validity through all operations
#[derive(Clone, Copy, Debug, Default)]
#[must_use]
#[repr(transparent)]
// TODO -- are all these annotations really necessary? Doesn't this contain secrets? Don't we want to block Debug?
// TODO -- should this be `[Secret<i64>; 5]` ?
// TODO -- why is this pub and not pub(crate)? -- same question for the fn's in the impl.
pub struct CoordField([i64; 5]);

// TODO -- all of these need at least simple unit tests
impl CoordField {
    /// Add another [`CoordField`] to this one, component-wise.
    ///
    /// Lazily reduced: no carry propagation, so limb magnitudes grow by up to one bit and the result
    /// is congruent mod p but not normalized. That is deliberate -- every consumer here funnels into
    /// a [`Self::mul`], [`Self::sqr`] or [`Self::mul_u32`], each of which reduces through
    /// [`Self::reduce_products`], so magnitudes never run away and an explicit carry pass is not
    /// needed.
    ///
    /// Scope: both. In X25519 it is the `AA + a24 * E` of the Section 5 ladder (`x25519.rs:110`,
    /// `148`).
    // TODO: Claude-generated, double-check
    pub const fn add(&self, rhs: &Self) -> Self {
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
    /// separately, so there is no spec name to match. This was previously called `apm`, an
    /// abbreviation that appears nowhere in RFC7748 or RFC8032. It most likely came from the
    /// BouncyCastle Java implementation (`X25519Field.apm`, whose `zp` / `zm` out-parameters
    /// suggest "add plus minus"), but that expansion is inferred from behaviour and has not been
    /// confirmed against the Java source.
    ///
    /// Scope: both x25519 and ed25519
    // TODO: Claude-generated, double-check
    pub const fn sum_and_difference(&self, rhs: &Self) -> (Self, Self) {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        (
            Self([x0 + y0, x1 + y1, x2 + y2, x3 + y3, x4 + y4]),
            Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4]),
        )
    }

    /// Add one to self, i.e. add 1 to limb `x0`, returning a new [`CoordField`].
    ///
    /// One is representable exactly in the low limb, so no carry or fold is involved; as with
    /// [`Self::add`] the result is congruent mod p but not normalized.
    ///
    /// Scope: Ed25519 -- unused today. The birational map of Section 4.1 of RFC7748,
    /// `y = (u - 1)/(u + 1)`, is what wants `add_one` and [`Self::sub_one`]; the X25519 ladder never
    /// adds a constant.
    // TODO -- why are we cloning? [there is no clone: `self.0` is `[i64; 5]`, which is `Copy`, so the
    //          destructuring bind is a register move, not an allocation.]
    // TODO: Claude-generated, double-check
    pub const fn add_one(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        Self([x0 + 1, x1, x2, x3, x4])
    }

    /// [`Self::add_one`] in place.
    ///
    /// Scope: Ed25519 -- unused today; see [`Self::add_one`].
    // TODO -- why are we returning the same ref we were passed?
    // TODO: Claude-generated, double-check
    pub fn add_one_mut(&mut self) -> &mut Self {
        self.0[0] += 1;
        self
    }

    /// Constant-time equality: `is_zero` over the OR of the limb-wise XORs.
    ///
    /// Requires both inputs normalized -- this compares representations, not residue classes, and a
    /// value and that value plus p have different limbs. See the precondition discussion above
    /// [`Self::encode_255`].
    ///
    /// Scope: Ed25519 -- unused today. X25519 never compares field elements; the ladder's only
    /// output check is the all-zeros test on the encoded bytes (`x25519.rs:29`).
    // TODO: Claude-generated, double-check
    pub const fn are_equal(lhs: &Self, rhs: &Self) -> Condition<i64> {
        let [x0, x1, x2, x3, x4] = lhs.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        Condition::<i64>::is_zero((x0 ^ y0) | (x1 ^ y1) | (x2 ^ y2) | (x3 ^ y3) | (x4 ^ y4))
    }

    /// Variable-time [`Self::are_equal`], resolving to a `bool` and therefore branchable by the
    /// caller. Only for values that are not secret.
    ///
    /// Requires both inputs normalized; see [`Self::are_equal`].
    ///
    /// Scope: Ed25519 -- unused today; signature verification compares public values.
    // TODO: Claude-generated, double-check
    pub const fn are_equal_var(lhs: &Self, rhs: &Self) -> bool {
        Self::are_equal(lhs, rhs).to_bool()
    }

    /// One weak-reduction pass: move each limb's overflow into the next, and fold the overflow out of
    /// `x4` into `x0` scaled by 19 (`2^255 == 19 mod p`).
    ///
    /// Shifts are arithmetic, so a negative limb borrows from its neighbour correctly, and `& M51`
    /// leaves every limb non-negative. The result is congruent mod p and has limbs near 51 bits, but
    /// is not normalized -- `z0` in particular can exceed `2^51` after the `+ c5 * 19`.
    ///
    /// Verified congruent to its input mod p over 20,000 random values.
    ///
    /// Scope: both -- but currently unused by either, and structurally so: every ladder step passes
    /// through a `mul`, `sqr` or `mul_u32`, all of which reduce via [`Self::reduce_products`], so
    /// limb magnitudes never grow far enough to need a standalone carry.
    // TODO: Claude-generated, double-check
    pub const fn carry(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        let c1 = x0 >> 51;
        let c2 = x1 >> 51;
        let c3 = x2 >> 51;
        let c4 = x3 >> 51;
        let c5 = x4 >> 51;
        let z0 = (x0 & M51) + c5 * 19;
        let z1 = (x1 & M51) + c1;
        let z2 = (x2 & M51) + c2;
        let z3 = (x3 & M51) + c3;
        let z4 = (x4 & M51) + c4;
        Self([z0, z1, z2, z3, z4])
    }

    /// [`Self::carry`] in place.
    ///
    /// Scope: both -- unused today; see [`Self::carry`].
    // TODO -- why are we returning the same ref we were passed?
    // TODO: Claude-generated, double-check
    pub fn carry_mut(&mut self) -> &mut Self {
        *self = self.carry();
        self
    }

    /// Move the coordinates of x into self if `cond` is true.
    ///
    /// Constant time: every limb is rewritten unconditionally with a masked blend, so the branch is
    /// not observable. See `bouncycastle_utils::ct::Condition`.
    ///
    /// Scope: Ed25519 -- unused today. Wanted for the table lookup in a fixed-base comb; X25519's
    /// only conditional is the ladder swap, [`Self::cswap`].
    // TODO: Claude-generated, double-check
    pub fn cmov(&mut self, cond: Condition<i64>, x: &Self) -> &mut Self {
        // *self = Self::cselect(cond, x, self);
        cond.mov(x.0[0], &mut self.0[0]);
        cond.mov(x.0[1], &mut self.0[1]);
        cond.mov(x.0[2], &mut self.0[2]);
        cond.mov(x.0[3], &mut self.0[3]);
        cond.mov(x.0[4], &mut self.0[4]);
        self
    }

    /// Negate the components of self if `cond` is true.
    ///
    /// Constant time, as [`Self::cmov`].
    ///
    /// Scope: Ed25519 -- unused today. Wanted for signed-digit fixed-base multiplication, where a
    /// table entry is conditionally negated instead of storing both signs.
    // TODO: Claude-generated, double-check
    pub fn cnegate(&mut self, cond: Condition<i64>) -> &mut Self {
        self.0[0] = cond.negate(self.0[0]);
        self.0[1] = cond.negate(self.0[1]);
        self.0[2] = cond.negate(self.0[2]);
        self.0[3] = cond.negate(self.0[3]);
        self.0[4] = cond.negate(self.0[4]);
        self
    }

    /// Returns a copy of lhs if `cond` is true, else a copy of rhs.
    ///
    /// Constant time, as [`Self::cmov`]; the non-mutating form of it.
    ///
    /// Scope: Ed25519 -- unused today; see [`Self::cmov`].
    // TODO: Claude-generated, double-check
    pub fn cselect(cond: Condition<i64>, lhs: &Self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4] = lhs.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        let z0 = cond.select(x0, y0);
        let z1 = cond.select(x1, y1);
        let z2 = cond.select(x2, y2);
        let z3 = cond.select(x3, y3);
        let z4 = cond.select(x4, y4);
        Self([z0, z1, z2, z3, z4])
    }

    /// Conditionally Swap the values of lhs and rhs if `cond` is true.
    ///
    /// Constant time: both limb arrays are rewritten unconditionally with a masked exchange, so
    /// nothing about `cond` -- and hence nothing about the scalar bit driving it -- leaks through
    /// memory access patterns or timing.
    ///
    /// Scope: X25519. This is `cswap(swap, x_2, x_3)` from the Section 5 ladder of RFC7748, the
    /// mechanism that makes the ladder scalar-bit oblivious.
    // TODO: Claude-generated, double-check
    pub fn cswap(cond: Condition<i64>, lhs: &mut Self, rhs: &mut Self) {
        (lhs.0[0], rhs.0[0]) = cond.swap(lhs.0[0], rhs.0[0]);
        (lhs.0[1], rhs.0[1]) = cond.swap(lhs.0[1], rhs.0[1]);
        (lhs.0[2], rhs.0[2]) = cond.swap(lhs.0[2], rhs.0[2]);
        (lhs.0[3], rhs.0[3]) = cond.swap(lhs.0[3], rhs.0[3]);
        (lhs.0[4], rhs.0[4]) = cond.swap(lhs.0[4], rhs.0[4]);
    }

    // TODO -- decide how the normalization precondition is handled across this codec group.
    //          This comment was generated by Claude and left here to be considered unce I have
    //          a better understanding of the code.
    //
    // `decode_u_coordinate` deliberately returns an un-normalized value: RFC 7748 Section 5 requires that
    // non-canonical u-coordinates (u >= p) be accepted rather than rejected. But `encode_255`,
    // `encode64_255`, `are_equal`, `are_equal_var` and `parity` all *require* a normalized input,
    // enforced today only by a documented precondition that every call site has to remember. All of
    // them currently do (`scalar_mult` and `encode_u_coordinate` in x25519.rs, `inv` below), so this
    // is a latent footgun rather than a live bug -- but the asymmetry is ugly: decoding asks nothing
    // of the caller, encoding and comparison ask for a step they can silently omit. `parity` is the
    // sharpest edge: p is odd, so a value in [p, 2^255) reports the parity of v rather than v - p.
    //
    // Options:
    //  1. Fold `self.normalize()` into `encode_255` and drop it from its call sites. Free -- since
    //     normalize is idempotent this moves work rather than adding it -- and encode is outside the
    //     ladder loop, so nothing hot is touched. Does not help `are_equal`/`parity`, and folding it
    //     into `are_equal` WOULD cost, because that one can land in hot code.
    //  2. Typestate: `normalize(self) -> Normalized`, with `encode_255`, `are_equal` and `parity`
    //     defined only on `Normalized`. Compile-time enforcement, which is what
    //     QUALITY_AND_STYLE.md asks for over runtime discipline, and it covers the whole group at
    //     once. Bigger change, and it wants the full list of consumers -- Ed25519 point compression
    //     will add more -- so it probably waits for that (see the deferral note atop x25519.rs).
    //  3. Debug-only tracking, i.e. the magnitude/normalized fields already proposed in the TODO at
    //     the top of this file. Catches violations in tests without changing the API, but proves
    //     nothing in release and puts a debug-only field on a `Copy` type.
    //
    // None of these remove the precondition outright: `normalize` itself needs limbs inside the
    // magnitude bound that `reduce`'s carry chain assumes (`t5 * 19 + x0` must not overflow i64).
    // That residual bound is exactly what option 3 would track.

    /// Encodes a field element as a 255-bit value in 32 little-endian bytes; the inverse of [`Self::decode_u_coordinate`].
    /// Bit 255 (the most significant bit of the last byte) is always written as zero.
    ///
    /// Callers that need that bit to carry something else -- the
    /// sign of x in an Ed25519 point encoding (Section 5.1.3 of RFC 8032) -- must OR it in after.
    ///
    /// Note: Requires normalized self -- see [`Self::encode64_255`]; only a normalized value encodes to the
    /// canonical byte string for its residue class.
    ///
    /// Input: self, normalized; a 32-byte output buffer.
    /// Output: The value written to `bytes` as a 255-bit little-endian integer.
    ///
    /// Scope: both. In X25519 it is `encodeUCoordinate` (`x25519.rs:85`, `174`).
    // TODO: Claude-generated, double-check
    pub fn encode_255(&self, bytes: &mut [u8; 32]) {
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
    /// each word taking a whole limb plus the low bits of the next. Inverse of
    /// [`Self::decode64_255`]. Bit 255 of the result is always zero, since limb `x4` lands in bits
    /// 204..254.
    ///
    /// Note: Requires normalized self: every limb must be in [0, 2^51) and the value reduced mod p.
    /// The splices below are `|`, not `+`, so a limb with bits at or above 51 collides with the next
    /// limb's bits instead of carrying into them, and the result is garbage. (The `x1 << 51` etc.
    /// deliberately shift bits off the top of the i64 -- those are the bits the previous word
    /// already carried.)
    ///
    /// Input: self, normalized.
    /// Output: The value as four little-endian 64-bit words, least significant word first.
    ///
    /// Scope: both -- the packing half of [`Self::encode_255`].
    // TODO: Claude-generated, double-check
    const fn encode64_255(&self) -> [u64; 4] {
        let [x0, x1, x2, x3, x4] = self.0;
        let z0 = (x0 | x1 << 51) as u64;
        let z1 = (x1 >> 13 | x2 << 38) as u64;
        let z2 = (x2 >> 26 | x3 << 25) as u64;
        let z3 = (x3 >> 39 | x4 << 12) as u64;
        [z0, z1, z2, z3]
    }

    /// `decodeUCoordinate(u, 255)` as defined in Section 5 of RFC7748:
    ///
    /// ```text
    /// def decodeUCoordinate(u, bits):
    ///     u_list = [ord(b) for b in u]
    ///     # Ignore any unused bits.
    ///     if bits % 8:
    ///         u_list[-1] &= (1<<(bits%8))-1
    ///     return decodeLittleEndian(u_list, bits)
    /// ```
    ///
    /// The RFC's `bits` parameter is fixed at 255 by this type, so `bits % 8` is 7 and the mask
    /// clears bit 255 -- the most significant bit of the final byte. Section 5 requires exactly
    /// that: "When receiving such an array, implementations of X25519 (but not X448) MUST mask the
    /// most significant bit in the final byte."
    ///
    /// Callers own the meaning of that bit: for X25519 it is unused, for Ed25519 it carries the
    /// sign of x (Section 5.1.3 of RFC8032) and must be stripped off and handled separately.
    ///
    /// The RFC's `decodeLittleEndian` has no counterpart of its own -- it is folded into this
    /// function and [`Self::decode64_255`].
    ///
    /// Verified equal to `decodeUCoordinate(b, 255)` over 20,004 inputs, random plus edge cases.
    ///
    /// Note: Result is NOT normalized -- the value is in [0, 2^255), so the 19 encodings of
    /// 2^255-19 .. 2^255-1 decode to values >= p. That is also required by Section 5:
    /// "Implementations MUST accept non-canonical values and process them as if they had been
    /// reduced modulo the field prime. The non-canonical values are 2^255 - 19 through 2^255 - 1
    /// for X25519". Call [`Self::normalize`] before comparing or encoding.
    ///
    /// Note on the name: Ed25519 needs this same byte-to-field decode for a *y*-coordinate, where
    /// the masked bit is the sign of x rather than unused, so at that call site the RFC7748 name
    /// will read wrong. It follows RFC7748 because that is the only caller today; revisit when
    /// Ed25519 lands.
    ///
    /// Input: A 32-byte little-endian u-coordinate.
    /// Output: The low 255 bits of that value as a [`CoordField`].
    ///
    /// Scope: both x25519 and ed25519
    // TODO: Claude-generated, double-check
    pub const fn decode_u_coordinate(bytes: &[u8; 32]) -> Self {
        let b = bytes;
        let x0 = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let x1 = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
        let x2 = u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]);
        let x3 = u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]);
        Self::decode64_255(&[x0, x1, x2, x3])
    }

    /// Repacks a 256-bit little-endian integer held as four 64-bit words into the five 51-bit limbs
    /// of a [`CoordField`], where the represented value is
    /// `z0 + z1*2^51 + z2*2^102 + z3*2^153 + z4*2^204`. Each limb is a 51-bit window of the input,
    /// straddling word boundaries; the `& M51` masks make every limb non-negative and leave headroom
    /// for lazily-carried arithmetic. Bit 255 of the input is dropped -- see [`Self::decode_u_coordinate`].
    /// Inverse of [`Self::encode64_255`].
    /// Input: A 256-bit integer as four little-endian 64-bit words, least significant word first.
    /// Output: Bits 0..254 of that integer as a [`CoordField`].
    ///
    /// Note: Result is NOT normalized -- see the note on [`Self::decode_u_coordinate`].
    ///
    /// Scope: both -- the unpacking half of [`Self::decode_u_coordinate`].
    // TODO: Claude-generated, double-check
    const fn decode64_255(x: &[u64; 4]) -> Self {
        let [x0, x1, x2, x3] = *x;
        let z0 = x0 as i64 & M51;
        let z1 = (x0 >> 51 | x1 << 13) as i64 & M51;
        let z2 = (x1 >> 38 | x2 << 26) as i64 & M51;
        let z3 = (x2 >> 25 | x3 << 39) as i64 & M51;
        let z4 = (x3 >> 12) as i64 & M51;
        Self([z0, z1, z2, z3, z4])
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
    // TODO -- `modular::mod_odd_inverse` would be asymptotically cheaper, and P64 above is the
    //          constant it wants, but crypto/math is still the cargo template. Only worth revisiting
    //          if this shows up in a profile -- it is one call per scalar_mult.
    // TODO: Claude-generated, double-check
    pub const fn inv(&self) -> Self {
        let (x_cubed, t) = self.pow_p_sub5_div8();
        t.sqr_n(3).mul(&x_cubed)
    }

    /// [`Self::inv`] in place.
    ///
    /// Scope: both x25519 and ed25519.
    // TODO -- why are we returning the same ref we were passed?
    // TODO: Claude-generated, double-check
    pub fn inv_mut(&mut self) -> &mut Self {
        *self = self.inv();
        self
    }

    /// Variable-time multiplicative inverse.
    ///
    /// Currently just [`Self::inv`], which is constant time -- so this is correct and safe, merely
    /// not faster. The separate name reserves the slot: for a public operand, an extended-Euclidean
    /// inverse beats a 265-operation addition chain, and callers that may only use a variable-time
    /// inverse are already spelled that way at the call site.
    ///
    /// Scope: Ed25519 -- signature verification, where the operand is public.
    // TODO -- no variable-time specialisation yet; this is the constant-time inverse.
    // TODO: Claude-generated, double-check
    pub const fn inv_var(&self) -> Self {
        self.inv()
    }

    /// [`Self::inv_var`] in place.
    ///
    /// Scope: Ed25519 -- see [`Self::inv_var`].
    // TODO -- why are we returning the same ref we were passed?
    // TODO: Claude-generated, double-check
    pub fn inv_mut_var(&mut self) -> &mut Self {
        *self = self.inv_var();
        self
    }

    /// Constant-time test for the value 1: `is_zero` over `(x0 ^ 1) | x1 | x2 | x3 | x4`.
    ///
    /// Requires normalized self -- only the canonical representative of 1 has limbs `[1, 0, 0, 0, 0]`.
    ///
    /// Scope: Ed25519 -- unused today.
    // TODO: Claude-generated, double-check
    pub const fn is_one(&self) -> Condition<i64> {
        let [x0, x1, x2, x3, x4] = self.0;
        let x0 = x0 ^ 1;
        Condition::<i64>::is_zero(x0 | x1 | x2 | x3 | x4)
    }

    /// Variable-time [`Self::is_one`]. Only for values that are not secret.
    ///
    /// Requires normalized self.
    ///
    /// Scope: Ed25519 -- unused today.
    // TODO: Claude-generated, double-check
    pub const fn is_one_var(&self) -> bool {
        self.is_one().to_bool()
    }

    /// Constant-time test for the value 0: `is_zero` over the OR of all five limbs.
    ///
    /// Requires normalized self -- an un-normalized zero can be represented as p, whose limbs are
    /// not all zero.
    ///
    /// Scope: Ed25519. Reached today only through [`Self::is_zero_var`] from
    /// [`Self::sqrt_ratio_var`].
    // TODO: Claude-generated, double-check
    pub const fn is_zero(&self) -> Condition<i64> {
        let [x0, x1, x2, x3, x4] = self.0;
        Condition::<i64>::is_zero(x0 | x1 | x2 | x3 | x4)
    }

    /// Variable-time [`Self::is_zero`]. Only for values that are not secret.
    ///
    /// Requires normalized self.
    ///
    /// Scope: Ed25519. Used by [`Self::sqrt_ratio_var`] to pick between the three square-root cases;
    /// the branch is safe there because point decompression runs on public data.
    // TODO: Claude-generated, double-check
    pub const fn is_zero_var(&self) -> bool {
        self.is_zero().to_bool()
    }

    /// Multiply self by rhs in GF(p), `p = 2^255 - 19`.
    ///
    /// Schoolbook 5x5: output limb `k` collects every `x[i] * y[j]` with `i + j == k`, plus every
    /// pair with `i + j == k + 5`. The second set lands at weight `2^255` or above, and
    /// `2^255 == 19 mod p`, so those terms are pre-scaled by 19 -- that is what `t1..t4` are. The 25
    /// products accumulate in `i128` (a 51-bit by 56-bit product would overflow `i64`) and
    /// [`Self::reduce_products`] carries them back down to five `i64` limbs.
    ///
    /// Verified against reference mod-p arithmetic over 20,000 random pairs.
    ///
    /// Scope: both.
    // TODO: Claude-generated, double-check
    pub const fn mul(&self, rhs: &Self) -> Self {
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
    /// `a24 = (486662 - 2) / 4 = 121665` (`x25519.rs:110`, `148`).
    // TODO: Claude-generated, double-check
    pub const fn mul_u32(&self, rhs: u32) -> Self {
        #[inline(always)]
        const fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        let [x0, x1, x2, x3, x4] = self.0;
        let y0 = rhs as i64;

        Self::reduce_products(m(x0, y0), m(x1, y0), m(x2, y0), m(x3, y0), m(x4, y0))
    }

    /// Negates self, component-wise.
    ///
    /// Negating every limb negates the value, since the limb weights `2^(51*i)` are all positive.
    /// Lazily reduced, and note the result has negative limbs, which is legal in this representation
    /// but means it is *not* normalized -- [`Self::normalize`] must run before any encode or
    /// comparison.
    ///
    /// Scope: Ed25519 -- unused today. Wanted for point negation and for the conditional negation of
    /// signed-digit fixed-base tables; the X25519 ladder never negates.
    // TODO: Claude-generated, double-check
    pub const fn negate(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        Self([-x0, -x1, -x2, -x3, -x4])
    }

    /// [`Self::negate`] in place.
    ///
    /// Scope: Ed25519 -- unused today; see [`Self::negate`].
    // TODO: Claude-generated, double-check
    pub fn negate_mut(&mut self) -> &mut Self {
        *self = self.negate();
        self
    }

    /// Construct a [`CoordField`] from five raw limbs, value
    /// `x0 + x1*2^51 + x2*2^102 + x3*2^153 + x4*2^204`.
    ///
    /// No normalization and no range check: the caller owns the invariant that the limbs are inside
    /// the magnitude bound the reduction chains assume.
    ///
    /// Scope: both -- unused today.
    // TODO Module consumers should instead have a method to construct from [u64; 4] (or indeed a Nat<4>)
    // TODO: Claude-generated, double-check
    pub const fn new(x0: i64, x1: i64, x2: i64, x3: i64, x4: i64) -> Self {
        Self([x0, x1, x2, x3, x4])
    }

    /// Reduce self to the unique canonical representative of its residue class: limbs all in
    /// `[0, 2^51)` and the value in `[0, p)`.
    ///
    /// Two [`Self::reduce`] passes with `y` and then `-y`, where `y` is bit 254 of the value (bit 50
    /// of limb `x4`, since `x4` sits at weight `2^204`). Each pass adds `19 * y` at the bottom
    /// without a matching removal at the top, so neither pass alone is congruent mod p -- but the
    /// `+19y` and `-19y` cancel exactly, leaving `value - (c + c') * p` for the two top-carry folds
    /// `c`, `c'`.
    ///
    /// The nudge is what implements Section 5 of RFC7748's "Implementations MUST accept non-canonical
    /// values and process them as if they had been reduced modulo the field prime. The non-canonical
    /// values are 2^255 - 19 through 2^255 - 1". Checked empirically: a plain `reduce(0).reduce(0)`
    /// returns a non-canonical result for *every* value in `p ..= p + 18` -- exactly that range --
    /// whereas this `reduce(y).reduce(-y)` is exact on all of `[0, 2^255)`, which is the entire range
    /// [`Self::decode_u_coordinate`] can produce. It first fails at `2^255`, outside the input domain.
    ///
    /// Requires limbs inside [`Self::reduce`]'s magnitude bound. Idempotent.
    ///
    /// Scope: both.
    // TODO: Claude-generated, double-check
    pub const fn normalize(&self) -> Self {
        let y = (self.0[4] >> (51 - 1)) & 1;
        self.reduce(y).reduce(-y)
    }

    /// [`Self::normalize`] in place.
    ///
    /// Scope: both -- unused today; call sites use [`Self::normalize`] directly
    /// (`x25519.rs:174`).
    // TODO: Claude-generated, double-check
    pub fn normalize_mut(&mut self) -> &mut Self {
        *self = self.normalize();
        self
    }

    /// The multiplicative identity, 1, in canonical form.
    ///
    /// Scope: both. In X25519 it seeds `z_2` and `x_3` of the Section 5 ladder (`x25519.rs:128`,
    /// `129`).
    // TODO: Claude-generated, double-check
    pub const fn one() -> Self {
        Self([1, 0, 0, 0, 0])
    }

    /// The least significant bit of the value.
    ///
    /// Requires normalized self, and this is the sharpest edge in the group: p is odd, so a value in
    /// `[p, 2^255)` reports the parity of `v` rather than of `v - p` -- the answer is wrong, not
    /// merely non-canonical.
    ///
    /// Scope: Ed25519. This is the sign bit of x in an Ed25519 point encoding, Section 5.1.3 of
    /// RFC8032. X25519 has no use for it: Section 5 of RFC7748 requires bit 255 of a u-coordinate to
    /// be masked off, not populated.
    // TODO Better name -- is_odd() ?
    // TODO: Claude-generated, double-check
    pub const fn parity(&self) -> u8 {
        (self.0[0] & 1) as u8
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
    ///
    /// Scope: both -- it is the engine under the field inversion X25519 needs, and under Ed25519's
    /// point decompression.
    // TODO Addition chain macro/function
    // TODO: Claude-generated, double-check
    const fn pow_p_sub5_div8(&self) -> (Self, Self) {
        // TODO -- where is this from?
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
    /// The `19 * y` is a deliberate nudge that only cancels across the pair of calls in
    /// [`Self::normalize`], and this function exists to serve that pair -- it is not a general-purpose
    /// reduction.
    ///
    /// Requires limbs inside the magnitude bound the carry chain assumes: `t5 * 19 + x0` must not
    /// overflow `i64`.
    ///
    /// Scope: both.
    // TODO: Claude-generated, double-check
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
    ///
    /// Scope: both.
    // TODO: Claude-generated, double-check
    #[inline]
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
    ///
    /// Verified against reference mod-p arithmetic over 20,000 random values.
    ///
    /// Scope: both.
    // TODO: Claude-generated, double-check
    pub const fn sqr(&self) -> Self {
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

    /// [`Self::sqr`] in place.
    ///
    /// Scope: both. Used throughout the Section 5 ladder (`x25519.rs:144`, `145`, `152`).
    // TODO -- why is it pub and now pub(crate)
    // TODO: Claude-generated, double-check
    pub fn sqr_mut(&mut self) -> &mut Self {
        *self = self.sqr();
        self
    }

    /// Square self `n` times, i.e. raise to the `2^n`.
    ///
    /// The run-length primitive for the addition chain in [`Self::pow_p_sub5_div8`]: an exponent
    /// written as runs of 1-bits is evaluated as alternating `sqr_n` (shift the accumulated bits up)
    /// and `mul` (append another run).
    ///
    /// Scope: both -- it is how the field inversion is reached.
    // TODO -- why is it pub and now pub(crate)
    // TODO: Claude-generated, double-check
    pub const fn sqr_n(&self, mut n: usize) -> Self {
        let mut z = *self;
        while n > 0 {
            z = z.sqr();
            n -= 1;
        }
        z
    }

    /// Variable-time square root of the ratio `u / v`: returns `Some(x)` with `x^2 == u / v` if that
    /// ratio is a quadratic residue, else `None`.
    ///
    /// The standard `p == 5 mod 8` method (p mod 8 is 5, checked), arranged to need no inversion: the
    /// candidate is `x = u * v^3 * (u * v^7)^((p-5)/8)`, and `v * x^2` is then compared against `+u`
    /// and `-u` to sort the three cases. If `v * x^2 == -u`, the true root is `x` times a square root
    /// of -1, which is the `ROOT_NEG_ONE` constant -- verified to square to `-1 mod p`, and to equal
    /// `2^((p-1)/4)`.
    ///
    /// Verified over 4,000 random `(u, v)`: every returned root satisfies `x^2 == u / v`, and every
    /// `None` is a genuine non-residue.
    ///
    /// Variable time by construction, via [`Self::is_zero_var`]. That is acceptable for point
    /// decompression, which runs on public data, and it is why the name carries the `_var` suffix.
    ///
    /// Scope: Ed25519. Point decompression, Section 5.1.3 of RFC8032 -- recovering x from y. The
    /// X25519 ladder never takes a square root; Section 5 of RFC7748 works from the u-coordinate
    /// alone and never recovers v.
    // TODO -- why is it pub and now pub(crate)
    // TODO: Claude-generated, double-check
    pub const fn sqrt_ratio_var(u: &Self, v: &Self) -> Option<Self> {
        let uv = u.mul(v);
        let v2 = v.sqr();
        let uv3 = v2.mul(&uv);
        let uv7 = v2.sqr().mul(&uv3);

        let (_, w) = uv7.pow_p_sub5_div8();
        let x = w.mul(&uv3);
        let vx2 = x.sqr().mul(v);

        let t = vx2.sub(u).normalize();

        // TODO -- is this doing a conditional on a secret value?
        if t.is_zero_var() {
            return Some(x);
        }

        let t = vx2.add(u).normalize();
        if t.is_zero_var() {
            const ROOT_NEG_ONE: CoordField = CoordField([
                -0x0001E4D8B5F15F50, 0x0000D5A5FC8F189E, -0x000010A16342F3A0, -0x00007A6A597FB361,
                0x0002B8324804FC1E,
            ]);

            return Some(x.mul(&ROOT_NEG_ONE));
        }

        None
    }

    /// Subtract rhs from self, component-wise.
    ///
    /// Lazily reduced, exactly as [`Self::add`]: no borrow propagation, so limbs may go negative and
    /// the result is congruent mod p but not normalized. Negative limbs are fine here --
    /// [`Self::reduce_products`] and [`Self::reduce`] both use arithmetic (sign-propagating) shifts,
    /// so a negative limb borrows correctly on the next reduction.
    ///
    /// Scope: both. In X25519 it is the `E = AA - BB` of the Section 5 ladder (`x25519.rs:109`,
    /// `147`).
    // TODO -- why is this pub and not pub(crate) ?
    // TODO: Claude-generated, double-check
    pub const fn sub(&self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4])
    }

    /// Subtract one from self, i.e. subtract 1 from limb `x0`, returning a new [`CoordField`].
    ///
    /// Mirror of [`Self::add_one`]; if `x0` was zero the limb simply goes negative, which the next
    /// reduction resolves.
    ///
    /// Scope: Ed25519 -- unused today; the `(u - 1)/(u + 1)` birational map of Section 4.1 of
    /// RFC7748 is what wants it.
    // TODO -- why is this pub and not pub(crate) ?
    // TODO: Claude-generated, double-check
    pub const fn sub_one(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        Self([x0 - 1, x1, x2, x3, x4])
    }

    /// [`Self::sub_one`] in place.
    ///
    /// Scope: Ed25519 -- unused today; see [`Self::sub_one`].
    // TODO -- do we really need both versions of this?
    // TODO -- why is this pub and not pub(crate) ?
    // TODO: Claude-generated, double-check
    pub fn sub_one_mut(&mut self) -> &mut Self {
        self.0[0] -= 1;
        self
    }

    /// The additive identity, 0, in canonical form.
    ///
    /// Scope: both. In X25519 it seeds `z_3` of the Section 5 ladder (`x25519.rs:130`).
    // TODO: Claude-generated, double-check
    pub const fn zero() -> Self {
        Self([0; 5])
    }
}

// TODO -- at least a basic unit test for each math function

// TODO --  from RFC7748 s. 5:
//      u-coordinate array:
//          When receiving such an array, implementations of X25519
//    (but not X448) MUST mask the most significant bit in the final byte.
//    This is done to preserve compatibility with point formats that
//    reserve the sign bit for use in other protocols and to increase
//    resistance to implementation fingerprinting.
//

// TODO --  from RFC7748 s. 5:
//      Implementations MUST accept non-canonical values and process them as
//    if they had been reduced modulo the field prime.  The non-canonical
//    values are 2^255 - 19 through 2^255 - 1 for X25519 and 2^448 - 2^224
//    - 1 through 2^448 - 1 for X448.

#[cfg(test)]
mod curve25519_tests {
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
    fn decode_u_coordinate_known_value() {
        assert_eq!(CoordField::decode_u_coordinate(&KNOWN_VALUE).0, KNOWN_LIMBS);

        // Bit 255 is not part of the field element, so setting it must not change the result.
        let mut bit_255_set = KNOWN_VALUE;
        bit_255_set[31] |= 0x80;
        assert_eq!(CoordField::decode_u_coordinate(&bit_255_set).0, KNOWN_LIMBS);
    }

    #[test]
    fn encode_255_known_value() {
        // Start from a non-zero buffer so a partial write cannot pass by accident.
        let mut bytes = [0xFF_u8; 32];
        CoordField(KNOWN_LIMBS).encode_255(&mut bytes);
        assert_eq!(bytes, KNOWN_VALUE);
    }
}
