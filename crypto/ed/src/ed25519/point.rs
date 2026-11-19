//! Points of edwards25519, the curve `-x^2 + y^2 = 1 + d x^2 y^2` of RFC 8032 Section 5.1:
//! encoding and decoding, the group law, the fixed-base multiplication that signing and key
//! generation use, and the variable-time multiplications of verification.
//!
//! [`scalar_mult_base`] and what it calls are constant time: fixed loops, table lookups that
//! pass over every entry, and negation by mask. Everything named `_var` branches on its
//! inputs and takes public values only. Every coordinate is a [`FieldElement25519`], which
//! wipes itself when dropped, so the point types need no wiping of their own.

use super::precomp::{COMB_BASE, WNAF_BASE, WNAF_BASE_128};
use super::scalar;
use crate::bits;
use crate::curve25519::{FieldElement25519, NormalizedFieldElement25519};
use crate::wnaf;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;

/// d = -121665/121666 (RFC 8032 Section 5.1, Table 1).
const C_D: FieldElement25519 = FieldElement25519::new([
    0x034DCA135978A3, 0x01A8283B156EBD, 0x05E7A26001C029, 0x0739C663A03CBB, 0x052036CEE2B6FF,
]);
/// 2 d.
const C_D2: FieldElement25519 = FieldElement25519::new([
    0x069B9426B2F159, 0x035050762ADD7A, 0x03CF44C0038052, 0x06738CC7407977, 0x02406D9DC56DFF,
]);

/// Window width for the two 128-bit scalars of verification and for the group order.
const WNAF_WIDTH_128: usize = 4;
/// Window width for the base point in verification; fixes the size of the `WNAF_BASE` tables.
const WNAF_WIDTH_BASE: usize = 6;
/// Points in a table of odd multiples at [`WNAF_WIDTH_128`].
const WNAF_POINTS_128: usize = 1 << (WNAF_WIDTH_128 - 2);

// The fixed-base comb: the 256 signed digits of the scalar are cut into 8 blocks of 32, and
// each block into 4 teeth 8 digits apart, so that one table entry per block serves the 4 digits
// at one spacing position. `scalar_mult_base` is written for these values.
pub(super) const PRECOMP_BLOCKS: usize = 8;
pub(super) const PRECOMP_TEETH: usize = 4;
pub(super) const PRECOMP_SPACING: usize = 8;
/// Entries per block: one for each setting of the lower teeth, the top tooth giving the sign.
pub(super) const PRECOMP_POINTS: usize = 1 << (PRECOMP_TEETH - 1);
/// Entries in each of `WNAF_BASE` and `WNAF_BASE_128`.
pub(super) const PRECOMP_WNAF_POINTS: usize = 1 << (WNAF_WIDTH_BASE - 2);

/// The fixed-base multiplication checks its result before encoding it, and the check failed:
/// a fault in the arithmetic, not a property of any input.
#[derive(Debug)]
pub(super) struct ResultCheckFailed;

/// A point `(x, y)` in canonical coordinates.
#[derive(Clone)]
pub(super) struct PointAffine {
    x: NormalizedFieldElement25519,
    y: NormalizedFieldElement25519,
}

impl PointAffine {
    /// Decodes a point by RFC 8032 Section 5.1.3, or returns `None` where "decoding fails".
    /// Variable time: an encoded point is public.
    pub(super) fn decode_var(p: &[u8; 32]) -> Option<Self> {
        // Step 1: "Bit 255 of this number is the least significant bit of the x-coordinate
        // and denote this value x_0. The y-coordinate is recovered simply by clearing this
        // bit. If the resulting value is >= p, decoding fails."
        // decode_255 drops bit 255 and accepts any 255-bit value; the value was below p
        // exactly if its canonical form encodes back to the same octets.
        let x_0 = p[31] >> 7;
        let y = FieldElement25519::decode_255(p).normalize();
        let mut canonical = [0_u8; 32];
        y.encode_255(&mut canonical);
        canonical[31] |= x_0 << 7;
        if canonical != *p {
            return None;
        }

        // Step 2: "Let u = y^2 - 1 and v = d y^2 + 1."
        let y2 = y.sqr();
        let u = y2.sub(&FieldElement25519::one());
        let v = y2.mul(&C_D).add(&FieldElement25519::one());
        // Steps 2 and 3: the square root of u/v; "Otherwise, no square root exists for
        // modulo p, and decoding fails."
        let x = FieldElement25519::sqrt_ratio_var(&u, &v)?.normalize();

        // Step 4: "If x = 0, and x_0 = 1, decoding fails. Otherwise, if x_0 != x mod 2, set
        // x <-- p - x."
        if x_0 == 1 && x.is_zero_var() {
            return None;
        }
        let x = if x_0 != x.parity() { x.negate().normalize() } else { x };

        Some(Self { x, y })
    }

    /// Encodes the point by RFC 8032 Section 5.1.2: the y-coordinate in 32 little-endian
    /// octets, with "the least significant bit of the x-coordinate" in "the most significant
    /// bit of the final octet". Constant time.
    pub(super) fn encode(&self, r: &mut [u8; 32]) {
        self.y.encode_255(r);
        r[31] |= self.x.parity() << 7;
    }

    /// `-P`, which is `(-x, y)`.
    pub(super) fn negate(&self) -> Self {
        Self { x: self.x.negate().normalize(), y: self.y.clone() }
    }

    /// TRUE iff the coordinates satisfy the curve equation and y is not zero. Constant time.
    ///
    /// This is the check on a computed result. No multiple of B has y = 0 (the two points
    /// that do have order 4), so a result that does is as wrong as one off the curve.
    fn is_valid_result(&self) -> Condition<i64> {
        let (x2, y2) = (self.x.sqr(), self.y.sqr());
        let lhs = y2.sub(&x2);
        let rhs = x2.mul(&y2).mul(&C_D).add(&FieldElement25519::one());
        lhs.sub(&rhs).normalize().is_zero() & !self.y.is_zero()
    }
}

/// A public key as a point: on the curve, in the subgroup generated by B, and not the neutral
/// element. The only constructor is [`Self::decode_var`], so holding one is holding a fully
/// validated key.
#[derive(Clone)]
pub(crate) struct PublicPoint(PointAffine);

impl PublicPoint {
    /// Decodes and fully validates a public key, or returns `None`: the encoding must be that
    /// of a point (RFC 8032 Section 5.1.3), and the point must have order L. Costs about one
    /// scalar multiplication. Variable time: a public key is public.
    pub(crate) fn decode_var(pk: &[u8; 32]) -> Option<Self> {
        let point = PointAffine::decode_var(pk)?;
        // x = 0 is the neutral element (0, 1), and (0, -1) of order 2. The neutral element
        // would pass the order check below; every other point outside the subgroup, of small
        // order or of mixed order, fails it, because L is odd.
        if point.x.is_zero_var() {
            return None;
        }
        if !scalar_mult_order_var(&point).normalizes_to_neutral_var() {
            return None;
        }
        Some(Self(point))
    }

    /// The encoding the key was decoded from.
    pub(crate) fn encode(&self, pk: &mut [u8; 32]) {
        self.0.encode(pk);
    }

    pub(super) fn point(&self) -> &PointAffine {
        &self.0
    }
}

/// A point `(X : Y : Z)` in projective coordinates, x = X/Z and y = Y/Z, with the product
/// `T = U V` of extended coordinates (RFC 8032 Section 5.1.4, x y = T/Z) kept as its two
/// factors, which is how a doubling or an addition leaves it (the RFC's E and H).
#[derive(Default)]
pub(super) struct PointAccum {
    x: FieldElement25519,
    y: FieldElement25519,
    z: FieldElement25519,
    u: FieldElement25519,
    v: FieldElement25519,
}

impl PointAccum {
    /// The neutral element, (0, 1).
    pub(super) fn neutral() -> Self {
        Self {
            x: FieldElement25519::zero(),
            y: FieldElement25519::one(),
            z: FieldElement25519::one(),
            u: FieldElement25519::zero(),
            v: FieldElement25519::one(),
        }
    }

    /// `self = 2 self`, by the doubling formulas of RFC 8032 Section 5.1.4. Constant time.
    fn double(&mut self) {
        // A = X1^2, B = Y1^2, and c = Z1^2 where C = 2 c
        let a = self.x.sqr();
        let b = self.y.sqr();
        let c = self.z.sqr();
        let e = self.x.add(&self.y);
        // H = A + B, G = A - B
        let (h, g) = a.sum_and_difference(&b);
        self.v = h;
        // E = H - (X1 + Y1)^2
        self.u = self.v.sub(&e.sqr()).carry();
        // F = C + G
        let f = g.add(&c).add(&c).carry();
        // X3 = E F, Y3 = G H, Z3 = F G; T3 = E H stays as u and v.
        self.x = f.mul(&self.u);
        self.y = g.mul(&self.v);
        self.z = f.mul(&g);
    }

    /// `self += p`, by the addition formulas of RFC 8032 Section 5.1.4 with Z2 = 1. The
    /// table entry holds half of Y2 - X2 and of Y2 + X2 and half of 2 d T2, so every one of
    /// the RFC's A to H comes out halved and the result is scaled by 1/4, which a projective
    /// point does not notice. Constant time.
    fn accumulate_precomp(&mut self, p: &PointPrecomp) {
        // b = Y1 + X1, a = Y1 - X1
        let (b, a) = self.y.sum_and_difference(&self.x);
        // A/2, B/2, and C/2 = T1 d T2
        let a = a.mul(&p.ymx_h);
        let b = b.mul(&p.ypx_h);
        let c = self.u.mul(&self.v).mul(&p.xyd);
        // H/2 = B/2 + A/2, E/2 = B/2 - A/2
        let (h, e) = b.sum_and_difference(&a);
        self.v = h;
        self.u = e;
        // D/2 = Z1; G/2 = D/2 + C/2, F/2 = D/2 - C/2
        let (g, f) = self.z.sum_and_difference(&c);
        self.x = f.mul(&self.u);
        self.y = g.mul(&self.v);
        self.z = f.mul(&g);
    }

    /// `self += p`, or `self -= p` when `negate`: [`Self::accumulate_precomp`], where taking
    /// `-p` exchanges the entry's first two fields and negates the third, which exchanges F
    /// and G. Variable time in `negate`.
    fn accumulate_precomp_var(&mut self, negate: bool, p: &PointPrecomp) {
        let (b, a) = self.y.sum_and_difference(&self.x);
        let (a, b) = if negate {
            (a.mul(&p.ypx_h), b.mul(&p.ymx_h))
        } else {
            (a.mul(&p.ymx_h), b.mul(&p.ypx_h))
        };
        let c = self.u.mul(&self.v).mul(&p.xyd);
        let (h, e) = b.sum_and_difference(&a);
        self.v = h;
        self.u = e;
        let (sum, difference) = self.z.sum_and_difference(&c);
        let (f, g) = if negate { (sum, difference) } else { (difference, sum) };
        self.x = f.mul(&self.u);
        self.y = g.mul(&self.v);
        self.z = f.mul(&g);
    }

    /// As [`Self::accumulate_precomp_var`] for an entry with a Z coordinate: here the entry
    /// holds Y2 - X2, Y2 + X2, 2 d T2 and 2 Z2 whole, so the RFC's A to H are not halved.
    fn accumulate_precomp_z_var(&mut self, negate: bool, p: &PointPrecompZ) {
        let (b, a) = self.y.sum_and_difference(&self.x);
        let (a, b) =
            if negate { (a.mul(&p.ypx), b.mul(&p.ymx)) } else { (a.mul(&p.ymx), b.mul(&p.ypx)) };
        let c = self.u.mul(&self.v).mul(&p.t2d);
        let d = self.z.mul(&p.z2);
        let (h, e) = b.sum_and_difference(&a);
        self.v = h;
        self.u = e;
        let (sum, difference) = d.sum_and_difference(&c);
        let (f, g) = if negate { (sum, difference) } else { (difference, sum) };
        self.x = f.mul(&self.u);
        self.y = g.mul(&self.v);
        self.z = f.mul(&g);
    }

    /// The point in canonical affine coordinates, by one inversion (a fixed addition chain).
    /// Constant time.
    fn to_affine(&self) -> PointAffine {
        let z_inv = self.z.inv();
        PointAffine { x: self.x.mul(&z_inv).normalize(), y: self.y.mul(&z_inv).normalize() }
    }

    /// Writes the encoding of the point to `r` and returns whether the point passed
    /// [`PointAffine::is_valid_result`]; the caller must not release an encoding that did not.
    /// Constant time.
    fn encode_checked(&self, r: &mut [u8; 32]) -> Condition<i64> {
        let q = self.to_affine();
        q.encode(r);
        q.is_valid_result()
    }

    /// Whether this is the neutral element: X = 0 and Y = Z, not zero. Variable time.
    pub(super) fn normalizes_to_neutral_var(&self) -> bool {
        let (x, y, z) = (self.x.normalize(), self.y.normalize(), self.z.normalize());
        x.is_zero_var() && !y.is_zero_var() && NormalizedFieldElement25519::are_equal_var(&y, &z)
    }
}

/// A point in the extended coordinates `(X, Y, Z, T)` of RFC 8032 Section 5.1.4.
struct PointExtended {
    x: FieldElement25519,
    y: FieldElement25519,
    z: FieldElement25519,
    t: FieldElement25519,
}

impl PointExtended {
    fn from_affine(p: &PointAffine) -> Self {
        Self { x: (*p.x).clone(), y: (*p.y).clone(), z: FieldElement25519::one(), t: p.x.mul(&p.y) }
    }

    /// `self + rhs`, by the addition formulas of RFC 8032 Section 5.1.4.
    fn add(&self, rhs: &Self) -> Self {
        // b = Y1 + X1, a = Y1 - X1; d = Y2 + X2, c = Y2 - X2
        let (b, a) = self.y.sum_and_difference(&self.x);
        let (d, c) = rhs.y.sum_and_difference(&rhs.x);
        // A = (Y1-X1)*(Y2-X2), B = (Y1+X1)*(Y2+X2), C = T1*2*d*T2, D = Z1*2*Z2
        let a = a.mul(&c);
        let b = b.mul(&d);
        let c = self.t.mul(&rhs.t).mul(&C_D2);
        let d = self.z.add(&self.z).mul(&rhs.z);
        // H = B+A, E = B-A, G = D+C, F = D-C
        let (h, e) = b.sum_and_difference(&a);
        let (g, f) = d.sum_and_difference(&c);
        // X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
        Self { x: f.mul(&e), y: g.mul(&h), z: f.mul(&g), t: e.mul(&h) }
    }
}

/// An entry of a fixed table, for a point in affine coordinates: what
/// [`PointAccum::accumulate_precomp`] multiplies by.
pub(super) struct PointPrecomp {
    /// (y - x)/2
    pub(super) ymx_h: FieldElement25519,
    /// (y + x)/2
    pub(super) ypx_h: FieldElement25519,
    /// x y d
    pub(super) xyd: FieldElement25519,
}

/// An entry of a table built for one verification, for a point in extended coordinates.
struct PointPrecompZ {
    /// Y - X
    ymx: FieldElement25519,
    /// Y + X
    ypx: FieldElement25519,
    /// 2 d T
    t2d: FieldElement25519,
    /// 2 Z
    z2: FieldElement25519,
}

impl PointPrecompZ {
    fn from_extended(p: &PointExtended) -> Self {
        let (ypx, ymx) = p.y.sum_and_difference(&p.x);
        Self { ymx, ypx, t2d: p.t.mul(&C_D2), z2: p.z.add(&p.z) }
    }
}

/// The odd multiples `P, 3P, .., (2N - 1)P`.
fn precompute_z_var<const N: usize>(p: &PointAffine) -> [PointPrecompZ; N] {
    let mut q = PointExtended::from_affine(p);
    let twice = q.add(&q);
    core::array::from_fn(|i| {
        if i > 0 {
            q = twice.add(&q);
        }
        PointPrecompZ::from_extended(&q)
    })
}

/// Selects entry `index` of one block of the comb table into `p`, reading every entry.
/// Constant time in `index`, which is secret.
fn lookup(block: &[PointPrecomp; PRECOMP_POINTS], index: i64, p: &mut PointPrecomp) {
    for (i, entry) in block.iter().enumerate() {
        let hit = Condition::<i64>::is_zero(i as i64 ^ index);
        p.ymx_h.cmov(hit, &entry.ymx_h);
        p.ypx_h.cmov(hit, &entry.ypx_h);
        p.xyd.cmov(hit, &entry.xyd);
    }
}

/// Gathers the comb's digits in each limb: on return, each 32-bit half of a limb (a block)
/// holds eight 4-bit groups, group j having the block's digits `j, j + 8, j + 16, j + 24`,
/// the four teeth at spacing position j. Constant time.
fn group_comb_bits(n: &mut [u64; 4]) {
    for n_i in n {
        let mut x = *n_i;
        x = bits::bit_permute_step_64(x, 0x0000F0F00000F0F0, 12);
        x = bits::bit_permute_step_64(x, 0x00CC00CC00CC00CC, 6);
        x = bits::bit_permute_step_64(x, 0x2222222222222222, 1);
        x = bits::bit_permute_step_64(x, 0x0C0C0C0C0C0C0C0C, 2);
        *n_i = x;
    }
}

/// `r = [k]B` for a scalar `k < 2^256 - L` in 32 little-endian octets: the pruned secret
/// scalar `s` or a reduced `r` (RFC 8032 Sections 5.1.5, step 3, and 5.1.6, step 3).
///
/// A fixed-base comb: `k` is recoded to 256 digits of +1 and -1
/// ([`scalar::to_signed_digits`]), and the table in `precomp` holds, for each block, the sums
/// of that block's four teeth over every setting of the lower three, with the top tooth
/// negative. A group whose top tooth is positive selects the entry for the complement of the
/// lower three and takes its negation.
///
/// Constant time: 64 lookups and additions and 7 doublings whatever `k` is; the lookup reads
/// every entry of its block, and negation is by mask. Instead of negating the entry, the
/// accumulator is negated whenever the sign changes from the one before and once more at the
/// end. The recoded scalar is held in a [`Secret`]; the selected entry and the accumulator
/// wipe themselves, `r` when its owner drops it.
pub(super) fn scalar_mult_base(k: &[u8; 32], r: &mut PointAccum) {
    let mut n = Secret::<[u64; 4]>::new();
    scalar::decode_into(k, &mut *n);
    scalar::to_signed_digits(&mut n);
    group_comb_bits(&mut n);

    let mut p = PointPrecomp {
        ymx_h: FieldElement25519::zero(),
        ypx_h: FieldElement25519::zero(),
        xyd: FieldElement25519::zero(),
    };
    *r = PointAccum::neutral();
    // 1 while r holds the negation of the running sum.
    let mut result_sign = 0_i64;

    for position in (0..PRECOMP_SPACING).rev() {
        for (block, table) in COMB_BASE.iter().enumerate() {
            let block32 = (n[block >> 1] >> ((block & 1) << 5)) as u32;
            let w = block32 >> (position * PRECOMP_TEETH);
            let sign = ((w >> (PRECOMP_TEETH - 1)) & 1) as i64;
            let abs = (w as i64 ^ -sign) & (PRECOMP_POINTS as i64 - 1);

            lookup(table, abs, &mut p);

            let flip = Condition::<i64>::is_not_zero(result_sign ^ sign);
            r.x.cnegate(flip);
            r.u.cnegate(flip);
            result_sign = sign;

            r.accumulate_precomp(&p);
        }

        if position > 0 {
            r.double();
        }
    }

    let flip = Condition::<i64>::is_not_zero(result_sign);
    r.x.cnegate(flip);
    r.u.cnegate(flip);
}

/// Writes the encoding of `[k]B` to `r`, for `k` as [`scalar_mult_base`] takes it, after
/// checking that the result is a point of the curve; on failure `r` is cleared. Constant
/// time; the outcome of the check is not secret.
pub(super) fn scalar_mult_base_encoded(
    k: &[u8; 32],
    r: &mut [u8; 32],
) -> Result<(), ResultCheckFailed> {
    let mut p = PointAccum::default();
    scalar_mult_base(k, &mut p);
    if p.encode_checked(r).to_bool() {
        Ok(())
    } else {
        r.fill(0);
        Err(ResultCheckFailed)
    }
}

/// `[L]P`. Variable time.
fn scalar_mult_order_var(p: &PointAffine) -> PointAccum {
    let mut ws_p = [0_i8; 253];
    scalar::get_order_wnaf_var(WNAF_WIDTH_128, &mut ws_p);

    let tp = precompute_z_var::<WNAF_POINTS_128>(p);

    let mut r = PointAccum::neutral();
    for bit in (0..ws_p.len()).rev() {
        let wp = ws_p[bit];
        if wp != 0 {
            r.accumulate_precomp_z_var(wp < 0, &tp[wnaf_index(wp)]);
        }
        if bit > 0 {
            r.double();
        }
    }
    r
}

/// Where the odd digit `w` finds its magnitude in a table of odd multiples: `(|w| - 1) / 2`.
fn wnaf_index(w: i8) -> usize {
    (w >> 1 ^ w >> 7) as usize
}

/// `[8]([nb]B + [np]P + [nq]Q)`, for `nb < L` and signed 128-bit `np` and `nq` in two's
/// complement: the left-hand side of the cofactored verification equation, by Straus's method
/// over width-w NAFs, with `nb` split into two 128-bit halves that share the doublings through
/// the table for `[2^128]B`. Variable time.
pub(super) fn scalar_mult_straus_128_var(
    nb: &[u64; 4],
    np: &[u64; 2],
    p: &PointAffine,
    nq: &[u64; 2],
    q: &PointAffine,
) -> PointAccum {
    debug_assert_eq!(0, nb[3] >> 61);

    let mut ws_b = [0_i8; 256];
    let mut ws_p = [0_i8; 128];
    let mut ws_q = [0_i8; 128];
    wnaf::get_signed_var(nb, WNAF_WIDTH_BASE, &mut ws_b);
    wnaf::get_signed_var(np, WNAF_WIDTH_128, &mut ws_p);
    wnaf::get_signed_var(nq, WNAF_WIDTH_128, &mut ws_q);

    let tp = precompute_z_var::<WNAF_POINTS_128>(p);
    let tq = precompute_z_var::<WNAF_POINTS_128>(q);

    let mut r = PointAccum::neutral();

    // Start at the highest position with a digit.
    let mut bit = 127;
    while bit > 0 && ws_b[bit] | ws_b[128 + bit] | ws_p[bit] | ws_q[bit] == 0 {
        bit -= 1;
    }

    loop {
        let wb = ws_b[bit];
        if wb != 0 {
            r.accumulate_precomp_var(wb < 0, &WNAF_BASE[wnaf_index(wb)]);
        }
        let wb128 = ws_b[128 + bit];
        if wb128 != 0 {
            r.accumulate_precomp_var(wb128 < 0, &WNAF_BASE_128[wnaf_index(wb128)]);
        }
        let wp = ws_p[bit];
        if wp != 0 {
            r.accumulate_precomp_z_var(wp < 0, &tp[wnaf_index(wp)]);
        }
        let wq = ws_q[bit];
        if wq != 0 {
            r.accumulate_precomp_z_var(wq < 0, &tq[wnaf_index(wq)]);
        }

        r.double();

        if bit == 0 {
            break;
        }
        bit -= 1;
    }

    // With the doubling that ends the loop, these multiply by the cofactor, 8.
    r.double();
    r.double();
    r
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::String;
    use std::vec::Vec;

    // Known answers from the prototype this module was ported from (bc-rust-nursery,
    // crates/ed25519): its `scalar_mult_base`, point decoding (`check_point_var` then
    // `decode_point_var`), `validate_public_key_full` and `scalar_mult_straus_128_var`, on
    // edge values and on values from splitmix64 with a fixed seed. Printed by the scratch
    // program described in `nat.rs` (`kat-gen points`, not in this repository). Scalars and
    // points are 32 little-endian octets in hexadecimal.

    // (k, the encoding of [k]B)
    const BASE_MULT_KATS: &[(&str, &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "5866666666666666666666666666666666666666666666666666666666666666",
        ),
        (
            "0200000000000000000000000000000000000000000000000000000000000000",
            "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "58666666666666666666666666666666666666666666666666666666666666e6",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000040",
            "693e47972caf527c7883ad1b39822f026f47db2ab0e1919955b8993aa04411d1",
        ),
        (
            "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "12e9a68b73fd5aacdbcaf3e88c46fea6ebedb1aa84eed1842f07f8edab65e3a7",
        ),
        (
            "d6772870d612a733e92a1321c88aa71b62c24a7f691213b3d17a3bb62c3abb00",
            "03e8b7886e8f418a88a8b29a93999e7bae1a9985be798dc0f5260136bf47c153",
        ),
        (
            "704268cf0c7da884b9655167cebb3f71d9941d943fec3d8aa45be104a1006f72",
            "0b1a8cc7ce0977eea5992c175943ac05af4de829622a2900b5c53019891ce895",
        ),
        (
            "eb87d7d3fb078e2fab69793bc4ec1810326a1d8940843fd9bcf9d7a452bde70d",
            "ea9850dbdbff307589a202376aef43274f10be74391c7af2c697533712009648",
        ),
        (
            "e87ea21b735309bf078e074e96932b5ba6b5e0ba0b5c6355c8525b377a3be879",
            "2ca01c916216e980ee3e50ce5d86245af3bde148c9918a1350c9e89f4fbcd140",
        ),
        (
            "749819169f22449a745d6f35b73cac85046542812534cfa5ff74fc9b17c8c70e",
            "f60263213a05a2d3d6be8ee1a5053d9124b61f186b4db404b0a0ba6cab7e81f5",
        ),
        (
            "504fd42788d32d4addc6284e59840492225c77ecd95abcdbedc051cb517d467c",
            "ab44975e5e71c58a97cdf12f3612f37f04eaecac4d1ded700ddfffd00facd3c9",
        ),
        (
            "0cdd3fcd79b9786fdba765e6a7d1f164ff15a21b28cf796836152a56a1107802",
            "7afc3da3f5d04ccbeffe407258b90b040c1ef969bedbbbaa0c9f9fcfd169ac8f",
        ),
        (
            "388ae5534f260976d38e9e4c819fcd78152e03ff416fd51b8f77c1c38f08a54b",
            "f851654b7d455e49ef87a5693ba69b257254b0f43a7b1f92be36cc9c3dc95943",
        ),
        (
            "b70375d136050c96dc6cc22ad985ff4e3a41f54d7fd85c07e2c5f5b4f1dfaf05",
            "068acf94ac2f0e3880408f6217a08213efe459fafd059f23b35e3b81cdf8fb94",
        ),
        (
            "b8749e5b0f89e0956101875467fd530bedba4371a62785c1a63ded4d5a2d734f",
            "cca6fd0f1850982a805839a68007a5aae12cc7ff45c0757da9fb87b3520b2eaf",
        ),
        (
            "c9d16bed6478a1377ea65ec722efb6ae1bbc491a081cc2ea787919fb85788b0b",
            "54e8603a752a95b736496524fcce4a41a3d001386aef61fc9c244b0e0cd3fed4",
        ),
        (
            "e8e8be935de9744a8faf18823be9bbe83a29d14819eebb01d20851246c070972",
            "4883ba8cf09696ead4c9b0d1dfec5ee1bb7b480c8d5fca11d50a4a192e588e92",
        ),
        (
            "66dceedd31b63407cd4beea949eeafc76d1975ded8c103819a93c40949be7700",
            "5f12e9015a8229481b9af392fbd449f82a6bba57a96e0fb431361b04d28b9731",
        ),
        (
            "88a66ba8a9f1ba9ca580b369d7ee0e3adf1e5b46360811625d42674b1e095c7d",
            "032ca33952f457ae817f0c4aa87fce7015489ef298540d1733731d2f6ffe6ce3",
        ),
        (
            "d8fc057ce84420532de99efea2584f4bdf5d16ba3f27be01b8e6db5376155e09",
            "456511bd43c329218622fd224f8f370ea275c17d9d46deca801b90fe0aa54ac6",
        ),
        (
            "007d4880c3b4d6d0c0ecda9eaa9896fe83dae98b038dc8764050c5b0fbaf786e",
            "044fd6fd0b07a169e1500b3988b1ab6068d4303a49822ee98cc720499b795b72",
        ),
        (
            "d9818d544bb55468ade4eea256f52799256a8f68d2e6edb33027c5cb5178a40d",
            "408a08c78a944ae205954c3d0f819e460e211fb47803e13c737a300b56e0170e",
        ),
        (
            "6011224c101764fe935e5b0c3f0229331192f41230109fc2a61e1032a429f94f",
            "9383d5060c526f9346d65db5908bc63cc1ae59a534fff029a1178830254cc71b",
        ),
        (
            "c8ba62a1e07210036725195087d1de17e9ed7efbc78753afba939cc0603f1f0a",
            "c30100c4ab11e08883f22afb415646c292c283f4d4f16026ef3f5c709f1758ab",
        ),
        (
            "f8d34bca6e72cc3f8a86542da249bc3ce5c00f58b79004d881078a4661b30867",
            "f6ab27981d5cebee3963753686981df598a517b7e27e3dc64c8022775aa3b703",
        ),
    ];

    // (encoding, the x-coordinate if it decodes)
    const DECODE_KATS: &[(&str, Option<&str>)] = &[
        (
            "5866666666666666666666666666666666666666666666666666666666666666",
            Some("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921"),
        ),
        (
            "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
            Some("0ece43284ea1c5835fa4d715458e0d08ace733187d3b043d6c045a9f4c38ab36"),
        ),
        (
            "58666666666666666666666666666666666666666666666666666666666666e6",
            Some("d32ada709fd2a9364d58da6a9f38d396a3232902ce1d5b3f01ac91322cc9965e"),
        ),
        (
            "693e47972caf527c7883ad1b39822f026f47db2ab0e1919955b8993aa04411d1",
            Some("1d864ecff73710258f12fb19fbe0ed10c8e2f575b133c0960dfb156c0d075f05"),
        ),
        (
            "12e9a68b73fd5aacdbcaf3e88c46fea6ebedb1aa84eed1842f07f8edab65e3a7",
            Some("fbdb12757ad51e2437078b8d291427dc62282da2c46374089d9770e9a4143b1b"),
        ),
        (
            "03e8b7886e8f418a88a8b29a93999e7bae1a9985be798dc0f5260136bf47c153",
            Some("a825c78405845861e360cd25e7aed86c50c5c846c39b489f153b7a27932c032c"),
        ),
        (
            "0b1a8cc7ce0977eea5992c175943ac05af4de829622a2900b5c53019891ce895",
            Some("db371b344640b7fb391f445bd50d90e7e12337f1c1eba001ca55d7e9cfce2b26"),
        ),
        (
            "58666666666666666666666666666666666666666666666666666666666666e6",
            Some("d32ada709fd2a9364d58da6a9f38d396a3232902ce1d5b3f01ac91322cc9965e"),
        ),
        (
            "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd60a2",
            Some("df31bcd7b15e3a7ca05b28eaba71f2f75318cce782c4fbc293fba560b3c75449"),
        ),
        (
            "5866666666666666666666666666666666666666666666666666666666666666",
            Some("1ad5258f602d56c9b2a7259560c72c695cdcd6fd31e2a4c0fe536ecdd3366921"),
        ),
        (
            "693e47972caf527c7883ad1b39822f026f47db2ab0e1919955b8993aa0441151",
            Some("d079b13008c8efda70ed04e6041f12ef371d0a8a4ecc3f69f204ea93f2f8a07a"),
        ),
        (
            "12e9a68b73fd5aacdbcaf3e88c46fea6ebedb1aa84eed1842f07f8edab65e327",
            Some("f223ed8a852ae1dbc8f87472d6ebd8239dd7d25d3b9c8bf762688f165bebc464"),
        ),
        (
            "03e8b7886e8f418a88a8b29a93999e7bae1a9985be798dc0f5260136bf47c1d3",
            Some("45da387bfa7ba79e1c9f32da18512793af3a37b93c64b760eac485d86cd3fc53"),
        ),
        (
            "0b1a8cc7ce0977eea5992c175943ac05af4de829622a2900b5c53019891ce815",
            Some("12c8e4cbb9bf4804c6e0bba42af26f181edcc80e3e145ffe35aa28163031d459"),
        ),
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        ),
        ("0100000000000000000000000000000000000000000000000000000000000080", None),
        (
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        ),
        ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", None),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            Some("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b"),
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000080",
            Some("3d5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54"),
        ),
        ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", None),
        ("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", None),
        ("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", None),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", None),
        ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", None),
        ("0200000000000000000000000000000000000000000000000000000000000000", None),
        (
            "0300000000000000000000000000000000000000000000000000000000000000",
            Some("e205ae011fe6f6fe07bc30dd4b960d1c3128efb158af48f48e601326d4bffe68"),
        ),
        (
            "0400000000000000000000000000000000000000000000000000000000000000",
            Some("2e5aa4f90b86f32dd444eddf6464943830746c180020494341ea432802dee839"),
        ),
        (
            "0500000000000000000000000000000000000000000000000000000000000000",
            Some("a2a2efbf72402f2b2f922418ba42d3fe9a732f1c59c8ecd5ef8ee21b01f1af57"),
        ),
        ("8942d8954e32f7766e67848627ac1f462c5fb965b7975cf1cd10dbdd08058f88", None),
        (
            "aeee0f4f8da5f19bbc650d1d5e3ef0cdf8a188ac52086f0c1bd64444e32c3480",
            Some("973ec1727f4b8b846f4847dff87ec8bf36e09e3d1ffd2e853f92615d13289b44"),
        ),
        (
            "f611492ac85a820c7338adf1120545c95adb296b6b342bf93f12493845e46e0a",
            Some("78c0592e4370ee4957cd7014eeffce3c558a0596adb7d0ce2243908c0c413b04"),
        ),
        ("265785c2319883d2a3cb23ca442ec55a659024ecc678f153d7b75e3a2a124a95", None),
        ("2856753edc8b724cfc329b0202116ae202ecd1659503c52f8d03e69fa0e3fb05", None),
        (
            "58d61eb60f262880168b69310dc11f6ddc05fc8f0a36d6f995bf4e49ddd097e1",
            Some("799f35c686ea21c4b2b9a10df13c031acc534e8c78e3d0261f322bf24430ce3a"),
        ),
        (
            "5279fc402866387a6c1df4ce264f448e882fef853640982f2cd84ecc7977b18f",
            Some("8979fa7d9c71c23dc8a2af7b210bb22712aeaf3803979e2742007618730f1071"),
        ),
        ("19412f6b025bb5128c9d2c6cd1979979dd7ade736e2a82a9e98a271d7cce547d", None),
        (
            "1272645896b2d9274fd9e280de8e44705d82e327805fa85937247768767f63ec",
            Some("75f5d309a88791a462a01ca9c820518cc1a153e4977c54e86ab95f1aa46b400f"),
        ),
        (
            "2c65211a649f32b9795f3666c907992153415668d8181bb716a84161599a9d8a",
            Some("7105c00740742550f9ad6896c68ac769231d5f0038b36f28bd9950d0bc0d663d"),
        ),
    ];

    // (encoding, whether it is a fully valid public key)
    const PUBLIC_KEY_KATS: &[(&str, bool)] = &[
        ("0100000000000000000000000000000000000000000000000000000000000000", false),
        ("5866666666666666666666666666666666666666666666666666666666666666", true),
        ("c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022", true),
        ("58666666666666666666666666666666666666666666666666666666666666e6", true),
        ("693e47972caf527c7883ad1b39822f026f47db2ab0e1919955b8993aa04411d1", true),
        ("12e9a68b73fd5aacdbcaf3e88c46fea6ebedb1aa84eed1842f07f8edab65e3a7", true),
        ("03e8b7886e8f418a88a8b29a93999e7bae1a9985be798dc0f5260136bf47c153", true),
        ("0b1a8cc7ce0977eea5992c175943ac05af4de829622a2900b5c53019891ce895", true),
        ("ea9850dbdbff307589a202376aef43274f10be74391c7af2c697533712009648", true),
        ("2ca01c916216e980ee3e50ce5d86245af3bde148c9918a1350c9e89f4fbcd140", true),
        ("f60263213a05a2d3d6be8ee1a5053d9124b61f186b4db404b0a0ba6cab7e81f5", true),
        ("ab44975e5e71c58a97cdf12f3612f37f04eaecac4d1ded700ddfffd00facd3c9", true),
        ("7afc3da3f5d04ccbeffe407258b90b040c1ef969bedbbbaa0c9f9fcfd169ac8f", true),
        ("f851654b7d455e49ef87a5693ba69b257254b0f43a7b1f92be36cc9c3dc95943", true),
        ("068acf94ac2f0e3880408f6217a08213efe459fafd059f23b35e3b81cdf8fb94", true),
        ("cca6fd0f1850982a805839a68007a5aae12cc7ff45c0757da9fb87b3520b2eaf", true),
        ("54e8603a752a95b736496524fcce4a41a3d001386aef61fc9c244b0e0cd3fed4", true),
        ("4883ba8cf09696ead4c9b0d1dfec5ee1bb7b480c8d5fca11d50a4a192e588e92", true),
        ("5f12e9015a8229481b9af392fbd449f82a6bba57a96e0fb431361b04d28b9731", true),
        ("032ca33952f457ae817f0c4aa87fce7015489ef298540d1733731d2f6ffe6ce3", true),
        ("456511bd43c329218622fd224f8f370ea275c17d9d46deca801b90fe0aa54ac6", true),
        ("044fd6fd0b07a169e1500b3988b1ab6068d4303a49822ee98cc720499b795b72", true),
        ("408a08c78a944ae205954c3d0f819e460e211fb47803e13c737a300b56e0170e", true),
        ("9383d5060c526f9346d65db5908bc63cc1ae59a534fff029a1178830254cc71b", true),
        ("c30100c4ab11e08883f22afb415646c292c283f4d4f16026ef3f5c709f1758ab", true),
        ("f6ab27981d5cebee3963753686981df598a517b7e27e3dc64c8022775aa3b703", true),
        ("0000000000000000000000000000000000000000000000000000000000000000", false),
        ("0000000000000000000000000000000000000000000000000000000000000080", false),
        ("0100000000000000000000000000000000000000000000000000000000000000", false),
        ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false),
        ("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", false),
        ("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", false),
        ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", false),
        ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", false),
        ("0100000000000000000000000000000000000000000000000000000000000080", false),
        ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false),
        ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false),
        ("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false),
        ("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false),
        ("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", false),
        ("1a13da9b7029cc519ce4c9eb5599d18573ada881d2d739b62d72dcb730e682e1", false),
        ("8020ce03f6452e15bf35b49794ae67a57361ae33296e2c637723b16ce8cd8a32", false),
        ("c15fe36e9de9167f11c1af31a279dba50c421eb7366e75ecaf361760b0432ebf", false),
        ("c08492724aecfadba45a8f1f54e9a4eedf508aed0fae92fdc24afaa75a0ec5b1", false),
        ("d1791a31d92b2b6681d6ffc73a866f74a419df2643efd269ff6b75ee7dc74199", false),
        ("3bbf565aeb89b54f55de1d49277d364ecbd8963aa2829fcb3b90ca5fc72ef8a3", false),
        ("c383dae84d3847997409e078815d152820f3e1633c6adbc68fd5219899319abe", false),
        ("de6f1e398aa03c8fb6f45a84f54a7b679aa379b8d59b20e58cf36218e71fbd1a", false),
        ("87a565b43e0b15dad9407f89af90e6df75025b9d59b57cd4873e3f38b35a8103", false),
        ("4770d46bbc66c0b2fb0ce10e6892b38a0d5f994ce9f502140c09cb524f7c629c", false),
        ("137601e67076b4267e373527a69643644404beb7960f71cbe23070e8efa67455", true),
        ("494149341fc6e0134a581f07751e792dda0de33955e718f6d155d8f53c2aefbc", false),
        ("bc32219d659633541ac96b377981372b5db9630bc83d13a7d67c9b1a67eceff5", false),
        ("c00db5eea1fe9c12caff69bb05f74f64745196b9f315ef90d7819bd5a5e1becd", true),
        ("2f77aefd31b7ed9845f513064f9187e1c425bd091af0eda5ac94bce6cb597f5e", false),
        ("f0c4ea83c7ea96b0f27101d2c8064458b152b309f4df7ed95f340d950be75c79", false),
        ("8882919174a5ec94b49098bb06b68c32e7ed06d9dcac7e07b1d6d0906839ed9f", false),
        ("fe75af43544c6f9242945cdcde7b35d2d03f64b94aa119248f18336c4986a1d6", false),
        ("5eebd5981ec6cb2e1c233630f715ab83b1422741202103c83ced9f356101486e", false),
    ];

    // (nb, np, P, nq, Q, the encoding of [8]([nb]B + [np]P + [nq]Q)); np and nq are
    // 16 octets of two's complement
    const STRAUS_KATS: &[(&str, &str, &str, &str, &str, &str)] = &[
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "5866666666666666666666666666666666666666666666666666666666666666",
            "00000000000000000000000000000000",
            "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "0100000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "5866666666666666666666666666666666666666666666666666666666666666",
            "00000000000000000000000000000000",
            "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
            "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "01000000000000000000000000000000",
            "5866666666666666666666666666666666666666666666666666666666666666",
            "00000000000000000000000000000000",
            "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
            "b4b937fca95b2f1e93e41e62fc3c78818ff38a66096fad6e7973e5c90006d321",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "00000000000000000000000000000000",
            "5866666666666666666666666666666666666666666666666666666666666666",
            "ffffffffffffffffffffffffffffffff",
            "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
            "eb2767c137ab7ad8279c078eff116ab0786ead3a2e0f989f72c37f82f29696f0",
        ),
        (
            "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
            "ffffffffffffffffffffffffffffff7f",
            "58666666666666666666666666666666666666666666666666666666666666e6",
            "01000000000000000000000000000080",
            "693e47972caf527c7883ad1b39822f026f47db2ab0e1919955b8993aa04411d1",
            "51778771bf4b84a4dd5cd1deb1703cb0680360497972da8eea2f76b9b3dbfaa9",
        ),
        (
            "c67971d52f74b63fe9f124cae935e0665acd3f8cc6e71d25acdd57914017890b",
            "b6fd06fb0137b92fe703b541568994cb",
            "03e8b7886e8f418a88a8b29a93999e7bae1a9985be798dc0f5260136bf47c153",
            "39858de15c602b9902a32551bd01d72c",
            "0b1a8cc7ce0977eea5992c175943ac05af4de829622a2900b5c53019891ce895",
            "665cbf985b01c29b260134fdec5db2ddbdff85e510971f8b74b44d94c1e44649",
        ),
        (
            "48b04a31d50f7a658bc31c5b094375bdc722c823bc4d139a0b93e8a210936605",
            "7857927c3d5e44dd4ef1dcbd992bfa49",
            "0b1a8cc7ce0977eea5992c175943ac05af4de829622a2900b5c53019891ce895",
            "612d1cd1ddd899489a0527c944a85227",
            "ea9850dbdbff307589a202376aef43274f10be74391c7af2c697533712009648",
            "70e64fcea26e25933d02148a3fc10b116c515bcf94e0d230c982bfe661091d76",
        ),
        (
            "55a8911ca5f8193bd7d7ea441dc010651b79668d19a860ddc5368113a7c56c03",
            "73c88abd10b3a1ce89110b83d163aca7",
            "ea9850dbdbff307589a202376aef43274f10be74391c7af2c697533712009648",
            "fdb05528f2adb0f474cd9dcef857ac20",
            "2ca01c916216e980ee3e50ce5d86245af3bde148c9918a1350c9e89f4fbcd140",
            "4c25779e96db1244958509bd61399ea98b472924b2e0f113312114a842bf598e",
        ),
        (
            "f6400c9b7101723382b8a8b4716cfcab917307cee51ff48a2db87966ff7aa30c",
            "7d4549a5709a1fbe129b1a153a526f84",
            "2ca01c916216e980ee3e50ce5d86245af3bde148c9918a1350c9e89f4fbcd140",
            "81aa0120b7911dff6fedfa8eddc69896",
            "f60263213a05a2d3d6be8ee1a5053d9124b61f186b4db404b0a0ba6cab7e81f5",
            "ebec8ce7baefd8fe2765f2e4b33472795de77e4f37ab4847495b91c4a49db271",
        ),
        (
            "a1988cfa9d2605254cf8bc505902ecfffa7d8bd5d3d54068665a6602e581840f",
            "3f653f823f1ddc0566341114a921c1e4",
            "f60263213a05a2d3d6be8ee1a5053d9124b61f186b4db404b0a0ba6cab7e81f5",
            "5dcbbcdd70ecf59cc00a7952bde9f64c",
            "ab44975e5e71c58a97cdf12f3612f37f04eaecac4d1ded700ddfffd00facd3c9",
            "3a294f1f6e57561023d119b785d9e2b60f72a64f72dc8792e6cf9fccbf809560",
        ),
        (
            "cd7a0c7665b09b1f9fdb98159eb3076916ace9912962744ecb88db5a797a6a00",
            "35435e2e7c2c4ecd0adb091227cfa764",
            "ab44975e5e71c58a97cdf12f3612f37f04eaecac4d1ded700ddfffd00facd3c9",
            "613e478e2e520fac20e4ccd214a7b4bd",
            "7afc3da3f5d04ccbeffe407258b90b040c1ef969bedbbbaa0c9f9fcfd169ac8f",
            "47ead7584028cf649c2c867607e72203938cfd147f5e57f97179d2326d8be905",
        ),
        (
            "00a93e36e903465d37f6d91212a21f7243b11cf908b174fcd1113065bf5b6a03",
            "2a4fe6982dde053ef9fd32f6f8987f2e",
            "7afc3da3f5d04ccbeffe407258b90b040c1ef969bedbbbaa0c9f9fcfd169ac8f",
            "30a87b277d394b2155afe18d4d260f83",
            "f851654b7d455e49ef87a5693ba69b257254b0f43a7b1f92be36cc9c3dc95943",
            "8d5c4a9384877dfcaa82035fdc7cc8e62a57bf9bf67affa2551fa63bde7d7545",
        ),
        (
            "2bea39a061fd671e1ebc7af84b52c7bdd3c0c18c9e54a030d99d30d86072d50c",
            "bc4897d82a92a1a752ebfe8d1e187b39",
            "f851654b7d455e49ef87a5693ba69b257254b0f43a7b1f92be36cc9c3dc95943",
            "64171fe6899ec3a4cf8118357e91fcf5",
            "068acf94ac2f0e3880408f6217a08213efe459fafd059f23b35e3b81cdf8fb94",
            "f8448c847a68c94beb39ab2287630c7e2c4be4924f85e85e0934a79fdc8b1d3e",
        ),
        (
            "058dfbcf8e85871998a1309e378e3b3536e2b04294494109d269e2d3be923402",
            "f30b0e8a905728547216eeea5cc2f8cf",
            "068acf94ac2f0e3880408f6217a08213efe459fafd059f23b35e3b81cdf8fb94",
            "d77cc7ccc468b52e9bf4882646f272d0",
            "cca6fd0f1850982a805839a68007a5aae12cc7ff45c0757da9fb87b3520b2eaf",
            "62fd262168e83897c4a0bf73e7c07352b2905ff5e599c0243c78fef7ef0d45aa",
        ),
        (
            "fbb47b595b69e2d0dc827236e0b1f5d943ee7b1573fe62da86056fc8faf5850f",
            "a7548a58ee868aa344252dc42e9b24bb",
            "cca6fd0f1850982a805839a68007a5aae12cc7ff45c0757da9fb87b3520b2eaf",
            "8d8c89e416340db606c3ef3683e9fcb8",
            "54e8603a752a95b736496524fcce4a41a3d001386aef61fc9c244b0e0cd3fed4",
            "bcbd41336aeb10bdaee447b241f9f4165fa5c9ffea3047b95e117da79fdd4016",
        ),
    ];

    // RFC 8032 Section 5.1, Table 1, lifted from the RFC text by script: the coordinates of
    // B and the value of d, in decimal.
    const B_X: &str =
        "15112221349535400772501151409588531511454012693041857206046113283949847762202";
    const B_Y: &str =
        "46316835694926478169428394003475163141307993866256225615783033603165251855960";
    const D: &str = "37095705934669439343138083508754565189542113879843219016388785533085940283555";

    fn octets<const N: usize>(hex: &str) -> [u8; N] {
        bouncycastle_hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn halves(hex: &str) -> [u64; 2] {
        let v: [u8; 16] = octets(hex);
        [
            u64::from_le_bytes(v[..8].try_into().unwrap()),
            u64::from_le_bytes(v[8..].try_into().unwrap()),
        ]
    }

    fn limbs(k: &[u8; 32]) -> [u64; 4] {
        let mut n = [0_u64; 4];
        scalar::decode_into(k, &mut n);
        n
    }

    /// splitmix64: a fixed stream of test values.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn small(value: i64) -> FieldElement25519 {
        FieldElement25519::new([value, 0, 0, 0, 0])
    }

    fn decimal(digits: &str) -> FieldElement25519 {
        digits.bytes().fold(FieldElement25519::zero(), |acc, c| {
            acc.mul_u32(10).add(&small((c - b'0') as i64))
        })
    }

    /// The canonical encoding of a field element.
    fn canonical(x: &FieldElement25519) -> [u8; 32] {
        let mut octets = [0_u8; 32];
        x.normalize().encode_255(&mut octets);
        octets
    }

    /// The base point, from the RFC's coordinates.
    fn base_point() -> PointAffine {
        PointAffine { x: decimal(B_X).normalize(), y: decimal(B_Y).normalize() }
    }

    fn encoded(p: &PointAffine) -> [u8; 32] {
        let mut r = [0_u8; 32];
        p.encode(&mut r);
        r
    }

    fn encoded_extended(p: &PointExtended) -> [u8; 32] {
        let z_inv = p.z.inv();
        encoded(&PointAffine { x: p.x.mul(&z_inv).normalize(), y: p.y.mul(&z_inv).normalize() })
    }

    fn encoded_accum(p: &PointAccum) -> [u8; 32] {
        encoded(&p.to_affine())
    }

    fn base_mult(k: &[u8; 32]) -> [u8; 32] {
        let mut r = [0xA5_u8; 32];
        scalar_mult_base_encoded(k, &mut r).unwrap();
        r
    }

    fn neutral_extended() -> PointExtended {
        PointExtended {
            x: FieldElement25519::zero(),
            y: FieldElement25519::one(),
            z: FieldElement25519::one(),
            t: FieldElement25519::zero(),
        }
    }

    fn accum_to_extended(p: &PointAccum) -> PointExtended {
        PointExtended { x: p.x.clone(), y: p.y.clone(), z: p.z.clone(), t: p.u.mul(&p.v) }
    }

    /// `[k]P` by doubling and adding with the RFC's addition formulas alone, a bit at a
    /// time: an independent reference for the multiplications.
    fn reference_mult(k: &[u8], p: &PointAffine) -> PointExtended {
        let p = PointExtended::from_affine(p);
        let mut acc = neutral_extended();
        for bit in (0..8 * k.len()).rev() {
            acc = acc.add(&acc);
            if (k[bit / 8] >> (bit % 8)) & 1 == 1 {
                acc = acc.add(&p);
            }
        }
        acc
    }

    /// `[y]P` for a signed 128-bit `y` in two's complement, by the reference.
    fn reference_mult_signed(y: &[u64; 2], p: &PointAffine) -> PointExtended {
        let value = ((y[1] as u128) << 64 | y[0] as u128) as i128;
        let p = if value < 0 { p.negate() } else { p.clone() };
        reference_mult(&value.unsigned_abs().to_le_bytes(), &p)
    }

    #[test]
    fn the_constants_are_those_of_the_rfc() {
        // d = -121665/121666
        assert_eq!(canonical(&C_D), canonical(&decimal(D)));
        assert_eq!(canonical(&C_D.mul_u32(121666)), canonical(&small(121665).negate()));
        assert_eq!(canonical(&C_D2), canonical(&C_D.add(&C_D)));

        let b = base_point();
        assert!(b.is_valid_result().to_bool());
        // [1]B from the comb is the RFC's B, and decodes back to its coordinates.
        let mut one = [0_u8; 32];
        one[0] = 1;
        assert_eq!(base_mult(&one), encoded(&b));
        let decoded = PointAffine::decode_var(&encoded(&b)).unwrap();
        assert_eq!(
            (canonical(&decoded.x), canonical(&decoded.y)),
            (canonical(&b.x), canonical(&b.y))
        );
    }

    #[test]
    fn scalar_mult_base_matches_the_prototype() {
        for (k, expected) in BASE_MULT_KATS {
            assert_eq!(base_mult(&octets(k)), octets::<32>(expected), "{k}");
        }
    }

    /// The comb against the bit-at-a-time reference, on the known-answer scalars and on
    /// pseudo-random ones with the top bit clear (so that an even one has room for L).
    #[test]
    fn scalar_mult_base_agrees_with_double_and_add() {
        let b = base_point();
        let mut ks: Vec<[u8; 32]> = BASE_MULT_KATS.iter().map(|(k, _)| octets(k)).collect();
        let mut state = 0x636F_6D62;
        for _ in 0..40 {
            let mut k: [u8; 32] = core::array::from_fn(|_| next(&mut state) as u8);
            k[31] &= 0x7F;
            ks.push(k);
        }
        // One digit set in each block and at each spacing position.
        for bit in (0..255).step_by(5) {
            let mut k = [0_u8; 32];
            k[bit / 8] = 1 << (bit % 8);
            ks.push(k);
        }
        for k in &ks {
            assert_eq!(base_mult(k), encoded_extended(&reference_mult(k, &b)), "{k:02x?}");
        }
    }

    /// `[L]B` is the neutral element and `[L - 1]B` is `-B`, by three different routes.
    #[test]
    fn the_base_point_has_order_l() {
        let b = base_point();
        assert!(scalar_mult_order_var(&b).normalizes_to_neutral_var());

        let l: [u8; 32] = scalar::L
            .iter()
            .flat_map(|limb| limb.to_le_bytes())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let mut neutral = [0_u8; 32];
        neutral[0] = 1;
        assert_eq!(encoded_extended(&reference_mult(&l, &b)), neutral);

        let mut l_minus_1 = l;
        l_minus_1[0] -= 1;
        assert_eq!(base_mult(&l_minus_1), encoded(&b.negate()));

        // A point that is not of order L does not pass.
        let mut not_neutral = scalar_mult_order_var(&b);
        not_neutral.accumulate_precomp_var(false, &WNAF_BASE[0]);
        assert!(!not_neutral.normalizes_to_neutral_var());
    }

    #[test]
    fn decoding_matches_the_prototype_and_round_trips() {
        for (encoding, x) in DECODE_KATS {
            let encoding: [u8; 32] = octets(encoding);
            match (PointAffine::decode_var(&encoding), x) {
                (Some(point), Some(x)) => {
                    assert_eq!(canonical(&point.x), octets::<32>(x));
                    assert_eq!(encoded(&point), encoding);
                    // -P has the same y and the other x.
                    let negated = point.negate();
                    assert_eq!(canonical(&negated.x.add(&point.x)), [0_u8; 32]);
                    assert_eq!(canonical(&negated.y), canonical(&point.y));
                }
                (None, None) => {}
                (decoded, _) => panic!("{encoding:02x?} decoded: {}", decoded.is_some()),
            }
        }
    }

    /// RFC 8032 Section 5.1.3, step 1: every y at or above p fails, with either sign bit,
    /// including those whose reduced value would decode; step 4: x = 0 with x_0 = 1 fails.
    #[test]
    fn decoding_rejects_non_canonical_encodings() {
        // p + y for y = 0 .. 18: the 19 values from p to 2^255 - 1.
        for y in 0..19_u8 {
            let mut encoding = [0xFF_u8; 32];
            encoding[0] = 0xED + y;
            for top in [0x7F, 0xFF] {
                encoding[31] = top;
                assert!(PointAffine::decode_var(&encoding).is_none(), "{y} {top:#x}");
            }
        }
        // p - 1 is canonical.
        let mut p_minus_1 = [0xFF_u8; 32];
        (p_minus_1[0], p_minus_1[31]) = (0xEC, 0x7F);
        assert!(PointAffine::decode_var(&p_minus_1).is_some());

        // x = 0 at y = 1 and y = -1: the sign bit must be clear. (y = 1 decoding shows that
        // p + 1 above was refused for its encoding, not for its point.)
        let mut neutral = [0_u8; 32];
        neutral[0] = 1;
        assert!(PointAffine::decode_var(&neutral).is_some());
        neutral[31] = 0x80;
        assert!(PointAffine::decode_var(&neutral).is_none());
        p_minus_1[31] = 0xFF;
        assert!(PointAffine::decode_var(&p_minus_1).is_none());
    }

    #[test]
    fn public_key_validation_matches_the_prototype() {
        for (encoding, valid) in PUBLIC_KEY_KATS {
            let key = PublicPoint::decode_var(&octets(encoding));
            assert_eq!(key.is_some(), *valid, "{encoding}");
            if let Some(key) = key {
                let mut back = [0_u8; 32];
                key.encode(&mut back);
                assert_eq!(back, octets::<32>(encoding));
                assert_eq!(encoded(key.point()), back);
            }
        }
    }

    /// Independently of the prototype: the points of small order are found as the multiples
    /// of a point of order 8, each is rejected as a public key, and so is each of them added
    /// to a point of the subgroup (mixed order), while the subgroup's own points pass.
    #[test]
    fn public_keys_outside_the_subgroup_are_rejected() {
        // [L]P for a point P that decodes off the subgroup has order dividing 8; find one of
        // order exactly 8 among the encodings y = 2, 3, ..
        let l: [u8; 32] = scalar::L
            .iter()
            .flat_map(|limb| limb.to_le_bytes())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap();
        let mut neutral = [0_u8; 32];
        neutral[0] = 1;
        let torsion = (2..=255_u8)
            .find_map(|y| {
                let mut encoding = [0_u8; 32];
                encoding[0] = y;
                let t = reference_mult(&l, &PointAffine::decode_var(&encoding)?);
                let t = PointAffine::decode_var(&encoded_extended(&t)).unwrap();
                (encoded_extended(&reference_mult(&[4], &t)) != neutral).then_some(t)
            })
            .unwrap();

        let b = base_point();
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for multiple in 0..8_u8 {
            let small_order = reference_mult(&[multiple], &torsion);
            let encoding = encoded_extended(&small_order);
            assert_eq!(
                encoded_extended(&reference_mult(
                    &[8],
                    &PointAffine::decode_var(&encoding).unwrap()
                )),
                neutral
            );
            assert!(!seen.contains(&encoding));
            seen.push(encoding);
            assert!(PublicPoint::decode_var(&encoding).is_none(), "small order {multiple}");

            // [5]B + T is in the subgroup only for T neutral.
            let mixed = encoded_extended(&reference_mult(&[5], &b).add(&small_order));
            assert_eq!(
                PublicPoint::decode_var(&mixed).is_some(),
                multiple == 0,
                "mixed {multiple}"
            );
        }
    }

    #[test]
    fn straus_matches_the_prototype_and_double_and_add() {
        let b = base_point();
        for (nb, np, p, nq, q, expected) in STRAUS_KATS {
            let nb: [u8; 32] = octets(nb);
            let (np, nq) = (halves(np), halves(nq));
            let p = PointAffine::decode_var(&octets(p)).unwrap();
            let q = PointAffine::decode_var(&octets(q)).unwrap();

            let r = scalar_mult_straus_128_var(&limbs(&nb), &np, &p, &nq, &q);
            assert_eq!(encoded_accum(&r), octets::<32>(expected));

            let sum = reference_mult(&nb, &b)
                .add(&reference_mult_signed(&np, &p))
                .add(&reference_mult_signed(&nq, &q));
            let sum = PointAffine::decode_var(&encoded_extended(&sum)).unwrap();
            assert_eq!(encoded_accum(&r), encoded_extended(&reference_mult(&[8], &sum)));
        }
    }

    /// The check on a computed result: a point off the curve and a point with y = 0 fail it,
    /// through the encoding function too.
    #[test]
    fn the_result_check_rejects_what_is_not_a_multiple_of_b() {
        let b = base_point();
        let off_curve = PointAffine { x: b.x.clone(), y: b.y.add(&small(1)).normalize() };
        assert!(!off_curve.is_valid_result().to_bool());

        // (sqrt(-1), 0) is on the curve, of order 4.
        let order_4 = PointAffine::decode_var(&[0_u8; 32]).unwrap();
        assert_eq!(canonical(&order_4.x.sqr()), canonical(&small(1).negate()));
        assert!(!order_4.is_valid_result().to_bool());

        let mut r = [0_u8; 32];
        let mut accum = PointAccum::neutral();
        assert!(accum.encode_checked(&mut r).to_bool());
        accum.x = small(1);
        assert!(!accum.encode_checked(&mut r).to_bool());
    }

    /// The neutral-element test sees X, and Y against Z, and refuses the all-zero triple.
    #[test]
    fn normalizes_to_neutral_var_wants_x_zero_and_y_equal_to_z() {
        let mut p = PointAccum::neutral();
        assert!(p.normalizes_to_neutral_var());
        (p.y, p.z) = (small(7), small(7));
        assert!(p.normalizes_to_neutral_var());
        p.z = small(8);
        assert!(!p.normalizes_to_neutral_var());
        (p.y, p.z) = (small(0), small(0));
        assert!(!p.normalizes_to_neutral_var());
        (p.x, p.y, p.z) = (small(1), small(7), small(7));
        assert!(!p.normalizes_to_neutral_var());
    }

    // The base-point tables of `precomp`, rebuilt from B.

    /// One table entry as the canonical encodings of its three fields.
    type Entry = [[u8; 32]; 3];

    fn entry_of(p: &PointPrecomp) -> Entry {
        [canonical(&p.ymx_h), canonical(&p.ypx_h), canonical(&p.xyd)]
    }

    /// The table entry for a point: with x/2 and y/2 from one inversion of 2 Z,
    /// ((y - x)/2, (y + x)/2, x y d).
    fn entry_from_extended(p: &PointExtended) -> Entry {
        let half_z_inv = p.z.add(&p.z).inv();
        let (x_h, y_h) = (p.x.mul(&half_z_inv), p.y.mul(&half_z_inv));
        let (ypx_h, ymx_h) = y_h.sum_and_difference(&x_h);
        let d4 = C_D2.add(&C_D2);
        [canonical(&ymx_h), canonical(&ypx_h), canonical(&x_h.mul(&y_h).mul(&d4))]
    }

    /// The odd multiples `P, 3P, ..`, as table entries.
    fn odd_multiples(p: &PointExtended) -> Vec<Entry> {
        let twice = p.add(p);
        let mut q = p.add(&neutral_extended());
        let mut entries = Vec::new();
        for _ in 0..PRECOMP_WNAF_POINTS {
            entries.push(entry_from_extended(&q));
            q = q.add(&twice);
        }
        entries
    }

    /// (the comb table block by block, the odd multiples of B, those of [2^128]B)
    fn build_tables() -> (Vec<Entry>, Vec<Entry>, Vec<Entry>) {
        let b = base_point();
        let wnaf_base = odd_multiples(&PointExtended::from_affine(&b));

        let mut b128 = PointAccum::neutral();
        b128.accumulate_precomp_var(false, &WNAF_BASE[0]);
        // WNAF_BASE[0] is checked against B below, before anything rests on it.
        assert_eq!(entry_of(&WNAF_BASE[0]), wnaf_base[0]);
        for _ in 0..128 {
            b128.double();
        }
        let wnaf_base_128 = odd_multiples(&accum_to_extended(&b128));

        // p walks through [2^i]B. Each block starts from minus the sum of its four teeth,
        // and adding twice a tooth turns that tooth's sign.
        let mut comb: Vec<PointExtended> = Vec::new();
        let mut p = PointAccum::neutral();
        p.accumulate_precomp_var(false, &WNAF_BASE[0]);
        for _block in 0..PRECOMP_BLOCKS {
            let mut sum = neutral_extended();
            let mut twice_teeth: Vec<PointExtended> = Vec::new();
            for _tooth in 0..PRECOMP_TEETH {
                sum = sum.add(&accum_to_extended(&p));
                p.double();
                twice_teeth.push(accum_to_extended(&p));
                for _ in 1..PRECOMP_SPACING {
                    p.double();
                }
            }
            sum.x = sum.x.negate();
            sum.t = sum.t.negate();
            comb.push(sum);
            for (tooth, twice_tooth) in twice_teeth[..PRECOMP_TEETH - 1].iter().enumerate() {
                for _ in 0..1 << tooth {
                    let from = &comb[comb.len() - (1 << tooth)];
                    let next = from.add(twice_tooth);
                    comb.push(next);
                }
            }
        }
        (comb.iter().map(entry_from_extended).collect(), wnaf_base, wnaf_base_128)
    }

    #[test]
    fn the_base_point_tables_are_what_b_generates() {
        let (comb, wnaf_base, wnaf_base_128) = build_tables();
        let table: Vec<Entry> = COMB_BASE.iter().flatten().map(entry_of).collect();
        assert_eq!(table, comb);
        assert_eq!(WNAF_BASE.iter().map(entry_of).collect::<Vec<Entry>>(), wnaf_base);
        assert_eq!(WNAF_BASE_128.iter().map(entry_of).collect::<Vec<Entry>>(), wnaf_base_128);
    }

    /// Prints the tables of `precomp.rs`, from `#[rustfmt::skip]` above `COMB_BASE` to the
    /// end of the file; see that file for how to run it.
    #[test]
    #[ignore = "a generator, not a test"]
    fn print_base_point_tables() {
        fn limbs_of(encoding: &[u8; 32]) -> String {
            let words: Vec<u64> =
                encoding.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
            let limbs: Vec<String> = (0..5)
                .map(|i| {
                    let (word, bit) = (51 * i / 64, 51 * i % 64);
                    let mut limb = words[word] >> bit;
                    if bit > 13 && word < 3 {
                        limb |= words[word + 1] << (64 - bit);
                    }
                    std::format!("0x{:013X}", limb & ((1 << 51) - 1))
                })
                .collect();
            std::format!("[{}]", limbs.join(", "))
        }
        fn print_entry(indent: &str, entry: &Entry) {
            std::println!("{indent}entry(");
            for field in entry {
                std::println!("{indent}    {},", limbs_of(field));
            }
            std::println!("{indent}),");
        }

        let (comb, wnaf_base, wnaf_base_128) = build_tables();
        std::println!("#[rustfmt::skip]");
        std::println!(
            "pub(super) static COMB_BASE: [[PointPrecomp; PRECOMP_POINTS]; PRECOMP_BLOCKS] = ["
        );
        for block in comb.chunks(PRECOMP_POINTS) {
            std::println!("    [");
            block.iter().for_each(|entry| print_entry("        ", entry));
            std::println!("    ],");
        }
        std::println!("];\n");
        std::println!("/// The odd multiples `B, 3B, .., 31B`, for verification.");
        std::println!("#[rustfmt::skip]");
        std::println!("pub(super) static WNAF_BASE: [PointPrecomp; PRECOMP_WNAF_POINTS] = [");
        wnaf_base.iter().for_each(|entry| print_entry("    ", entry));
        std::println!("];\n");
        std::println!("/// The odd multiples of `[2^128]B`, for verification.");
        std::println!("#[rustfmt::skip]");
        std::println!("pub(super) static WNAF_BASE_128: [PointPrecomp; PRECOMP_WNAF_POINTS] = [");
        wnaf_base_128.iter().for_each(|entry| print_entry("    ", entry));
        std::println!("];");
    }
}
