//! Points of edwards448, the curve `x^2 + y^2 = 1 + d x^2 y^2` of RFC 8032 Section 5.2:
//! encoding and decoding, the group law, the fixed-base multiplication that signing and key
//! generation use, and the variable-time multiplications of verification.
//!
//! The group law is that of RFC 8032 Section 5.2.4, in projective coordinates. Its formulas
//! "are complete, i.e., they work for any pair of valid input points", because d is not a
//! square, so there is no exceptional case to branch on: doubling, adding the neutral element
//! and adding a point of small order all go through the same arithmetic.
//!
//! [`scalar_mult_base`] and what it calls are constant time: fixed loops, table lookups that
//! pass over every entry, and negation by mask. Everything named `_var` branches on its
//! inputs and takes public values only. Every coordinate is a [`FieldElement448`], which
//! wipes itself when dropped, so the point types need no wiping of their own.

use super::precomp::{COMB_BASE, WNAF_BASE, WNAF_BASE_225};
use super::scalar::{self, SCALAR_LEN, SIGNED_DIGITS};
use crate::ed::curve448::{FieldElement448, NormalizedFieldElement448};
use crate::ed::wnaf;
use bouncycastle_utils::ct::Condition;
use bouncycastle_utils::secret::Secret;
use bouncycastle_utils::stack_wipe::wipe_stack_below;

/// Octets in an encoded point (RFC 8032 Section 5.2.2).
pub(super) const POINT_LEN: usize = 57;

/// -d, for d = -39081 (RFC 8032 Section 5.2, Table 2).
const C_NEG_D: u32 = 39081;

/// Window width for the two 225-bit scalars of verification and for the group order.
const WNAF_WIDTH_225: usize = 5;
/// Window width for the base point in verification; fixes the size of the `WNAF_BASE` tables.
const WNAF_WIDTH_BASE: usize = 7;
/// Points in a table of odd multiples at [`WNAF_WIDTH_225`].
const WNAF_POINTS_225: usize = 1 << (WNAF_WIDTH_225 - 2);

// The fixed-base comb: the 450 signed digits of the scalar are cut into 5 blocks of 90, and
// each block into 5 teeth 18 digits apart, so that one table entry per block serves the 5
// digits at one spacing position.
pub(super) const PRECOMP_BLOCKS: usize = 5;
pub(super) const PRECOMP_TEETH: usize = 5;
pub(super) const PRECOMP_SPACING: usize = 18;
/// Entries per block: one for each setting of the lower teeth, the top tooth giving the sign.
pub(super) const PRECOMP_POINTS: usize = 1 << (PRECOMP_TEETH - 1);
/// Entries in each of `WNAF_BASE` and `WNAF_BASE_225`.
pub(super) const PRECOMP_WNAF_POINTS: usize = 1 << (WNAF_WIDTH_BASE - 2);

const _: () = assert!(PRECOMP_BLOCKS * PRECOMP_TEETH * PRECOMP_SPACING == SIGNED_DIGITS);

/// The fixed-base multiplication checks its result before encoding it, and the check failed:
/// a fault in the arithmetic, not a property of any input.
#[derive(Debug)]
pub(super) struct ResultCheckFailed;

/// A point `(x, y)` in canonical coordinates.
#[derive(Clone)]
pub(super) struct PointAffine {
    x: NormalizedFieldElement448,
    y: NormalizedFieldElement448,
}

impl PointAffine {
    /// Decodes a point by RFC 8032 Section 5.2.3, or returns `None` where "decoding fails".
    /// Variable time: an encoded point is public.
    pub(super) fn decode_var(p: &[u8; POINT_LEN]) -> Option<Self> {
        // Step 1: "Bit 455 of this number is the least significant bit of the x-coordinate,
        // and denote this value x_0. The y-coordinate is recovered simply by clearing this
        // bit. If the resulting value is >= p, decoding fails."
        // decode_448 reads the first 56 octets and accepts any 448-bit value; the whole value
        // was below p exactly if its canonical form encodes back to the same 57 octets, which
        // also refuses anything in bits 448 to 454.
        let x_0 = p[POINT_LEN - 1] >> 7;
        let mut y_octets = [0_u8; 56];
        y_octets.copy_from_slice(&p[..56]);
        let y = FieldElement448::decode_448(&y_octets).normalize();
        let mut canonical = [0_u8; POINT_LEN];
        y.encode_448(&mut y_octets);
        canonical[..56].copy_from_slice(&y_octets);
        canonical[POINT_LEN - 1] = x_0 << 7;
        if canonical != *p {
            return None;
        }

        // Step 2: "Let u = y^2 - 1 and v = d y^2 - 1."
        let y2 = y.sqr();
        let u = y2.sub(&FieldElement448::one());
        let v = y2.mul_u32(C_NEG_D).negate().sub(&FieldElement448::one());
        // Steps 2 and 3: the square root of u/v; "Otherwise, no square root exists, and the
        // decoding fails."
        let x = FieldElement448::sqrt_ratio_var(&u, &v)?.normalize();

        // Step 4: "If x = 0, and x_0 = 1, decoding fails. Otherwise, if x_0 != x mod 2, set
        // x <-- p - x."
        if x_0 == 1 && x.is_zero_var() {
            return None;
        }
        let x = if x_0 != x.parity() { x.negate().normalize() } else { x };

        Some(Self { x, y })
    }

    /// Encodes the point by RFC 8032 Section 5.2.2: the y-coordinate in 57 little-endian
    /// octets, of which "The final octet is always zero", with "the least significant bit of
    /// the x-coordinate" in "the most significant bit of the final octet". Constant time.
    pub(super) fn encode(&self, r: &mut [u8; POINT_LEN]) {
        // The y-coordinate of a secret multiple of B is public only once the result check
        // has passed, so the staging copy is wiped.
        let mut y_octets = Secret::<[u8; 56]>::new();
        self.y.encode_448(&mut y_octets);
        r[..56].copy_from_slice(&*y_octets);
        r[POINT_LEN - 1] = self.x.parity() << 7;
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
        // x^2 + y^2 = 1 + d x^2 y^2
        let lhs = x2.add(&y2);
        let rhs = FieldElement448::one().sub(&x2.mul(&y2).mul_u32(C_NEG_D));
        lhs.sub(&rhs).normalize().is_zero() & !self.y.is_zero()
    }
}

/// A public key as a point: on the curve, in the subgroup generated by B, and not the neutral
/// element. [`Self::decode_var`] is the constructor for an encoding from anywhere, so holding
/// one is holding a fully validated key; [`Self::decode_base_multiple_var`] is for a key this
/// module has just computed.
#[derive(Clone)]
pub(in crate::ed) struct PublicPoint(PointAffine);

impl PublicPoint {
    /// Decodes and fully validates a public key, or returns `None`: the encoding must be that
    /// of a point (RFC 8032 Section 5.2.3), and the point must have order L. Costs about one
    /// scalar multiplication. Variable time: a public key is public.
    pub(in crate::ed) fn decode_var(pk: &[u8; POINT_LEN]) -> Option<Self> {
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

    /// Decodes `pk` without the order check of [`Self::decode_var`], for the one caller that
    /// knows the answer: `pk` must be an encoding [`scalar_mult_base_encoded`] wrote. Such a
    /// point is in the subgroup B generates by construction, which is what the skipped check
    /// establishes, at the cost of a scalar multiplication. `None` if `pk` is not the
    /// encoding of a point, which breaks the condition, or is the neutral element: unlike
    /// Ed25519's, a pruned Ed448 scalar can be a multiple of L (`4 L` is one), so that the
    /// neutral element is not ruled out by construction and is refused here. Variable time.
    pub(in crate::ed) fn decode_base_multiple_var(pk: &[u8; POINT_LEN]) -> Option<Self> {
        let point = PointAffine::decode_var(pk)?;
        // In the subgroup, x = 0 is the neutral element alone.
        if point.x.is_zero_var() {
            return None;
        }
        Some(Self(point))
    }

    /// The encoding the key was decoded from.
    pub(in crate::ed) fn encode(&self, pk: &mut [u8; POINT_LEN]) {
        self.0.encode(pk);
    }

    pub(super) fn point(&self) -> &PointAffine {
        &self.0
    }
}

/// A point `(X, Y, Z)` in the projective coordinates of RFC 8032 Section 5.2.4, "with
/// x = X/Z, y = Y/Z".
pub(super) struct PointProjective {
    x: FieldElement448,
    y: FieldElement448,
    z: FieldElement448,
}

impl PointProjective {
    /// The neutral element, (0, 1).
    pub(super) fn neutral() -> Self {
        Self { x: FieldElement448::zero(), y: FieldElement448::one(), z: FieldElement448::one() }
    }

    fn from_affine(p: &PointAffine) -> Self {
        Self { x: (*p.x).clone(), y: (*p.y).clone(), z: FieldElement448::one() }
    }

    /// `self = 2 self`, by the doubling formulas of RFC 8032 Section 5.2.4. Constant time.
    fn double(&mut self) {
        // B = (X1+Y1)^2, C = X1^2, D = Y1^2
        let b = self.x.add(&self.y).sqr();
        let c = self.x.sqr();
        let d = self.y.sqr();
        // E = C+D, H = Z1^2, J = E-2*H
        let e = c.add(&d).carry();
        let h = self.z.sqr();
        let j = e.sub(&h).carry().sub(&h);
        // X3 = (B-E)*J, Y3 = E*(C-D), Z3 = E*J
        self.x = b.sub(&e).mul(&j);
        self.y = c.sub(&d).mul(&e);
        self.z = e.mul(&j);
    }

    /// The addition formulas of RFC 8032 Section 5.2.4 from their A on, for
    /// `(X2, Y2) = (x2, y2)` and `A = a`. Where the RFC has E = d*C*D this has `-E`, d being
    /// negative, which exchanges the sum and the difference that make F and G.
    #[inline(always)]
    fn add_from_a(&mut self, x2: &FieldElement448, y2: &FieldElement448, a: &FieldElement448) {
        // B = A^2, C = X1*X2, D = Y1*Y2
        let b = a.sqr();
        let c = x2.mul(&self.x);
        let d = y2.mul(&self.y);
        // -E = 39081*C*D; F = B-E, G = B+E
        let minus_e = c.mul(&d).mul_u32(C_NEG_D);
        let (f, g) = b.sum_and_difference(&minus_e);
        // H = (X1+Y1)*(X2+Y2)
        let h = x2.add(y2).mul(&self.x.add(&self.y));
        // X3 = A*F*(H-C-D), Y3 = A*G*(D-C), Z3 = F*G
        let (c_plus_d, d_minus_c) = d.sum_and_difference(&c);
        let ah = h.sub(&c_plus_d.carry()).mul(a);
        let ad = d_minus_c.mul(a);
        self.x = f.mul(&ah);
        self.y = g.mul(&ad);
        self.z = f.mul(&g);
    }

    /// `self += p` for a table entry, a point with Z2 = 1, so that the RFC's A is Z1.
    /// Constant time.
    fn add_precomp(&mut self, p: &PointPrecomp) {
        let a = self.z.clone();
        self.add_from_a(&p.x, &p.y, &a);
    }

    /// `self += p`, or `self -= p` when `negate`: [`Self::add_precomp`], where `-p` has the
    /// entry's x negated. Variable time in `negate`.
    fn add_precomp_var(&mut self, negate: bool, p: &PointPrecomp) {
        let a = self.z.clone();
        if negate {
            self.add_from_a(&p.x.negate(), &p.y, &a);
        } else {
            self.add_from_a(&p.x, &p.y, &a);
        }
    }

    /// `self += p`. Constant time.
    fn add(&mut self, p: &Self) {
        // A = Z1*Z2
        let a = p.z.mul(&self.z);
        self.add_from_a(&p.x, &p.y, &a);
    }

    /// `self += p`, or `self -= p` when `negate`. Variable time in `negate`.
    fn add_var(&mut self, negate: bool, p: &Self) {
        let a = p.z.mul(&self.z);
        if negate {
            self.add_from_a(&p.x.negate(), &p.y, &a);
        } else {
            self.add_from_a(&p.x, &p.y, &a);
        }
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
    fn encode_checked(&self, r: &mut [u8; POINT_LEN]) -> Condition<i64> {
        let q = self.to_affine();
        q.encode(r);
        q.is_valid_result()
    }

    /// Whether this is the neutral element: X = 0 and Y = Z, not zero. Variable time.
    pub(super) fn normalizes_to_neutral_var(&self) -> bool {
        let (x, y, z) = (self.x.normalize(), self.y.normalize(), self.z.normalize());
        x.is_zero_var() && !y.is_zero_var() && NormalizedFieldElement448::are_equal_var(&y, &z)
    }
}

/// An entry of a fixed table: a point in affine coordinates, in canonical limbs.
pub(super) struct PointPrecomp {
    pub(super) x: FieldElement448,
    pub(super) y: FieldElement448,
}

/// The odd multiples `P, 3P, .., (2N - 1)P`.
fn precompute_var<const N: usize>(p: &PointAffine) -> [PointProjective; N] {
    let mut twice = PointProjective::from_affine(p);
    twice.double();
    let mut q = PointProjective::from_affine(p);
    core::array::from_fn(|i| {
        if i > 0 {
            q.add(&twice);
        }
        PointProjective { x: q.x.clone(), y: q.y.clone(), z: q.z.clone() }
    })
}

/// Selects entry `index` of one block of the comb table into `p`, reading every entry.
/// Constant time in `index`, which is secret.
fn lookup(block: &[PointPrecomp; PRECOMP_POINTS], index: i64, p: &mut PointPrecomp) {
    for (i, entry) in block.iter().enumerate() {
        let hit = Condition::<i64>::is_zero(i as i64 ^ index);
        p.x.cmov(hit, &entry.x);
        p.y.cmov(hit, &entry.y);
    }
}

/// `r = [k]B` for a scalar `k < 2^448` in 57 little-endian octets: the pruned secret scalar
/// `s` or a reduced `r` (RFC 8032 Sections 5.2.5, step 3, and 5.2.6, step 3).
///
/// A fixed-base comb: `k` is recoded to 450 digits of +1 and -1
/// ([`scalar::to_signed_digits`]), and the table in `precomp` holds, for each block, the sums
/// of that block's five teeth over every setting of the lower four, with the top tooth
/// negative. A group whose top tooth is positive selects the entry for the complement of the
/// lower four and takes its negation.
///
/// Constant time: 90 lookups and additions and 17 doublings whatever `k` is; the lookup reads
/// every entry of its block, the positions of the digits read are fixed, and negation is by
/// mask. The recoded scalar is held in a [`Secret`]; the selected entry and the accumulator
/// wipe themselves, `r` when its owner drops it.
pub(super) fn scalar_mult_base(k: &[u8; SCALAR_LEN], r: &mut PointProjective) {
    let mut n = Secret::<[u64; 8]>::new();
    scalar::decode_into(k, &mut *n);
    scalar::to_signed_digits(&mut n);

    let mut p = PointPrecomp { x: FieldElement448::zero(), y: FieldElement448::zero() };
    *r = PointProjective::neutral();

    for position in (0..PRECOMP_SPACING).rev() {
        for (block, table) in COMB_BASE.iter().enumerate() {
            // The block's five digits at this spacing position, the lowest tooth in bit 0.
            let mut w = 0_u64;
            for tooth in 0..PRECOMP_TEETH {
                let digit = position + PRECOMP_SPACING * (PRECOMP_TEETH * block + tooth);
                w |= ((n[digit >> 6] >> (digit & 63)) & 1) << tooth;
            }
            let sign = ((w >> (PRECOMP_TEETH - 1)) & 1) as i64;
            let abs = (w as i64 ^ -sign) & (PRECOMP_POINTS as i64 - 1);

            lookup(table, abs, &mut p);
            p.x.cnegate(Condition::<i64>::is_not_zero(sign));

            r.add_precomp(&p);
        }

        if position > 0 {
            r.double();
        }
    }
}

/// Writes the encoding of `[k]B` to `r`, for `k` as [`scalar_mult_base`] takes it, after
/// checking that the result is a point of the curve; on failure `r` is cleared. Constant
/// time; the outcome of the check is not secret.
///
/// The coordinates wipe themselves, but the compiler also spills limbs of them, and of the
/// inversion that normalizes the result, to stack slots no wipe in the source reaches, so the
/// computation runs in a frame of its own and the stack it used is overwritten afterwards.
pub(super) fn scalar_mult_base_encoded(
    k: &[u8; SCALAR_LEN],
    r: &mut [u8; POINT_LEN],
) -> Result<(), ResultCheckFailed> {
    let checked = scalar_mult_base_encoded_in_own_frame(k, r);
    wipe_stack_below::<WIPED_STACK_WORDS>();
    checked
}

/// How much stack [`wipe_stack_below`] overwrites, in 64-bit words: 4096 bytes. The check of
/// `dev_scripts/ecdsa_stack_harness` passes with 2816 bytes wiped and fails with 2752 (rustc
/// 1.97, x86-64 release build), and passes with 2944 and fails with 2816 with rustc 1.88. The
/// rest is room for a compiler that lays the frames out less tightly.
const WIPED_STACK_WORDS: usize = 512;

/// The computation of [`scalar_mult_base_encoded`]. Never inlined, so that what it spills lies
/// below its caller's frame, where [`wipe_stack_below`] reaches it.
#[inline(never)]
fn scalar_mult_base_encoded_in_own_frame(
    k: &[u8; SCALAR_LEN],
    r: &mut [u8; POINT_LEN],
) -> Result<(), ResultCheckFailed> {
    let mut p = PointProjective::neutral();
    scalar_mult_base(k, &mut p);
    if p.encode_checked(r).to_bool() {
        Ok(())
    } else {
        r.fill(0);
        Err(ResultCheckFailed)
    }
}

/// `[L]P`. Variable time.
fn scalar_mult_order_var(p: &PointAffine) -> PointProjective {
    let mut ws_p = [0_i8; 447];
    scalar::get_order_wnaf_var(WNAF_WIDTH_225, &mut ws_p);

    let tp = precompute_var::<WNAF_POINTS_225>(p);

    let mut r = PointProjective::neutral();
    for bit in (0..ws_p.len()).rev() {
        let wp = ws_p[bit];
        if wp != 0 {
            r.add_var(wp < 0, &tp[wnaf_index(wp)]);
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

/// `[4]([nb]B + [np]P + [nq]Q)`, for `nb < 2^446` and signed `np` and `nq` below `2^224` in
/// magnitude, in four limbs of two's complement: the left-hand side of the cofactored
/// verification equation, by Straus's method over width-w NAFs, with `nb` split into two
/// 225-bit halves that share the doublings through the table for `[2^225]B`. Variable time.
pub(super) fn scalar_mult_straus_225_var(
    nb: &[u64; 7],
    np: &[u64; 4],
    p: &PointAffine,
    nq: &[u64; 4],
    q: &PointAffine,
) -> PointProjective {
    debug_assert_eq!(0, nb[6] >> 62);
    debug_assert_eq!(np[3] as i64 >> 63, np[3] as i64 >> 32);
    debug_assert_eq!(nq[3] as i64 >> 63, nq[3] as i64 >> 32);

    let mut ws_b = [0_i8; 450];
    let mut ws_p = [0_i8; 225];
    let mut ws_q = [0_i8; 225];
    wnaf::get_signed_var(nb, WNAF_WIDTH_BASE, &mut ws_b);
    wnaf::get_signed_var(np, WNAF_WIDTH_225, &mut ws_p);
    wnaf::get_signed_var(nq, WNAF_WIDTH_225, &mut ws_q);

    let tp = precompute_var::<WNAF_POINTS_225>(p);
    let tq = precompute_var::<WNAF_POINTS_225>(q);

    let mut r = PointProjective::neutral();

    // Start at the highest position with a digit.
    let mut bit = 224;
    while bit > 0 && ws_b[bit] | ws_b[225 + bit] | ws_p[bit] | ws_q[bit] == 0 {
        bit -= 1;
    }

    loop {
        let wb = ws_b[bit];
        if wb != 0 {
            r.add_precomp_var(wb < 0, &WNAF_BASE[wnaf_index(wb)]);
        }
        let wb225 = ws_b[225 + bit];
        if wb225 != 0 {
            r.add_precomp_var(wb225 < 0, &WNAF_BASE_225[wnaf_index(wb225)]);
        }
        let wp = ws_p[bit];
        if wp != 0 {
            r.add_var(wp < 0, &tp[wnaf_index(wp)]);
        }
        let wq = ws_q[bit];
        if wq != 0 {
            r.add_var(wq < 0, &tq[wnaf_index(wq)]);
        }

        r.double();

        if bit == 0 {
            break;
        }
        bit -= 1;
    }

    // With the doubling that ends the loop, this multiplies by the cofactor, 4.
    r.double();
    r
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::string::String;
    use std::vec::Vec;

    // Known answers from the prototype this module was ported from: its `scalar_mult_base`,
    // point decoding (`check_point_var` then `decode_point_var`), `validate_public_key_full`
    // and `scalar_mult_straus_225_var`, on edge values and on values from splitmix64 with a
    // fixed seed. Printed by a scratch program (`kat-gen points`, not in this repository) and
    // recomputed there with the Python library of RFC 8032 Appendix A. Scalars and points are
    // 57 little-endian octets in hexadecimal.

    // (k, the encoding of [k]B)
    const BASE_MULT_KATS: &[(&str, &str)] = &[
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6900",
            ),
        ),
        (
            concat!(
                "02000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            concat!(
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03",
                "b0c2865020d659b38d04d74a63e905ae80",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6980",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000008000",
            ),
            concat!(
                "94585a26204cca479294c18524401287a58f7be9e3b36e61d1b9b79c6a578d4c3713d9200f00d376",
                "f8e1c48ab91b937b063733d4f17412f500",
            ),
        ),
        (
            concat!(
                "fcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            concat!(
                "b89b163867480913d3f6143162b3657cfc38fc41facb97ac48fa0b604568ec4c616f3fbf668feffc",
                "6fee4527a70aa01f96a98129d5e5e0bf00",
            ),
        ),
        (
            concat!(
                "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            concat!(
                "81ef460ab56155fa0dd5cd446a25bbdb9a054d532c5e47a02ac41198b46008a0f42476a732bb9f65",
                "bad9bd35141bdb3a9a0babde3f0e9c6000",
            ),
        ),
        (
            concat!(
                "4cbd71c53d59db6cdf0e85787f545b2252e9b5b8ad9f4fcc518568c8286cb085fabce4cd426b0869",
                "4892bbdf0c857e9bbccca171ea82072500",
            ),
            concat!(
                "994bab718042b5c358d2ba9fd02efed42296b570228aafab530556e817b62d741c615f53af9fd9c0",
                "269af3f670907a059c3f512165af97dd80",
            ),
        ),
        (
            concat!(
                "d058fd8ae581896e2ccdaebcf81bf6735a3f26a365d728fc028d5816dc95526c882c198cdde9124f",
                "5d372c795316deb69a8c87d9758747fb00",
            ),
            concat!(
                "ea5cc90479fc658085eb16cb5b97b6c7295984247802ba18eb0ec300a47e60cada9470357cb9283e",
                "70a3b0e39479f004a8d28fd77398951100",
            ),
        ),
        (
            concat!(
                "18158a3a8c87e1219ac4ed9ba9677d9d4205f405a8f2425bcbfb21b10275339a8c65d8d7242373e4",
                "abeae0ba953ca7f4abf603962dc0270600",
            ),
            concat!(
                "b0f23b7dedec9ccb12537b8c17c27ea382d4d25c4e9186bd2581be4c1e00eceda1a483c1b3588be9",
                "6dca2e04858e956414961b9bffb1b67300",
            ),
        ),
        (
            concat!(
                "1c55d62af93055ee4e4478b4c9de8dbc5264cfcab7fb402564be0cf372d79b20dac31acd7ffdfea7",
                "448d06b9b2dd3c19ccf82fc90a95bca400",
            ),
            concat!(
                "75b29c097a4cebd4ee07f22b995f3cd442d3015a5a5206359cf408ea95e63d548e880ca2e2d331d0",
                "e5b68641154f0a3b70d391733640dfe000",
            ),
        ),
        (
            concat!(
                "9a9055dfd4205aefc5b0f715fc7f99c1e165b564532c431ecf5e2b4beebf697353af7adb4be1e533",
                "28373cdeceae90c5a367425737990a0a00",
            ),
            concat!(
                "abbf2934c56aa0379b9dd124dd16acad810cd49609007bb12f5f8aa6836cf23f69deda71d001cacb",
                "52108860ce139c0c9444ed1c8decf2e880",
            ),
        ),
        (
            concat!(
                "6055d324cf7ee9a60f9193482fc6985d1871f06850a0296ceb3948c6b0981c51286fd984509326ba",
                "e24e14721f937fe555e5a9a9b97462c800",
            ),
            concat!(
                "1efc654e7a65d03785bb23a415190a1855eae6be7a23933e87294557d0dce278f8e2c6a00dba2f2f",
                "8a9d22b2102a1ca3beb93ca253bf75ee00",
            ),
        ),
        (
            concat!(
                "f54c1ffb3c4f31c04a3ff6edd44b7894e016ff543c1364d8408a7cc75dffb64aedfa9f10fca424c0",
                "40edcb4e1125c272944041a0598bdf3400",
            ),
            concat!(
                "41ac9ac4c078828769325f7223379688914474b4c22b2de77afb209d726ab15b1e5fea27d65ec2c9",
                "e9512e169e4f37536c95550c20c5cfbf80",
            ),
        ),
        (
            concat!(
                "8ce20b30bd8c254a38f8c6daafc4a5cd2d9521335280b8cf30f33d60f4f4e03855ea920f0a7a7cc4",
                "06467f82deab4306ac5d3047ff7a7ed600",
            ),
            concat!(
                "bddf805b6adf4816007d8f3c3563c112527c48ace068355f36d247677f53128c333cdeb2ded56f8a",
                "4e717051c7046791405e79d546cb9f8980",
            ),
        ),
        (
            concat!(
                "eee3584b251b92bd799b7f9fe36b4a4a7ac6d781ad4e6905da4aebe56e8a9de03c3c2b1df9135853",
                "c72816c6ffc6f4def9e5e8089463592b00",
            ),
            concat!(
                "8512130916de332e34fe29720bbd1a66baad2053ce28be27640fd4b0589854ab4ed0205ca6d7dd5a",
                "29ea48f432a0be5737987411b8b2285d80",
            ),
        ),
        (
            concat!(
                "44de177bb8d004f74bc671066e7486ba86e8e3c100c0c58dd90a3534f9a0e49b1aefa567a5684532",
                "042168489c9a8dfe0a6a85a0c396789f00",
            ),
            concat!(
                "2e79242eadf42233f44f8329d12bb8d4c74c749f949439c0dc5c68aa6ae54c45488434b15b834532",
                "cb2e6759a926745110abe0bbfbc71d0d00",
            ),
        ),
        (
            concat!(
                "c7b20df22a86286c16c3f0c068982f04d9c8c30684f1f965b14cf42e263f1d632bd6931ffd036b41",
                "eea0ee1936b4288b05db7442aac1780900",
            ),
            concat!(
                "093ad98c0bdb6411fdb62ae1383b1bbcfaa5b64f14365b836f48aa41c962df648a542b9d6d889f43",
                "ff212bed1fb0101fe5e13a0c504d581a00",
            ),
        ),
        (
            concat!(
                "2833ef16b5a0e6afb273ba7dc23b6c586d7c219790512c8839b4b2e28282821150aaaecd2d190ecd",
                "998251d0dda909f587e373ac66236ffd00",
            ),
            concat!(
                "14df4bd454d4b651bd03b540179a6c6a56a2c46017dee74a1c05366c1843def5fa23875197c4a30c",
                "1feb4f0c6ba22660f233bda42c31b06a00",
            ),
        ),
        (
            concat!(
                "79e45ff9cce0a2da4aa7c5e1f93ed19a157c78f3b663b46fceebfde38e3a78c61e5c4f987be7b042",
                "07530142bc8640bf0bbcb7f8789b041e00",
            ),
            concat!(
                "edce5ef02a6f5648b3ee3bef978f6fd1cf2732faac4e2863b106b43c8795053dd2cdcb123181a355",
                "b3b64b43abcb256896669a6cf6c9881380",
            ),
        ),
        (
            concat!(
                "c00c95e2d9e08bff29046918dcee99960e7efc3bdc80fa07f9cbe6592d0acffae140ae58acdcfd7a",
                "1328d5ab5c44b4b762c7e9724d0a99a500",
            ),
            concat!(
                "79f40522ee03245aaedd4dddd622af244ef07a8572b453ef581e3294deb1df011870aecbf3771039",
                "f7705bfeda175b446815ad9c7ca5620300",
            ),
        ),
        (
            concat!(
                "810181dea6154523021423e34b95adc7dc1fefab20ecdefceb5d833c20fa26a115175714c641b38b",
                "dee3e8931058a079026414ddffe0523800",
            ),
            concat!(
                "f4b4cd16d1743e9201ab43068a91e2651b5940764c3807e0f65b15154c55c9f91f9227c4fbe3d755",
                "2c5b9bca26ad62c4d1cb771b05705f6100",
            ),
        ),
        (
            concat!(
                "c84289c704178780e1a713fc7194454bcdd9d6e620f038cfc8b93113fefc2dd85f5cd0f488c5b13a",
                "8d747914aca4676595772f275cde06d300",
            ),
            concat!(
                "01ec4c8ec77ad338c39346130bb49605a56fdc7cdba20a11e8073783d610508310ec02d3370abc70",
                "a63b1d63eca52b3e519a3f562a2be8ca80",
            ),
        ),
        (
            concat!(
                "6550e5d6adcb96fc9d07a333b6fa0cc2ad9e4db9b915c4204caaee72405d69786ee2bfcaaff263ab",
                "bb117029cb79051fbfa0cbb3a2da1e0c00",
            ),
            concat!(
                "8ac7a4817bf7f0a06f662f37811fd78414bd5b34e143fe34a3f81bec04034045836a7f95872f633d",
                "254fd7fafd7acf0df7e63e11bbab232f80",
            ),
        ),
        (
            concat!(
                "acfe74a2f55b41e2d92f6bc7354f9f30d2dc866e7f53744738ea149a312cdf678294d1d0830d8372",
                "2b13576aa5c8c4dcc0a78b07d99fa88400",
            ),
            concat!(
                "81bccfde082eb715e015b5fc0d92c0c82caa563ccb9edd082a17350513d129b441e034d10c04be2b",
                "27b1d62f5d3dfcc78cfcd60ec8a2254600",
            ),
        ),
        (
            concat!(
                "9bae37b82f1c3d495f6f6666cd63746f14e288e4389be1d37aaea0cc641548d909f0cfd138e383cc",
                "883be1547cc408497b03501780604f1d00",
            ),
            concat!(
                "ac949fdf38db6463ecf495decc3e63946d89e9f270b3f86856bc218a308e47db4c994f21f42ae51f",
                "94b4be521df1e2b69ca25372431550aa80",
            ),
        ),
        (
            concat!(
                "d453ac25d4e20aad2a9c16eaa334f5828689544f8bd865225fb51fed3ae0bf02fd465b9dbaaee495",
                "1d4c0481324f139993a17502a23ea9de00",
            ),
            concat!(
                "55af7f17ef6e30971b2c9a24edeb5d69199b5a2e681bdee09c32be2562498700e22ec7f2510bbd26",
                "455fba3f096f95cb1e296949238bd89e00",
            ),
        ),
    ];

    // (encoding, the x-coordinate if it decodes)
    const DECODE_KATS: &[(&str, Option<&str>)] = &[
        (
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6900",
            ),
            Some(concat!(
                "5ec00cc72ba826268e93008be1803b431165b62af71aae1264a4d3a324e36dea67170f477065149e",
                "da36bf22a6151d22ed0ded6bc670194f",
            )),
        ),
        (
            concat!(
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03",
                "b0c2865020d659b38d04d74a63e905ae80",
            ),
            Some(concat!(
                "55555555555555555555555555555555555555555555555555555555a9aaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )),
        ),
        (
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6980",
            ),
            Some(concat!(
                "a13ff338d457d9d9716cff741e7fc4bcee9a49d508e551ed9b5b2c5cda1c921598e8f0b88f9aeb61",
                "25c940dd59eae2dd12f21294398fe6b0",
            )),
        ),
        (
            concat!(
                "94585a26204cca479294c18524401287a58f7be9e3b36e61d1b9b79c6a578d4c3713d9200f00d376",
                "f8e1c48ab91b937b063733d4f17412f500",
            ),
            Some(concat!(
                "6c390256ec814483cd38b8087f184f49fbc9fb496875299d1770098745b5e4bb5ea2f5597b6307e4",
                "f94695fea4a60953f089ed89e70e135a",
            )),
        ),
        (
            concat!(
                "b89b163867480913d3f6143162b3657cfc38fc41facb97ac48fa0b604568ec4c616f3fbf668feffc",
                "6fee4527a70aa01f96a98129d5e5e0bf00",
            ),
            Some(concat!(
                "e2b83fc8c67c255aaf1a54fe9aea91d2d57a9cbfbed5924859999f953a08f28cc71e5112655ffe21",
                "0c0c02cfb5ec8fa44c8769bd7e272444",
            )),
        ),
        (
            concat!(
                "994bab718042b5c358d2ba9fd02efed42296b570228aafab530556e817b62d741c615f53af9fd9c0",
                "269af3f670907a059c3f512165af97dd80",
            ),
            Some(concat!(
                "3d5947abb6b647701a6b77675a7802e827969591ad1dca90ff6f5c71710db71ef090fbe093e22c01",
                "a342d095c362715ec9e2ca156fe59686",
            )),
        ),
        (
            concat!(
                "ea5cc90479fc658085eb16cb5b97b6c7295984247802ba18eb0ec300a47e60cada9470357cb9283e",
                "70a3b0e39479f004a8d28fd77398951100",
            ),
            Some(concat!(
                "2603078f6a1b7b1000f12905dcd7ef9d40c5e7825edf71aadf0d5529dac709f4c02e9e8be641b532",
                "e17bd2df80e4e3c63ec1be616b945819",
            )),
        ),
        (
            concat!(
                "b0f23b7dedec9ccb12537b8c17c27ea382d4d25c4e9186bd2581be4c1e00eceda1a483c1b3588be9",
                "6dca2e04858e956414961b9bffb1b67300",
            ),
            Some(concat!(
                "f44dcdc29c3cb26e7ef7da5c8c1a527e1e175fb3f1e84269b837522431478c953896158932599d67",
                "f336b35c1199b36bfd5ca87c002a6f6d",
            )),
        ),
        (
            concat!(
                "75b29c097a4cebd4ee07f22b995f3cd442d3015a5a5206359cf408ea95e63d548e880ca2e2d331d0",
                "e5b68641154f0a3b70d391733640dfe000",
            ),
            Some(concat!(
                "90a729de7638dbd07507cdd41af3a6d8086e708d03138ffbe6c3bf99b36cba76f8441ece5ca33b36",
                "edb8da653bc2b7804032edcb2e9f211d",
            )),
        ),
        (
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6980",
            ),
            Some(concat!(
                "a13ff338d457d9d9716cff741e7fc4bcee9a49d508e551ed9b5b2c5cda1c921598e8f0b88f9aeb61",
                "25c940dd59eae2dd12f21294398fe6b0",
            )),
        ),
        (
            concat!(
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03",
                "b0c2865020d659b38d04d74a63e905ae00",
            ),
            Some(concat!(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa555555555555555555555555",
                "55555555555555555555555555555555",
            )),
        ),
        (
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6900",
            ),
            Some(concat!(
                "5ec00cc72ba826268e93008be1803b431165b62af71aae1264a4d3a324e36dea67170f477065149e",
                "da36bf22a6151d22ed0ded6bc670194f",
            )),
        ),
        (
            concat!(
                "94585a26204cca479294c18524401287a58f7be9e3b36e61d1b9b79c6a578d4c3713d9200f00d376",
                "f8e1c48ab91b937b063733d4f17412f580",
            ),
            Some(concat!(
                "93c6fda9137ebb7c32c747f780e7b0b6043604b6978ad662e88ff678b94a1b44a15d0aa6849cf81b",
                "06b96a015b59f6ac0f76127618f1eca5",
            )),
        ),
        (
            concat!(
                "b89b163867480913d3f6143162b3657cfc38fc41facb97ac48fa0b604568ec4c616f3fbf668feffc",
                "6fee4527a70aa01f96a98129d5e5e0bf80",
            ),
            Some(concat!(
                "1d47c0373983daa550e5ab0165156e2d2a856340412a6db7a666606ac4f70d7338e1aeed9aa001de",
                "f3f3fd304a13705bb378964281d8dbbb",
            )),
        ),
        (
            concat!(
                "994bab718042b5c358d2ba9fd02efed42296b570228aafab530556e817b62d741c615f53af9fd9c0",
                "269af3f670907a059c3f512165af97dd00",
            ),
            Some(concat!(
                "c2a6b8544949b88fe5948898a587fd17d8696a6e52e2356f0090a38e8df248e10f6f041f6c1dd3fe",
                "5cbd2f6a3c9d8ea1361d35ea901a6979",
            )),
        ),
        (
            concat!(
                "ea5cc90479fc658085eb16cb5b97b6c7295984247802ba18eb0ec300a47e60cada9470357cb9283e",
                "70a3b0e39479f004a8d28fd77398951180",
            ),
            Some(concat!(
                "d9fcf87095e484efff0ed6fa23281062bf3a187da1208e5520f2aad62438f60b3fd1617419be4acd",
                "1e842d207f1b1c39c13e419e946ba7e6",
            )),
        ),
        (
            concat!(
                "b0f23b7dedec9ccb12537b8c17c27ea382d4d25c4e9186bd2581be4c1e00eceda1a483c1b3588be9",
                "6dca2e04858e956414961b9bffb1b67380",
            ),
            Some(concat!(
                "0bb2323d63c34d91810825a373e5ad81e1e8a04c0e17bd9647c8addbcdb8736ac769ea76cda66298",
                "0cc94ca3ee664c9402a35783ffd59092",
            )),
        ),
        (
            concat!(
                "75b29c097a4cebd4ee07f22b995f3cd442d3015a5a5206359cf408ea95e63d548e880ca2e2d331d0",
                "e5b68641154f0a3b70d391733640dfe080",
            ),
            Some(concat!(
                "6f58d62189c7242f8af8322be50c5927f7918f72fcec7004193c40664b93458907bbe131a35cc4c9",
                "1247259ac43d487fbfcd1234d160dee2",
            )),
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            Some(concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
            )),
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000080",
            ),
            None,
        ),
        (
            concat!(
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            Some(concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
            )),
        ),
        (
            concat!(
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff80",
            ),
            None,
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            Some(concat!(
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff",
            )),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000080",
            ),
            Some(concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000",
            )),
        ),
        (
            concat!(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            None,
        ),
        (
            concat!(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff80",
            ),
            None,
        ),
        (
            concat!(
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            None,
        ),
        (
            concat!(
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff80",
            ),
            None,
        ),
        (
            concat!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            None,
        ),
        (
            concat!(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff80",
            ),
            None,
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000001",
            ),
            None,
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000040",
            ),
            None,
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000000000007f",
            ),
            None,
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "00000000000000000000000000000000ff",
            ),
            None,
        ),
        (
            concat!(
                "fdfffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            None,
        ),
        (
            concat!(
                "02000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            None,
        ),
        (
            concat!(
                "03000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            Some(concat!(
                "56fc238830d27b8bd9071609a76739ef95202c7453cd7d97b3ec523697db2b494138ca9956b18f75",
                "797b62b057eb1ab7d75f18ecc4d0c429",
            )),
        ),
        (
            concat!(
                "04000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            Some(concat!(
                "ac987579afde17b65386cfe7099760645bfe15cd9e8155e2fa20fa47bfb4ab13451d3060b92920cb",
                "e33842e44f3552d4d0cf1f1fa0c838eb",
            )),
        ),
        (
            concat!(
                "05000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            Some(concat!(
                "70b87326d7123986088fdf0dfff48740a4b8786f6c9f493e627ae0d15a2e71a93b570d53e8c46f23",
                "8a25c3a6ce3818e167bff527b1c793ff",
            )),
        ),
        (
            concat!(
                "06000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            None,
        ),
        (
            concat!(
                "4b3fe6600e6f69e1d654cd47f5c685bc3ab9b88f61040dedba31b76cb59bcc070d47ff99455cc41c",
                "d07f89f38466ec93578a15d17544dea780",
            ),
            None,
        ),
        (
            concat!(
                "12931da85261362553a655c87400246a97889b78c392e7c27ace995731fbcc263e47ba3fbc1fbfe6",
                "1177da01af521cc35bce79b2d50d29b700",
            ),
            Some(concat!(
                "32a19adcfbd107eae769e91ba875a066f4b1ef158c924bea0c72f800622600ca01db465b96b41b87",
                "a6945a2b1de0386093c224e8055ff00a",
            )),
        ),
        (
            concat!(
                "64fd9b75ac68b85e038f3ba700699870588b062cafc11473c9bd4ca1e6571e5b9b72d825da5ce883",
                "a8f4f5732d4cb174ad31d325ccf8125d80",
            ),
            None,
        ),
        (
            concat!(
                "4ba279e168ec949042c1cec1ec94cf2cea149f5d328cd00d88e18d6658921dd2d30c3c1d4980fd3f",
                "cd3fcff8449ef64e924c8be90418a77c80",
            ),
            None,
        ),
        (
            concat!(
                "e37c28779d9b5647e7c08cbc8333b5488d4da56fda9bf789bdd63164cfdf4903bf9bce0767b64468",
                "369b8ef4461a0a5310039a140da7781b80",
            ),
            Some(concat!(
                "17e8b549517ca95f76bd778c1881b2f8c82988ffe832eb224fc255c837f8adc9d6c4bed54ed7699d",
                "65f885db065344cd78cf3b28009bfb75",
            )),
        ),
        (
            concat!(
                "be5d3ce3592c016a5beb75ee62896427b9d65b8ad3f987b3b33a99c98f8c758fcb8af5a9221c241d",
                "b9f6c6a159d65a0423f13f0202f79b7300",
            ),
            None,
        ),
        (
            concat!(
                "55d8e9ed3a5457b9ea2a5122f85bb645914cf01db5121067b174c8e62ebed0c26fe2acfcfd7746ec",
                "fd19a57bf4eb0b114f0f657998ddef7680",
            ),
            Some(concat!(
                "654d88ea995b124d4fed7fbaf3b10716154814357dba753e583afb930e77a8c37b6b2a6eabfddd1b",
                "c573690aac4d3ffe110a3b8501097070",
            )),
        ),
        (
            concat!(
                "7dada2c8674eaa6d0d7a442461621dc60a8bdabbc595d8ca81f32f1652c59fcb252f5be7afb1611f",
                "30a866810062890ad84a8189856895af00",
            ),
            None,
        ),
        (
            concat!(
                "2f5c3651facba2d2e01d61a2ce1f7beca008b61235ca5134eab8064be5ab024e617d73d92c09f97b",
                "0f15ae1af6b566239857641c1496e14180",
            ),
            None,
        ),
        (
            concat!(
                "6eaf69e95b978c9e3a0682b07b74f6243f9c6d3c1b7e76b59dee2e03c2fc96597c829f678ccd7d51",
                "45d2e13f0173fff53bd95a34563203cd00",
            ),
            None,
        ),
    ];

    // (encoding, whether it is a fully valid public key)
    const PUBLIC_KEY_KATS: &[(&str, bool)] = &[
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            false,
        ),
        (
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6900",
            ),
            true,
        ),
        (
            concat!(
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03",
                "b0c2865020d659b38d04d74a63e905ae80",
            ),
            true,
        ),
        (
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6980",
            ),
            true,
        ),
        (
            concat!(
                "94585a26204cca479294c18524401287a58f7be9e3b36e61d1b9b79c6a578d4c3713d9200f00d376",
                "f8e1c48ab91b937b063733d4f17412f500",
            ),
            true,
        ),
        (
            concat!(
                "b89b163867480913d3f6143162b3657cfc38fc41facb97ac48fa0b604568ec4c616f3fbf668feffc",
                "6fee4527a70aa01f96a98129d5e5e0bf00",
            ),
            true,
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            false,
        ),
        (
            concat!(
                "81ef460ab56155fa0dd5cd446a25bbdb9a054d532c5e47a02ac41198b46008a0f42476a732bb9f65",
                "bad9bd35141bdb3a9a0babde3f0e9c6000",
            ),
            true,
        ),
        (
            concat!(
                "994bab718042b5c358d2ba9fd02efed42296b570228aafab530556e817b62d741c615f53af9fd9c0",
                "269af3f670907a059c3f512165af97dd80",
            ),
            true,
        ),
        (
            concat!(
                "ea5cc90479fc658085eb16cb5b97b6c7295984247802ba18eb0ec300a47e60cada9470357cb9283e",
                "70a3b0e39479f004a8d28fd77398951100",
            ),
            true,
        ),
        (
            concat!(
                "b0f23b7dedec9ccb12537b8c17c27ea382d4d25c4e9186bd2581be4c1e00eceda1a483c1b3588be9",
                "6dca2e04858e956414961b9bffb1b67300",
            ),
            true,
        ),
        (
            concat!(
                "75b29c097a4cebd4ee07f22b995f3cd442d3015a5a5206359cf408ea95e63d548e880ca2e2d331d0",
                "e5b68641154f0a3b70d391733640dfe000",
            ),
            true,
        ),
        (
            concat!(
                "abbf2934c56aa0379b9dd124dd16acad810cd49609007bb12f5f8aa6836cf23f69deda71d001cacb",
                "52108860ce139c0c9444ed1c8decf2e880",
            ),
            true,
        ),
        (
            concat!(
                "1efc654e7a65d03785bb23a415190a1855eae6be7a23933e87294557d0dce278f8e2c6a00dba2f2f",
                "8a9d22b2102a1ca3beb93ca253bf75ee00",
            ),
            true,
        ),
        (
            concat!(
                "41ac9ac4c078828769325f7223379688914474b4c22b2de77afb209d726ab15b1e5fea27d65ec2c9",
                "e9512e169e4f37536c95550c20c5cfbf80",
            ),
            true,
        ),
        (
            concat!(
                "bddf805b6adf4816007d8f3c3563c112527c48ace068355f36d247677f53128c333cdeb2ded56f8a",
                "4e717051c7046791405e79d546cb9f8980",
            ),
            true,
        ),
        (
            concat!(
                "8512130916de332e34fe29720bbd1a66baad2053ce28be27640fd4b0589854ab4ed0205ca6d7dd5a",
                "29ea48f432a0be5737987411b8b2285d80",
            ),
            true,
        ),
        (
            concat!(
                "2e79242eadf42233f44f8329d12bb8d4c74c749f949439c0dc5c68aa6ae54c45488434b15b834532",
                "cb2e6759a926745110abe0bbfbc71d0d00",
            ),
            true,
        ),
        (
            concat!(
                "093ad98c0bdb6411fdb62ae1383b1bbcfaa5b64f14365b836f48aa41c962df648a542b9d6d889f43",
                "ff212bed1fb0101fe5e13a0c504d581a00",
            ),
            true,
        ),
        (
            concat!(
                "14df4bd454d4b651bd03b540179a6c6a56a2c46017dee74a1c05366c1843def5fa23875197c4a30c",
                "1feb4f0c6ba22660f233bda42c31b06a00",
            ),
            true,
        ),
        (
            concat!(
                "edce5ef02a6f5648b3ee3bef978f6fd1cf2732faac4e2863b106b43c8795053dd2cdcb123181a355",
                "b3b64b43abcb256896669a6cf6c9881380",
            ),
            true,
        ),
        (
            concat!(
                "79f40522ee03245aaedd4dddd622af244ef07a8572b453ef581e3294deb1df011870aecbf3771039",
                "f7705bfeda175b446815ad9c7ca5620300",
            ),
            true,
        ),
        (
            concat!(
                "f4b4cd16d1743e9201ab43068a91e2651b5940764c3807e0f65b15154c55c9f91f9227c4fbe3d755",
                "2c5b9bca26ad62c4d1cb771b05705f6100",
            ),
            true,
        ),
        (
            concat!(
                "01ec4c8ec77ad338c39346130bb49605a56fdc7cdba20a11e8073783d610508310ec02d3370abc70",
                "a63b1d63eca52b3e519a3f562a2be8ca80",
            ),
            true,
        ),
        (
            concat!(
                "8ac7a4817bf7f0a06f662f37811fd78414bd5b34e143fe34a3f81bec04034045836a7f95872f633d",
                "254fd7fafd7acf0df7e63e11bbab232f80",
            ),
            true,
        ),
        (
            concat!(
                "81bccfde082eb715e015b5fc0d92c0c82caa563ccb9edd082a17350513d129b441e034d10c04be2b",
                "27b1d62f5d3dfcc78cfcd60ec8a2254600",
            ),
            true,
        ),
        (
            concat!(
                "ac949fdf38db6463ecf495decc3e63946d89e9f270b3f86856bc218a308e47db4c994f21f42ae51f",
                "94b4be521df1e2b69ca25372431550aa80",
            ),
            true,
        ),
        (
            concat!(
                "55af7f17ef6e30971b2c9a24edeb5d69199b5a2e681bdee09c32be2562498700e22ec7f2510bbd26",
                "455fba3f096f95cb1e296949238bd89e00",
            ),
            true,
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            false,
        ),
        (
            concat!(
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            false,
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            false,
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000080",
            ),
            false,
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000080",
            ),
            false,
        ),
        (
            concat!(
                "fefffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff80",
            ),
            false,
        ),
        (
            concat!(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            false,
        ),
        (
            concat!(
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff00",
            ),
            false,
        ),
        (
            concat!(
                "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffffff80",
            ),
            false,
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000001",
            ),
            false,
        ),
        (
            concat!(
                "15a336fb86039a7f7a14e934a4684938d6a67bdb87fd45e714f13cff5a819f35256b8fca8346d7c1",
                "8f5c4f1c6b860ffb572d70288c676aee80",
            ),
            false,
        ),
        (
            concat!(
                "f44dcdc29c3cb26e7ef7da5c8c1a527e1e175fb3f1e84269b837522431478c953896158932599d67",
                "f336b35c1199b36bfd5ca87c002a6f6d80",
            ),
            false,
        ),
        (
            concat!(
                "6f58d62189c7242f8af8322be50c5927f7918f72fcec7004193c40664b93458907bbe131a35cc4c9",
                "1247259ac43d487fbfcd1234d160dee280",
            ),
            false,
        ),
        (
            concat!(
                "c7509850abdce6e272cd8ce088d078d457719818b61b146e9754224ed23ccf4c50e8e54d52d5ad07",
                "d591f1d53806316d986c6a90c6ac609a80",
            ),
            true,
        ),
        (
            concat!(
                "6d1f6d40de20823ec1aea4591c5afea5c25e7c39d42333d6ff5dd68c736ff81adb22272394fcdd25",
                "d5dc5f74f6ce12e4cde1f72cfd6b15e700",
            ),
            false,
        ),
        (
            concat!(
                "dc3077682a2f5ac3048ecf52aca53a262bcbebc3f46fe154f129b81cd39ad5909d69820d268b9ab2",
                "6c5df7ff6b77b831d928e817a8b4223180",
            ),
            false,
        ),
        (
            concat!(
                "7aee44d356b5ad7f98706033666207ea669721cc346cdd5aebc639128af6ebf0f7645a5a2c101dfc",
                "f4a195162563e38eb8476c023ea8cbd280",
            ),
            false,
        ),
        (
            concat!(
                "b3ef8facd482399b8ef49c512bfbf39c3b84481eb64ba3265e29a57d8dd7d821364f4b8ca02538ac",
                "a1dbea2652c1ed4a717af5b5bd2a805380",
            ),
            false,
        ),
        (
            concat!(
                "de9cc37359f072cef42b3feec270c0f831d2a856696bbd2c0cbec97d2b9bad9ce1f315fd46886f51",
                "9efa0c3e0d0f9ffa31e200ec2d457f7080",
            ),
            false,
        ),
        (
            concat!(
                "dfd21c14e993031e5f3244d169e2d57a3cd2378eb1e4232bfe85fee3f292078db451230da4aa6863",
                "5481449ce1216c677286652596641aea00",
            ),
            true,
        ),
        (
            concat!(
                "8a4237941e2db9ad92a9e8015914deaefaae5cbe66d49887c6da95165acf77e630d3c596eddfb3fd",
                "21da316e35563f75e8fc7217eda766c900",
            ),
            false,
        ),
        (
            concat!(
                "5bf7f738b18d26ffbe75148512583f7817f005d7045f4d0bead756816e4a93ff2208b1d46649ea42",
                "efbc5cdaa225d7f431058bda141e7d8980",
            ),
            false,
        ),
        (
            concat!(
                "e5f8e889bf5018a13aad80153b8ca4a336c3acffb19dc36ac1da450da8005e308babe925451dfafd",
                "e84a87708d7b7e1e2966e0bf11b5e3c880",
            ),
            false,
        ),
        (
            concat!(
                "04f1d6045697fb30b9831e65f3ea9b2b53cf45f5046c8121937183b44bfa5e8daeffcac3644ae75f",
                "71b0b5506956c066e89d14e5abf7e46480",
            ),
            false,
        ),
        (
            concat!(
                "c69f0b0992920819be63e6fd807733dc83c4447eb26c47253f73913d47a5eae78107e3e44ba17ad4",
                "8642eca2b176092d2e4e78e2ce61ea9380",
            ),
            false,
        ),
    ];

    // (nb, np, P, nq, Q, the encoding of [4]([nb]B + [np]P + [nq]Q)); np and nq are
    // 32 octets of two's complement
    const STRAUS_KATS: &[(&str, &str, &str, &str, &str, &str)] = &[
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            "0000000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6900",
            ),
            "0000000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03",
                "b0c2865020d659b38d04d74a63e905ae80",
            ),
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
        ),
        (
            concat!(
                "01000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            "0000000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6900",
            ),
            "0000000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03",
                "b0c2865020d659b38d04d74a63e905ae80",
            ),
            concat!(
                "3918e56df836e2325b4f0d5d2844d4b57294caa17ef9d8c0c15b8a7b22c30dc945d857042fc0b79c",
                "971b02dea5334b1627e5cdace47790d400",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            "0100000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6900",
            ),
            "0000000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03",
                "b0c2865020d659b38d04d74a63e905ae80",
            ),
            concat!(
                "3918e56df836e2325b4f0d5d2844d4b57294caa17ef9d8c0c15b8a7b22c30dc945d857042fc0b79c",
                "971b02dea5334b1627e5cdace47790d400",
            ),
        ),
        (
            concat!(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000",
            ),
            "0000000000000000000000000000000000000000000000000000000000000000",
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6900",
            ),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            concat!(
                "ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a726de3b7d74d8835a0d76e03",
                "b0c2865020d659b38d04d74a63e905ae80",
            ),
            concat!(
                "9be069ce73b84e45eec84b1663169fd8a83b00f70882ad86d3ea984b7b4cd97b3bb9a4b3386b8c40",
                "ba46ff74351f7de8da9bea9b4e4f56c780",
            ),
        ),
        (
            concat!(
                "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffff",
                "ffffffffffffffffffffffffffffff3f00",
            ),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000",
            concat!(
                "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b",
                "62c7c9563720768824bcb66e71463f6980",
            ),
            "00000000000000000000000000000000000000000000000000000000ffffffff",
            concat!(
                "94585a26204cca479294c18524401287a58f7be9e3b36e61d1b9b79c6a578d4c3713d9200f00d376",
                "f8e1c48ab91b937b063733d4f17412f500",
            ),
            concat!(
                "f124b78b026208573824472b2ffb1d0532c0e322e18cb4ac993abd0d519f0e01fa92fba28505bd77",
                "538e88a3c25678010c0247eb74ac3c1100",
            ),
        ),
        (
            concat!(
                "e527d90abeacf4f78768b943002a8864a0b451980ecd456b625e8be191801fcf604594d908e91a34",
                "28119d7e8a923629bd85d8aed377c23200",
            ),
            "721a1f27ca5cafde849a5cca4da1b730d5b5217c05b7158c2944fdd400000000",
            concat!(
                "994bab718042b5c358d2ba9fd02efed42296b570228aafab530556e817b62d741c615f53af9fd9c0",
                "269af3f670907a059c3f512165af97dd80",
            ),
            "a9a720b4c7ce3ac96d2a6b89fab21494adf6694baa18c69c5856df7f00000000",
            concat!(
                "ea5cc90479fc658085eb16cb5b97b6c7295984247802ba18eb0ec300a47e60cada9470357cb9283e",
                "70a3b0e39479f004a8d28fd77398951100",
            ),
            concat!(
                "a33192b3325d6d16165d77993459753c289e325c0d6075df129534ddceb574c93bc5d895f8e5ef2f",
                "ad9f46d0ed38653a7a6553abdc7742d380",
            ),
        ),
        (
            concat!(
                "69c31bb7cd4559e1505a05c5a3e4c7e7e98533d3cacc683fd588627117bfd01f076f86136e2ec310",
                "132b5a98eac206aeae21b3482c69790d00",
            ),
            "aaaa8c3851a340f7549397857047fa21461740eb1117897c7c98eeceffffffff",
            concat!(
                "ea5cc90479fc658085eb16cb5b97b6c7295984247802ba18eb0ec300a47e60cada9470357cb9283e",
                "70a3b0e39479f004a8d28fd77398951100",
            ),
            "787b4ccc6d5d909836d3d39b6db0afdd627224c1b684aa9dabaef45900000000",
            concat!(
                "b0f23b7dedec9ccb12537b8c17c27ea382d4d25c4e9186bd2581be4c1e00eceda1a483c1b3588be9",
                "6dca2e04858e956414961b9bffb1b67300",
            ),
            concat!(
                "b675183b1a0ba656a7aaf57a71b83812c542b5563da404fa28ab70998cf6d81eefa7ca524d9ceb03",
                "b75cd32174d82bb39a424cb0fb4e1deb80",
            ),
        ),
        (
            concat!(
                "3c7bc7a56618d23b33175e78b477c53d0a149a96992676385fc2445757de550561e669c1c24958f0",
                "28b4ff47cedd51206400b6752677cd2600",
            ),
            "9e42b08dad87e1f05205bd3d4ca77dafa47f6599bcde9a4b9e20accf00000000",
            concat!(
                "b0f23b7dedec9ccb12537b8c17c27ea382d4d25c4e9186bd2581be4c1e00eceda1a483c1b3588be9",
                "6dca2e04858e956414961b9bffb1b67300",
            ),
            "d0ad717796ef798f0854bf568b6d4e094a831e57c3a61237dc9a5c4e00000000",
            concat!(
                "75b29c097a4cebd4ee07f22b995f3cd442d3015a5a5206359cf408ea95e63d548e880ca2e2d331d0",
                "e5b68641154f0a3b70d391733640dfe000",
            ),
            concat!(
                "29974b394b6bddcabc2e10a646e87483f61d074cc6f0a7f159879fcb45482c467d6b34a882a1678e",
                "2aae9f3a3af0d6e325a475ea967f36f380",
            ),
        ),
        (
            concat!(
                "feed852967281ab661e7e70134094e98995f21e1ac92d310128253a1ff538e7f16076e1ae73756c3",
                "3f3fd0fe2f55ffb0b3290f28e113ac3900",
            ),
            "1ce7f65aa3063dcdc4040e260df94b7bb68cc16d6bb75a906251841f00000000",
            concat!(
                "75b29c097a4cebd4ee07f22b995f3cd442d3015a5a5206359cf408ea95e63d548e880ca2e2d331d0",
                "e5b68641154f0a3b70d391733640dfe000",
            ),
            "8e011db5ec5aabdc96e2f625f85c5014b8b7d2fa833dd30c1b40e621ffffffff",
            concat!(
                "abbf2934c56aa0379b9dd124dd16acad810cd49609007bb12f5f8aa6836cf23f69deda71d001cacb",
                "52108860ce139c0c9444ed1c8decf2e880",
            ),
            concat!(
                "69472cf3bd5d53155e08d380e1693be3c8751cd6a5fc39219631073c9d1ba415af0944c0fd350a30",
                "8be72f3a5238c808ccdaeba74fb4a62780",
            ),
        ),
        (
            concat!(
                "2a28837838aae7d43064f68bb2b184a98dcf7c36861d16a14e50e54329fbb4e16ec38477d3fad294",
                "b568d2f1eb117b607335c06bcba7531400",
            ),
            "ac59e682a22ad60ec1c6e32e5c2a8669a332cfe7fe372f97a63bca7200000000",
            concat!(
                "abbf2934c56aa0379b9dd124dd16acad810cd49609007bb12f5f8aa6836cf23f69deda71d001cacb",
                "52108860ce139c0c9444ed1c8decf2e880",
            ),
            "7e41da7799e93876138e24a71be21c6079e703c5d0894eb887761f3500000000",
            concat!(
                "1efc654e7a65d03785bb23a415190a1855eae6be7a23933e87294557d0dce278f8e2c6a00dba2f2f",
                "8a9d22b2102a1ca3beb93ca253bf75ee00",
            ),
            concat!(
                "e884152b8ec31941ed65c827bb83a15ce65cc1c2f0df234ed3fb5724ed4432e60fd1b16d776a61a1",
                "638bacd5954ff676088b04f88f5e1b5380",
            ),
        ),
        (
            concat!(
                "c813f4b6cf0c139ee6d4ddbfe1d20cac3c8b3e51b68676ae28e8d2a57f952c8ca6bf7cc32f622e51",
                "264b8308b554a1967297fc202ac31a3000",
            ),
            "130d8617adcdb108857948c68c8ca42f41a1edc29f0222203efef90c00000000",
            concat!(
                "1efc654e7a65d03785bb23a415190a1855eae6be7a23933e87294557d0dce278f8e2c6a00dba2f2f",
                "8a9d22b2102a1ca3beb93ca253bf75ee00",
            ),
            "665e7a13aa02e06b048feebf80d1bd239f913f053fc4f6249bf8623300000000",
            concat!(
                "41ac9ac4c078828769325f7223379688914474b4c22b2de77afb209d726ab15b1e5fea27d65ec2c9",
                "e9512e169e4f37536c95550c20c5cfbf80",
            ),
            concat!(
                "d0950ba7fdce9997c217f06a7002ec2227b5c6f4d64c51553224d0eac15c04f25e1c46e011834b7a",
                "025f569af541b31e766c0cf440c069dc80",
            ),
        ),
        (
            concat!(
                "900facaf3b88e5f8f1e3e3605d29feda31c630becce8534db6434b1c9b4464be6a2ca72e28ffc960",
                "dbda165ead0b7389a8c709545c08ef3400",
            ),
            "fde302d36e40e0df6fcd556e6a4c0ba75b6ee706391a3e611ff4f71f00000000",
            concat!(
                "41ac9ac4c078828769325f7223379688914474b4c22b2de77afb209d726ab15b1e5fea27d65ec2c9",
                "e9512e169e4f37536c95550c20c5cfbf80",
            ),
            "61cad90653d6e72b8f7992af9480f4bfb44d79e8056410a909e96b9affffffff",
            concat!(
                "bddf805b6adf4816007d8f3c3563c112527c48ace068355f36d247677f53128c333cdeb2ded56f8a",
                "4e717051c7046791405e79d546cb9f8980",
            ),
            concat!(
                "6dd314ad37b9b631664e28af6222fa51204d505f085e401aa687c64ee3ce82039491f239e2e57cc0",
                "dc02ac89dea81d6e812cd3c513eff2bb80",
            ),
        ),
        (
            concat!(
                "80331dcf8dc2339a3cccb9844e5cee2c83d5f3f7acb62006d1a71a2594358d64ca61b01c94c3d47b",
                "8a320fdaa12acd6f37eb15d472b4f90a00",
            ),
            "f9726a7b7b1e827a7dc74d70f316271c3840c882017ed08c91fba42cffffffff",
            concat!(
                "bddf805b6adf4816007d8f3c3563c112527c48ace068355f36d247677f53128c333cdeb2ded56f8a",
                "4e717051c7046791405e79d546cb9f8980",
            ),
            "214fa3960dbd486de0f2833d5f86d142b96a7c909030c6660e0f280a00000000",
            concat!(
                "8512130916de332e34fe29720bbd1a66baad2053ce28be27640fd4b0589854ab4ed0205ca6d7dd5a",
                "29ea48f432a0be5737987411b8b2285d80",
            ),
            concat!(
                "98333d86d053c0c29549f708c2859f9f68ad5f60e9ea6519be92ee66626cdadfaf57eeed758ca065",
                "cc02d35024005cd97e0a02cc57b5d19480",
            ),
        ),
        (
            concat!(
                "1c287c27945bd26ad01ab5090e35f692478634fc3aadf1a265d1fb5b0f829af6a54477f64fd7dc0d",
                "ef3355b82feac77c5753eb1176c8491f00",
            ),
            "115e8babee345ea5b9ea1e84e936183b1d758517311c07ae32c1834f00000000",
            concat!(
                "8512130916de332e34fe29720bbd1a66baad2053ce28be27640fd4b0589854ab4ed0205ca6d7dd5a",
                "29ea48f432a0be5737987411b8b2285d80",
            ),
            "caf176d81f1d5391074812e7d69e86e637e169f1122074005859b407ffffffff",
            concat!(
                "2e79242eadf42233f44f8329d12bb8d4c74c749f949439c0dc5c68aa6ae54c45488434b15b834532",
                "cb2e6759a926745110abe0bbfbc71d0d00",
            ),
            concat!(
                "8465132edd4e60b08d9c8322da501db003f852f1dc1b71ccfd3da64e787fc0d61c1d6ae6a40742bf",
                "bb8fa473d595cbfe8db42aa9cf5421b500",
            ),
        ),
        (
            concat!(
                "5c7516106e7b6d8b7ac72ae032b52665a0e068d5c50e760beb1bf71058b7ff1b039fd321846838f7",
                "1352eafa10e07a8e679761f959759c2700",
            ),
            "95dea666ff40673d406a44622e402648c9463b1799728de8477b702300000000",
            concat!(
                "2e79242eadf42233f44f8329d12bb8d4c74c749f949439c0dc5c68aa6ae54c45488434b15b834532",
                "cb2e6759a926745110abe0bbfbc71d0d00",
            ),
            "280f2d7fdaa5b1f6507158aa9fa8853d6790a5b53a83389bf1b24d1100000000",
            concat!(
                "093ad98c0bdb6411fdb62ae1383b1bbcfaa5b64f14365b836f48aa41c962df648a542b9d6d889f43",
                "ff212bed1fb0101fe5e13a0c504d581a00",
            ),
            concat!(
                "695b18948958a5d87267320616b2607b9d93b87ed626cc77e0051a227a480f1745e3bc073bf2ba4d",
                "cde37da96d857420b944b58b485e3be980",
            ),
        ),
    ];

    // RFC 8032 Section 5.2, Table 2, lifted from the RFC text by script: the coordinates of
    // B, in decimal.
    const B_X: &str = concat!(
        "22458004029592430018760433409989603624678964163256413424612546168695041546740603",
        "2909029192869357953282578032075146446173674602635247710",
    );
    const B_Y: &str = concat!(
        "29881921007848149267601793044393067343754404015408024209592824137233150618983587",
        "6003536878655418784733982303233503462500531545062832660",
    );

    fn octets<const N: usize>(hex: &str) -> [u8; N] {
        bouncycastle_core::hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn quarter(hex: &str) -> [u64; 4] {
        let v: [u8; 32] = octets(hex);
        core::array::from_fn(|i| u64::from_le_bytes(v[8 * i..8 * i + 8].try_into().unwrap()))
    }

    fn limbs(k: &[u8; SCALAR_LEN]) -> [u64; 7] {
        let mut n = [0_u64; 7];
        scalar::decode_into(k, &mut n);
        n
    }

    /// L as an encoded scalar.
    fn order() -> [u8; SCALAR_LEN] {
        let mut l = [0_u8; SCALAR_LEN];
        for (chunk, limb) in l.chunks_mut(8).zip(scalar::L) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        l
    }

    /// splitmix64: a fixed stream of test values.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn small(value: i64) -> FieldElement448 {
        FieldElement448::new([value, 0, 0, 0, 0, 0, 0, 0])
    }

    fn decimal(digits: &str) -> FieldElement448 {
        digits
            .bytes()
            .fold(FieldElement448::zero(), |acc, c| acc.mul_u32(10).add(&small((c - b'0') as i64)))
    }

    /// The canonical encoding of a field element.
    fn canonical(x: &FieldElement448) -> [u8; 56] {
        let mut octets = [0_u8; 56];
        x.normalize().encode_448(&mut octets);
        octets
    }

    /// The base point, from the RFC's coordinates.
    fn base_point() -> PointAffine {
        PointAffine { x: decimal(B_X).normalize(), y: decimal(B_Y).normalize() }
    }

    fn neutral_affine() -> PointAffine {
        PointAffine { x: small(0).normalize(), y: small(1).normalize() }
    }

    fn encoded(p: &PointAffine) -> [u8; POINT_LEN] {
        let mut r = [0_u8; POINT_LEN];
        p.encode(&mut r);
        r
    }

    fn encoded_projective(p: &PointProjective) -> [u8; POINT_LEN] {
        encoded(&p.to_affine())
    }

    fn base_mult(k: &[u8; SCALAR_LEN]) -> [u8; POINT_LEN] {
        let mut r = [0xA5_u8; POINT_LEN];
        scalar_mult_base_encoded(k, &mut r).unwrap();
        r
    }

    /// The encoding of the neutral element.
    fn neutral_encoding() -> [u8; POINT_LEN] {
        let mut neutral = [0_u8; POINT_LEN];
        neutral[0] = 1;
        neutral
    }

    // An independent reference for the group law: the affine formulas of RFC 8032 Section 3
    // with a = 1,
    //   x3 = (x1 y2 + x2 y1) / (1 + d x1 x2 y1 y2),  y3 = (y1 y2 - x1 x2) / (1 - d x1 x2 y1 y2)
    // and multiplication by doubling and adding with them, a bit at a time.

    fn reference_add(p: &PointAffine, q: &PointAffine) -> PointAffine {
        let one = FieldElement448::one();
        let (x1x2, y1y2) = (p.x.mul(&q.x), p.y.mul(&q.y));
        // t = d x1 x2 y1 y2
        let t = x1x2.mul(&y1y2).mul_u32(C_NEG_D).negate();
        let (one_plus_t, one_minus_t) = (one.add(&t), one.sub(&t));
        let inverse = one_plus_t.mul(&one_minus_t).inv();
        let x3 = p.x.mul(&q.y).add(&q.x.mul(&p.y)).mul(&one_minus_t).mul(&inverse);
        let y3 = y1y2.sub(&x1x2).mul(&one_plus_t).mul(&inverse);
        PointAffine { x: x3.normalize(), y: y3.normalize() }
    }

    /// `[k]P` for `k` in little-endian octets.
    fn reference_mult(k: &[u8], p: &PointAffine) -> PointAffine {
        let mut acc = neutral_affine();
        let top = (0..8 * k.len()).rev().find(|bit| (k[bit / 8] >> (bit % 8)) & 1 == 1);
        for bit in (0..top.map_or(0, |top| top + 1)).rev() {
            acc = reference_add(&acc, &acc);
            if (k[bit / 8] >> (bit % 8)) & 1 == 1 {
                acc = reference_add(&acc, p);
            }
        }
        acc
    }

    /// `[y]P` for a signed `y` in four limbs of two's complement, by the reference.
    fn reference_mult_signed(y: &[u64; 4], p: &PointAffine) -> PointAffine {
        let negative = (y[3] as i64) < 0;
        let mut magnitude: Vec<u8> = y.iter().flat_map(|limb| limb.to_le_bytes()).collect();
        if negative {
            let mut carry = 1_u16;
            for octet in &mut magnitude {
                carry += (!*octet) as u16;
                *octet = carry as u8;
                carry >>= 8;
            }
        }
        reference_mult(&magnitude, &if negative { p.negate() } else { p.clone() })
    }

    /// A point of the subgroup other than B, with a Z that is not one.
    fn sample_projective(multiple: u8) -> (PointAffine, PointProjective) {
        let affine = reference_mult(&[multiple], &base_point());
        let z = small(0x1234_5678_9ABC + multiple as i64);
        let projective = PointProjective { x: affine.x.mul(&z), y: affine.y.mul(&z), z };
        (affine, projective)
    }

    #[test]
    fn the_constants_are_those_of_the_rfc() {
        assert_eq!((POINT_LEN, C_NEG_D), (57, 39081));
        assert_eq!((PRECOMP_POINTS, PRECOMP_WNAF_POINTS, WNAF_POINTS_225), (16, 32, 8));

        let b = base_point();
        assert!(b.is_valid_result().to_bool());
        // [1]B from the comb is the RFC's B, and decodes back to its coordinates.
        let mut one = [0_u8; SCALAR_LEN];
        one[0] = 1;
        assert_eq!(base_mult(&one), encoded(&b));
        let decoded = PointAffine::decode_var(&encoded(&b)).unwrap();
        assert_eq!(
            (canonical(&decoded.x), canonical(&decoded.y)),
            (canonical(&b.x), canonical(&b.y))
        );
    }

    /// The projective formulas against the affine reference: doubling and the four additions,
    /// on points of the subgroup, on the neutral element, on a point and its negation, and on
    /// the points of order 2 and 4, for which complete formulas need no special case.
    #[test]
    fn the_group_law_agrees_with_the_affine_formulas() {
        let b = base_point();
        let order_2 = PointAffine { x: small(0).normalize(), y: small(-1).normalize() };
        let order_4 = PointAffine { x: small(1).normalize(), y: small(0).normalize() };
        let (three, three_projective) = sample_projective(3);
        let (seven, seven_projective) = sample_projective(7);
        let others = [b.clone(), three.clone(), three.negate(), neutral_affine(), order_2, order_4];

        for (p, projective) in [(&three, &three_projective), (&seven, &seven_projective)] {
            let copy = || PointProjective {
                x: projective.x.clone(),
                y: projective.y.clone(),
                z: projective.z.clone(),
            };
            let mut doubled = copy();
            doubled.double();
            assert_eq!(encoded_projective(&doubled), encoded(&reference_add(p, p)));

            for q in &others {
                let sum = encoded(&reference_add(p, q));
                let difference = encoded(&reference_add(p, &q.negate()));
                let entry = PointPrecomp { x: (*q.x).clone(), y: (*q.y).clone() };
                let q_projective =
                    PointProjective { x: q.x.mul(&small(5)), y: q.y.mul(&small(5)), z: small(5) };

                let mut r = copy();
                r.add_precomp(&entry);
                assert_eq!(encoded_projective(&r), sum);
                let mut r = copy();
                r.add_precomp_var(false, &entry);
                assert_eq!(encoded_projective(&r), sum);
                let mut r = copy();
                r.add_precomp_var(true, &entry);
                assert_eq!(encoded_projective(&r), difference);

                let mut r = copy();
                r.add(&q_projective);
                assert_eq!(encoded_projective(&r), sum);
                let mut r = copy();
                r.add_var(false, &q_projective);
                assert_eq!(encoded_projective(&r), sum);
                let mut r = copy();
                r.add_var(true, &q_projective);
                assert_eq!(encoded_projective(&r), difference);
            }
        }

        // Doubling the points of small order: 2 (0, -1) = (0, 1), 2 (1, 0) = (0, -1).
        let mut r = PointProjective::neutral();
        r.double();
        assert!(r.normalizes_to_neutral_var());
        let mut r = PointProjective { x: small(0), y: small(-3), z: small(3) };
        r.double();
        assert!(r.normalizes_to_neutral_var());
        let mut r = PointProjective { x: small(3), y: small(0), z: small(3) };
        r.double();
        assert_eq!(canonical(&r.to_affine().y), canonical(&small(-1)));
    }

    /// The odd multiples, for the two table sizes in use, and where a digit finds its entry.
    #[test]
    fn precompute_var_holds_the_odd_multiples() {
        let (p, _) = sample_projective(3);
        let table = precompute_var::<8>(&p);
        for (i, entry) in table.iter().enumerate() {
            let expected = reference_mult(&[2 * i as u8 + 1], &p);
            assert_eq!(encoded_projective(entry), encoded(&expected), "{i}");
        }
        let one = precompute_var::<1>(&p);
        assert_eq!(encoded_projective(&one[0]), encoded(&p));

        for magnitude in (1..=63_i8).step_by(2) {
            assert_eq!(wnaf_index(magnitude), (magnitude as usize - 1) / 2);
            assert_eq!(wnaf_index(-magnitude), (magnitude as usize - 1) / 2);
        }
    }

    /// The lookup returns each entry of each block at its index, and leaves `p` alone for an
    /// index outside the block.
    #[test]
    fn lookup_selects_the_entry_at_the_index() {
        for block in &COMB_BASE {
            for (index, entry) in block.iter().enumerate() {
                let mut p = PointPrecomp { x: small(3), y: small(4) };
                lookup(block, index as i64, &mut p);
                assert_eq!(
                    (canonical(&p.x), canonical(&p.y)),
                    (canonical(&entry.x), canonical(&entry.y))
                );
            }
            let mut p = PointPrecomp { x: small(3), y: small(4) };
            lookup(block, PRECOMP_POINTS as i64, &mut p);
            assert_eq!(
                (canonical(&p.x), canonical(&p.y)),
                (canonical(&small(3)), canonical(&small(4)))
            );
        }
    }

    #[test]
    fn scalar_mult_base_matches_the_prototype() {
        for (k, expected) in BASE_MULT_KATS {
            assert_eq!(base_mult(&octets(k)), octets::<POINT_LEN>(expected), "{k}");
        }
    }

    /// The comb against the bit-at-a-time reference, on the known-answer scalars and on
    /// pseudo-random ones below 2^448.
    #[test]
    fn scalar_mult_base_agrees_with_double_and_add() {
        let b = base_point();
        let mut ks: Vec<[u8; SCALAR_LEN]> = BASE_MULT_KATS.iter().map(|(k, _)| octets(k)).collect();
        let mut state = 0x636F_6D62;
        for _ in 0..20 {
            let mut k: [u8; SCALAR_LEN] = core::array::from_fn(|_| next(&mut state) as u8);
            k[SCALAR_LEN - 1] = 0;
            ks.push(k);
        }
        // One digit set, in each block, at each tooth and at varying spacing positions.
        for bit in (0..448).step_by(7) {
            let mut k = [0_u8; SCALAR_LEN];
            k[bit / 8] = 1 << (bit % 8);
            ks.push(k);
        }
        for k in &ks {
            assert_eq!(base_mult(k), encoded(&reference_mult(k, &b)), "{k:02x?}");
        }
    }

    /// `[L]B` is the neutral element and `[L - 1]B` is `-B`, by three different routes.
    #[test]
    fn the_base_point_has_order_l() {
        let b = base_point();
        assert!(scalar_mult_order_var(&b).normalizes_to_neutral_var());

        let l = order();
        assert_eq!(encoded(&reference_mult(&l, &b)), neutral_encoding());
        assert_eq!(base_mult(&l), neutral_encoding());

        let mut l_minus_1 = l;
        l_minus_1[0] -= 1;
        assert_eq!(base_mult(&l_minus_1), encoded(&b.negate()));

        // A point that is not of order L does not pass.
        let mut not_neutral = scalar_mult_order_var(&b);
        not_neutral.add_precomp_var(false, &WNAF_BASE[0]);
        assert!(!not_neutral.normalizes_to_neutral_var());
        // [L]P against the reference on a point outside the subgroup: B + (0, -1).
        let order_2 = PointAffine { x: small(0).normalize(), y: small(-1).normalize() };
        let mixed = reference_add(&b, &order_2);
        assert_eq!(encoded_projective(&scalar_mult_order_var(&mixed)), encoded(&order_2));
    }

    #[test]
    fn decoding_matches_the_prototype_and_round_trips() {
        for (encoding, x) in DECODE_KATS {
            let encoding: [u8; POINT_LEN] = octets(encoding);
            match (PointAffine::decode_var(&encoding), x) {
                (Some(point), Some(x)) => {
                    assert_eq!(canonical(&point.x), octets::<56>(x));
                    assert_eq!(encoded(&point), encoding);
                    assert!(point.is_valid_result().to_bool() || encoding[..56] == [0; 56]);
                    // -P has the same y and the other x.
                    let negated = point.negate();
                    assert_eq!(canonical(&negated.x.add(&point.x)), [0_u8; 56]);
                    assert_eq!(canonical(&negated.y), canonical(&point.y));
                }
                (None, None) => {}
                (decoded, _) => panic!("{encoding:02x?} decoded: {}", decoded.is_some()),
            }
        }
    }

    /// RFC 8032 Section 5.2.3, step 1: every y at or above p fails, with either sign bit,
    /// including those whose reduced value would decode, and so does anything in bits 448 to
    /// 454; step 4: x = 0 with x_0 = 1 fails.
    #[test]
    fn decoding_rejects_non_canonical_encodings() {
        // p = 2^448 - 2^224 - 1: octet 28 is 0xFE and the other 55 are 0xFF.
        let mut p = [0xFF_u8; POINT_LEN];
        (p[28], p[56]) = (0xFE, 0);
        // p + y for small y, and for y with one octet set in each half; 2^448 - 1 is the last.
        let mut above: Vec<[u8; POINT_LEN]> = Vec::new();
        above.push(p);
        for y in 1..=19_u8 {
            // p + y: the low 224 bits wrap to y - 1 and the carry makes octet 28 0xFF.
            let mut encoding = p;
            encoding[..28].fill(0);
            (encoding[0], encoding[28]) = (y - 1, 0xFF);
            above.push(encoding);
        }
        for octet in [1, 13, 27] {
            let mut encoding = p;
            encoding[..28].fill(0);
            (encoding[octet], encoding[28]) = (0x5A, 0xFF);
            above.push(encoding);
        }
        let mut all_ones = [0xFF_u8; POINT_LEN];
        all_ones[56] = 0;
        above.push(all_ones);
        for mut encoding in above {
            for top in [0x00, 0x80] {
                encoding[56] = top;
                assert!(PointAffine::decode_var(&encoding).is_none(), "{encoding:02x?}");
            }
        }

        // p - 1, which is (0, -1), is canonical; so is p - 2^224, the largest value whose
        // high half differs from p's.
        let mut p_minus_1 = p;
        p_minus_1[0] = 0xFE;
        assert!(PointAffine::decode_var(&p_minus_1).is_some());
        let mut high_differs = [0xFF_u8; POINT_LEN];
        (high_differs[28], high_differs[56]) = (0xFD, 0);
        let mut canonical_form = [0_u8; 56];
        FieldElement448::decode_448(high_differs[..56].try_into().unwrap())
            .normalize()
            .encode_448(&mut canonical_form);
        assert_eq!(canonical_form, high_differs[..56]);

        // Bits 448 to 454: y = 1 is the neutral element, and y = 1 + 2^(448 + i) is refused.
        let neutral = neutral_encoding();
        assert!(PointAffine::decode_var(&neutral).is_some());
        for bit in 0..7 {
            for sign in [0x00, 0x80] {
                let mut encoding = neutral;
                encoding[56] = sign | 1 << bit;
                assert!(PointAffine::decode_var(&encoding).is_none(), "{bit} {sign:#x}");
            }
        }

        // x = 0 at y = 1 and y = -1: the sign bit must be clear.
        let mut encoding = neutral;
        encoding[56] = 0x80;
        assert!(PointAffine::decode_var(&encoding).is_none());
        p_minus_1[56] = 0x80;
        assert!(PointAffine::decode_var(&p_minus_1).is_none());
    }

    #[test]
    fn public_key_validation_matches_the_prototype() {
        for (encoding, valid) in PUBLIC_KEY_KATS {
            let key = PublicPoint::decode_var(&octets(encoding));
            assert_eq!(key.is_some(), *valid, "{encoding}");
            if let Some(key) = key {
                let mut back = [0_u8; POINT_LEN];
                key.encode(&mut back);
                assert_eq!(back, octets::<POINT_LEN>(encoding));
                assert_eq!(encoded(key.point()), back);
            }
        }
    }

    /// Independently of the prototype: the four points of small order are the multiples of
    /// (1, 0), each is rejected as a public key, and so is each of them added to a point of
    /// the subgroup (mixed order), while the subgroup's own points pass.
    #[test]
    fn public_keys_outside_the_subgroup_are_rejected() {
        // (1, 0) is on the curve, 1 + 0 = 1 + 0, and has order 4.
        let torsion = PointAffine { x: small(1).normalize(), y: small(0).normalize() };
        let b = base_point();
        let five_b = reference_mult(&[5], &b);
        let mut seen: Vec<[u8; POINT_LEN]> = Vec::new();
        for multiple in 0..4_u8 {
            let small_order = reference_mult(&[multiple], &torsion);
            let encoding = encoded(&small_order);
            assert_eq!(encoded(&reference_mult(&[4], &small_order)), neutral_encoding());
            assert!(PointAffine::decode_var(&encoding).is_some());
            assert!(!seen.contains(&encoding));
            seen.push(encoding);
            assert!(PublicPoint::decode_var(&encoding).is_none(), "small order {multiple}");

            // [5]B + T is in the subgroup only for T neutral.
            let mixed = encoded(&reference_add(&five_b, &small_order));
            assert_eq!(
                PublicPoint::decode_var(&mixed).is_some(),
                multiple == 0,
                "mixed {multiple}"
            );
        }
    }

    /// The decoding of a key this module computed skips the order check and nothing else: it
    /// takes any point of the curve but the two with x = 0, and no encoding that is not a
    /// point.
    #[test]
    fn decode_base_multiple_var_refuses_the_neutral_element() {
        let b = encoded(&base_point());
        let key = PublicPoint::decode_base_multiple_var(&b).unwrap();
        assert_eq!(encoded(key.point()), b);

        // [4 L]B, which a pruned scalar can be.
        assert!(PublicPoint::decode_base_multiple_var(&neutral_encoding()).is_none());
        assert!(PointAffine::decode_var(&neutral_encoding()).is_some());
        // Not a point: y = 2 has no x (the prototype's table above has it failing to decode).
        let mut two = [0_u8; POINT_LEN];
        two[0] = 2;
        assert_eq!(
            PublicPoint::decode_base_multiple_var(&two).is_some(),
            PointAffine::decode_var(&two).is_some()
        );
        let undecodable = DECODE_KATS.iter().find(|(_, x)| x.is_none()).unwrap().0;
        assert!(PublicPoint::decode_base_multiple_var(&octets(undecodable)).is_none());
    }

    #[test]
    fn straus_matches_the_prototype_and_double_and_add() {
        let b = base_point();
        for (nb, np, p, nq, q, expected) in STRAUS_KATS {
            let nb: [u8; SCALAR_LEN] = octets(nb);
            let (np, nq) = (quarter(np), quarter(nq));
            let p = PointAffine::decode_var(&octets(p)).unwrap();
            let q = PointAffine::decode_var(&octets(q)).unwrap();

            let r = scalar_mult_straus_225_var(&limbs(&nb), &np, &p, &nq, &q);
            assert_eq!(encoded_projective(&r), octets::<POINT_LEN>(expected));

            let sum = reference_add(
                &reference_add(&reference_mult(&nb, &b), &reference_mult_signed(&np, &p)),
                &reference_mult_signed(&nq, &q),
            );
            assert_eq!(encoded_projective(&r), encoded(&reference_mult(&[4], &sum)));
        }
    }

    /// The scan for the highest digit must stop where any of the four recodings has one, also
    /// when two of them have the same digit there, and the cofactor is 4 whatever the start.
    #[test]
    fn straus_starts_at_a_position_two_scalars_share() {
        let b = base_point();
        let p = reference_mult(&[5], &b);
        let q = reference_mult(&[7], &b);
        let top = 1_u64 << 28; // bit 220 of a 225-bit half, in its fourth limb
        for (nb, np, nq) in [
            // the two halves of nb have their only digit at the same position: bits 220 and
            // 225 + 220 = 445
            ([0, 0, 0, top, 0, 0, 1 << 61], [3, 0, 0, 0], [1_u64, 0, 0, 0]),
            // nb's low half and np do
            ([0, 0, 0, top, 0, 0, 0], [0, 0, 0, top], [1, 0, 0, 0]),
            // nb's high half and np do, and nothing else is there: bit 225 + 220 of nb and bit
            // 220 of np, each the digit 1 at position 220
            ([0, 0, 0, 0, 0, 0, 1 << 61], [0, 0, 0, top], [1, 0, 0, 0]),
            // np and nq do
            ([0; 7], [0, 0, 0, top], [0, 0, 0, top]),
            // nb's low half and nq do
            ([0, 0, 0, top, 0, 0, 0], [1, 0, 0, 0], [0, 0, 0, top]),
            // only nq has a digit, at position 0
            ([0; 7], [0; 4], [1, 0, 0, 0]),
            // nothing has one
            ([0; 7], [0; 4], [0; 4]),
        ] {
            let r = scalar_mult_straus_225_var(&nb, &np, &p, &nq, &q);

            let nb_octets: Vec<u8> = nb.iter().flat_map(|limb| limb.to_le_bytes()).collect();
            let sum = reference_add(
                &reference_add(&reference_mult(&nb_octets, &b), &reference_mult_signed(&np, &p)),
                &reference_mult_signed(&nq, &q),
            );
            assert_eq!(encoded_projective(&r), encoded(&reference_mult(&[4], &sum)));
        }
    }

    /// The check on a computed result: a point off the curve and a point with y = 0 fail it,
    /// through the encoding function too.
    #[test]
    fn the_result_check_rejects_what_is_not_a_multiple_of_b() {
        let b = base_point();
        let off_curve = PointAffine { x: b.x.clone(), y: b.y.add(&small(1)).normalize() };
        assert!(!off_curve.is_valid_result().to_bool());
        let off_curve = PointAffine { x: b.x.add(&small(1)).normalize(), y: b.y.clone() };
        assert!(!off_curve.is_valid_result().to_bool());

        // (1, 0) is on the curve, of order 4.
        let order_4 = PointAffine::decode_var(&{
            let mut encoding = [0_u8; POINT_LEN];
            encoding[56] = 0x80;
            encoding
        })
        .unwrap();
        assert_eq!(canonical(&order_4.x), canonical(&small(1)));
        assert!(!order_4.is_valid_result().to_bool());
        // The neutral element and (0, -1) pass: y is not zero.
        assert!(neutral_affine().is_valid_result().to_bool());

        let mut r = [0_u8; POINT_LEN];
        let mut accum = PointProjective::neutral();
        assert!(accum.encode_checked(&mut r).to_bool());
        assert_eq!(r, neutral_encoding());
        accum.x = small(1);
        assert!(!accum.encode_checked(&mut r).to_bool());
    }

    /// The neutral-element test sees X, and Y against Z, and refuses the all-zero triple.
    #[test]
    fn normalizes_to_neutral_var_wants_x_zero_and_y_equal_to_z() {
        let mut p = PointProjective::neutral();
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

    // The base-point tables of `precomp`, rebuilt from B with the affine reference.

    /// One table entry as the canonical encodings of its two coordinates.
    type Entry = [[u8; 56]; 2];

    fn entry_of(p: &PointPrecomp) -> Entry {
        [canonical(&p.x), canonical(&p.y)]
    }

    fn entry_from_affine(p: &PointAffine) -> Entry {
        [canonical(&p.x), canonical(&p.y)]
    }

    /// The odd multiples `P, 3P, ..`, as table entries.
    fn odd_multiples(p: &PointAffine) -> Vec<Entry> {
        let twice = reference_add(p, p);
        let mut q = p.clone();
        let mut entries = Vec::new();
        for _ in 0..PRECOMP_WNAF_POINTS {
            entries.push(entry_from_affine(&q));
            q = reference_add(&q, &twice);
        }
        entries
    }

    /// (the comb table block by block, the odd multiples of B, those of [2^225]B)
    fn build_tables() -> (Vec<Entry>, Vec<Entry>, Vec<Entry>) {
        let b = base_point();
        let wnaf_base = odd_multiples(&b);

        let mut b225 = b.clone();
        for _ in 0..225 {
            b225 = reference_add(&b225, &b225);
        }
        let wnaf_base_225 = odd_multiples(&b225);

        // p walks through [2^i]B. Each block starts from minus the sum of its five teeth,
        // and adding twice a tooth turns that tooth's sign.
        let mut comb: Vec<PointAffine> = Vec::new();
        let mut p = b;
        for _block in 0..PRECOMP_BLOCKS {
            let mut sum = neutral_affine();
            let mut twice_teeth: Vec<PointAffine> = Vec::new();
            for _tooth in 0..PRECOMP_TEETH {
                sum = reference_add(&sum, &p);
                p = reference_add(&p, &p);
                twice_teeth.push(p.clone());
                for _ in 1..PRECOMP_SPACING {
                    p = reference_add(&p, &p);
                }
            }
            comb.push(sum.negate());
            for (tooth, twice_tooth) in twice_teeth[..PRECOMP_TEETH - 1].iter().enumerate() {
                for _ in 0..1 << tooth {
                    let from = &comb[comb.len() - (1 << tooth)];
                    let next = reference_add(from, twice_tooth);
                    comb.push(next);
                }
            }
        }
        (comb.iter().map(entry_from_affine).collect(), wnaf_base, wnaf_base_225)
    }

    #[test]
    fn the_base_point_tables_are_what_b_generates() {
        let (comb, wnaf_base, wnaf_base_225) = build_tables();
        let table: Vec<Entry> = COMB_BASE.iter().flatten().map(entry_of).collect();
        assert_eq!(table, comb);
        assert_eq!(WNAF_BASE.iter().map(entry_of).collect::<Vec<Entry>>(), wnaf_base);
        assert_eq!(WNAF_BASE_225.iter().map(entry_of).collect::<Vec<Entry>>(), wnaf_base_225);
    }

    /// Prints the tables of `precomp.rs`, from `#[rustfmt::skip]` above `COMB_BASE` to the
    /// end of the file; see that file for how to run it.
    #[test]
    #[ignore = "a generator, not a test"]
    fn print_base_point_tables() {
        // Eight limbs of 56 bits are seven octets each.
        fn limbs_of(encoding: &[u8; 56]) -> String {
            let limbs: Vec<String> = encoding
                .chunks(7)
                .map(|c| {
                    let limb = c.iter().rev().fold(0_u64, |acc, &octet| acc << 8 | octet as u64);
                    std::format!("0x{limb:014X}")
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

        let (comb, wnaf_base, wnaf_base_225) = build_tables();
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
        std::println!("/// The odd multiples `B, 3B, .., 63B`, for verification.");
        std::println!("#[rustfmt::skip]");
        std::println!("pub(super) static WNAF_BASE: [PointPrecomp; PRECOMP_WNAF_POINTS] = [");
        wnaf_base.iter().for_each(|entry| print_entry("    ", entry));
        std::println!("];\n");
        std::println!("/// The odd multiples of `[2^225]B`, for verification.");
        std::println!("#[rustfmt::skip]");
        std::println!("pub(super) static WNAF_BASE_225: [PointPrecomp; PRECOMP_WNAF_POINTS] = [");
        wnaf_base_225.iter().for_each(|entry| print_entry("    ", entry));
        std::println!("];");
    }
}
