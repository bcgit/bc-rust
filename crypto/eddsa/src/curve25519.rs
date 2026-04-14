//! This is duplicated between EdDSA and XDH in order to avoid needing another public crate.

use arrayref::{array_mut_ref, array_ref};
use utils::ct::Condition;
use math::modular;

const M51: i64 = (1 << 51) - 1;

pub const P32: [u32; 8] = [
    0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
];
pub const P64: [u64; 4] =
    [0xFFFFFFFFFFFFFFED, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x7FFFFFFFFFFFFFFF];

// TODO Add magnitude, normalized fields to CoordField in debug mode and track validity through all operations
#[derive(Clone, Copy, Debug, Default)]
#[must_use]
#[repr(transparent)]
pub struct CoordField([i64; 5]);

#[rustfmt::skip]
impl CoordField {
    pub const fn add(&self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        Self([x0 + y0, x1 + y1, x2 + y2, x3 + y3, x4 + y4])
    }

    pub const fn apm(&self, rhs: &Self) -> (Self, Self) {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        (
            Self([x0 + y0, x1 + y1, x2 + y2, x3 + y3, x4 + y4]),
            Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4]),
        )
    }

    pub const fn add_one(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        Self([x0 + 1, x1, x2, x3, x4])
    }

    pub fn add_one_mut(&mut self) -> &mut Self {
        self.0[0] += 1;
        self
    }

    // TODO Requires normalized inputs
    pub const fn are_equal(lhs: &Self, rhs: &Self) -> Condition<i64> {
        let [x0, x1, x2, x3, x4] = lhs.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        Condition::<i64>::is_zero((x0 ^ y0) | (x1 ^ y1) | (x2 ^ y2) | (x3 ^ y3) | (x4 ^ y4))
    }

    // TODO Requires normalized inputs
    pub const fn are_equal_var(lhs: &Self, rhs: &Self) -> bool {
        Self::are_equal(lhs, rhs).to_bool_var()
    }

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

    pub fn carry_mut(&mut self) -> &mut Self {
        *self = self.carry();
        self
    }

    pub fn cmov(&mut self, cond: Condition<i64>, x: &Self) -> &mut Self {
        // *self = Self::cselect(cond, x, self);
        cond.mov(x.0[0], &mut self.0[0]);
        cond.mov(x.0[1], &mut self.0[1]);
        cond.mov(x.0[2], &mut self.0[2]);
        cond.mov(x.0[3], &mut self.0[3]);
        cond.mov(x.0[4], &mut self.0[4]);
        self
    }

    pub fn cnegate(&mut self, cond: Condition<i64>) -> &mut Self {
        self.0[0] = cond.negate(self.0[0]);
        self.0[1] = cond.negate(self.0[1]);
        self.0[2] = cond.negate(self.0[2]);
        self.0[3] = cond.negate(self.0[3]);
        self.0[4] = cond.negate(self.0[4]);
        self
    }

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

    pub fn cswap(cond: Condition<i64>, lhs: &mut Self, rhs: &mut Self) {
        (lhs.0[0], rhs.0[0]) = cond.swap(lhs.0[0], rhs.0[0]);
        (lhs.0[1], rhs.0[1]) = cond.swap(lhs.0[1], rhs.0[1]);
        (lhs.0[2], rhs.0[2]) = cond.swap(lhs.0[2], rhs.0[2]);
        (lhs.0[3], rhs.0[3]) = cond.swap(lhs.0[3], rhs.0[3]);
        (lhs.0[4], rhs.0[4]) = cond.swap(lhs.0[4], rhs.0[4]);
    }

    // TODO Result is NOT normalized
    pub fn decode_255(bytes: &[u8; 32]) -> Self {
        let (chunks, _) = bytes.as_chunks::<8>();
        let chunks = array_ref![chunks, 0, 4];
        Self::decode64_255(&chunks.map(u64::from_le_bytes))
    }

    // TODO Result is NOT normalized
    const fn decode64_255(x: &[u64; 4]) -> Self {
        let [x0, x1, x2, x3] = *x;
        let z0 =             x0        as i64 & M51;
        let z1 = (x0 >> 51 | x1 << 13) as i64 & M51;
        let z2 = (x1 >> 38 | x2 << 26) as i64 & M51;
        let z3 = (x2 >> 25 | x3 << 39) as i64 & M51;
        let z4 = (x3 >> 12)            as i64 & M51;
        Self([z0, z1, z2, z3, z4])
    }

    // TODO Requires normalized self
    pub fn encode(&self, bytes: &mut [u8; 32]) {
        let (chunks, _) = bytes.as_chunks_mut::<8>();
        let chunks = array_mut_ref![chunks, 0, 4];
        *chunks = self.encode64().map(|t| t.to_le_bytes());
    }

    // TODO Requires normalized self
    const fn encode64(&self) -> [u64; 4] {
        let [x0, x1, x2, x3, x4] = self.0;
        let z0 = (x0       | x1 << 51) as u64;
        let z1 = (x1 >> 13 | x2 << 38) as u64;
        let z2 = (x2 >> 26 | x3 << 25) as u64;
        let z3 = (x3 >> 39 | x4 << 12) as u64;
        [z0, z1, z2, z3]
    }

    pub fn inv(&self) -> Self {
        // let (x2, t) = self.pow_p_sub5_div8();
        // t.sqr_n(3).mul(&x2)

        #[inline(always)]
        fn is_zero(x: &[u64; 4]) -> Condition<u64> {
            Condition::<u64>::is_zero(x[0] | x[1] | x[2] | x[3])
        }

        let u = self.normalize().encode64();
        let mut v = [0; 4];
        // TODO modular::mod_odd_inverse is vartime
        let success = modular::mod_odd_inverse(&P64, &u, &mut v);
        debug_assert!((success | (is_zero(&u) & is_zero(&v))).to_bool_var());
        Self::decode64_255(&v)
    }

    pub fn inv_mut(&mut self) -> &mut Self {
        *self = self.inv();
        self
    }

    pub fn inv_var(&self) -> Self {
        // TODO Use a vartime optimized version of modular::mod_odd_inverse
        self.inv()
    }

    pub fn inv_mut_var(&mut self) -> &mut Self {
        *self = self.inv_var();
        self
    }

    // TODO Requires normalized self
    pub const fn is_one(&self) -> Condition<i64> {
        let [x0, x1, x2, x3, x4] = self.0;
        let x0 = x0 ^ 1;
        Condition::<i64>::is_zero(x0 | x1 | x2 | x3 | x4)
    }

    // TODO Requires normalized self
    pub const fn is_one_var(&self) -> bool {
        self.is_one().to_bool_var()
    }

    // TODO Requires normalized self
    pub const fn is_zero(&self) -> Condition<i64> {
        let [x0, x1, x2, x3, x4] = self.0;
        Condition::<i64>::is_zero(x0 | x1 | x2 | x3 | x4)
    }

    // TODO Requires normalized self
    pub const fn is_zero_var(&self) -> bool {
        self.is_zero().to_bool_var()
    }

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

    pub const fn mul_u32(&self, rhs: u32) -> Self {
        #[inline(always)]
        const fn m(x: i64, y: i64) -> i128 {
            x as i128 * y as i128
        }

        let [x0, x1, x2, x3, x4] = self.0;
        let y0 = rhs as i64;

        Self::reduce_products(m(x0, y0), m(x1, y0), m(x2, y0), m(x3, y0), m(x4, y0))
    }

    pub const fn negate(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        Self([-x0, -x1, -x2, -x3, -x4])
    }

    pub fn negate_mut(&mut self) -> &mut Self {
        *self = self.negate();
        self
    }

    // TODO Module consumers should instead have a method to construct from [u64; 4] (or indeed a Nat<4>)
    pub const fn new(x0: i64, x1: i64, x2: i64, x3: i64, x4: i64) -> Self {
        Self([x0, x1, x2, x3, x4])
    }

    pub const fn normalize(&self) -> Self {
        let y = (self.0[4] >> (51 - 1)) & 1;
        self.reduce(y).reduce(-y)
    }

    pub fn normalize_mut(&mut self) -> &mut Self {
        *self = self.normalize();
        self
    }

    pub const fn one() -> Self {
        Self([1, 0, 0, 0, 0])
    }

    // TODO Better name
    pub const fn parity(&self) -> u8 {
        (self.0[0] & 1) as u8
    }

    // TODO Addition chain macro/function
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
             t4        + (u3 >> 51),
        ])
    }

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

    pub fn sqr_mut(&mut self) -> &mut Self {
        *self = self.sqr();
        self
    }

    pub const fn sqr_n(&self, mut n: usize) -> Self {
        let mut z = *self;
        while n > 0 {
            z = z.sqr();
            n -= 1;
        }
        z
    }

    pub const fn sqrt_ratio_var(u: &Self, v: &Self) -> Option<Self> {
        let uv = u.mul(v);
        let v2 = v.sqr();
        let uv3 = v2.mul(&uv);
        let uv7 = v2.sqr().mul(&uv3);

        let (_, w) = uv7.pow_p_sub5_div8();
        let x = w.mul(&uv3);
        let vx2 = x.sqr().mul(v);

        let t = vx2.sub(u).normalize();
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

    pub const fn sub(&self, rhs: &Self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        let [y0, y1, y2, y3, y4] = rhs.0;
        Self([x0 - y0, x1 - y1, x2 - y2, x3 - y3, x4 - y4])
    }

    pub const fn sub_one(&self) -> Self {
        let [x0, x1, x2, x3, x4] = self.0;
        Self([x0 - 1, x1, x2, x3, x4])
    }

    pub fn sub_one_mut(&mut self) -> &mut Self {
        self.0[0] -= 1;
        self
    }

    pub const fn zero() -> Self {
        Self([0; 5])
    }
}
