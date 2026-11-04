//! A polynomial over the ML-KEM ring, with the NTT (FIPS 203 Algorithms 9-12), the message
//! encoding of K-PKE, the compression of one polynomial, and the reductions modulo 𝑞.

use crate::params::MLKEMParamsBase;
use crate::{N, q, q_inv};
use core::ops::{Index, IndexMut};

/// A polynomial over the ML-KEM ring.
///
/// # 🚨 Security Considerations 🚨
/// Polynomials themselves are not inherently secret since sometimes they are part of public keys
/// and sometimes private keys.
/// It is the responsibility of the caller to wrap sensitive instances in `Secret<..>`.
///
/// `coeffs` is public because the two ML-KEM crates build their vector types and key encodings
/// on it; outside them a `Polynomial` is an opaque handle.
#[derive(Clone, Copy)]
pub struct Polynomial {
    /// The 256 coefficients.
    pub coeffs: [i16; N],
}

impl Default for Polynomial {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to avoid ".0" all over the place.
impl Index<usize> for Polynomial {
    type Output = i16;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coeffs[index]
    }
}
/// Convenience function to avoid ".0" all over the place.
impl IndexMut<usize> for Polynomial {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.coeffs[index]
    }
}

impl Polynomial {
    /// Create a new polynomial with all coefficients set to zero.
    pub const fn new() -> Self {
        Self { coeffs: [0i16; N] }
    }

    /// Encodes a 32-byte message `m` into a `Polynomial`, implementing the message
    /// encoding step of K-PKE.Encrypt `Decompress_1(ByteDecode_1(m))`,
    /// (FIPS 203, Alg. 14). Each message bit becomes one coefficient: `Decompress_1`
    /// (§4.2.1) maps bit `1` to `⌈q/2⌉ = (q + 1) / 2 = 1665` (for `q = 3329`) and bit
    /// `0` to `0`, placing a set bit at the point farthest from `0` to maximize the
    /// decryption noise margin. The mapping is computed branchlessly (constant-time)
    /// via a bit-derived all-ones / all-zeros mask, and bits are read LSB-first. This
    /// is the exact inverse of [`to_msg`].
    pub fn from_msg(m: &[u8; 32]) -> Self {
        let mut w = Polynomial::new();

        for (i, b) in m.iter().enumerate() {
            for j in 0..8 {
                let mask = -(((*b >> j) & 1) as i16);
                w[8 * i + j] = mask & ((q + 1) / 2);
            }
        }

        w
    }

    /// Decodes a `Polynomial` into its 32-byte message `m`, implementing the message
    /// recovery step of K-PKE.Decrypt `ByteEncode_1(Compress_1(self))`,
    /// (FIPS 203, Alg. 15). Each coefficient yields one message bit: `Compress_1`
    /// (§4.2.1) sets the bit when the coefficient lies nearer `q/2` than `0`, i.e. in
    /// the central interval `[833, 2496]` for `q = 3329`. The decision is computed
    /// branchlessly and the bits are packed LSB-first.
    /// Coefficients are expected to already be canonical in `[0, q]`: the unsigned
    /// interval test is not periodic mod `q`, so the caller reduces beforehand (`poly_reduce()`
    /// in `pke_decrypt`) and no reduction is repeated here.
    pub fn to_msg(self) -> [u8; 32] {
        const LOWER: i32 = q as i32 >> 2; // ⌊q/4⌋     = 832
        const UPPER: i32 = q as i32 - LOWER; // q - ⌊q/2⌋ = 2497

        let mut msg = [0u8; 32];

        // No reduction here: the only caller, pke_decrypt, reduces every coefficient immediately
        // before this call (see the type's docs on the canonical range).

        // for (i, item) in msg.iter_mut().enumerate().take(N/8) {
        for i in 0..N / 8 {
            for j in 0..8 {
                let c_j = self[8 * i + j] as i32;
                let t = (((LOWER - c_j) & (c_j - UPPER)) >> 31) & 0x01;
                msg[i] |= (t << j) as u8;
            }
        }

        msg
    }

    /// Multiplication of two polynomials in the NTT domain, in place: `self` becomes
    /// MultiplyNTTs(self, b) (FIPS 203 Algorithm 11). See [`base_mult_montgomery`] for the form
    /// that returns a new polynomial.
    ///
    /// Borrowed from:
    /// <https://github.com/pq-crystals/kyber/blob/main/ref/poly.c#L290>
    pub fn base_mult_montgomery(&mut self, b: &Polynomial) {
        for i in 0..(N / 4) {
            let a0: i16 = self[4 * i];
            let a1: i16 = self[4 * i + 1];
            ntt_base_mult(
                self.coeffs.as_mut(),
                4 * i,
                a0,
                a1,
                b[4 * i],
                b[4 * i + 1],
                ZETAS[64 + i],
            );

            let a0: i16 = self[4 * i + 2];
            let a1: i16 = self[4 * i + 3];
            ntt_base_mult(
                self.coeffs.as_mut(),
                4 * i + 2,
                a0,
                a1,
                b[4 * i + 2],
                b[4 * i + 3],
                -ZETAS[64 + i],
            );
        }
    }

    /// Adds `w` coefficient by coefficient; no reduction.
    pub fn add(&mut self, w: &Self) {
        for i in 0..N {
            self[i] += w[i];
        }
    }

    /// Subtracts `w` coefficient by coefficient; no reduction.
    pub fn sub(&mut self, w: &Self) {
        for i in 0..N {
            self[i] -= w[i];
        }
    }

    /// Barrett-reduces every coefficient into \[0, 𝑞] (see [`barrett_reduce`] for the closed end).
    pub fn poly_reduce(&mut self) {
        for i in 0..N {
            self[i] = barrett_reduce(self[i]);
        }
    }

    /// In-place conversion of all coefficients of a polynomial
    /// from normal domain to Montgomery domain
    ///
    /// Borrowed from:
    /// <https://github.com/pq-crystals/kyber/blob/main/ref/poly.c#L307>
    pub fn convert_to_mont(&mut self) {
        const F: i16 = ((1u64 << 32) % q as u64) as i16;
        for i in 0..N {
            self[i] = montgomery_reduce((self[i] as i32) * (F as i32));
        }
    }

    /// This is an optimized version of
    ///   ByteEncode_𝑑𝑣( Compress_𝑑𝑣(𝑣) )
    /// which packs a single polynomial according to the packing coefficient dv
    pub fn compress_poly<P: MLKEMParamsBase>(&self, out: &mut [u8]) {
        // make sure we have received a P::dv
        debug_assert!(P::dv == 4 || P::dv == 5);

        // make sure the right size output buffer is given
        // each of the N i16's will take P::dv bits
        debug_assert_eq!(out.len(), N * (P::dv as usize) / 8);

        let mut t = [0u8; 8];
        let mut idx = 0;

        // No conditional subtraction of q here (the reference implementation has one): every
        // caller reduces the polynomial immediately before packing it.

        match P::dv {
            4 => {
                // MLKEM512 and MLKEM768
                for i in 0..N / 8 {
                    // fill the temp array t
                    for (j, item) in t.iter_mut().enumerate() {
                        *item = (((((self[8 * i + j] as i32) << 4) + (q as i32 / 2)) / (q as i32))
                            & 15) as u8;
                    }

                    out[idx] = t[0] | (t[1] << 4);
                    out[idx + 1] = t[2] | (t[3] << 4);
                    out[idx + 2] = t[4] | (t[5] << 4);
                    out[idx + 3] = t[6] | (t[7] << 4);
                    idx += 4;
                }
            }
            5 => {
                // MLKEM1024
                for i in 0..N / 8 {
                    // fill the temp array t
                    for (j, item) in t.iter_mut().enumerate() {
                        *item = (((((self[8 * i + j] as i32) << 5) + (q as i32 / 2)) / (q as i32))
                            & 31) as u8;
                    }

                    out[idx] = t[0] | (t[1] << 5);
                    out[idx + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
                    out[idx + 2] = (t[3] >> 1) | (t[4] << 4);
                    out[idx + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
                    out[idx + 4] = (t[6] >> 2) | (t[7] << 3);
                    idx += 5;
                }
            }
            _ => unreachable!(),
        };
    }

    /// This is an optimized version of
    /// Decompress_𝑑𝑣( ByteDecode_𝑑𝑣(𝑐2) )
    /// which unpacks a single polynomial according to the packing coefficient dv
    pub fn decompress_poly<P: MLKEMParamsBase>(compressed_v: &[u8]) -> Polynomial {
        // make sure the right size output buffer is given
        // each of the N i16's will take P::dv bits
        debug_assert_eq!(compressed_v.len(), N * (P::dv as usize) / 8);

        let mut v = Polynomial::new();

        let mut idx = 0usize;

        match P::dv {
            // MLKEM512 and MLKEM768
            4 => {
                for i in 0..N / 2 {
                    v[2 * i] =
                        (((((compressed_v[idx] & 15) as i16) as i32 * (q as i32)) + 8) >> 4) as i16;
                    v[2 * i + 1] =
                        (((((compressed_v[idx] >> 4) as i16) as i32 * (q as i32)) + 8) >> 4) as i16;
                    idx += 1;
                }
            }
            // MLKEM1024
            5 => {
                let mut t = [0u8; 8];
                for i in 0..N / 8 {
                    t[0] = compressed_v[idx];
                    t[1] = (compressed_v[idx] >> 5) | (compressed_v[idx + 1] << 3);
                    t[2] = compressed_v[idx + 1] >> 2;
                    t[3] = (compressed_v[idx + 1] >> 7) | (compressed_v[idx + 2] << 1);
                    t[4] = (compressed_v[idx + 2] >> 4) | (compressed_v[idx + 3] << 4);
                    t[5] = compressed_v[idx + 3] >> 1;
                    t[6] = (compressed_v[idx + 3] >> 6) | (compressed_v[idx + 4] << 2);
                    t[7] = compressed_v[idx + 4] >> 3;
                    idx += 5;
                    for (j, item) in t.iter_mut().enumerate() {
                        v[8 * i + j] = (((*item & 31) as i32 * (q as i32) + 16) >> 5) as i16;
                    }
                }
            }
            _ => unreachable!(),
        }

        v
    }

    /// Algorithm 9 NTT(𝑓)
    /// Computes the NTT representation 𝑓_hat of the given polynomial 𝑓 ∈ 𝑅𝑞.
    /// Input: array 𝑓 ∈ ℤ256  ▷ the coefficients of the input polynomial
    /// Output: array 𝑓_hat ∈ ℤ256  ▷ the coefficients of the NTT of the input polynomial
    pub fn ntt(&mut self) {
        let mut len = 128;
        let mut k = 1;

        while len >= 2 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS[k];
                k += 1;
                let mut j = start;
                while j < start + len {
                    let t = mul_mont(zeta, self[j + len]);
                    self[j + len] = self[j] - t;
                    self[j] += t;
                    j += 1;
                }
                start = j + len;
            }
            len >>= 1;
        }
    }

    /// Algorithm 10 NTT (𝑓_hat)
    /// Computes the polynomial 𝑓 ∈ 𝑅𝑞 that corresponds to the given NTT representation 𝑓 ∈ 𝑇𝑞.
    /// Input: array 𝑓 ∈ ℤ_{256}  ▷ the coefficients of input NTT representation
    /// Output: array 𝑓 ∈ ℤ_{256}  ▷ the coefficients of the inverse NTT of the input
    pub fn inv_ntt(&mut self) {
        // FIPS 203 Alg 10 wants you to copy f_hat into f, and then act on f
        // but here it is performed in-place in order to optimize memory usage.

        let mut len = 2;
        let mut k = 0;

        while len <= 128 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS_INV[k];
                k += 1;
                let mut j = start;
                while j < start + len {
                    let t = self[j];
                    let u = self[j + len];

                    self[j] = barrett_reduce(t + u);
                    self[j + len] = mul_mont(zeta, t - u);
                    j += 1;
                }
                start = j + len;
            }
            len <<= 1;
        }

        // 14: 𝑓 ← 𝑓 ⋅ 3303 mod 𝑞
        //   ▷ multiply every entry by 3303 ≡ 128−1 mod 𝑞
        for i in 0..N {
            self[i] = mul_mont(self[i], ZETAS_INV[127]);
        }
    }
}

/// [`Polynomial::base_mult_montgomery`] into a new polynomial: MultiplyNTTs(a, b).
#[must_use]
pub fn base_mult_montgomery(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let mut r = *a;
    r.base_mult_montgomery(b);
    r
}

/// The twiddle factors 𝜁^BitRev7(𝑖) of FIPS 203 Appendix A, in Montgomery form.
pub const ZETAS: [i16; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 573,
    2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652,
    2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239,
    3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226, 430, 555,
    843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322,
    2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819,
    2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

/// The twiddles the inverse NTT consumes in order, in Montgomery form; the last entry, 1441,
/// is Algorithm 10 line 14's 3303 ≡ 128^(−1) mod 𝑞 carried as 3303 ⋅ 2^32 mod 𝑞, so that one
/// Montgomery multiplication applies it and leaves the result in Montgomery form.
pub const ZETAS_INV: [i16; 128] = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676,
    1755, 460, 291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275,
    2652, 1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853, 1860, 3203,
    1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552, 2677, 2106, 1571, 205, 2918,
    1542, 2721, 2597, 2312, 681, 130, 1602, 1871, 829, 2946, 3065, 1325, 2756, 1861, 1474, 1202,
    2367, 3147, 1752, 2707, 171, 3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
];

/// Montgomery multiplication: 𝑎 ⋅ 𝑏 ⋅ 2^(−16) mod 𝑞.
pub fn mul_mont(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

/// Montgomery reduction: 𝑎 ⋅ 2^(−16) mod 𝑞, for |𝑎| < 𝑞 ⋅ 2^15; the result is in (−𝑞, 𝑞).
pub fn montgomery_reduce(a: i32) -> i16 {
    let u = a.wrapping_mul(q_inv) as i16;
    let mut t = (u as i32) * q as i32;
    t = a - t;
    t >>= 16;
    t as i16
}

/// Barrett reduction into \[0, 𝑞]: the floor variant, not pq-crystals' centered one, which the
/// compression code relies on for its unsigned casts. The result is 𝑞 rather than 0 for a
/// negative multiple of 𝑞; [`cond_sub_q`] folds that when a canonical value is needed. Valid for
/// every `i16`: the subtraction is done in `i32`, since for `a <= -9q` the product `t * q` does
/// not fit an `i16` and a narrowed subtraction overflowed in debug builds.
pub fn barrett_reduce(a: i16) -> i16 {
    let v = (((1u32 << 26) + ((q / 2) as u32)) / (q as u32)) as i32;
    let t = (v * (a as i32)) >> 26;
    (a as i32 - t * q as i32) as i16
}

/// Folds 𝑞 to 0: for `a` in \[0, 𝑞], the canonical representative in \[0, 𝑞).
pub fn cond_sub_q(a: i16) -> i16 {
    let tmp = a - q;
    tmp + ((tmp >> 15) & q)
}

/// Multiplication of polynomials in Zq\[X]/(X^2-zeta)
/// used for multiplication of elements in Rq in NTT domain
///
/// Borrowed from:
/// <https://github.com/pq-crystals/kyber/blob/main/ref/ntt.c#L139>
pub fn ntt_base_mult(r: &mut [i16], off: usize, a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) {
    let mut out_val0 = mul_mont(a1, b1);
    out_val0 = mul_mont(out_val0, zeta);
    out_val0 += mul_mont(a0, b0);
    r[off] = out_val0;

    let mut out_val1 = mul_mont(a0, b1);
    out_val1 += mul_mont(a1, b0);
    r[off + 1] = out_val1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrett_reduce_lands_in_zero_to_q_inclusive() {
        // The floor variant, over every i16 (the NTT arithmetic produces |a| < 8q; the whole
        // range is checked so that no input can overflow): the result is congruent to a and in
        // [0, q], reaching q only at negative multiples of q, which the compression masks fold
        // and the encoders never see (their inputs are reduced sums of Montgomery products,
        // each in (-q, q)).
        for a in i16::MIN..=i16::MAX {
            let r = barrett_reduce(a);
            assert!((0..=q).contains(&r), "barrett_reduce({a}) = {r} not in [0, q]");
            assert_eq!((r as i32 - a as i32).rem_euclid(q as i32), 0, "barrett_reduce({a}) = {r}");
            assert!((0..q).contains(&cond_sub_q(r)), "cond_sub_q({r})");
        }
        assert_eq!(barrett_reduce(-q), q);
        assert_eq!(cond_sub_q(q), 0);
    }

    #[test]
    fn montgomery_reduce_is_a_times_2_pow_minus_16() {
        const MONT: i32 = (1i32 << 16) % q as i32;
        for &a in &[0i32, 1, -1, q as i32 - 1, -(q as i32), 3329 * 100 + 7, -(3329 * 200 + 11)] {
            let r = montgomery_reduce(a) as i32;
            assert!(r.abs() < q as i32, "montgomery_reduce({a}) = {r}");
            assert_eq!((r * MONT - a).rem_euclid(q as i32), 0, "montgomery_reduce({a})");
        }
    }

    #[test]
    fn ntt_round_trips_up_to_the_montgomery_factor() {
        // ZETAS_INV[127] = 3303 * 2^32 mod q: Algorithm 10 line 14's 128^(-1), in the form one
        // Montgomery multiplication applies, leaving the result times 2^16.
        const MONT: i32 = (1i32 << 16) % q as i32;
        assert_eq!(ZETAS_INV[127] as i32, (3303 * MONT % q as i32) * MONT % q as i32);

        let mut f = Polynomial::new();
        for (i, c) in f.coeffs.iter_mut().enumerate() {
            *c = (i as i16 * 7) % q;
        }
        let original = f;
        f.ntt();
        f.inv_ntt();
        for i in 0..N {
            // strip the 2^16: mul_mont(c, 1) = c * 2^-16
            let back = barrett_reduce(mul_mont(f[i], 1));
            assert_eq!(back, original[i], "coefficient {i}");
        }
    }

    /// `compress_poly` is pinned by the ACVP ciphertexts; `decompress_poly` is not: ML-KEM's
    /// decryption tolerates a decompressed coefficient being off by a little, so a rounding error
    /// in it still yields the right shared secret on every vector. These check the two against
    /// FIPS 203 Section 4.2.1, eq. (4.7) and (4.8), coefficient by coefficient.
    mod compression {
        use super::*;
        extern crate std;
        use crate::params::{MLKEM512Params, MLKEM1024Params};
        use std::vec;
        use std::vec::Vec;

        /// Compress_d(x) = round((2^d / q) * x) mod 2^d; q is odd, so there is no half-way case and
        /// floor((2^d * x + q/2) / q) is the rounding.
        fn compress_ref(d: u32, x: i16) -> u16 {
            ((((x as u32) << d) + (q as u32) / 2) / (q as u32) % (1 << d)) as u16
        }

        /// Decompress_d(y) = round((q / 2^d) * y).
        fn decompress_ref(d: u32, y: u16) -> i16 {
            (((y as u32) * (q as u32) + (1 << (d - 1))) >> d) as i16
        }

        /// Unpacks `d`-bit little-endian fields, as ByteDecode_d does.
        fn fields(d: u32, bytes: &[u8]) -> Vec<u16> {
            let mut out = Vec::new();
            let mut acc: u32 = 0;
            let mut bits = 0;
            for &b in bytes {
                acc |= (b as u32) << bits;
                bits += 8;
                while bits >= d {
                    out.push((acc & ((1 << d) - 1)) as u16);
                    acc >>= d;
                    bits -= d;
                }
            }
            out
        }

        fn check<P: MLKEMParamsBase>() {
            let d = P::dv as u32;
            let packed_len = N * (d as usize) / 8;

            // decompress: every field of a pseudo-random block comes out as eq. (4.8)
            let mut bytes = vec![0u8; packed_len];
            let mut state: u32 = 3 + d;
            for b in bytes.iter_mut() {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                *b = (state >> 24) as u8;
            }
            let v = Polynomial::decompress_poly::<P>(&bytes);
            for (n, &y) in fields(d, &bytes).iter().enumerate() {
                assert_eq!(v[n], decompress_ref(d, y), "d={d} field {n}");
            }

            // compress: every coefficient value 0..q, over as many polynomials as that takes
            let mut x: i16 = 0;
            while x < q {
                let mut v = Polynomial::new();
                let first = x;
                for j in 0..N {
                    v[j] = x;
                    x = (x + 1) % q;
                }
                let mut out = vec![0u8; packed_len];
                v.compress_poly::<P>(&mut out);
                for (n, &f) in fields(d, &out).iter().enumerate() {
                    assert_eq!(f, compress_ref(d, v[n]), "d={d} coefficient {n} from {first}");
                }
                if x < first {
                    break; // wrapped past q - 1
                }
            }
        }

        #[test]
        fn compress_and_decompress_match_fips_203_for_dv_4() {
            check::<MLKEM512Params>();
        }

        #[test]
        fn compress_and_decompress_match_fips_203_for_dv_5() {
            check::<MLKEM1024Params>();
        }
    }
}
