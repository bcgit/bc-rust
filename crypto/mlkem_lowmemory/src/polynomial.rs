//! Represents a polynomial over the ML-DSA ring.

use crate::aux_functions::{
    ZETAS, ZETAS_INV, barrett_reduce, montgomery_reduce, mul_mont, ntt_base_mult,
};
use crate::mlkem::{N, q};
use bouncycastle_core::traits::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::ops::{Index, IndexMut};

/// A polynomial over the ML-KEM ring.
/// Dev note: this doesn't strictly need to be pub ... ie there's no good reason for a caller to use this class directly,
/// but in order to test the Debug and Display traits, you need STD, so those can't be tested from inline tests in this file
/// and the real unit tests are in a different crate, so here we are.
#[derive(Clone)]
pub struct Polynomial {
    pub(crate) coeffs: [i16; N],
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

    /// Create a Polynomial from the message m
    pub(crate) fn from_msg(m: [u8; 32]) -> Self {
        let mut w = Polynomial::new();

        for (i, b) in m.iter().enumerate() {
            for j in 0..8 {
                let mask = -(((*b >> j) & 1) as i16);
                w[8 * i + j] = mask & ((q + 1) / 2);
            }
        }

        w
    }

    /// Convert a Polynomial back into a message m
    pub(crate) fn to_msg(self) -> [u8; 32] {
        const LOWER: i32 = q as i32 >> 2; // 832
        const UPPER: i32 = q as i32 - LOWER; // 2497

        let mut msg = [0u8; 32];

        // you would expect to use a full reduce() here, but since this is data coming from
        // out matrix math and not from an attacker, we can get away with the lighter cond_sub_q()
        // Actually; further testing against the bc-test-data set of KATs shows that everything passes even with nothing
        // self.cond_sub_q();

        // for (i, item) in msg.iter_mut().enumerate().take(N/8) {
        for i in 0..N / 8 {
            for j in 0..8 {
                let c_j = self[8 * i + j] as i32;
                let t = (((LOWER - c_j) & (c_j - UPPER)) >> 31) & 0x0000000000000001;
                msg[i] |= (t << j) as u8;
            }
        }

        msg
    }

    // not currently used, but I'll leave it here because it's useful for debugging if you want to output values
    // that are normalized to [0,q] to compare against intermediate results from other libraries.
    // pub(crate) fn conditional_add_q(&mut self) {
    //     for x in self.0.iter_mut() {
    //         *x = conditional_add_q(*x);
    //     }
    // }

    pub(crate) fn add(&mut self, w: &Self) {
        for i in 0..N {
            self[i] += w[i];
        }
    }

    pub(crate) fn sub(&mut self, w: &Self) {
        for i in 0..N {
            self[i] -= w[i];
        }
    }

    /// Multiplication of two polynomials in NTT domain
    ///
    /// Borrowed from:
    /// https://github.com/pq-crystals/kyber/blob/main/ref/poly.c#L290
    pub(crate) fn base_mult_montgomery(&mut self, b: &Polynomial) {
        for i in 0..(N / 4) {
            let a1: i16 = self[4 * i];
            let a2: i16 = self[4 * i + 1];
            ntt_base_mult(&mut self.coeffs, 4 * i, a1, a2, b[4 * i], b[4 * i + 1], ZETAS[64 + i]);

            let a1: i16 = self[4 * i + 2];
            let a2: i16 = self[4 * i + 3];
            ntt_base_mult(
                &mut self.coeffs,
                4 * i + 2,
                a1,
                a2,
                b[4 * i + 2],
                b[4 * i + 3],
                -ZETAS[64 + i],
            );
        }
    }

    pub(crate) fn poly_reduce(&mut self) {
        for i in 0..N {
            self[i] = barrett_reduce(self[i]);
        }
    }

    /// In-place conversion of all coefficients of a polynomial
    /// from normal domain to Montgomery domain
    ///
    /// Borrowed from:
    /// https://github.com/pq-crystals/kyber/blob/main/ref/poly.c#L307
    pub(crate) fn convert_to_mont(&mut self) {
        const F: i16 = ((1u64 << 32) % q as u64) as i16;
        for i in 0..N {
            self[i] = montgomery_reduce((self[i] as i32) * (F as i32));
        }
    }

    /// This is an optimized version of
    ///   ByteEncode_𝑑𝑣( Compress_𝑑𝑣(𝑣) )
    /// which packs a single polynomial according to the packing coefficient dv
    pub(crate) fn compress_poly<const dv: i16>(&self, out: &mut [u8]) {
        // make sure we have received a dv
        debug_assert!(dv == 4 || dv == 5);

        // make sure we were given the right size output buffer
        // each of the N i16's will take dv bits
        debug_assert_eq!(out.len(), N * (dv as usize) / 8);

        let mut t = [0u8; 8];
        let mut idx = 0;

        // bc-java has a cond_sub_q() here, but unit tests show that we don't need it.
        // let mut s = self.clone();
        // s.cond_sub_q();

        match dv {
            4 => {
                // MLKEM512 and MLKEM768
                for i in 0..N / 8 {
                    // fill the temp array t
                    for (j, item) in t.iter_mut().enumerate() {
                        *item = ((((self[8 * i + j] as i32) << 4) + (q as i32 / 2)) / (q as i32)
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
    ///   Decompress_𝑑𝑣( ByteDecode_𝑑𝑣(𝑐2) )
    /// which unpacks a single polynomial according to the packing coefficient dv
    pub(crate) fn decompress_poly<const dv: i16>(compressed_v: &[u8]) -> Polynomial {
        // make sure we have received a dv
        debug_assert!(dv == 4 || dv == 5);

        // make sure we were given the right size output buffer
        // each of the N i16's will take dv bits
        debug_assert_eq!(compressed_v.len(), N * (dv as usize) / 8);

        let mut v = Polynomial::new();

        let mut idx = 0usize;

        // if self.m_engine.poly_compressed_bytes() == 128 {
        match dv {
            4 => {
                // MLKEM512 and MLKEM768
                for i in 0..N / 2 {
                    v[2 * i] =
                        (((((compressed_v[idx] & 15) as i16) as i32 * (q as i32)) + 8) >> 4) as i16;
                    v[2 * i + 1] =
                        (((((compressed_v[idx] >> 4) as i16) as i32 * (q as i32)) + 8) >> 4) as i16;
                    idx += 1;
                }
            }
            5 => {
                // MLKEM1024
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

    // not currently used, but I'll leave it here because it's useful for debugging if you want to output values
    // that are normalized to [0,q] to compare against intermediate results from other libraries.
    // pub(crate) fn cond_sub_q(&mut self) {
    //     for i in 0..N {
    //         self[i] = cond_sub_q(self[i]);
    //     }
    // }

    /// Algorithm 9 NTT(𝑓)
    /// Computes the NTT representation 𝑓_hat of the given polynomial 𝑓 ∈ 𝑅𝑞.
    /// Input: array 𝑓 ∈ ℤ256  ▷ the coefficients of the input polynomial
    /// Output: array 𝑓_hat ∈ ℤ256  ▷ the coefficients of the NTT of the input polynomial
    pub(crate) fn ntt(&mut self) {
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
    /// Input: array 𝑓 ∈ ℤ256  ▷ the coefficients of input NTT representation
    /// Output: array 𝑓 ∈ ℤ256  ▷ the coefficients of the inverse NTT of the input
    pub(crate) fn inv_ntt(&mut self) {
        // FIPS 203 ALg 10 wants you to copy f_hat into f, and then act of f
        // but we're going to do this in-place for memory-saving reasons.

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

impl Secret for Polynomial {}

impl Drop for Polynomial {
    fn drop(&mut self) {
        self.coeffs.fill(0i16);
    }
}

impl Debug for Polynomial {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Polynomial (data masked)")
    }
}

impl Display for Polynomial {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Polynomial (data masked)")
    }
}

// Not currently used, but I'll leave it here because it's useful for debugging if you want to output values
// that are normalized to [0,q] to compare against intermediate results from other libraries.
// /// if a is in \[-q..0], then it shifts it up by q to be in \[0..q]
// pub(crate) fn conditional_add_q(a: i16) -> i16 {
//     a + ((a >> 15) & q)
// }
//
// #[test]
// /// These are the results it's giving; I'm not sure if these are "correct" or not.
// fn test_conditional_add_q() {
//     assert_eq!(conditional_add_q(-q -1), -1);
//     assert_eq!(conditional_add_q(-q), 0);
//     assert_eq!(conditional_add_q(-q -2), -2);
//     assert_eq!(conditional_add_q(-q +1), 1);
//     assert_eq!(conditional_add_q(-1), q -1);
//     assert_eq!(conditional_add_q(0), 0);
//     assert_eq!(conditional_add_q(1), 1);
//     assert_eq!(conditional_add_q(q -1), q -1);
//     assert_eq!(conditional_add_q(q), q);
//     assert_eq!(conditional_add_q(q +1), q +1);
// }
