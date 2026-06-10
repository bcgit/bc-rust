//! Represents a polynomial over the ML-DSA ring.

use crate::aux_functions::{
    ZETAS, conditional_add_q, high_bits, low_bits, make_hint, montgomery_reduce,
};
use crate::mldsa::{MLDSA44_POLY_W1_PACKED_LEN, MLDSA65_POLY_W1_PACKED_LEN, N, q};
use bouncycastle_core::traits::Secret;
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::ops::{Index, IndexMut};

/// A polynomial over the ML-DSA ring.
/// Dev note: this doesn't strictly need to be pub ... ie there's no good reason for a caller to use this class directly,
/// but in order to test the Debug and Display traits, you need STD, so those can't be tested from inline tests in this file
/// and the real unit tests are in a different crate, so here we are.
#[derive(Clone)]
pub struct Polynomial {
    pub(crate) coeffs: [i32; N],
}

/// Convenience function to avoid ".0" all over the place.
impl Index<usize> for Polynomial {
    type Output = i32;

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
        Self { coeffs: [0i32; N] }
    }

    pub(crate) fn conditional_add_q(&mut self) {
        for x in self.coeffs.iter_mut() {
            *x = conditional_add_q(*x);
        }
    }

    pub(crate) fn reduce(&mut self) {
        for i in 0..N {
            self[i] = montgomery_reduce(self[i] as i64);
        }
    }

    /// Algorithm 44 AddNTT(𝑎, 𝑏)̂
    /// Computes the sum a + 𝑏 of two elements 𝑎, 𝑏 ∈ 𝑇𝑞.
    /// Note: result could be up to 2q.
    pub(crate) fn add_ntt(&mut self, w: &Self) {
        for i in 0..N {
            self[i] += w[i];
        }
    }

    pub(crate) fn sub(&mut self, w: &Self) {
        for i in 0..N {
            self[i] -= w[i];
        }
    }

    pub(crate) fn high_bits<const GAMMA2: i32>(&self) -> Self {
        let mut w = Self::new();
        for i in 0..N {
            w[i] = high_bits::<GAMMA2>(self[i]);
        }

        w
    }

    pub(crate) fn low_bits<const GAMMA2: i32>(&self) -> Self {
        let mut w = Self::new();
        for i in 0..N {
            w[i] = low_bits::<GAMMA2>(self[i]);
        }

        w
    }

    pub(crate) fn check_norm<const BOUND: i32>(&self) -> bool {
        // Fine that this is not constant-time (returns true early) because it is used in a rejection loop.
        // IE the early quit here leads to rejection and continuing to the top of the rejection loop, or failing the signature validation.
        // So the i32 that we just checked in a non-constant-time manner is about to get thrown away.

        // Note: this formulation of the check_norm function usually requires this bounds check
        //  if bound > (q - 1) / 8 {
        //     return true;
        //  }
        // but since BOUND is a constant here, we'll just do a debug_assert to make sure the value is what we expect.
        debug_assert!(BOUND <= (q - 1) / 8);

        let mut t: i32;
        for x in self.coeffs.iter() {
            t = *x >> 31;
            t = *x - (t & (2 * *x));

            if t >= BOUND {
                return true;
            }
        }
        false
    }

    pub(crate) fn shift_left<const d: i32>(&mut self) {
        for x in self.coeffs.iter_mut() {
            *x <<= d;
        }
    }

    /// Creates the hint vector, and also returns its hamming weight (ie the number of 1's).
    pub(crate) fn make_hint<const GAMMA2: i32>(&self, r: &Self) -> (Self, i32) {
        let mut out = Polynomial::new();
        let mut count = 0i32;
        for i in 0..N {
            let x = make_hint::<GAMMA2>(self[i], r[i]);
            out[i] = x;

            // mutants note: this chains up to hint_hamming_weight > OMEGA and there is no test KAT that triggers this branch
            count += x;
        }

        (out, count)
    }

    pub(crate) fn w1_encode<const POLY_W1_PACKED_LEN: usize>(&self) -> [u8; POLY_W1_PACKED_LEN] {
        let mut r = [0u8; POLY_W1_PACKED_LEN];

        match POLY_W1_PACKED_LEN {
            MLDSA44_POLY_W1_PACKED_LEN => {
                for i in 0..N / 4 {
                    r[3 * i] = ((self[4 * i]) as u8) | ((self[4 * i + 1] << 6) as u8);
                    r[3 * i + 1] = ((self[4 * i + 1] >> 2) as u8) | ((self[4 * i + 2] << 4) as u8);
                    r[3 * i + 2] = ((self[4 * i + 2] >> 4) as u8) | ((self[4 * i + 3] << 2) as u8);
                }
            }
            // ML-DSA65 and 87 share a POLY_W1_PACKED_LEN value
            MLDSA65_POLY_W1_PACKED_LEN => {
                for i in 0..N / 2 {
                    r[i] = ((self[2 * i]) | (self[2 * i + 1] << 4)) as u8;
                }
            }
            _ => {
                unreachable!()
            }
        }

        r
    }

    /// Algorithm 41 NTT(𝑤)
    /// Computes the NTT.
    /// Input: Polynomial 𝑤(𝑋)
    /// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞.
    /// Output: 𝑤_hat = (𝑤_hat\[0], ..., 𝑤_hat\[255]) ∈ 𝑇𝑞.
    ///
    /// Note: by convention, variables holding the output of the NTT function should be named "_ntt"
    /// to indicate that they are in the NTT domain (sometimes called the frequency domain), not the natural domain.
    /// I considered using the rust type system to enforce this, but it seemed like overkill, cause that's what
    /// NIST test vectors are for.
    ///
    /// Design choice: don't do the NTT in-place, but copy data to a new array.
    /// This uses slightly more memory and requires a copy, but makes the code easier to read
    /// and less likely to contain a bug. But this optimization could be considered in the future.
    pub(crate) fn ntt(&mut self) {
        let mut m: usize = 0;
        let mut len: usize = 128;

        while len >= 1 {
            let mut start: usize = 0;
            while start < N {
                m += 1;
                let z: i32 = ZETAS[m];

                for j in start..start + len {
                    let t = montgomery_reduce(z as i64 * self[j + len] as i64);
                    self[j + len] = self[j] - t; // '% q' not strictly needed cause it gets reduced at some point later. Removing it gave +5% in benchmarking
                    self[j] = self[j] + t; // '% q' not strictly needed
                }
                start = start + 2 * len;
            }
            len >>= 1;
        }
    }

    /// Algorithm 42 NTT−1(𝑤)̂
    /// Computes the inverse of the NTT.
    /// Input: ̂̂ ̂ 𝑤 = (𝑤\[0], … , 𝑤\[255]) ∈ 𝑇𝑞.
    /// Output: Polynomial 𝑤(𝑋) = ∑255
    /// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞
    pub(crate) fn inv_ntt(&mut self) {
        let mut m: usize = N;
        let mut len: usize = 1;

        while len < N {
            let mut start: usize = 0;
            while start < N {
                m -= 1;
                let z = (-1) * ZETAS[m];

                // j = start;
                // while j < start + len {
                for j in start..start + len {
                    // 𝑡 ← 𝑤𝑗
                    let t: i32 = self[j];

                    // 𝑤𝑗 ← (𝑡 + 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                    self[j] = t + self[j + len];

                    // 𝑤𝑗+𝑙𝑒𝑛 ← (𝑡 − 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                    self[j + len] = t - self[j + len];

                    // 𝑤𝑗+𝑙𝑒𝑛 ← (𝑧 ⋅ 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                    self[j + len] = montgomery_reduce(z as i64 * self[j + len] as i64);
                }
                start = start + 2 * len; // could be optimized to save the multiply-by-two since j finishes as `start + len`. That said 2* is just << 1, which is basically free.
            }
            len <<= 1;
        }

        // f = 256^-1 mod q
        // const f: i64 = 8347681;
        // bc-java uses this value rather than the one in FIPS 204
        const f: i64 = 41978;
        for j in 0..N {
            // equiv. to the global constant N
            self[j] = montgomery_reduce(f * self[j] as i64);
        }
    }
}

impl Secret for Polynomial {}

impl Drop for Polynomial {
    fn drop(&mut self) {
        self.coeffs.fill(0i32);
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
