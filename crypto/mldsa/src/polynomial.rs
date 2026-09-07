//! Represents a polynomial over the ML-DSA ring.

use crate::aux_functions::{
    ZETAS, conditional_add_q, high_bits, low_bits, make_hint, montgomery_reduce,
};
use crate::mldsa::{N, d, q};
use crate::params::{GAMMA2_Q_MINUS_1_OVER_32, GAMMA2_Q_MINUS_1_OVER_88, MLDSAParams};
use bouncycastle_utils::secret::ZeroizablePrimitive;
use core::ops::{Index, IndexMut};

/// A polynomial over the ML-DSA ring.
///
/// # 🚨 Security 🚨
/// Polynomials themselves are not inherently secret since sometimes they are part of public keys
/// and sometimes private keys.
/// It is the responsibility of the caller to wrap sensitive instances in `Secret<Polynomial>`.
///
/// Public only because it appears in [`crate::VectorTrait`]'s signatures; its fields and
/// operations are crate-private, so from outside it is an opaque handle.
#[derive(Clone, Copy)]
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
    pub(crate) const fn new() -> Self {
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

    pub(crate) fn high_bits<P: MLDSAParams>(&self) -> Self {
        let mut w = Self::new();
        for i in 0..N {
            w[i] = high_bits::<P>(self[i]);
        }

        w
    }

    pub(crate) fn low_bits<P: MLDSAParams>(&self) -> Self {
        let mut w = Self::new();
        for i in 0..N {
            w[i] = low_bits::<P>(self[i]);
        }

        w
    }

    /// Tests whether any coefficient has absolute value at least `bound`.
    ///
    /// `bound` is a runtime argument rather than a const generic because every call site passes a
    /// value derived from the parameter set (𝛾1 − 𝛽, 𝛾2 − 𝛽, or 𝛾2), and an associated const of a
    /// type parameter cannot be used as a const generic argument. It is still a constant after
    /// monomorphization, so this costs nothing.
    pub(crate) fn check_norm(&self, bound: i32) -> bool {
        // It is acceptable that this function is not constant-time (returns true early)
        // The reason being because it is used in a rejection loop.
        // That is, the early quit here leads to rejection, dropping the secret values and
        // continuing to the top of the rejection loop with generating new secret values,
        // or failing the signature validation.
        // So the i32 that we just checked in a non-constant-time manner is about to get thrown away.

        // Note: this formulation of the check_norm function usually requires this bounds check
        //  if bound > (q - 1) / 8 {
        //     return true;
        //  }
        // but since every caller passes a parameter-set constant, a debug_assert is performed
        // instead to make sure the value is what we expect.
        debug_assert!(bound <= (q - 1) / 8);

        let mut t: i32;
        for x in self.coeffs.iter() {
            t = *x >> 31;
            t = *x - (t & (2 * *x));

            if t >= bound {
                return true;
            }
        }
        false
    }

    /// Multiplies every coefficient by 2^𝑑.
    ///
    /// 𝑑 is 13 for all three parameter sets (FIPS 204, Table 1), so it is read from the global
    /// constant rather than being passed in.
    pub(crate) fn shift_left_d(&mut self) {
        for x in self.coeffs.iter_mut() {
            *x <<= d;
        }
    }

    /// Creates the hint vector, and also returns its hamming weight (i.e. the number of 1's).
    pub(crate) fn make_hint<P: MLDSAParams>(&self, r: &Self) -> (Self, i32) {
        let mut out = Polynomial::new();
        let mut count = 0i32;
        for i in 0..N {
            let x = make_hint::<P>(self[i], r[i]);
            out[i] = x;

            // mutants note: this chains up to hint_hamming_weight > OMEGA and there is no test KAT that triggers this branch
            count += x;
        }

        (out, count)
    }

    /// SimpleBitPack(𝐰1[𝑖], (𝑞 − 1)/(2𝛾2) − 1), the per-coordinate body of
    /// FIPS 204, Algorithm 28 (w1Encode), line 3.
    pub(crate) fn w1_encode<P: MLDSAParams>(&self) -> P::PolyW1Packed {
        let mut out = <P::PolyW1Packed as ZeroizablePrimitive>::ZEROED;
        let r = out.as_mut();

        match P::GAMMA2 {
            // ML-DSA-44: (𝑞 − 1)/(2𝛾2) − 1 = 43, so four 6-bit coefficients pack into three bytes.
            GAMMA2_Q_MINUS_1_OVER_88 => {
                for i in 0..N / 4 {
                    r[3 * i] = ((self[4 * i]) as u8) | ((self[4 * i + 1] << 6) as u8);
                    r[3 * i + 1] = ((self[4 * i + 1] >> 2) as u8) | ((self[4 * i + 2] << 4) as u8);
                    r[3 * i + 2] = ((self[4 * i + 2] >> 4) as u8) | ((self[4 * i + 3] << 2) as u8);
                }
            }
            // ML-DSA-65 and ML-DSA-87 share this 𝛾2: (𝑞 − 1)/(2𝛾2) − 1 = 15, so two 4-bit
            // coefficients pack into one byte.
            GAMMA2_Q_MINUS_1_OVER_32 => {
                for i in 0..N / 2 {
                    r[i] = ((self[2 * i]) | (self[2 * i + 1] << 4)) as u8;
                }
            }
            _ => {
                unreachable!()
            }
        }

        out
    }

    /// Algorithm 41 NTT(𝑤)
    /// Computes the NTT.
    /// Input: Polynomial 𝑤(𝑋) = Σ_{j=0}^{255} 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞.
    /// Output: 𝑤_hat = (𝑤_hat\[0], ..., 𝑤_hat\[255]) ∈ 𝑇𝑞.
    ///
    /// Note: by convention, variables holding the output of the NTT function should be named "_hat"
    /// to indicate that they are in the NTT domain (sometimes called the frequency domain), not the natural domain.
    /// Usage of the rust type system to enforce this is arguably unnecessary, since that's what the NIST
    /// test vectors are for.
    ///
    /// Lazy reduction: the butterfly omits an explicit reduction modulo `q`
    /// This is safe only because ‖input‖∞ ≤ q-1 (i.e. intermediates stay below ~5q
    /// (well within i32) and the input of montgomery_reduce input stays below q·2^{31}) and
    /// the final result is reduced downstream.
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
                    // '% q' not strictly needed cause it gets reduced at some point later.
                    // Removing it gave +5% in benchmarking
                    self[j + len] = self[j] - t;
                    self[j] = self[j] + t; // '% q' not strictly needed
                }
                start = start + 2 * len;
            }
            len >>= 1;
        }
    }

    /// Algorithm 42 NTT−1(𝑤_hat)
    /// Computes the inverse of the NTT.
    /// Input: 𝑤_hat = (𝑤_hat[0], … , 𝑤_hat[255]) ∈ 𝑇𝑞.
    /// Output: Polynomial 𝑤(𝑋) = Σ_{j=0}^{255} 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞
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
                start = start + 2 * len;
                // could be optimized to save the multiply-by-two since j finishes as `start + len`.
                // That said 2* is just << 1, which is basically free.
            }
            len <<= 1;
        }

        // Final 1/256 normalization, in Montgomery form to match the montgomery_reduce
        // bookkeeping used by every butterfly above (each contributes a 2^-32 factor).
        // Note: f != 256^-1 mod q = 8347681. That value is only correct
        // applied as a plain multiply (FIPS 204 Alg 42: w_j <- f * w_j mod q).
        // Here we apply f via montgomery_reduce(f * w_j), so the constant is the
        // Montgomery-domain form:  f = mont^2 / 256 mod q = 41978,  mont = 2^32 mod q.
        // Do NOT substitute 8347681, as it is invalid through montgomery_reduce.
        const f: i64 = 41978;
        for j in 0..N {
            // equiv. to the global constant N
            self[j] = montgomery_reduce(f * self[j] as i64);
        }
    }
}
