//! These are somewhat unnecessary wrappers around simple arrays, but they are helpful to me in clearly
//! keeping the types and sizes obvious.

use crate::aux_functions::multiply_ntt;
use crate::mldsa::H;
use crate::polynomial::Polynomial;
use bouncycastle_core::traits::XOF;
use core::ops::{Index, IndexMut};

/// A matrix over the ML-DSA ring.
#[derive(Clone)]
pub struct Matrix<const k: usize, const l: usize>(/*pub(crate)*/ [[Polynomial; l]; k]);

/// Convenience function to avoid ".0" all over the place.
impl<const k: usize, const l: usize> Index<usize> for Matrix<k, l> {
    type Output = [Polynomial; l];

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}
/// Convenience function to avoid ".0" all over the place.
impl<const k: usize, const l: usize> IndexMut<usize> for Matrix<k, l> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<const k: usize, const l: usize> Matrix<k, l> {
    pub(crate) fn new() -> Self {
        Self { 0: [[(); l]; k].map(|_| [(); l].map(|_| Polynomial::new())) }
    }

    /// Algorithm 48 MatrixVectorNTT(𝐌, 𝐯)
    /// Computes the product 𝐌 ∘̂ 𝐯_hat of a matrix 𝐌_hat and a vector 𝐯_hat over 𝑇𝑞.
    /// Input: 𝑘, ℓ ∈ ℕ, 𝐌 ∈ 𝑇𝑞
    /// 𝑘×ℓ ̂ 𝑞 .
    /// Performs dot product multiplication of this matrix by a vector
    /// Input: vector of length l
    /// Output: vector of length k
    pub fn matrix_vector_ntt(&self, v: &Vector<l>) -> Vector<k> {
        let mut w = Vector::<k>::new();
        for i in 0..k {
            // split out the 0 case to skip a no-op add_ntt()
            w[i].coeffs.copy_from_slice(&multiply_ntt(&self[i][0], &v[0]).coeffs);

            let mut w1: Polynomial;
            for j in 1..l {
                // dot product a vector into a matrix: multiply the input vector
                // into each row of the matrix, then sum the results to produce a vector of
                // length k.
                w1 = multiply_ntt(&self[i][j], &v[j]);
                w[i].add_ntt(&w1);
            }
        }

        w
    }
}

// Matrix and Vector do not need to impl Secret because the actual data is in the polynomials, which have their own zeroizing drop.
// Technically all matrices and some vectors are only part of the public key and might not need to be zeroized,
// but I'll leave it zeroizing for now and leave this as a potential future optimization.

#[derive(Clone)]
pub(crate) struct Vector<const k: usize> {
    pub(crate) vec: [Polynomial; k],
}

/// Convenience function to avoid ".0" all over the place.
impl<const k: usize> Index<usize> for Vector<k> {
    type Output = Polynomial;

    fn index(&self, index: usize) -> &Self::Output {
        &self.vec[index]
    }
}
/// Convenience function to avoid ".0" all over the place.
impl<const k: usize> IndexMut<usize> for Vector<k> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.vec[index]
    }
}

impl<const LEN: usize> Vector<LEN> {
    pub(crate) fn new() -> Self {
        Self { vec: [(); LEN].map(|_| Polynomial::new()) }
    }

    /// Algorithm 46 AddVectorNTT(𝐯, 𝐰)̂
    /// Computes the sum 𝐯_hat + 𝐰_hat of two vectors 𝐯_hat, 𝐰_hat over 𝑇𝑞.
    /// Input: ℓ ∈ ℕ, v_hat ∈ T^ℓ, w_hat ∈ 𝑇^ℓ
    /// Output: u_hat ∈ T^ℓ_𝑞.
    /// Add another vector to this vector
    pub(crate) fn add_vector_ntt(&mut self, s: &Self) {
        for i in 0..LEN {
            // perform montgomery addition of each polynomial in the vector
            self[i].add_ntt(&s[i]);
        }
    }

    pub(crate) fn sub_vector(&self, s: &Self) -> Self {
        let mut out = self.clone();
        for i in 0..LEN {
            out[i].sub(&s[i]);
        }
        out
    }

    /// Algorithm 47 ScalarVectorNTT(𝑐,̂ 𝐯)̂
    /// Computes the product 𝑐_hat * 𝐯_hat of a scalar 𝑐_hat and a vector 𝐯_hat over 𝑇𝑞.
    /// Input: 𝑐_hat ∈ 𝑇𝑞, ℓ ∈ ℕ, 𝐯_hat ∈ 𝑇^ℓ
    /// Output: 𝑞 .
    pub(crate) fn scalar_vector_ntt(&self, w: &Polynomial) -> Self {
        let mut s_hat = Self::new();
        for i in 0..LEN {
            s_hat[i] = multiply_ntt(&self[i], &w);
        }

        s_hat
    }

    pub(crate) fn conditional_add_q(&mut self) {
        for i in 0..LEN {
            self[i].conditional_add_q();
        }
    }

    pub(crate) fn reduce(&mut self) {
        for i in 0..LEN {
            self[i].reduce();
        }
    }

    pub(crate) fn ntt(&mut self) {
        for i in 0..LEN {
            self[i].ntt();
        }
    }

    pub(crate) fn inv_ntt(&mut self) {
        for i in 0..LEN {
            self[i].inv_ntt();
        }
    }

    pub(crate) fn high_bits<const GAMMA2: i32>(&self) -> Self {
        let mut s = Self::new();

        for i in 0..LEN {
            s[i] = self[i].high_bits::<GAMMA2>();
        }

        s
    }

    pub(crate) fn low_bits<const GAMMA2: i32>(&self) -> Self {
        let mut s = Self::new();

        for i in 0..LEN {
            s[i] = self[i].low_bits::<GAMMA2>();
        }

        s
    }

    pub(crate) fn shift_left<const d: i32>(&self) -> Self {
        let mut out = self.clone();
        for i in 0..LEN {
            out[i].shift_left::<d>();
        }

        out
    }

    pub(crate) fn check_norm<const BOUND: i32>(&self) -> bool {
        // Fine that this is not constant-time because it is used in a rejection loop -- the early quit leads to rejection.
        for x in self.vec.iter() {
            if x.check_norm::<BOUND>() {
                return true;
            }
        }
        false
    }

    /// Algorithm 28 w1Encode(𝐰1)
    /// Encodes a polynomial vector 𝐰1 into a byte string.
    /// Input: 𝐰1 ∈ 𝑅𝑘 whose polynomial coordinates have coefficients in \[0, (𝑞 − 1)/(2𝛾2) − 1].
    /// Output: A byte string representation 𝐰1_tilde ∈ 𝔹32𝑘⋅bitlen ((𝑞−1)/(2𝛾2)−1)
    /// Optimized from FIPS 204 to feed into the hash one row at a time to reduce overall memory footprint.
    pub(crate) fn w1_encode_and_hash<const POLY_W1_PACKED_LEN: usize>(&self, h: &mut H) {
        // 1: 𝐰̃1 ← ()
        // don't need to allocate anything since we're feeding it into the hash row-wise

        // 2: for 𝑖 from 0 to 𝑘 − 1 do
        // 3:   𝐰̃1 ← 𝐰̃1 || SimpleBitPack (𝐰1[𝑖], (𝑞 − 1)/(2𝛾2) − 1)
        // 4: end for
        for w in self.vec.iter() {
            h.absorb(&w.w1_encode::<POLY_W1_PACKED_LEN>());
        }
    }
}
