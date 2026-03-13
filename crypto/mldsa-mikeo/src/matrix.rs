//! These are somewhat unnecessary wrappers around simple arrays, but they are helpful to me in clearly
//! keeping the types and sizes obvious.

use crate::aux_functions::{inv_ntt, ntt};
use crate::polynomial;
use crate::polynomial::{Polynomial};


pub(crate) struct Matrix<const k: usize, const l: usize>
{
    pub(crate) matrix: [[Polynomial; l]; k],
}

impl<const k: usize, const l: usize> Matrix<k, l> {
    pub fn new() -> Self {
        Self { matrix: [[(); l]; k].map(|_| [(); l].map(|_| Polynomial::new())) }
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
        for i in 0 .. k {
            // split out the 0 case to skip a no-op add_ntt()
            w.vec[i].0.copy_from_slice(&polynomial::multiply_ntt(&self.matrix[i][0], &v.vec[0]).0);

            let mut t: Polynomial;
            for j in 1 .. l {
                // dot product a vector into a matrix: multiply the input vector
                // into each row of the matrix, then sum the results to produce a vector of
                // length k.
                t = polynomial::multiply_ntt(&self.matrix[i][j], &v.vec[j]);
                w.vec[i].add_ntt(&t);
            }
        }

        w
    }
}

// Matrix and Vector do not need to impl Secret because the actual data is in the polynomials, which have their own zeroizing drop.
// Technically all matrices and some vectors are only part of the public key and might not need to be zeroized,
// but I'll leave it zeroizing for now and leave this as a potential future optimization.


#[derive(Clone)]
pub(crate) struct Vector<const LEN: usize>
{
    pub(crate) vec: [Polynomial; LEN],
}

impl<const LEN: usize> Vector<LEN>
{
    pub(crate) fn new() -> Self {
        Self { vec: [(); LEN].map(|_| Polynomial::new()) }
    }

    /// negates each entry
    pub(crate) fn neg(&self) -> Self {
        let mut out = self.clone();
        for i in 0..LEN {
           out.vec[i].neg();
        }

        out
    }

    /// Algorithm 46 AddVectorNTT(𝐯, 𝐰)̂
    /// Computes the sum 𝐯_hat + 𝐰_hat of two vectors 𝐯_hat, 𝐰_hat over 𝑇𝑞.
    /// Input: ℓ ∈ ℕ, v_hat ∈ T^ℓ, w_hat ∈ 𝑇^ℓ
    /// Output: u_hat ∈ T^ℓ_𝑞.
    /// Add another vector to this vector
    pub(crate) fn add_vector_ntt(&mut self, s: &Self) {
        for i in 0 .. LEN {
            // perform montgomery addition of each polynomial in the vector
            self.vec[i].add_ntt(&s.vec[i]);
        }
    }

    pub(crate) fn sub_vector(&self, s: &Self) -> Self {
        let mut out = self.clone();
        for i in 0 .. LEN {
            out.vec[i].sub(&s.vec[i]);
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
            s_hat.vec[i] = polynomial::multiply_ntt(&self.vec[i], &w);
        }

        s_hat
    }

    pub(crate) fn reduce(&mut self) {
        for i in 0 .. LEN {
            polynomial::reduce_poly(&mut self.vec[i]);
        }
    }

    pub(crate) fn conditional_add_q(&mut self) {
        for i in 0 .. LEN {
            // polynomial::conditional_add_q(&mut self.vec[i]);
            self.vec[i].conditional_add_q();
        }
    }

    pub(crate) fn ntt(&self) -> Self {
        let mut s_hat = Self::new();

        for i in 0..LEN {
            s_hat.vec[i] = ntt(&self.vec[i]);
        }

        s_hat
    }

    pub(crate) fn inv_ntt(&self) -> Self {
        let mut s = Self::new();

        for i in 0..LEN {
            s.vec[i] = inv_ntt(&self.vec[i]);
        }

        s
    }

    pub(crate) fn high_bits<const GAMMA2: i32>(&self) -> Self {
        let mut s = Self::new();

        for i in 0..LEN {
            s.vec[i] = self.vec[i].high_bits::<GAMMA2>();
        }

        s
    }

    pub(crate) fn low_bits<const GAMMA2: i32>(&self) -> Self {
        let mut s = Self::new();

        for i in 0..LEN {
            s.vec[i] = self.vec[i].low_bits::<GAMMA2>();
        }

        s
    }

    pub(crate) fn shift_left<const d: i32>(&self) -> Self {
        let mut out = self.clone();
        for i in 0..LEN {
            out.vec[i].shift_left::<d>();
        }

        out
    }

    pub(crate) fn check_norm(&self, bound: i32) -> bool {
        // Fine that this is not constant-time because it is used in a rejection loop -- the early quit leads to rejection.
        for x in self.vec.iter() {
            if x.check_norm(bound) {
                return true;
            }
        }
        false
    }

    /// Algorithm 28 w1Encode(𝐰1)
    /// Encodes a polynomial vector 𝐰1 into a byte string.
    /// Input: 𝐰1 ∈ 𝑅𝑘 whose polynomial coordinates have coefficients in \[0, (𝑞 − 1)/(2𝛾2) − 1].
    /// Output: A byte string representation 𝐰1_tilde ∈ 𝔹32𝑘⋅bitlen ((𝑞−1)/(2𝛾2)−1)
    pub(crate) fn w1_encode<const W1_PACKED_LEN: usize, const POLY_W1_PACKED_LEN: usize>(&self) -> [u8; W1_PACKED_LEN] {        
        // 1: 𝐰̃1 ← ()
        let mut w1_tilde = [0u8; W1_PACKED_LEN];

        // 2: for 𝑖 from 0 to 𝑘 − 1 do
        // 3:   𝐰̃1 ← 𝐰̃1 || SimpleBitPack (𝐰1[𝑖], (𝑞 − 1)/(2𝛾2) − 1)
        // 4: end for
        for i in 0..LEN {
            w1_tilde[i*POLY_W1_PACKED_LEN .. (i+1)*POLY_W1_PACKED_LEN].copy_from_slice(
                // todo -- optimize this to take a slice and write directly to it?
                &self.vec[i].w1_encode::<POLY_W1_PACKED_LEN>()
            )
        }

        // 5: return 𝐰̃1
        w1_tilde
    }
}