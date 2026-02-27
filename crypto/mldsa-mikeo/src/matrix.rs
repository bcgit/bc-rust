//! These are somewhat unnecessary wrappers around simple arrays, but they are helpful to me in clearly
//! keeping the types and sizes obvious.

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
    /// Computes the product 𝐌 ∘̂ 𝐯̂ of a matrix 𝐌̂ and a vector 𝐯̂ over 𝑇𝑞.
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

// does not need to impl drop because the actual data is in the polynomials, which have their own zeroizing drop.



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

    /// Algorithm 46 AddVectorNTT(𝐯,̂ 𝐰)̂
    /// Computes the sum ̂̂ ̂̂ 𝐯 + 𝐰 of two vectors 𝐯, 𝐰 over 𝑇𝑞.
    /// Input: ℓ ∈ ℕ, ̂ 𝑞 , ̂ 𝑞 .𝐯 ∈ 𝑇 ℓ 𝐰 ∈ 𝑇 ℓ
    /// Output: ̂ 𝑞 .
    /// Add another vector to this vector
    pub(crate) fn add_vector_ntt(&mut self, w: &Self) {
        for i in 0 .. LEN {
            // perform montgomery addition of each polynomial in the vector
            self.vec[i].add_ntt(&w.vec[i]);
        }
    }

    pub(crate) fn reduce(&mut self) {
        for i in 0 .. LEN {
            polynomial::reduce_poly(&mut self.vec[i]);
        }
    }

    pub(crate) fn conditional_add_q(&mut self) {
        for i in 0 .. LEN {
            polynomial::conditional_add_q_poly(&mut self.vec[i]);
        }
    }
}