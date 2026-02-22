//! These are somewhat unnecessary wrappers around simple arrays, but they are helpful to me in clearly
//! keeping the types and sizes obvious.

// todo: should this be combined with Polynomial into, like, an algebra.rs ?

use crate::polynomial;
use crate::polynomial::{Polynomial};



pub(crate) struct Matrix<const k: usize, const l: usize>
{
    pub(crate) matrix: [[Polynomial; l]; k],
}

impl<const k: usize, const l: usize> Matrix<k, l> {
    pub fn new() -> Self {
        Self { matrix: [[polynomial::new(); l]; k] }
    }

    /// Algorithm 48 MatrixVectorNTT(𝐌,̂ 𝐯)̂
    /// Computes the product 𝐌 ∘̂ 𝐯̂ of a matrix 𝐌̂ and a vector 𝐯̂ over 𝑇𝑞.
    /// Input: 𝑘, ℓ ∈ ℕ, 𝐌 ∈ 𝑇𝑞
    /// 𝑘×ℓ ̂ 𝑞 .
    /// Performs dot product multiplication of this matrix by a vector
    /// Input: vector of length l
    /// Output: vector of length k
    pub fn matrix_vector_ntt(&mut self, v: &Vector<l>) -> Vector<k> {
        let mut w = Vector::<k>::new();
        for i in 0 .. k {
            for j in 0 .. l {
                // dot product a vector into a matrix: multiply the input vector
                // into each row of the matrix, then sum the results.
                let t = polynomial::multiply_ntt(&self.matrix[i][j], &v.vec[j]);
                w.vec[i] = polynomial::add_ntt(&w.vec[i], &t);
            }
        }
        // todo: is this redundant with other %q 's?
        // w.reduce();

        w
    }
}

#[derive(Clone)]
pub(crate) struct Vector<const LEN: usize>
{
    pub(crate) vec: [Polynomial; LEN],
}

impl<const LEN: usize> Vector<LEN>
{
    pub(crate) fn new() -> Self {
        Self { vec: [polynomial::new(); LEN] }
    }

    /// Algorithm 46 AddVectorNTT(𝐯,̂ 𝐰)̂
    /// Computes the sum ̂̂ ̂̂ 𝐯 + 𝐰 of two vectors 𝐯, 𝐰 over 𝑇𝑞.
    /// Input: ℓ ∈ ℕ, ̂ 𝑞 , ̂ 𝑞 .𝐯 ∈ 𝑇 ℓ 𝐰 ∈ 𝑇 ℓ
    /// Output: ̂ 𝑞 .
    /// Add another vector to this vector
    pub(crate) fn add_vector_ntt(&mut self, w: &Self) {
        for i in 0 .. LEN {
            // perform montgomery addition of each polynomial in the vector
            self.vec[i] = polynomial::add_ntt(&self.vec[i], &w.vec[i]);
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

    /// For debugging. OpenSSL's implementation uses only integers in \[0, q-1] while bc uses \[-q, q]
    /// rectify puts things into \[0, q-1] so that intermediate results can be compared with openssl
    /// TODO THIS IS FOR DEBUGGING AND IS NOT CONSTANT TIME
    pub(crate) fn debug_rectify(&mut self) {
        for i in 0 .. LEN {
            polynomial::debug_rectify(&mut self.vec[i]);
        }
    }
}