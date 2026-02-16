
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

    /// Performs dot product multiplication of this matrix by a vector, performing the appropriate
    /// montgomery reductions.
    /// Input: vector of length l
    /// Output: vector of length k
    pub fn mult_by_vec(&mut self, v: &Vector<l>) -> Vector<k> {
        let mut out_v = Vector::<k>::new();
        for i in 0 .. k {
            for j in 0 .. l {
                // dot product a vector into a matrix: multiply the input vector
                // into each row of the matrix, then sum the results.
                let t = polynomial::pointwise_mult(&self.matrix[i][j], &v.vec[j]);
                out_v.vec[i] = polynomial::add(&out_v.vec[i], &t);
            }
        }
        out_v
    }
}

#[derive(Clone)]
pub(crate) struct Vector<const LEN: usize>
{
    pub(crate) vec: [Polynomial; LEN],
}

impl<const LEN: usize> Vector<LEN>
{
    pub fn new() -> Self {
        Self { vec: [polynomial::new(); LEN] }
    }

    /// Add another vector to this vector, performing the montgomery reduction.
    pub fn add(&mut self, w: &Self) {
        for i in 0 .. LEN {
            // perform montgomery addition of each polynomial in the vector
            self.vec[i] = polynomial::add(&self.vec[i], &w.vec[i]);
        }
    }
}