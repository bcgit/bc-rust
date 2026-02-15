
// todo: should this be combined with Polynomial into, like, an algebra.rs ?

use crate::{MLDSAParams};
use crate::polynomial::Polynomial;

pub(crate) struct Matrix<PARAMS: MLDSAParams>
// where
//     [[Polynomial<PARAMS>; PARAMS::l]; PARAMS::k]: Sized,
{
    pub(crate) matrix: [[Polynomial<PARAMS>; PARAMS::l]; PARAMS::k],
}

impl<PARAMS: MLDSAParams> Matrix<PARAMS>
where
    [[Polynomial<PARAMS>; PARAMS::l]; PARAMS::k]: Sized,
{
    pub fn new() -> Self {
        Self { matrix: [[Polynomial::<PARAMS>::new(); PARAMS::l]; PARAMS::k] }
    }

    /// Performs dot product multiplication of this matrix by a vector, performing the appropriate montgomery reductions.
    /// Input: vector of length l
    /// Output: vector of length k
    pub fn mult_by_vec(&mut self, v: &VectorL<PARAMS>) -> VectorK<PARAMS> {
        let mut out_v = VectorK::<PARAMS>::new();
        for i in 0 .. PARAMS.k {
            for j in 0 .. PARAMS.l {
                // dot product a vector into a matrix: multiply the input vector
                // into each row of the matrix, then sum the results.
                let t = self.matrix[i][j].pointwise_mult(&v.vec[j]);
                out_v.vec[i].add(&t);
            }
        }
        out_v
    }
}

// Just some type aliases to help the compiler catch mistakes.
pub(crate) type VectorL<PARAMS: MLDSAParams> = Vector<PARAMS, {PARAMS::l}>;
pub(crate) type VectorK<PARAMS: MLDSAParams> = Vector<PARAMS, {PARAMS::k}>;


pub(crate) const fn new_vec_l<PARAMS: MLDSAParams>() -> [Polynomial<PARAMS>; {PARAMS::l}] {

}

pub(crate) struct Vector<PARAMS: MLDSAParams, const LEN: usize>
where
    [Polynomial<PARAMS>; LEN]: Sized,
{
    pub(crate) vec: [Polynomial<PARAMS>; LEN],
}

impl<PARAMS: MLDSAParams, const LEN: usize> Vector<PARAMS, LEN>
where
    [Polynomial<PARAMS>; LEN]: Sized,
{
    pub fn new() -> Self {
        Self { vec: [Polynomial::<PARAMS>::new(); LEN] }
    }

    /// Add another vector to this vector, performing the montgomery reduction.
    pub fn add(&mut self, w: &Self) {
        for i in 0 .. LEN {
            // perform montgomery addition of each polynomial in the vector
            self.vec[i].add(&w.vec[i]);
        }
    }
}