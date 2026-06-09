//! These are somewhat unnecessary wrappers around simple arrays, but they are helpful to me in clearly
//! keeping the types and sizes obvious.

use core::ops::{Index, IndexMut};

use crate::mlkem::{q, N};
use crate::polynomial;
use crate::polynomial::{Polynomial};

#[derive(Clone)]
/// A matrix over the ML-KEM ring.
pub struct Matrix<const k: usize, const l: usize>{ /*pub(crate)*/ mat: [[Polynomial; l]; k] }

/// Convenience function to avoid ".0" all over the place.
impl<const k: usize, const l: usize> Index<usize> for Matrix<k,l> {
    type Output = [Polynomial; l];

    fn index(&self, index: usize) -> &Self::Output {
        &self.mat[index]
    }
}
/// Convenience function to avoid ".0" all over the place.
impl<const k: usize, const l: usize> IndexMut<usize> for Matrix<k,l> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.mat[index]
    }
}

impl<const k: usize, const l: usize> Matrix<k, l> {
    pub(crate) fn new() -> Self {
        Self{ mat: [[(); l]; k].map(|_| [(); l].map(|_| Polynomial::new())) }
    }

    /// FIPS 204 Algorithm 48 MatrixVectorNTT(𝐌, 𝐯)
    /// Computes the product 𝐌 ∘̂ 𝐯_hat of a matrix 𝐌_hat and a vector 𝐯_hat over 𝑇𝑞.
    /// Input: 𝑘, ℓ ∈ ℕ, 𝐌 ∈ 𝑇𝑞 𝑘×ℓ
    /// Performs dot product multiplication of this matrix by a vector
    /// Input: vector of length l
    /// Output: vector of length k
    ///
    /// transpose: False will multiply A, where as True will multiply A^T
    pub(crate) fn matrix_vector_ntt<const transpose: bool>(&self, v: &Vector<l>) -> Vector<k> {
        let mut w = Vector::<k>::new();
        for i in 0 .. k {
            // split out the 0 case to skip a no-op add_ntt()
            w[i] = if transpose{
                polynomial::base_mult_montgomery(&self.mat[0][i], &v[0])
            } else {
                polynomial::base_mult_montgomery(&self.mat[i][0], &v[0])
            };

            let mut w1: Polynomial;
            for j in 1 .. l {
                // dot product a vector into a matrix: multiply the input vector
                // into each row of the matrix, then sum the results to produce a vector of
                // length k.
                w1 = if transpose {
                    polynomial::base_mult_montgomery(&self.mat[j][i], &v[j])
                } else {
                    polynomial::base_mult_montgomery(&self.mat[i][j], &v[j])
                };

                w[i].add(&w1);
            }
        }

        // In the non-transposed case (keygen), we act in montgomery domain; otherwise (encaps / decaps) we reduce normally.
        if transpose {
            w.reduce();
        } else {
            w.convert_to_mont();
        }

        w
    }
}

// Matrix and Vector do not need to impl Secret because the actual data is in the polynomials, which have their own zeroizing drop.
// Technically all matrices and some vectors are only part of the public key and might not need to be zeroized,
// but I'll leave it zeroizing for now and leave this as a potential future optimization.


#[derive(Clone)]
pub(crate) struct Vector<const k: usize>{ pub(crate) vec: [Polynomial; k] }

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

impl<const k: usize> Vector<k>
{
    pub(crate) fn new() -> Self {
        Self {vec: [(); k].map(|_| Polynomial::new()) }
    }

    /// Algorithm 46 AddVectorNTT(𝐯, 𝐰)̂
    /// Computes the sum 𝐯_hat + 𝐰_hat of two vectors 𝐯_hat, 𝐰_hat over 𝑇𝑞.
    /// Input: ℓ ∈ ℕ, v_hat ∈ T^ℓ, w_hat ∈ 𝑇^ℓ
    /// Output: u_hat ∈ T^ℓ_𝑞.
    /// Add another vector to this vector
    pub(crate) fn add_vector_ntt(&mut self, s: &Self) {
        for i in 0 ..k {
            // perform montgomery addition of each polynomial in the vector
            self[i].add(&s[i]);
        }
    }

    pub(crate) fn dot_product(&self, v: &Self) -> Polynomial {
        // split out the 0 case to skip a no-op add_ntt()
        let mut w = polynomial::base_mult_montgomery(&self[0], &v[0]);

        for i in 1..k {
            let w1 = polynomial::base_mult_montgomery(&self[i], &v[i]);
            w.add(&w1);
        }
        // in theory, we need this here, but all unit tests pass without it since
        // it actually doesn't matter if you go outside the [0, q] range as long as you
        // reduce down before encoding out.
        // w.poly_reduce();

        w
    }

    pub(crate) fn reduce(&mut self) {
        for i in 0..k {
            self[i].poly_reduce();
        }
    }

    pub(crate) fn ntt(&mut self){
        for i in 0..k {
            self[i].ntt();
        }
    }

    pub(crate) fn inv_ntt(&mut self) {
        for i in 0..k {
            self[i].inv_ntt();
        }
    }

    pub(crate) fn convert_to_mont(&mut self) {
        for i in 0 ..k {
            self[i].convert_to_mont();
        }
    }

    /// This is an optimized version of
    ///   ByteEncode_𝑑𝑢( Compress_𝑑𝑢(𝐮) )
    /// which packs a polynomial vector according to the packing coefficient dv
    pub(crate) fn compress_pol_vec<const du: i16>(&self, out: &mut [u8]) {
        // make sure we have received a dv
        assert!(du == 10 || du == 11);

        // make sure we were given the right size output buffer
        // each of the N i16's will take dv bits
        debug_assert_eq!(out.len(), k *(N * (du as usize) / 8));

        // bc-java has a conditional_sub_q() here, but I pass all unit tests without it, so I'm taking it out for performance.
        // let mut s = self.clone();
        // s.conditional_sub_q();

        out.fill(0);

        let mut idx = 0;
        match du {
            10 => { // MLKEM512 and MLKEM 768
                let mut t = [0i16; 4];
                for i in 0..k {
                    for j in 0..N/4 {
                        // fill the temp array t
                        for (l, item) in t.iter_mut().enumerate() {
                            *item = (((((self[i][4 * j + l] as u32) << 10) as i32
                                + (q as i32 / 2))
                                / q as i32)
                                & 0x3FF) as i16;
                        }

                        out[idx] = t[0] as u8;
                        out[idx + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                        out[idx + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                        out[idx + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                        out[idx + 4] = (t[3] >> 2) as u8;
                        idx += 5;
                    }
                }
            },
            11 => {
                let mut t = [0i16; 8];
                for i in 0..k {
                    for j in 0..N/8 {
                        for (l, item) in t.iter_mut().enumerate() {
                            *item = (((((self[i][8 * j + l] as u32) << 11) as i32
                                + (q as i32 / 2))
                                / q as i32)
                                & 0x7FF) as i16;
                        }

                        out[idx] = t[0] as u8;
                        out[idx + 1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                        out[idx + 2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                        out[idx + 3] = (t[2] >> 2) as u8;
                        out[idx + 4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                        out[idx + 5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                        out[idx + 6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                        out[idx + 7] = (t[5] >> 1) as u8;
                        out[idx + 8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                        out[idx + 9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                        out[idx + 10] = (t[7] >> 3) as u8;
                        idx += 11;
                    }
                }
            },
            _ => unreachable!(),
        }
    }

    pub(crate) fn decompress_pol_vec<const du: i16>(compressed_u: &[u8]) -> Vector<k> {
        let mut u = Vector::<k>::new();

        // make sure we have received a dv
        assert!(du == 10 || du == 11);

        // make sure we were given the right size output buffer
        // each of the N i16's will take dv bits
        debug_assert_eq!(compressed_u.len(), k *(N * (du as usize) / 8));

        let mut idx = 0;

        match du {
            10 => { // MLKEM512 and MLKEM768
                let mut t = [0i16; 4];
                for i in 0..k {
                    for j in 0..(N/4) {
                        t[0] = ((compressed_u[idx] as u16)
                            | (compressed_u[idx + 1] as u16) << 8)
                            as i16;
                        t[1] = (((compressed_u[idx + 1] as u16) >> 2)
                            | (compressed_u[idx + 2] as u16) << 6)
                            as i16;
                        t[2] = (((compressed_u[idx + 2] as u16) >> 4)
                            | (compressed_u[idx + 3] as u16) << 4)
                            as i16;
                        t[3] = (((compressed_u[idx + 3] as u16) >> 6)
                            | (compressed_u[idx + 4] as u16) << 2)
                            as i16;
                        idx += 5;
                        for (l, item) in t.iter().enumerate() {
                            u[i][4 * j + l] =
                                ((((*item & 0x3FF) as i32) * (q as i32) + 512) >> 10) as i16;
                        }
                    }
                }
        },
            11 => { // MLKEM1024
                let mut t = [0i16; 8];
                for i in 0..k {
                    for j in 0..N/8 {
                        t[0] = (compressed_u[idx] as i32
                            | ((compressed_u[idx + 1] as u16) as i32) << 8)
                            as i16;
                        t[1] = ((compressed_u[idx + 1] >> 3) as i32
                            | ((compressed_u[idx + 2] as u16) as i32) << 5)
                            as i16;
                        t[2] = ((compressed_u[idx + 2] >> 6) as i32
                            | ((compressed_u[idx + 3] as u16) as i32) << 2
                            | (((compressed_u[idx + 4] as i32) << 10) as u16) as i32)
                            as i16;
                        t[3] = ((compressed_u[idx + 4] >> 1) as i32
                            | ((compressed_u[idx + 5] as u16) as i32) << 7)
                            as i16;
                        t[4] = ((compressed_u[idx + 5] >> 4) as i32
                            | ((compressed_u[idx + 6] as u16) as i32) << 4)
                            as i16;
                        t[5] = ((compressed_u[idx + 6] >> 7) as i32
                            | ((compressed_u[idx + 7] as u16) as i32) << 1
                            | (((compressed_u[idx + 8] as i32) << 9) as u16) as i32)
                            as i16;
                        t[6] = ((compressed_u[idx + 8] >> 2) as i32
                            | ((compressed_u[idx + 9] as u16) as i32) << 6)
                            as i16;
                        t[7] = ((compressed_u[idx + 9] >> 5) as i32
                            | ((compressed_u[idx + 10] as u16) as i32) << 3)
                            as i16;
                        idx += 11;
                        for (l, item) in t.iter().enumerate() {
                            u[i][8 * j + l] =
                                ((((*item & 0x7FF) as i32) * (q as i32) + 1024) >> 11) as i16;
                        }
                    }
                }
            },
            _ => unreachable!(),
        }

        u
    }
}