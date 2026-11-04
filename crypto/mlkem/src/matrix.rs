//! These are somewhat unnecessary wrappers around simple arrays, but they are helpful for clearly
//! keeping the types and sizes obvious.

use core::ops::{Index, IndexMut};

use crate::mlkem::{N, q};
use crate::params::MLKEMParams;
use bouncycastle_mlkem_common::polynomial;
use bouncycastle_mlkem_common::polynomial::Polynomial;
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// The operations this crate performs on a vector of polynomials, i.e. on an element of 𝑅^LEN.
///
/// [`Vector`] is the only implementation; the trait exists so that code generic over a parameter
/// set can operate on `MLKEMParams::VecK` without knowing its length.
pub trait VectorTrait:
    Sized + Copy + ZeroizablePrimitive + Index<usize, Output = Polynomial> + IndexMut<usize>
{
    /// A vector with every coefficient set to zero.
    fn new() -> Self;

    /// The coordinates, for iteration and chunking.
    fn elems(&self) -> &[Polynomial];
    /// The coordinates, for iteration and chunking.
    fn elems_mut(&mut self) -> &mut [Polynomial];

    /// Adds another vector to this one, coordinatewise, in the NTT domain.
    fn add_vector_ntt(&mut self, s: &Self);
    /// The dot product of two vectors in the NTT domain.
    fn dot_product(&self, v: &Self) -> Polynomial;
    /// Barrett-reduces every coefficient.
    fn reduce(&mut self);
    /// Applies the NTT to every coordinate.
    fn ntt(&mut self);
    /// Applies the inverse NTT to every coordinate.
    fn inv_ntt(&mut self);
    /// Converts every coefficient into the Montgomery domain.
    fn convert_to_mont(&mut self);
    /// FIPS 203, Algorithm 5 (ByteEncode) applied to the compressed vector.
    fn compress_pol_vec<P: MLKEMParams>(&self, out: &mut [u8]);
    /// The inverse of [`VectorTrait::compress_pol_vec`].
    fn decompress_pol_vec<P: MLKEMParams>(compressed_u: &[u8]) -> Self;
}

/// The operations this crate performs on the public matrix 𝐀̂.
///
/// [`Matrix`] is the only implementation; see [`VectorTrait`] for why the trait exists.
pub trait MatrixTrait: Sized + Clone {
    /// The vector this matrix maps between: an element of 𝑅^𝑘.
    type Vec: VectorTrait;

    /// A matrix with every coefficient set to zero.
    fn new() -> Self;
    /// Overwrites the polynomial at `elems[row][col]`.
    fn set_elem(&mut self, row: usize, col: usize, p: Polynomial);
    /// Computes 𝐀̂ ∘ 𝐯̂, transposing 𝐀̂ first when `transpose` is set.
    fn matrix_vector_ntt<const transpose: bool>(&self, v: &Self::Vec) -> Self::Vec;
}

#[derive(Clone)]
/// A matrix over the ML-KEM ring.
pub struct Matrix<const k: usize, const l: usize> {
    /// Indexed `elems[row][col]`
    pub(crate) elems: [[Polynomial; l]; k],
}

impl<const k: usize, const l: usize> Matrix<k, l> {
    pub(crate) fn new() -> Self {
        Self { elems: [[(); l]; k].map(|_| [(); l].map(|_| Polynomial::new())) }
    }

    /// The matrix-vector product over 𝑇𝑞 of FIPS 203 Section 2.4.7: 𝐰̂ ← 𝐀̂ ∘ 𝐮̂ (2.12), or
    /// 𝐲̂ ← 𝐀̂ᵀ ∘ 𝐮̂ (2.13) when `transpose` is true, each entry product being MultiplyNTTs
    /// (Algorithm 11).
    /// Input: vector of length l
    /// Output: vector of length k
    pub(crate) fn matrix_vector_ntt<const transpose: bool>(&self, v: &Vector<l>) -> Vector<k> {
        let mut w = Vector::<k>::new();
        for i in 0..k {
            // split out the 0 case to skip a no-op add_ntt()
            w[i] = if transpose {
                polynomial::base_mult_montgomery(&self.elems[0][i], &v[0])
            } else {
                polynomial::base_mult_montgomery(&self.elems[i][0], &v[0])
            };

            let mut w1: Polynomial;
            for j in 1..l {
                // dot product a vector into a matrix: multiply the input vector
                // into each row of the matrix, then sum the results to produce a vector of
                // length k.
                w1 = if transpose {
                    polynomial::base_mult_montgomery(&self.elems[j][i], &v[j])
                } else {
                    polynomial::base_mult_montgomery(&self.elems[i][j], &v[j])
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

/// ML-KEM's 𝐀̂ is always 𝑘 × 𝑘, so the trait is implemented only for the square case; that is what
/// lets [`MatrixTrait::Vec`] be one vector type rather than an input and an output type.
impl<const k: usize> MatrixTrait for Matrix<k, k> {
    type Vec = Vector<k>;

    fn new() -> Self {
        Matrix::new()
    }

    fn set_elem(&mut self, row: usize, col: usize, p: Polynomial) {
        self.elems[row][col] = p;
    }

    fn matrix_vector_ntt<const transpose: bool>(&self, v: &Vector<k>) -> Vector<k> {
        Matrix::matrix_vector_ntt::<transpose>(self, v)
    }
}

#[derive(Clone, Copy)]
/// A vector of `k` polynomials, i.e. an element of 𝑅^𝑘.
///
/// Public only because it is the value of `MLKEMParams::VecK`; its fields and operations are
/// crate-private, so from outside it is an opaque handle. Reach it through [`VectorTrait`].
pub struct Vector<const k: usize> {
    pub(crate) elems: [Polynomial; k],
}

/// Convenience function to avoid ".0" all over the place.
impl<const k: usize> Index<usize> for Vector<k> {
    type Output = Polynomial;

    fn index(&self, index: usize) -> &Self::Output {
        &self.elems[index]
    }
}
/// Convenience function to avoid ".0" all over the place.
impl<const k: usize> IndexMut<usize> for Vector<k> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.elems[index]
    }
}

impl<const k: usize> ZeroizablePrimitive for Vector<k> {
    const ZEROED: Self = Self::new();
}

impl<const k: usize> Vector<k> {
    pub(crate) const fn new() -> Self {
        Self { elems: [Polynomial::new(); k] }
    }
}

impl<const k: usize> VectorTrait for Vector<k> {
    fn new() -> Self {
        Vector::new()
    }

    fn elems(&self) -> &[Polynomial] {
        &self.elems
    }

    fn elems_mut(&mut self) -> &mut [Polynomial] {
        &mut self.elems
    }
    fn add_vector_ntt(&mut self, s: &Self) {
        for i in 0..k {
            // perform Montgomery addition of each polynomial in the vector
            self[i].add(&s[i]);
        }
    }

    fn dot_product(&self, v: &Self) -> Polynomial {
        // split out the 0 case to skip a no-op add_ntt()
        let mut w = polynomial::base_mult_montgomery(&self[0], &v[0]);

        for i in 1..k {
            let w1 = polynomial::base_mult_montgomery(&self[i], &v[i]);
            w.add(&w1);
        }
        // Reduced before it is returned: each product coefficient is a sum of two Montgomery
        // reductions in (-q, q), so the k-term sum is in (-2kq, 2kq), up to 16q for ML-KEM-1024,
        // and the callers feed it to `inv_ntt`, whose first butterfly adds two coefficients in
        // i16 (limit 9.84q). FIPS 203 Sec 3.3 allows deferring a reduction only while the result
        // is right for every input; without this one the margin was empirical (a search reached
        // 8.9q on a real key), and bc-java and the pq-crystals reference reduce at this point.
        w.poly_reduce();

        w
    }

    fn reduce(&mut self) {
        for i in 0..k {
            self[i].poly_reduce();
        }
    }

    fn ntt(&mut self) {
        for i in 0..k {
            self[i].ntt();
        }
    }

    fn inv_ntt(&mut self) {
        for i in 0..k {
            self[i].inv_ntt();
        }
    }

    fn convert_to_mont(&mut self) {
        for i in 0..k {
            self[i].convert_to_mont();
        }
    }

    /// This is an optimized version of
    ///   ByteEncode_𝑑𝑢( Compress_𝑑𝑢(𝐮) )
    /// which packs a polynomial vector according to the packing coefficient dv
    fn compress_pol_vec<P: MLKEMParams>(&self, out: &mut [u8]) {
        // make sure we have received a dv
        assert!(P::du == 10 || P::du == 11);

        // make sure we were given the right size output buffer
        // each of the N i16's will take dv bits
        debug_assert_eq!(out.len(), k * (N * (P::du as usize) / 8));

        // No conditional_sub_q needed (as done in bc-java): callers must reduce() first,
        // so coefficients are in [0, q) (barrett_reduce, floor variant). The Compress mask `& (2^du - 1)` folds
        // mod q, so values in [q, 2q) would also be correct. WARNING: the `as u32` cast
        // below REQUIRES non-negative coefficients. That is to say DO NOT switch barrett_reduce to a
        // signed/centered variant (e.g. pq-crystals' rounded form) without restoring a
        // reduction here, or this will silently produce garbage.
        // let mut s = self.clone();
        // s.conditional_sub_q();

        let mut idx = 0;
        match P::du {
            10 => {
                // MLKEM512 and MLKEM 768
                let mut t = [0i16; 4];
                for i in 0..k {
                    for j in 0..N / 4 {
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
            }
            11 => {
                let mut t = [0i16; 8];
                for i in 0..k {
                    for j in 0..N / 8 {
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
            }
            _ => unreachable!(),
        }
    }

    fn decompress_pol_vec<P: MLKEMParams>(compressed_u: &[u8]) -> Self {
        let mut u = Vector::<k>::new();

        // make sure we have received a dv
        assert!(P::du == 10 || P::du == 11);

        // make sure we were given the right size output buffer
        // each of the N i16's will take dv bits
        debug_assert_eq!(compressed_u.len(), k * (N * (P::du as usize) / 8));

        let mut idx = 0;

        match P::du {
            10 => {
                // MLKEM512 and MLKEM768
                let mut t = [0i16; 4];
                for i in 0..k {
                    for j in 0..(N / 4) {
                        t[0] = ((compressed_u[idx] as u16) | (compressed_u[idx + 1] as u16) << 8)
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
            }
            11 => {
                // MLKEM1024
                let mut t = [0i16; 8];
                for i in 0..k {
                    for j in 0..N / 8 {
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
            }
            _ => unreachable!(),
        }

        u
    }
}

#[cfg(test)]
mod tests {
    //! `compress_pol_vec` is pinned by the ACVP ciphertexts; `decompress_pol_vec` is not: ML-KEM's
    //! decryption tolerates a decompressed coefficient being off by a little, so a rounding error
    //! in it still yields the right shared secret on every vector. These check the two against
    //! FIPS 203 Section 4.2.1, eq. (4.7) and (4.8), coefficient by coefficient.
    use super::*;
    extern crate std;
    use crate::params::{MLKEM512Params, MLKEM1024Params};
    use std::vec;
    use std::vec::Vec;

    /// Compress_d(x) = round((2^d / q) * x) mod 2^d, with round-half-up; q is odd so the
    /// half-way case never occurs and floor((2^d * x + q/2) / q) is exact.
    fn compress_ref(d: u32, x: i16) -> u16 {
        ((((x as u32) << d) + (q as u32) / 2) / (q as u32) % (1 << d)) as u16
    }

    /// Decompress_d(y) = round((q / 2^d) * y).
    fn decompress_ref(d: u32, y: u16) -> i16 {
        (((y as u32) * (q as u32) + (1 << (d - 1))) >> d) as i16
    }

    /// Unpacks `d`-bit little-endian fields, as ByteDecode_d does.
    fn fields(d: u32, bytes: &[u8]) -> Vec<u16> {
        let mut out = Vec::new();
        let mut acc: u32 = 0;
        let mut bits = 0;
        for &b in bytes {
            acc |= (b as u32) << bits;
            bits += 8;
            while bits >= d {
                out.push((acc & ((1 << d) - 1)) as u16);
                acc >>= d;
                bits -= d;
            }
        }
        out
    }

    fn lcg_bytes(len: usize, mut state: u32) -> Vec<u8> {
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                (state >> 24) as u8
            })
            .collect()
    }

    fn check<P: MLKEMParams, const k: usize>() {
        let d = P::du as u32;
        let packed_len = k * N * (d as usize) / 8;

        // decompress: every field of a pseudo-random ciphertext block comes out as eq. (4.8)
        let bytes = lcg_bytes(packed_len, 7 + d);
        let u = Vector::<k>::decompress_pol_vec::<P>(&bytes);
        for (n, &y) in fields(d, &bytes).iter().enumerate() {
            assert_eq!(u[n / N][n % N], decompress_ref(d, y), "d={d} field {n}");
        }

        // compress: every coefficient value 0..q, laid out across the vector
        let mut v = Vector::<k>::new();
        let mut x: i16 = 0;
        for i in 0..k {
            for j in 0..N {
                v[i][j] = x;
                x = (x + 1) % q;
            }
        }
        let mut out = vec![0u8; packed_len];
        v.compress_pol_vec::<P>(&mut out);
        for (n, &f) in fields(d, &out).iter().enumerate() {
            assert_eq!(f, compress_ref(d, v[n / N][n % N]), "d={d} coefficient {n}");
        }
    }

    #[test]
    fn compress_and_decompress_match_fips_203_for_du_10() {
        check::<MLKEM512Params, 2>();
    }

    #[test]
    fn compress_and_decompress_match_fips_203_for_du_11() {
        check::<MLKEM1024Params, 4>();
    }

    /// `dot_product` returns reduced coefficients, in [0, q]: the k-term sum of Montgomery
    /// products is in (-2kq, 2kq) and the callers' `inv_ntt` adds two coefficients in i16, so
    /// the reduction at the end of `dot_product` is what keeps the sum in range (the review's
    /// M1, which arose from that reduction being commented out). An LCG spreads the inputs over
    /// (-q, q), the range NTT-domain coefficients take.
    #[test]
    fn dot_product_is_reduced() {
        let mut x: u32 = 0x2545_F491;
        let mut next = || {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            ((x % (2 * q as u32 - 1)) as i32 - (q as i32 - 1)) as i16
        };
        for _ in 0..64 {
            let mut a = Vector::<4>::new();
            let mut b = Vector::<4>::new();
            for i in 0..4 {
                for j in 0..N {
                    a[i][j] = next();
                    b[i][j] = next();
                }
            }
            let w = a.dot_product(&b);
            for j in 0..N {
                assert!((0..=q).contains(&w[j]), "coefficient {j} is {}", w[j]);
            }
        }
    }
}
