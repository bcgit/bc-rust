//! These are somewhat unnecessary wrappers around simple arrays, but they are helpful to me in clearly
//! keeping the types and sizes obvious.

use crate::aux_functions::multiply_ntt;
use crate::mldsa::H;
use crate::params::MLDSAParams;
use crate::polynomial::Polynomial;
use bouncycastle_core::traits::Hash;
use bouncycastle_utils::secret::ZeroizablePrimitive;
use core::ops::{Index, IndexMut};

/// The operations this crate performs on the public matrix 𝐀̂.
///
/// [`Matrix`] is the only implementation; see the module docs for why the trait exists.
pub(crate) trait MatrixTrait: Sized + Clone {
    /// The vector this matrix can be applied to: an element of 𝑅^ℓ.
    type VecL: VectorTrait;
    /// The vector applying this matrix produces: an element of 𝑅^𝑘.
    type VecK: VectorTrait;

    /// A matrix with every coefficient set to zero.
    fn new() -> Self;

    /// Overwrites the polynomial at `elems[row][col]`.
    fn set_elem(&mut self, row: usize, col: usize, p: Polynomial);

    /// Algorithm 48 MatrixVectorNTT(𝐌, 𝐯)
    /// Computes the product 𝐌 ∘̂ 𝐯_hat of a matrix 𝐌_hat and a vector 𝐯_hat over 𝑇𝑞.
    fn matrix_vector_ntt(&self, v: &Self::VecL) -> Self::VecK;
}

/// A matrix over the ML-DSA ring.
#[derive(Clone)]
pub struct Matrix<const k: usize, const l: usize> {
    /// Indexed `elems[row][col]`
    pub(crate) elems: [[Polynomial; l]; k],
}

impl<const k: usize, const l: usize> Matrix<k, l> {
    pub(crate) fn new() -> Self {
        Self { elems: [[(); l]; k].map(|_| [(); l].map(|_| Polynomial::new())) }
    }

    /// Algorithm 48 MatrixVectorNTT(𝐌, 𝐯)
    /// Computes the product 𝐌 ∘̂ 𝐯_hat of a matrix 𝐌_hat and a vector 𝐯_hat over 𝑇𝑞.
    /// Input: 𝑘, ℓ ∈ ℕ, 𝐌 ∈ 𝑇𝑞
    /// 𝑘×ℓ ̂ 𝑞 .
    /// Performs dot product multiplication of this matrix by a vector
    /// Input: vector of length l
    /// Output: vector of length k
    pub(crate) fn matrix_vector_ntt(&self, v: &Vector<l>) -> Vector<k> {
        let mut w = Vector::<k>::new();
        for i in 0..k {
            // split out the 0 case to skip a no-op add_ntt()
            w[i].coeffs.copy_from_slice(&multiply_ntt(&self.elems[i][0], &v[0]).coeffs);

            let mut w1: Polynomial;
            for j in 1..l {
                // dot product a vector into a matrix: multiply the input vector
                // into each row of the matrix, then sum the results to produce a vector of
                // length k.
                w1 = multiply_ntt(&self.elems[i][j], &v[j]);
                w[i].add_ntt(&w1);
            }
        }

        w
    }
}

impl<const k: usize, const l: usize> MatrixTrait for Matrix<k, l> {
    type VecL = Vector<l>;
    type VecK = Vector<k>;

    fn new() -> Self {
        Matrix::new()
    }

    fn set_elem(&mut self, row: usize, col: usize, p: Polynomial) {
        self.elems[row][col] = p;
    }

    fn matrix_vector_ntt(&self, v: &Vector<l>) -> Vector<k> {
        Matrix::matrix_vector_ntt(self, v)
    }
}

/// The operations this crate performs on a vector of polynomials, i.e. on an element of 𝑅^LEN.
///
/// [`Vector`] is the only implementation; the trait exists so that code generic over a parameter
/// set can operate on [`MLDSAParams::VecK`] and [`MLDSAParams::VecL`] without knowing their length.
pub trait VectorTrait:
    Sized + Copy + ZeroizablePrimitive + Index<usize, Output = Polynomial> + IndexMut<usize>
{
    /// The number of polynomial coordinates, i.e. 𝑘 or ℓ.
    const LEN: usize;

    /// A vector with every coefficient set to zero.
    fn new() -> Self;

    /// The coordinates, for iteration and chunking.
    fn elems(&self) -> &[Polynomial];
    /// The coordinates, for iteration and chunking.
    fn elems_mut(&mut self) -> &mut [Polynomial];

    /// Algorithm 46 AddVectorNTT(𝐯, 𝐰)̂
    /// Computes the sum 𝐯_hat + 𝐰_hat of two vectors 𝐯_hat, 𝐰_hat over 𝑇𝑞.
    fn add_vector_ntt(&mut self, s: &Self);

    /// Subtracts another vector from this one, coordinatewise.
    fn sub_vector(&self, s: &Self) -> Self;

    /// Algorithm 47 ScalarVectorNTT(𝑐,̂ 𝐯)̂
    /// Computes the product 𝑐_hat * 𝐯_hat of a scalar 𝑐_hat and a vector 𝐯_hat over 𝑇𝑞.
    fn scalar_vector_ntt(&self, w: &Polynomial) -> Self;

    /// Adds 𝑞 to every negative coefficient.
    fn conditional_add_q(&mut self);

    /// Montgomery-reduces every coefficient.
    fn reduce(&mut self);

    /// Applies Algorithm 41 NTT(𝑤) to every coordinate.
    fn ntt(&mut self);

    /// Applies Algorithm 42 NTT−1(𝑤_hat) to every coordinate.
    fn inv_ntt(&mut self);

    /// Applies Algorithm 37 HighBits(𝑟) coefficientwise.
    fn high_bits<P: MLDSAParams>(&self) -> Self;

    /// Applies Algorithm 38 LowBits(𝑟) coefficientwise.
    fn low_bits<P: MLDSAParams>(&self) -> Self;

    /// Multiplies every coefficient by 2^𝑑.
    fn shift_left_d(&self) -> Self;

    /// Tests whether any coefficient of any coordinate has absolute value at least `bound`.
    /// See `Polynomial::check_norm` for why `bound` is not a const generic.
    fn check_norm(&self, bound: i32) -> bool;

    /// Algorithm 28 w1Encode(𝐰1), fed straight into `h` rather than into a buffer.
    fn w1_encode_and_hash<P: MLDSAParams>(&self, h: &mut H);
}

/// A vector of `LEN` polynomials, i.e. an element of 𝑅^LEN.
///
/// Public only because it is the value of [`MLDSAParams::VecK`] and [`MLDSAParams::VecL`]; its
/// fields and operations are crate-private, so from outside it is an opaque handle. Reach it
/// through [`VectorTrait`].
#[derive(Clone, Copy)]
pub struct Vector<const LEN: usize> {
    pub(crate) elems: [Polynomial; LEN],
}

/// Convenience function to avoid ".0" all over the place.
impl<const LEN: usize> Index<usize> for Vector<LEN> {
    type Output = Polynomial;

    fn index(&self, index: usize) -> &Self::Output {
        &self.elems[index]
    }
}
/// Convenience function to avoid ".0" all over the place.
impl<const LEN: usize> IndexMut<usize> for Vector<LEN> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.elems[index]
    }
}

impl<const LEN: usize> ZeroizablePrimitive for Vector<LEN> {
    const ZEROED: Self = Self::new();
}

impl<const LEN: usize> Vector<LEN> {
    pub(crate) const fn new() -> Self {
        Self { elems: [Polynomial::new(); LEN] }
    }
}

impl<const LEN: usize> VectorTrait for Vector<LEN> {
    const LEN: usize = LEN;

    fn new() -> Self {
        Vector::new()
    }

    fn elems(&self) -> &[Polynomial] {
        &self.elems
    }

    fn elems_mut(&mut self) -> &mut [Polynomial] {
        &mut self.elems
    }

    /// Algorithm 46 AddVectorNTT(𝐯, 𝐰)̂
    /// Computes the sum 𝐯_hat + 𝐰_hat of two vectors 𝐯_hat, 𝐰_hat over 𝑇𝑞.
    /// Input: ℓ ∈ ℕ, v_hat ∈ T^ℓ, w_hat ∈ 𝑇^ℓ
    /// Output: u_hat ∈ T^ℓ_𝑞.
    /// Add another vector to this vector
    fn add_vector_ntt(&mut self, s: &Self) {
        for i in 0..LEN {
            // perform montgomery addition of each polynomial in the vector
            self[i].add_ntt(&s[i]);
        }
    }

    fn sub_vector(&self, s: &Self) -> Self {
        let mut out = *self;
        for i in 0..LEN {
            out[i].sub(&s[i]);
        }
        out
    }

    /// Algorithm 47 ScalarVectorNTT(𝑐,̂ 𝐯)̂
    /// Computes the product 𝑐_hat * 𝐯_hat of a scalar 𝑐_hat and a vector 𝐯_hat over 𝑇𝑞.
    /// Input: 𝑐_hat ∈ 𝑇𝑞, ℓ ∈ ℕ, 𝐯_hat ∈ 𝑇^ℓ
    /// Output: 𝑞 .
    fn scalar_vector_ntt(&self, w: &Polynomial) -> Self {
        let mut s_hat = Vector::<LEN>::new();
        for i in 0..LEN {
            s_hat[i] = multiply_ntt(&self[i], &w);
        }

        s_hat
    }

    fn conditional_add_q(&mut self) {
        for i in 0..LEN {
            self[i].conditional_add_q();
        }
    }

    fn reduce(&mut self) {
        for i in 0..LEN {
            self[i].reduce();
        }
    }

    fn ntt(&mut self) {
        for i in 0..LEN {
            self[i].ntt();
        }
    }

    fn inv_ntt(&mut self) {
        for i in 0..LEN {
            self[i].inv_ntt();
        }
    }

    fn high_bits<P: MLDSAParams>(&self) -> Self {
        let mut s = Vector::<LEN>::new();

        for i in 0..LEN {
            s[i] = self[i].high_bits::<P>();
        }

        s
    }

    fn low_bits<P: MLDSAParams>(&self) -> Self {
        let mut s = Vector::<LEN>::new();

        for i in 0..LEN {
            s[i] = self[i].low_bits::<P>();
        }

        s
    }

    fn shift_left_d(&self) -> Self {
        let mut out = *self;
        for i in 0..LEN {
            out[i].shift_left_d();
        }

        out
    }

    fn check_norm(&self, bound: i32) -> bool {
        // Fine that this is not constant-time because it is used in a rejection loop -- the early quit leads to rejection.
        for x in self.elems.iter() {
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
    /// Optimized from FIPS 204 to feed into the hash one row at a time to reduce overall memory footprint.
    fn w1_encode_and_hash<P: MLDSAParams>(&self, h: &mut H) {
        // 1: 𝐰̃1 ← ()
        // Nothing needs to be allocated since it is being fed into the hash row-wise

        // 2: for 𝑖 from 0 to 𝑘 − 1 do
        // 3:   𝐰̃1 ← 𝐰̃1 || SimpleBitPack (𝐰1[𝑖], (𝑞 − 1)/(2𝛾2) − 1)
        // 4: end for
        for w in self.elems.iter() {
            h.do_update(w.w1_encode::<P>().as_ref());
        }
    }
}
