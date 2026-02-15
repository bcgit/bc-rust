//! Implements auxiliary functions for ML-DSA as defined in Section 7 of FIPS 204.

use crate::matrix::{Matrix, Vector, VectorK, VectorL};
use crate::mldsa::{G, H};
use crate::polynomial::Polynomial;
use crate::{MLDSAParams, MldsaSize, Q, polynomial, D, N, POLY_T1PACKED_LEN};
use bouncycastle_core_interface::traits::XOF;

/// Algorithm 14 CoeffFromThreeBytes(𝑏0, 𝑏1, 𝑏2)
/// Output: An integer modulo 𝑞 or ⊥.
pub(crate) fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Result<i32, ()> {
    let mut b2_prime = b2;
    if b2_prime > 127 {
        // set the top bit of b2_prime to 0
        b2_prime = b2_prime - 128;

        // todo: possibly this whole if-block could be optimized (and constant-timed) by doing instead:
        // todo: b2_prime = b2 & 0x7F
        // todo: ?
        // todo: do that after I have unit tests and stuff to check that it's functionally equivalent
    }

    let z: i32 = ((b2_prime as i32) << 16) | ((b1 as i32) << 8) | (b0 as i32);

    if z < Q { Ok(z) } else { Err(()) }
}

/// Algorithm 15 CoeffFromHalfByte(𝑏)
/// Let 𝜂 ∈ {2, 4}. Generates an element of {−𝜂, −𝜂 + 1, … , 𝜂} ∪ {⊥}.
/// Input: Integer 𝑏 ∈ {0, 1, … , 15}.
/// Output: An integer between −𝜂 and 𝜂, or ⊥.
pub(crate) fn coeff_from_half_byte<PARAMS: MLDSAParams>(b: u8) -> Result<i32, ()> {
    if PARAMS::ETA == 2 && b < 15 {
        Ok(2 - (b % 5) as i32)
    }
    // todo: do some research if this cast from u8 to i32 is constant-time (it should be, but you never know). Otherwise: 0i32 | (2 - (b % 5))
    else {
        if PARAMS::ETA == 4 && b < 9 { Ok(4 - b as i32) } // todo: is constant-time?
        else { Err(()) }
    }
}

/// A specific instantiation of Algorithm 16 SimpleBitPack(𝑤, 𝑏) with the constants set for packing the t1 vector
///  Encodes a polynomial 𝑤 into a byte string.
/// Input: 𝑏 ∈ ℕ and 𝑤 ∈ 𝑅 such that the coefficients of 𝑤 are all in [0, 𝑏].
/// Output: A byte string of length 32 ⋅ bitlen 𝑏.
pub(crate) fn simple_bit_pack_t1<PARAMS: MLDSAParams>(w: &Polynomial<PARAMS>) -> [u8; POLY_T1PACKED_LEN] {
    let mut output = [0u8; POLY_T1PACKED_LEN];
    for i in 0..N/4 {
        output[5 * i] = w.coeffs[4 * i] as u8;
        output[5 * i + 1] = ((w.coeffs[4 * i] >> 8) | (w.coeffs[4 * i + 1] << 2)) as u8;
        output[5 * i + 2] =
            ((w.coeffs[4 * i + 1] >> 6) | (w.coeffs[4 * i + 2] << 4)) as u8;
        output[5 * i + 3] =
            ((w.coeffs[4 * i + 2] >> 4) | (w.coeffs[4 * i + 3] << 6)) as u8;
        output[5 * i + 4] = (w.coeffs[4 * i + 3] >> 2) as u8;
    }
    output
}

/// Algorithm 30 RejNTTPoly(𝜌)
/// This is supposed to take a rho: [u8; 34], which is: 𝜌||IntegerToBytes(𝑠, 1)||IntegerToBytes(𝑟, 1)
/// but to avoid needing to copy bytes and allocate more memory,
/// we'll split that into a [u8;32] and a [u8;2]
pub(crate) fn rej_ntt_poly<PARAMS: MLDSAParams>(
    rho: &[u8; 32],
    nonce: &[u8; 2],
) -> Polynomial<PARAMS> {
    let mut a = Polynomial::<PARAMS>::new();
    let mut j: usize = 0;
    let mut g = G::new();
    g.absorb(rho);
    g.absorb(nonce);

    while j < 256 {
        // note: this only works because the global param N (which is the length of Polynomial) is 256.
        let mut s = [0u8; 3];
        g.squeeze_out(&mut s);
        a.coeffs[j] = match coeff_from_three_bytes(s[0], s[1], s[2]) {
            Ok(c) => {
                j += 1;
                c
            }
            Err(_) => continue,
        }
    }

    a
}

/// Algorithm 31 RejBoundedPoly(𝜌)
/// Samples an element 𝑎 ∈ 𝑅 with coefficients in \[−𝜂, 𝜂\] computed via rejection sampling from 𝜌.
/// Input: A seed 𝜌 ∈ 𝔹66 .
/// Output: A polynomial 𝑎 ∈ 𝑅.
///
/// This is supposed to take a rho: [u8; 66], which is: 𝜌||IntegerToBytes(𝑠, 1)||IntegerToBytes(𝑟, 1)
/// but to avoid needing to copy bytes and allocate more memory,
/// we'll split that into a [u8;64] and a [u8;2]
pub(crate) fn rej_bounded_poly<PARAMS: MLDSAParams>(
    rho: &[u8; 64],
    nonce: &[u8; 2],
) -> Polynomial<PARAMS> {
    let mut a = Polynomial::<PARAMS>::new();
    let mut j: usize = 0;
    let mut h = H::new();
    h.absorb(&rho[..32]);
    h.absorb(nonce);

    while j < 256 {
        // note: this only works because the global param N (which is the length of Polynomial) is 256.
        let mut z_arr: [u8; 1] = [0u8];
        h.squeeze_out(&mut z_arr);

        let z0 = coeff_from_half_byte::<PARAMS>(z_arr[0] % 16); // todo: is this constant-time?
        let z1 = coeff_from_half_byte::<PARAMS>(z_arr[0].div_floor(16)); // todo: .div_floor() is currently an unstable feature,
        // todo: umm, aren't these equivalent to & 0x0F and >> 4 ?

        if z0.is_ok() {
            a.coeffs[j] = z0.unwrap();
            j += 1;
        } /* else: do nothing */
        if z1.is_ok() && j < 256 {
            a.coeffs[j] = z1.unwrap();
            j += 1;
        } /* else: do nothing */
    }

    a
}

/// Algorithm 32 ExpandA(𝜌)
/// Samples a 𝑘 × ℓ matrix 𝐀̂ of elements of 𝑇𝑞.
/// Input: A seed 𝜌 ∈ B^64.
/// Output: Vectors 𝐬1, 𝐬2 of polynomials in 𝑅.
pub(crate) fn expand_a<PARAMS: MLDSAParams>(rho: &[u8; 32]) -> Matrix<PARAMS> {
    #[allow(non_snake_case)]
    let mut A = Matrix::<PARAMS>::new();

    for r in 0..PARAMS::k {
        for s in 0..PARAMS::l {
            A.matrix[r][s] = rej_ntt_poly(rho, &[r as u8, s as u8]);
        }
    }

    A
}

/// Algorithm 33 ExpandS(𝜌)
/// Samples vectors 𝐬1 ∈ 𝑅ℓ and 𝐬2 ∈ 𝑅𝑘 , each with polynomial coordinates whose coefficients are
/// in the interval \[−𝜂, 𝜂].
/// Input: A seed 𝜌 ∈ 𝔹64 .
/// Output: Vectors 𝐬1, 𝐬2 of polynomials in 𝑅
pub(crate) fn expand_s<PARAMS: MLDSAParams>(
    rho: &[u8; 64],
) -> (VectorL<PARAMS>, VectorK<PARAMS>)
where
    VectorL<PARAMS>: Sized, VectorK<PARAMS>: Sized,
{
    let mut s1 = VectorL::<PARAMS>::new();
    let mut s2 = VectorK::<PARAMS>::new();

    for r in 0..PARAMS::l {
        s1.vec[r] = rej_bounded_poly::<PARAMS>(rho, &(r as u16).to_le_bytes());
    }

    for r in 0..PARAMS::k {
        s2.vec[r] = rej_bounded_poly(rho, &(r as u16 + PARAMS::l as u16).to_le_bytes());
    }

    (s1, s2)
}

/// Implements the meta-function described in FIPS 204 section 7.4 for applying power_2_round to a vector.
/// ((𝐫1\[𝑖])𝑗, (𝐫0\[𝑖])𝑗) = Power2Round((𝐫\[𝑖])𝑗).
pub(crate) fn power_2_round_vec<PARAMS: MLDSAParams, const LEN: usize>(
    v: &Vector<PARAMS, LEN>
) -> (Vector<PARAMS, LEN>, Vector<PARAMS, LEN>) {
    let mut r1 = Vector::<PARAMS, LEN>::new();
    let mut r0 = Vector::<PARAMS, LEN>::new();

    for i in 0 .. LEN {
        for j in 0 .. N {
            (r1.vec[i].coeffs[j], r0.vec[i].coeffs[j]) = power_2_round(v.vec[i].coeffs[j]);
        }
    }

    (r1, r0)
}

/// Algorithm 35 Power2Round(𝑟)
/// Decomposes 𝑟 into (𝑟1, 𝑟0) such that 𝑟 ≡ 𝑟1 2^𝑑 + 𝑟0 mod 𝑞.
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integers (𝑟1, 𝑟0).
// todo it would be nice to unit test this, but I don't know where I'd get test vectors from.
pub(crate) fn power_2_round(a: i32) -> (i32, i32) {
    let r0: i32 = (a + (1 << (D - 1)) - 1) >> D;
    let r1: i32 = a - (r0 << D);

    (r1, r0)
}

/// Constants for NTT
const ZETAS: [i32; 256] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];


/// I think there is an omission in FIPS 204 in that Algorithm 41 NTT is defined for a single polynomial,
/// but then is called with vectors of polynomials or matrices of polynomials with some hand-wany wording
/// in section 2.5 about doing the NTT "entry-wise".
///
/// Anyway, this fills in the missing overloaded version of NTT to act on a vector.
pub(crate) fn ntt_vec<PARAMS: MLDSAParams>(
    s: &VectorL<PARAMS>,
) -> VectorL<PARAMS> {
    let mut s_hat = VectorL::<PARAMS>::new();

    for i in 0..PARAMS::l {
        s_hat.vec[i] = ntt(s.vec[i]);
    }

    s_hat
}

/// I think there is an omission in FIPS 204 in that Algorithm 41 NTT is defined for a single polynomial,
/// but then is called with vectors of polynomials or matrices of polynomials with some hand-wany wording
/// in section 2.5 about doing the NTT "entry-wise".
///
/// Anyway, this fills in the missing overloads of NTT to act on a matrix.
/// TODO: this one might not be used?
#[allow(non_snake_case)]
pub(crate) fn ntt_matrix<PARAMS: MLDSAParams>(
    A: &Matrix<PARAMS>,
) -> Matrix<PARAMS> {
    #[allow(non_snake_case)]
    let mut A_hat = Matrix::<PARAMS>::new();

    for i in 0..PARAMS::k {
        for j in 0..PARAMS:l {
            A_hat.matrix[i][j] = ntt(A.matrix[i][j]);
        }
    }

    A_hat
}

/// Algorithm 41 NTT(𝑤)
/// Computes the NTT.
/// Input: Polynomial 𝑤(𝑋)
/// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞.
/// Output: 𝑤_hat = (𝑤_hat\[0], ..., 𝑤_hat\[255]) ∈ 𝑇𝑞.
///
/// Note: by convention, variables holding the output of the NTT function should be named "_hat"
/// to indicate that they are in the NTT domain (sometimes called the frequency domain), not the natural domain.
/// I considered using the rust type system to enforce this, but it seemed like overkill, cause that's what
/// NIST test vectors are for.
///
/// Design choice: don't do the NTT in-place, but copy data to a new array.
/// This uses slightly more memory and requires a copy, but makes the code easier to read
/// and less likely to contain a bug. But this optimization could be considered in the future.
pub(crate) fn ntt<PARAMS: MLDSAParams>(w: Polynomial<PARAMS>) -> Polynomial<PARAMS> {
    let mut w_hat = w.clone();

    let mut m: usize = 0;
    let mut len: usize = 128;

    while len >= 1 {
        let mut start: usize = 0;
        while start < 256 {
            // equiv. to the global constant N
            m += 1;
            let z: i32 = ZETAS[m];

            // j = start;
            // while j < start + len {
            for j in start..start + len {
                let t = polynomial::montgomery_reduce(z as i64 * w_hat.coeffs[j + len] as i64);
                w_hat.coeffs[j + len] = w_hat.coeffs[j] - t;
                w_hat.coeffs[j] += t;
                // j += 1;
            }
            start = start + 2 * len; // could be optimized to save the multiply-by-two since j finishes as `start + len`. That said 2* is just << 1, which is basically free.
        }
        len >>= 1;
    }

    w_hat
}


/// I think there is an omission in FIPS 204 in that Algorithm 41 NTT is defined for a single polynomial,
/// but then is called with vectors of polynomials or matrices of polynomials with some hand-wany wording
/// in section 2.5 about doing the NTT "entry-wise".
///
/// Anyway, this fills in the missing overloaded version of NTT to act on a vector.
pub(crate) fn inv_ntt_vec<PARAMS: MLDSAParams>(
    s_hat: &VectorK<PARAMS>,
) -> VectorK<PARAMS> {
    let mut s = VectorK::<PARAMS>::new();

    for i in 0..PARAMS::k {
        s.vec[i] = inv_ntt(s_hat.vec[i]);
    }

    s
}

/// I think there is an omission in FIPS 204 in that Algorithm 41 NTT is defined for a single polynomial,
/// but then is called with vectors of polynomials or matrices of polynomials with some hand-wany wording
/// in section 2.5 about doing the NTT "entry-wise".
///
/// Anyway, this fills in the missing overloads of NTT to act on a matrix.
/// TODO: this one might not be used?
#[allow(non_snake_case)]
pub(crate) fn inv_ntt_matrix<PARAMS: MLDSAParams>(
    A_hat: &Matrix<PARAMS>,
) -> Matrix<PARAMS> {
    #[allow(non_snake_case)]
    let mut A = Matrix::<PARAMS>::new();

    for i in 0..PARAMS::k {
        for j in 0..PARAMS:l {
            A.matrix[i][j] = inv_ntt(A_hat.matrix[i][j]);
        }
    }

    A
}

/// Algorithm 42 NTT−1(𝑤)̂
/// Computes the inverse of the NTT.
/// Input: ̂̂ ̂ 𝑤 = (𝑤\[0], … , 𝑤\[255]) ∈ 𝑇𝑞.
/// Output: Polynomial 𝑤(𝑋) = ∑255
/// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞
pub(crate) fn inv_ntt<PARAMS: MLDSAParams>(w_hat: Polynomial<PARAMS>) -> Polynomial<PARAMS> {
    let mut w = w_hat.clone();

    let mut m: usize = 256;
    let mut len: usize = 1;

    while len < 256 {
        // equiv. to the global constant N
        let mut start: usize = 0;
        while start < 256 {
            // equiv. to the global constant N
            m -= 1;
            let z = -ZETAS[m];

            // j = start;
            // while j < start + len {
            for j in start..start + len {
                // 𝑡 ← 𝑤𝑗
                let t: i32 = w_hat.coeffs[j];

                // 𝑤𝑗 ← (𝑡 + 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                // Note: the original bc-rust implementation had this line as:
                //   a[j] = t + a[j + len];
                // is there a mathematical reason that this can't overflow beyond Q and therefore doesn't need the reduction?
                // Worth testing once we have unit tests as that would be a small performance increase to skip the montgomery reduction.
                w.coeffs[j] = polynomial::montgomery_reduce(t as i64 + w.coeffs[j + len] as i64);

                // 𝑤𝑗+𝑙𝑒𝑛 ← (𝑡 − 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                // Same as above, original bc-rust impl had:
                //  a[j + len] = t - a[j + len];
                // with no reduction.
                w.coeffs[j + len] =
                    polynomial::montgomery_reduce(t as i64 - w.coeffs[j + len] as i64);

                // 𝑤𝑗+𝑙𝑒𝑛 ← (𝑧 ⋅ 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                w.coeffs[j + len] =
                    polynomial::montgomery_reduce(z as i64 * w.coeffs[j + len] as i64);
            }
            start = start + 2 * len; // could be optimized to save the multiply-by-two since j finishes as `start + len`. That said 2* is just << 1, which is basically free.
        }
        len <<= 1;
    }

    // f = 256^-1 mod q
    let f: i64 = 8347681;
    for j in 0usize..256 {
        // equiv. to the global constant N
        w.coeffs[j] = polynomial::montgomery_reduce(f * w.coeffs[j] as i64);
    }

    w
}
