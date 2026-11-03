//! The auxiliary functions of FIPS 204, Section 7, on single coefficients and single polynomials:
//! the samplers (7.3), the bit packing and unpacking of one coordinate (7.1) and the rounding and
//! hint functions (7.4). Anything over a whole vector or matrix is the business of the crate that
//! holds vectors.
//!
//! Where a function exists in an in-place or caller-buffer form and a value-returning form, the
//! former is the implementation and the latter wraps it.

use crate::params::{
    GAMMA1_2_POW_17, GAMMA1_2_POW_19, GAMMA2_Q_MINUS_1_OVER_32, GAMMA2_Q_MINUS_1_OVER_88,
    MLDSAParamsBase,
};
use crate::polynomial::Polynomial;
use crate::{G, H, N, POLY_T0PACKED_LEN, POLY_T1PACKED_LEN, d, q};
use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_utils::secret::ZeroizablePrimitive;

/// Algorithm 14 CoeffFromThreeBytes(𝑏0, 𝑏1, 𝑏2)
/// Output: An integer modulo 𝑞, or `None` for ⊥.
pub fn coeff_from_three_bytes(b: &[u8; 3]) -> Option<i32> {
    // This is the exact alg from FIPS 204:
    // let mut b2_prime = b2;
    // if b2_prime > 127 {
    //     // set the top bit of b2_prime to 0
    //     b2_prime = b2_prime - 128;
    // }

    // but this is equivalent and feels more constant-time:
    let b2_prime = b[2] & 0x7F;

    let z: i32 = ((b2_prime as i32) << 16) | ((b[1] as i32) << 8) | (b[0] as i32);

    // mutants note: yeah, this could be z <= q and nothing changes because z == q is the same as z == 0
    if z < q { Some(z) } else { None }
}

/// Algorithm 15 CoeffFromHalfByte(𝑏)
/// Let 𝜂 ∈ {2, 4}. Generates an element of {−𝜂, −𝜂 + 1, … , 𝜂} ∪ {⊥}.
/// Input: Integer 𝑏 ∈ {0, 1, … , 15}.
/// Output: An integer between −𝜂 and 𝜂, or `None` for ⊥.
#[inline(always)]
pub fn coeff_from_half_byte<P: MLDSAParamsBase>(b: u8) -> Option<i32> {
    if P::eta == 2 && b < 15 {
        // '%' is not constant-time, so `b mod 5` is written as a three-way range split. The
        // branch is on which third of 0..=14 `b` falls in; within each third the coefficient
        // 2 - (b mod 5) takes every value in -2..=2 once, so which branch ran is independent of
        // the coefficient it produced. The rejection of b = 15 (and of b > 8 for eta = 4) is the
        // branch every rejection sampler has, as in FIPS 204 Algorithm 15 itself.
        let b = match b {
            b if b < 5 => b,
            b if b < 10 => b - 5,
            _ => b - 10,
        };
        Some(2 - b as i32)
    } else {
        if P::eta == 4 && b < 9 { Some(4 - b as i32) } else { None }
    }
}

/// A specific instantiation of Algorithm 16 SimpleBitPack(𝑤, 𝑏) with the constants set for packing the t1 vector
/// Encodes a polynomial 𝑤 into a byte string.
/// Input: 𝑏 ∈ ℕ and 𝑤 ∈ 𝑅 such that the coefficients of 𝑤 are all in [0, 𝑏].
/// Output: A byte string of length 32 ⋅ bitlen 𝑏.
pub fn simple_bit_pack_t1(w: &Polynomial) -> [u8; POLY_T1PACKED_LEN] {
    let mut output = [0u8; POLY_T1PACKED_LEN];
    for i in 0..N / 4 {
        output[5 * i] = w[4 * i] as u8;
        output[5 * i + 1] = ((w[4 * i] >> 8) | (w[4 * i + 1] << 2)) as u8;
        output[5 * i + 2] = ((w[4 * i + 1] >> 6) | (w[4 * i + 2] << 4)) as u8;
        output[5 * i + 3] = ((w[4 * i + 2] >> 4) | (w[4 * i + 3] << 6)) as u8;
        output[5 * i + 4] = (w[4 * i + 3] >> 2) as u8;
    }
    output
}

/// A variant of Algorithm 17 BitPack specific to a=eta, b=eta
/// Encodes a polynomial 𝑤 into a byte string.
/// Input: 𝑎, 𝑏 ∈ ℕ and 𝑤 ∈ 𝑅 such that the coefficients of 𝑤 are all in \[−eta, eta].
/// Output: A byte string of length 32 ⋅ bitlen (𝑎 + 𝑏).
// `match P::eta` folds away per monomorphization, so 𝜂 = 2 and 𝜂 = 4 each compile to just their
// own arm, leaving no dispatch at runtime.
#[inline(always)]
pub fn bit_pack_eta<P: MLDSAParamsBase>(w: &Polynomial, r: &mut [u8]) {
    // `>=` rather than `==`: a caller may reuse one buffer sized for the largest 𝜂 across all
    // three parameter sets and copy out only the first `POLY_ETA_PACKED_LEN` bytes, so for 𝜂 = 2
    // the buffer is deliberately longer than what gets written. Exactly that many bytes are
    // written out either way, so this still catches an undersized buffer.
    debug_assert!(r.len() >= P::POLY_ETA_PACKED_LEN);

    // temp swap space
    let mut t: [u8; 8] = [0; 8];

    match P::eta {
        // MLDSA44 and MLDSA87
        2 => {
            let eta: i32 = 2;
            for i in 0..N / 8 {
                t[0] = (eta - w[8 * i]) as u8;
                t[1] = (eta - w[8 * i + 1]) as u8;
                t[2] = (eta - w[8 * i + 2]) as u8;
                t[3] = (eta - w[8 * i + 3]) as u8;
                t[4] = (eta - w[8 * i + 4]) as u8;
                t[5] = (eta - w[8 * i + 5]) as u8;
                t[6] = (eta - w[8 * i + 6]) as u8;
                t[7] = (eta - w[8 * i + 7]) as u8;

                r[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
                r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
            }
        }
        // MLDSA65
        4 => {
            let eta: i32 = 4;
            for i in 0..N / 2 {
                t[0] = (eta - w[2 * i]) as u8;
                t[1] = (eta - w[2 * i + 1]) as u8;
                r[i] = t[0] | t[1] << 4;
            }
        }
        _ => panic!("Invalid eta value"),
    }
}

/// A variant of Algorithm 17 BitPack specific to packing the t0 polynomial with a=2^{d-1}-1, b=2^{d-1}
/// Encodes a polynomial 𝑤 into a byte string.
/// Input: 𝑎, 𝑏 ∈ ℕ and 𝑤 ∈ 𝑅 such that the coefficients of 𝑤 are all in \[−𝑎, 𝑏].
/// Output: A byte string of length 32 ⋅ bitlen (𝑎 + 𝑏).
pub fn bit_pack_t0(t0: &Polynomial) -> [u8; POLY_T0PACKED_LEN] {
    let mut r = [0u8; POLY_T0PACKED_LEN];

    let mut t = [0; 8];
    for i in 0..N / 8 {
        t[0] = (1 << (d - 1)) - t0[8 * i];
        t[1] = (1 << (d - 1)) - t0[8 * i + 1];
        t[2] = (1 << (d - 1)) - t0[8 * i + 2];
        t[3] = (1 << (d - 1)) - t0[8 * i + 3];
        t[4] = (1 << (d - 1)) - t0[8 * i + 4];
        t[5] = (1 << (d - 1)) - t0[8 * i + 5];
        t[6] = (1 << (d - 1)) - t0[8 * i + 6];
        t[7] = (1 << (d - 1)) - t0[8 * i + 7];

        r[13 * i] = t[0] as u8;
        r[13 * i + 1] = (t[0] >> 8) as u8;
        r[13 * i + 1] |= (t[1] << 5) as u8;
        r[13 * i + 2] = (t[1] >> 3) as u8;
        r[13 * i + 3] = (t[1] >> 11) as u8;
        r[13 * i + 3] |= (t[2] << 2) as u8;
        r[13 * i + 4] = (t[2] >> 6) as u8;
        r[13 * i + 4] |= (t[3] << 7) as u8;
        r[13 * i + 5] = (t[3] >> 1) as u8;
        r[13 * i + 6] = (t[3] >> 9) as u8;
        r[13 * i + 6] |= (t[4] << 4) as u8;
        r[13 * i + 7] = (t[4] >> 4) as u8;
        r[13 * i + 8] = (t[4] >> 12) as u8;
        r[13 * i + 8] |= (t[5] << 1) as u8;
        r[13 * i + 9] = (t[5] >> 7) as u8;
        r[13 * i + 9] |= (t[6] << 6) as u8;
        r[13 * i + 10] = (t[6] >> 2) as u8;
        r[13 * i + 11] = (t[6] >> 10) as u8;
        r[13 * i + 11] |= (t[7] << 3) as u8;
        r[13 * i + 12] = (t[7] >> 5) as u8;
    }

    r
}

/// A variant of Algorithm 17 specific to packing z in the signature value in \[−𝛾1 + 1, 𝛾1].
///
/// The destination is a slice rather than a `P::PolyZPacked` so that a caller can write straight
/// into its window of a signature buffer, which is chunked at runtime because the chunk size
/// `P::POLY_Z_PACKED_LEN` cannot be a const generic argument. See [`bitpack_gamma1`] for the form
/// that returns the buffer.
pub fn bitpack_gamma1_out<P: MLDSAParamsBase>(z: &Polynomial, out: &mut [u8]) {
    debug_assert_eq!(out.len(), P::POLY_Z_PACKED_LEN);
    out.fill(0);

    let mut t: [u32; 4] = [0; 4];
    // One layout per distinct 𝛾1 rather than one per parameter set; `P::gamma1` is a constant
    // after monomorphization, so only the matching arm survives.
    match P::gamma1 {
        // MLDSA-44
        GAMMA1_2_POW_17 => {
            for i in 0..N / 4 {
                t[0] = (P::gamma1 - z[4 * i]) as u32;
                t[1] = (P::gamma1 - z[4 * i + 1]) as u32;
                t[2] = (P::gamma1 - z[4 * i + 2]) as u32;
                t[3] = (P::gamma1 - z[4 * i + 3]) as u32;

                out[9 * i] = t[0] as u8;
                out[9 * i + 1] = (t[0] >> 8) as u8;
                out[9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
                out[9 * i + 3] = (t[1] >> 6) as u8;
                out[9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
                out[9 * i + 5] = (t[2] >> 4) as u8;
                out[9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
                out[9 * i + 7] = (t[3] >> 2) as u8;
                out[9 * i + 8] = (t[3] >> 10) as u8;
            }
        }
        // MLDSA-65 and -87 have the same GAMMA1 value
        GAMMA1_2_POW_19 => {
            for i in 0..N / 2 {
                t[0] = (P::gamma1 - z[2 * i]) as u32;
                t[1] = (P::gamma1 - z[2 * i + 1]) as u32;

                out[5 * i] = t[0] as u8;
                out[5 * i + 1] = (t[0] >> 8) as u8;
                out[5 * i + 2] = ((t[0] >> 16) | (t[1] << 4)) as u8;
                out[5 * i + 3] = (t[1] >> 4) as u8;
                out[5 * i + 4] = (t[1] >> 12) as u8;
            }
        }
        _ => {
            panic!("Invalid gamma1 value")
        }
    }
}

/// [`bitpack_gamma1_out`] into a fresh `P::PolyZPacked`.
#[must_use]
pub fn bitpack_gamma1<P: MLDSAParamsBase>(z: &Polynomial) -> P::PolyZPacked {
    let mut out = <P::PolyZPacked as ZeroizablePrimitive>::ZEROED;
    bitpack_gamma1_out::<P>(z, out.as_mut());
    out
}

/// A specific instantiation of Algorithm 18 SimpleBitUnpack(v, 𝑏) with the constants set for unpacking the t1 vector
/// Input: 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen 𝑏.
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [0, 2𝑐 − 1], where 𝑐 = bitlen 𝑏.
/// When 𝑏 + 1 is a power of 2, the coefficients are in [0, 𝑏].
pub fn simple_bit_unpack_t1(v: &[u8; POLY_T1PACKED_LEN]) -> Polynomial {
    let mut w = Polynomial::new();

    for i in 0..N / 4 {
        w[4 * i] = ((v[5 * i] as i32) | ((v[5 * i + 1] as i32) << 8)) & 0x3FF;
        w[4 * i + 1] = (((v[5 * i + 1] as i32) >> 2) | ((v[5 * i + 2] as i32) << 6)) & 0x3FF;
        w[4 * i + 2] = (((v[5 * i + 2] as i32) >> 4) | ((v[5 * i + 3] as i32) << 4)) & 0x3FF;
        w[4 * i + 3] = (((v[5 * i + 3] as i32) >> 6) | ((v[5 * i + 4] as i32) << 2)) & 0x3FF;
    }

    w
}

/// A variant of Algorithm 19 BitUnpack specific to a=eta, b=eta, writing into `w`.
/// Input: 𝑎, 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen (𝑎 + 𝑏).
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [𝑏 − 2𝑐 + 1, 𝑏], where 𝑐 = bitlen (𝑎 + 𝑏).
/// When 𝑎 + 𝑏 + 1 is a power of 2, the coefficients are in [−𝑎, 𝑏].
///
/// Note: caller is responsible for ensuring correct input array size. See [`bit_unpack_eta`] for
/// the form that returns the polynomial.
// `match P::eta` folds away per monomorphization, so 𝜂 = 2 and 𝜂 = 4 each compile to just their
// own arm, leaving no dispatch at runtime.
#[inline(always)]
pub fn bit_unpack_eta_out<P: MLDSAParamsBase>(v: &[u8], w: &mut Polynomial) {
    debug_assert_eq!(v.len(), P::POLY_ETA_PACKED_LEN);

    match P::eta {
        // MLDSA44 and MLDSA87
        2 => {
            let eta: i32 = 2;
            for i in 0..N / 8 {
                w[8 * i] = (v[3 * i] & 7) as i32;
                w[8 * i + 1] = ((v[3 * i] >> 3) & 7) as i32;
                w[8 * i + 2] = ((v[3 * i] >> 6) | (v[3 * i + 1] << 2) & 7) as i32;
                w[8 * i + 3] = ((v[3 * i + 1] >> 1) & 7) as i32;
                w[8 * i + 4] = ((v[3 * i + 1] >> 4) & 7) as i32;
                w[8 * i + 5] = ((v[3 * i + 1] >> 7) | (v[3 * i + 2] << 1) & 7) as i32;
                w[8 * i + 6] = ((v[3 * i + 2] >> 2) & 7) as i32;
                w[8 * i + 7] = ((v[3 * i + 2] >> 5) & 7) as i32;

                w[8 * i] = eta - w[8 * i];
                w[8 * i + 1] = eta - w[8 * i + 1];
                w[8 * i + 2] = eta - w[8 * i + 2];
                w[8 * i + 3] = eta - w[8 * i + 3];
                w[8 * i + 4] = eta - w[8 * i + 4];
                w[8 * i + 5] = eta - w[8 * i + 5];
                w[8 * i + 6] = eta - w[8 * i + 6];
                w[8 * i + 7] = eta - w[8 * i + 7];
            }
        }
        // MLDSA65
        4 => {
            let eta: i32 = 4;
            for i in 0..N / 2 {
                w[2 * i] = (v[i] & 0x0F) as i32;
                w[2 * i + 1] = (v[i] >> 4) as i32;

                w[2 * i] = eta - w[2 * i];
                w[2 * i + 1] = eta - w[2 * i + 1];
            }
        }
        _ => panic!("Invalid eta value"),
    }
}

/// [`bit_unpack_eta_out`] into a fresh polynomial.
#[inline(always)]
#[must_use]
pub fn bit_unpack_eta<P: MLDSAParamsBase>(v: &[u8]) -> Polynomial {
    let mut w = Polynomial::new();
    bit_unpack_eta_out::<P>(v, &mut w);
    w
}

/// A variant of Algorithm 19 BitUnpack specific to unpacking the t0 polynomial with a=2^{d-1}-1, b=2^{d-1}
/// Input: 𝑎, 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen (𝑎 + 𝑏).
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [𝑏 − 2𝑐 + 1, 𝑏], where 𝑐 = bitlen (𝑎 + 𝑏).
/// When 𝑎 + 𝑏 + 1 is a power of 2, the coefficients are in [−𝑎, 𝑏].
pub fn bit_unpack_t0(a: &[u8; POLY_T0PACKED_LEN]) -> Polynomial {
    let mut t0 = Polynomial::new();

    for i in 0..N / 8 {
        t0[8 * i] = ((a[13 * i] as i32) | ((a[13 * i + 1] as i32) << 8)) & 0x1FFF;
        t0[8 * i + 1] = ((((a[13 * i + 1] as i32) >> 5) | (a[13 * i + 2] as i32) << 3)
            | ((a[13 * i + 3] as i32) << 11))
            & 0x1FFF;
        t0[8 * i + 2] = (((a[13 * i + 3] as i32) >> 2) | ((a[13 * i + 4] as i32) << 6)) & 0x1FFF;
        t0[8 * i + 3] = ((((a[13 * i + 4] as i32) >> 7) | (a[13 * i + 5] as i32) << 1)
            | ((a[13 * i + 6] as i32) << 9))
            & 0x1FFF;
        t0[8 * i + 4] = ((((a[13 * i + 6] as i32) >> 4) | (a[13 * i + 7] as i32) << 4)
            | ((a[13 * i + 8] as i32) << 12))
            & 0x1FFF;
        t0[8 * i + 5] = (((a[13 * i + 8] as i32) >> 1) | ((a[13 * i + 9] as i32) << 7)) & 0x1FFF;
        t0[8 * i + 6] = ((((a[13 * i + 9] as i32) >> 6) | (a[13 * i + 10] as i32) << 2)
            | ((a[13 * i + 11] as i32) << 10))
            & 0x1FFF;
        t0[8 * i + 7] = (((a[13 * i + 11] as i32) >> 3) | ((a[13 * i + 12] as i32) << 5)) & 0x1FFF;

        t0[8 * i] = (1 << (d - 1)) - t0[8 * i];
        t0[8 * i + 1] = (1 << (d - 1)) - t0[8 * i + 1];
        t0[8 * i + 2] = (1 << (d - 1)) - t0[8 * i + 2];
        t0[8 * i + 3] = (1 << (d - 1)) - t0[8 * i + 3];
        t0[8 * i + 4] = (1 << (d - 1)) - t0[8 * i + 4];
        t0[8 * i + 5] = (1 << (d - 1)) - t0[8 * i + 5];
        t0[8 * i + 6] = (1 << (d - 1)) - t0[8 * i + 6];
        t0[8 * i + 7] = (1 << (d - 1)) - t0[8 * i + 7];
    }

    t0
}

/// A variant of Algorithm 19 BitUnpack specific to a=𝛾1 − 1, b=𝛾1
/// Input: 𝑎, 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen (𝑎 + 𝑏).
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [𝑏 − 2𝑐 + 1, 𝑏], where 𝑐 = bitlen (𝑎 + 𝑏).
/// When 𝑎 + 𝑏 + 1 is a power of 2, the coefficients are in [−𝑎, 𝑏].
///
/// Note: caller is responsible for ensuring correct input array size
// `match P::gamma1` folds away per monomorphization, so each 𝛾1 compiles to just its own arm,
// leaving no dispatch at runtime.
#[inline(always)]
pub fn bit_unpack_gamma1<P: MLDSAParamsBase>(v: &[u8]) -> Polynomial {
    let mut w = Polynomial::new();

    match P::gamma1 {
        // MLDSA-44
        GAMMA1_2_POW_17 => {
            for i in 0..N / 4 {
                w[4 * i] = (((v[9 * i] as i32) | ((v[9 * i + 1] as i32) << 8))
                    | ((v[9 * i + 2] as i32) << 16))
                    & 0x3FFFF;
                w[4 * i + 1] = ((((v[9 * i + 2] as i32) >> 2) | ((v[9 * i + 3] as i32) << 6))
                    | ((v[9 * i + 4] as i32) << 14))
                    & 0x3FFFF;
                w[4 * i + 2] = ((((v[9 * i + 4] as i32) >> 4) | ((v[9 * i + 5] as i32) << 4))
                    | ((v[9 * i + 6] as i32) << 12))
                    & 0x3FFFF;
                w[4 * i + 3] = ((((v[9 * i + 6] as i32) >> 6) | ((v[9 * i + 7] as i32) << 2))
                    | ((v[9 * i + 8] as i32) << 10))
                    & 0x3FFFF;

                w[4 * i] = P::gamma1 - w[4 * i];
                w[4 * i + 1] = P::gamma1 - w[4 * i + 1];
                w[4 * i + 2] = P::gamma1 - w[4 * i + 2];
                w[4 * i + 3] = P::gamma1 - w[4 * i + 3];
            }
        }
        // MLDSA-65 and -87 have the same GAMMA1 value
        GAMMA1_2_POW_19 => {
            for i in 0..N / 2 {
                w[2 * i] = (((v[5 * i] as i32) | ((v[5 * i + 1] as i32) << 8))
                    | ((v[5 * i + 2] as i32) << 16))
                    & 0xFFFFF;
                w[2 * i + 1] = ((((v[5 * i + 2] as i32) >> 4) | ((v[5 * i + 3] as i32) << 4))
                    | ((v[5 * i + 4] as i32) << 12))
                    & 0xFFFFF;

                w[2 * i] = P::gamma1 - w[2 * i];
                w[2 * i + 1] = P::gamma1 - w[2 * i + 1];
            }
        }
        _ => {
            panic!("Invalid gamma1 value")
        }
    };

    w
}

/// Algorithm 29 SampleInBall(𝜌)
/// Samples a polynomial 𝑐 ∈ 𝑅 with coefficients from {−1, 0, 1} and Hamming weight 𝜏 ≤ 64.
/// Input: A seed 𝜌 ∈ 𝔹𝜆/4
/// Output: A polynomial 𝑐 in 𝑅.
pub fn sample_in_ball<P: MLDSAParamsBase>(rho: &P::SigCTilde) -> Polynomial {
    // 1: 𝑐 ← 0
    let mut c = Polynomial::new();

    // 2: ctx ← H.Init()
    // 3: ctx ← H.Absorb(ctx, 𝜌)
    // 4: (ctx, 𝑠) ← H.Squeeze(ctx, 8)
    let mut h = H::new();
    h.do_update(rho.as_ref());
    let mut s = [0u8; 8];
    let mut h = h.into_squeezer();
    h.do_output_out(&mut s);

    // 5: ℎ ← BytesToBits(𝑠)
    //   ▷ ℎ is a bit string of length 64
    let mut signs: u64 = 0;
    for (i, item) in s.iter().enumerate().take(8) {
        signs |= (*item as u64) << (8 * i);
    }

    // 6: for 𝑖 from 256 − 𝜏 to 255 do
    let mut j = [0u8];
    for i in (N - P::tau as usize)..N {
        // 7: (ctx, 𝑗) ← H.Squeeze(ctx, 1)
        // Note: Even though it may appear that pre-squeezing a buffer outside the loop would be faster,
        //       testing it both ways doesn't make a noticeable difference, so this has been left as is
        //       for better correspondence with the FIPS sample algorithm.
        h.do_output_out(&mut j);

        // 8: while 𝑗 > 𝑖 do
        while j[0] as usize > i {
            // ▷ rejection sampling in {0, … , 𝑖}
            // 9: (ctx, 𝑗) ← H.Squeeze(ctx, 1)
            h.do_output_out(&mut j);
        }

        // 11: 𝑐𝑖 ← 𝑐𝑗
        c[i] = c[j[0] as usize];

        // 12: 𝑐𝑗 ← (−1)^ℎ[𝑖+𝜏−256]
        c[j[0] as usize] = (1u64.wrapping_sub(2 * (signs & 1))) as i32;
        signs >>= 1;
    }

    // check post-condition
    // coefficients from {−1, 0, 1} and Hamming weight 𝜏 ≤ 64.
    #[cfg(debug_assertions)]
    {
        let mut hamming_weight: i32 = 0;
        for i in 0..N {
            debug_assert!((-1..=1).contains(&c[i]));
            if c[i] != 0 {
                hamming_weight += 1;
            }
        }
        debug_assert!(hamming_weight > 0);
        debug_assert!(hamming_weight <= 64);
    }

    c
}

/// Algorithm 30 RejNTTPoly(𝜌)
/// This is supposed to take a rho: `[u8; 34]`, which is: 𝜌||IntegerToBytes(𝑠, 1)||IntegerToBytes(𝑟, 1)
/// but to avoid needing to copy bytes and allocate more memory,
/// that is split into a `[u8; 32]` and a `[u8; 2]`
pub fn rej_ntt_poly(rho: &[u8; 32], nonce: &[u8; 2]) -> Polynomial {
    let mut w_hat = Polynomial::new();
    let mut j: usize = 0;
    let mut g = G::new();
    g.do_update(rho);
    g.do_update(nonce);

    // SHAKE is fairly inefficient if only 3 bytes are squeezed at a time, so instead this implementation does a block.
    // Size is not a limitation, so long as it's a multiple of 3.
    // 288 seemed to be the sweet spot found during experimentation and benchmarking.
    // It's probably around the average rejection rate, and 288 is a multiple of both 3 (required for this alg)
    // and 8 (efficient for SHAKE).
    let mut s = [0u8; 288];
    let mut g = g.into_squeezer();
    g.do_output_out(&mut s);
    let mut idx: usize = 0;

    while j < N {
        if idx == s.len() {
            g.do_output_out(&mut s);
            idx = 0;
        }
        w_hat[j] = match coeff_from_three_bytes(&s[idx..idx + 3].try_into().unwrap()) {
            Some(c) => c,
            None => {
                // those three bytes were out of range for a coefficient, so go again with the next three bytes
                // from the SHAKE stream.
                idx += 3;
                continue;
            }
        };
        idx += 3;
        j += 1;
    }

    w_hat
}

/// Algorithm 31 RejBoundedPoly(𝜌)
/// Samples an element 𝑎 ∈ 𝑅 with coefficients in \[−𝜂, 𝜂\] computed via rejection sampling from 𝜌.
/// Input: A seed 𝜌 ∈ 𝔹66 .
/// Output: A polynomial 𝑎 ∈ 𝑅.
///
/// This is supposed to take a rho: `[u8; 66]`, which is: 𝜌||IntegerToBytes(𝑠, 1)||IntegerToBytes(𝑟, 1)
/// but to avoid needing to copy bytes and allocate more memory,
/// that is split into a `[u8; 64]` and a `[u8; 2]`
pub fn rej_bounded_poly<P: MLDSAParamsBase>(rho: &[u8; 64], nonce: &[u8; 2]) -> Polynomial {
    let mut a = Polynomial::new();
    let mut j: usize = 0;
    let mut h = H::new();
    h.do_update(rho);
    h.do_update(nonce);

    // size doesn't really matter
    // 312 seemed to be the sweet spot from playing with benchmarks
    // maybe something to do with the average rejection rate?
    // Also, 312 is a multiple of 8 (efficient for SHAKE)
    let mut z_arr = [0u8; 312];
    let mut h = h.into_squeezer();
    h.do_output_out(&mut z_arr);
    let mut idx: usize = 0;

    while j < N {
        let z0 = coeff_from_half_byte::<P>(z_arr[idx] & 0x0F); // equiv to % 16 (but faster, and more importantly, constant-time)
        let z1 = coeff_from_half_byte::<P>(z_arr[idx] >> 4); // equiv to div_floor(16) (but faster, and more importantly, constant-time)

        if let Some(z0) = z0 {
            a[j] = z0;
            j += 1;
        } /* else: do nothing */
        if j < 256
            && let Some(z1) = z1
        {
            a[j] = z1;
            j += 1;
        } /* else: do nothing */

        idx += 1;
        if idx == z_arr.len() {
            h.do_output_out(&mut z_arr);
            idx = 0;
        }
    }

    a
}

/// One coordinate of Algorithm 34 ExpandMask(𝜌, 𝜇): the polynomial 𝐲\[𝑟] for `nonce` = 𝜇 + 𝑟,
/// with coefficients between −𝛾1 + 1 and 𝛾1.
/// Input: A seed 𝜌 ∈ 𝔹64 and a nonnegative integer 𝜇 + 𝑟.
/// Output: One polynomial of 𝐲 ∈ 𝑅ℓ.
pub fn expand_mask_poly<P: MLDSAParamsBase>(rho: &[u8; 64], nonce: u16) -> Polynomial {
    // 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
    //  ▷ 𝛾1 is always a power of 2
    // 3: 𝜌′ ← 𝜌||IntegerToBytes(𝜇 + 𝑟, 2)
    // 4: 𝑣 ← H(𝜌′, 32𝑐)
    // The 32𝑐 bytes squeezed on line 4 are exactly `P::POLY_Z_PACKED_LEN`, so the buffer for them
    // is `P::PolyZPacked`; see the docs on `MLDSAParamsBase::POLY_Z_PACKED_LEN`.
    let mut h = H::new();
    h.do_update(rho);
    h.do_update(&nonce.to_le_bytes());
    let mut v = <P::PolyZPacked as ZeroizablePrimitive>::ZEROED;
    let mut h = h.into_squeezer();
    h.do_output_out(v.as_mut());

    // 5: 𝐲[𝑟] ← BitUnpack(𝑣, 𝛾1 − 1, 𝛾1)
    bit_unpack_gamma1::<P>(v.as_ref())
}

/// Algorithm 35 Power2Round(𝑟)
/// Decomposes 𝑟 into (𝑟1, 𝑟0) such that 𝑟 ≡ 𝑟1 2^𝑑 + 𝑟0 mod 𝑞.
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integers (𝑟1, 𝑟0).
pub fn power_2_round(r: i32) -> (i32, i32) {
    const u: i32 = (1 << (d - 1)) - 1;
    const v: i32 = -1 << d;

    let t = r + u;
    let r0 = r - (t & v);

    (t >> d, r0)
}

/// Algorithm 36 Decompose(𝑟)
/// Decomposes 𝑟 into (𝑟1, 𝑟0) such that 𝑟 ≡ 𝑟1(2𝛾2) + 𝑟0 mod 𝑞.
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integers (𝑟1, 𝑟0).
// `match P::gamma2` folds away per monomorphization, so each 𝛾2 compiles to just its own arm,
// leaving no dispatch at runtime.
#[inline(always)]
pub fn decompose<P: MLDSAParamsBase>(r: i32) -> (i32, i32) {
    // 1: 𝑟+ ← 𝑟 mod 𝑞
    // 2: 𝑟0 ← 𝑟+ mod±(2𝛾2)
    // 3: if 𝑟+ − 𝑟0 = 𝑞 − 1 then
    // 4:   𝑟1 ← 0
    // 5:   𝑟0 ← 𝑟0 − 1
    // 6: else 𝑟1 ← (𝑟+ − 𝑟0)/(2𝛾2)
    // 7: end if
    // 8: return (𝑟1, 𝑟0)

    // The branch-free decompose() of the reference implementation (pq-crystals/dilithium,
    // ref/rounding.c), followed line for line. r1 is round(r / 2γ2) by a fixed-point multiply, and
    // the value one past the top (44 for γ2 = (q-1)/88, 16 for (q-1)/32, reached only when r+ is
    // within γ2 of q-1) is sent to 0: steps 3-4. r0 = r - r1 * 2γ2 is then moved into (-γ2, γ2] by
    // subtracting q when it exceeds (q-1)/2, which is step 2's mod± and, in the wrapped case where
    // r0 is still r+, the -1 of step 5 (r+ - q = (r+ - (q-1)) - 1).
    let mut r1 = (r + 127) >> 7;

    match P::gamma2 {
        // ML-DSA-44
        GAMMA2_Q_MINUS_1_OVER_88 => {
            r1 = (r1 * 11275 + (1 << 23)) >> 24;
            r1 ^= ((43 - r1) >> 31) & r1;
        }
        // ML-DSA-65 and -87 have the same gamma2
        GAMMA2_Q_MINUS_1_OVER_32 => {
            r1 = (r1 * 1025 + (1 << 21)) >> 22;
            r1 &= 15;
        }
        _ => {
            // this branch should never compile
            unimplemented!()
        }
    }

    let mut r0 = r - r1 * 2 * P::gamma2;

    // mutants note: the choice of (q - 1) is a bit arbitrary in that after doing the bit-shifting,
    //  this seems to work out mathematically equivalent if doing q/2, or (q+3)/2, but here it is left as (q-1)/2
    //  since that's algorithmically correct, and just ignore the mutants results.
    r0 -= (((q - 1) / 2 - r0) >> 31) & q;

    (r1, r0)
}

/// Algorithm 37 HighBits(𝑟)
/// Returns 𝑟1 from the output of Decompose (𝑟).
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integer 𝑟1.
pub fn high_bits<P: MLDSAParamsBase>(r: i32) -> i32 {
    // 1: (𝑟1, 𝑟0) ← Decompose(𝑟)
    // 2: return 𝑟1
    let (r1, _) = decompose::<P>(r);
    r1
}

/// Algorithm 38 LowBits(𝑟)
/// Returns 𝑟0 from the output of Decompose (𝑟).
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integer 𝑟0.
pub fn low_bits<P: MLDSAParamsBase>(r: i32) -> i32 {
    // 1: (𝑟1, 𝑟0) ← Decompose(𝑟)
    // 2: return 𝑟0
    let (_, r0) = decompose::<P>(r);
    r0
}

/// Algorithm 39 MakeHint(𝑧, 𝑟)
/// Computes hint bit indicating whether adding 𝑧 to 𝑟 alters the high bits of 𝑟.
/// Input: 𝑧, 𝑟 ∈ ℤ𝑞.
/// Output: Boolean.
///
/// Takes, in place of Algorithm 39's z and r, the two parts the reference implementation's
/// make_hint(a0, a1) works from (pq-crystals/dilithium, ref/rounding.c): `low` is
/// LowBits(w - cs2) + ct0 as a residue in [0, q), and `high` is HighBits(w). The hint is 1 exactly
/// when adding ct0 carries the low part out of (-γ2, γ2], except that landing on -γ2 itself only
/// changes the high bits when they are nonzero. `low <= γ2 || low > q - γ2` is mod± low in
/// [-γ2 + 1, γ2], and `low == q - γ2` is mod± low == -γ2.
pub fn make_hint<P: MLDSAParamsBase>(low: i32, high: i32) -> i32 {
    // Naïve implementation:
    // // 1: 𝑟1 ← HighBits(𝑟)
    // let r1 = high_bits::<P>(r);
    //
    // // 2: 𝑣1 ← HighBits(𝑟 + 𝑧)
    // let v1 = high_bits::<P>(r + z);
    //
    // // 3: return [[𝑟1 ≠ 𝑣1]]
    // if r1 != v1 { 1 } else { 0 }

    // Branch-free form of `low <= γ2 || low > q - γ2 || (low == q - γ2 && high == 0)`: each
    // comparison is the sign bit of a difference of values in [0, q), so nothing overflows, and
    // the combined mask is all ones exactly when the hint is 0.
    let le = (low - P::gamma2 - 1) >> 31; // low <= γ2
    let gt = (q - P::gamma2 - low) >> 31; // low > q - γ2
    let eq = ((low ^ (q - P::gamma2)) - 1) >> 31; // low == q - γ2
    let high_zero = (high - 1) >> 31; // high == 0
    (le | gt | (eq & high_zero)) + 1
}

/// Algorithm 40 UseHint(ℎ, 𝑟)
/// Returns the high bits of 𝑟 adjusted according to hint ℎ.
/// Input: Boolean ℎ, 𝑟 ∈ ℤ𝑞.
/// Output: 𝑟1 ∈ ℤ with 0 ≤ 𝑟1 ≤ (𝑞−1) / 2*gamma2).
pub fn use_hint<P: MLDSAParamsBase>(r: i32, hint: i32) -> i32 {
    // 1: 𝑚 ← (𝑞 − 1)/(2𝛾2)
    //   m is 44 for γ2 = (q-1)/88 and 16 for (q-1)/32; the "mod m" below is the wrap at the ends,
    //   or `& 15` when m is 16.
    // 2: (𝑟1, 𝑟0) ← Decompose(𝑟)
    let (r1, r0) = decompose::<P>(r);

    // 5: return 𝑟1
    if hint == 0 {
        return r1;
    }

    debug_assert!(hint == 1);

    // 3: if ℎ = 1 and 𝑟0 > 0 return (𝑟1 + 1) mod 𝑚
    // 4: if ℎ = 1 and 𝑟0 ≤ 0 return (𝑟1 − 1) mod 𝑚
    match P::gamma2 {
        // ML-DSA-44
        GAMMA2_Q_MINUS_1_OVER_88 => {
            // mutants note: this passes unit tests if it's r0 >= 0
            //      it is left like this because it matches the spec
            if r0 > 0 {
                if r1 == 43 { 0 } else { r1 + 1 }
            } else if r1 == 0 {
                43
            } else {
                r1 - 1
            }
        }
        // ML-DSA-65 and -87 have the same gamma2
        GAMMA2_Q_MINUS_1_OVER_32 => {
            // mutants note: this passes unit tests if it's r0 >= 0
            //      it is left like this because it matches the spec
            if r0 > 0 { (r1 + 1) & 15 } else { (r1 - 1) & 15 }
        }
        _ => {
            panic!("Invalid GAMMA2 value")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // FIPS 204 describes the output as easy to check:
    // Decomposes 𝑟 into (𝑟1, 𝑟0) such that 𝑟 ≡ 𝑟1 2^𝑑 + 𝑟0 mod 𝑞.
    fn test_power_2_round() {
        test(1);
        test(q - 3);
        test(q);
        test(q + 3);

        fn test(r: i32) {
            let (r1, r0) = power_2_round(r);
            let mut res = ((r1 << d) + r0) % q;
            if res < 0 {
                res += q;
            }
            assert_eq!(r % q, res);
        }
    }
}
