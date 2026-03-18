//! Implements auxiliary functions for ML-DSA as defined in Section 7 of FIPS 204.

use crate::matrix::{Matrix, Vector};
use crate::mldsa::{G, H};
use crate::mldsa::{
    MLDSA44_GAMMA1, MLDSA44_GAMMA2, MLDSA65_GAMMA1, MLDSA65_GAMMA2, N, POLY_T0PACKED_LEN,
    POLY_T1PACKED_LEN, d, q,
};
use crate::polynomial;
use crate::polynomial::Polynomial;
use bouncycastle_core_interface::traits::XOF;

/// Algorithm 14 CoeffFromThreeBytes(𝑏0, 𝑏1, 𝑏2)
/// Output: An integer modulo 𝑞 or ⊥.
// pub(crate) fn coeff_from_three_bytes(b0: u8, b1: u8, b2: u8) -> Result<i32, ()> {
pub(crate) fn coeff_from_three_bytes(b: &[u8; 3]) -> Result<i32, ()> {
    // This is the exact alg from FIPS 204:
    // let mut b2_prime = b2;
    // if b2_prime > 127 {
    //     // set the top bit of b2_prime to 0
    //     b2_prime = b2_prime - 128;
    // }

    // but this is equivalent and feels more constant-time:
    let b2_prime = b[2] & 0x7F;

    let z: i32 = ((b2_prime as i32) << 16) | ((b[1] as i32) << 8) | (b[0] as i32);

    if z < q { Ok(z) } else { Err(()) }
}

/// Algorithm 15 CoeffFromHalfByte(𝑏)
/// Let 𝜂 ∈ {2, 4}. Generates an element of {−𝜂, −𝜂 + 1, … , 𝜂} ∪ {⊥}.
/// Input: Integer 𝑏 ∈ {0, 1, … , 15}.
/// Output: An integer between −𝜂 and 𝜂, or ⊥.
#[inline(always)]
pub(crate) fn coeff_from_half_byte<const ETA: usize>(b: u8) -> Result<i32, ()> {
    if ETA == 2 && b < 15 {
        // Original code is bad because '%' is not constant-time.
        // Ok(2 - (b % 5) as i32)
        // I'm still not convinced this is constant-time, but maybe it's closer? And I can't come up with anything better.
        let b = match b {
            b if b < 5 => b,
            b if b < 10 => b - 5,
            _ => b - 10,
        };
        Ok(2 - b as i32)
    } else {
        if ETA == 4 && b < 9 { Ok(4 - b as i32) } else { Err(()) }
    }
}

/// A specific instantiation of Algorithm 16 SimpleBitPack(𝑤, 𝑏) with the constants set for packing the t1 vector
///  Encodes a polynomial 𝑤 into a byte string.
/// Input: 𝑏 ∈ ℕ and 𝑤 ∈ 𝑅 such that the coefficients of 𝑤 are all in [0, 𝑏].
/// Output: A byte string of length 32 ⋅ bitlen 𝑏.
pub(crate) fn simple_bit_pack_t1(w: &Polynomial) -> [u8; POLY_T1PACKED_LEN] {
    let mut output = [0u8; POLY_T1PACKED_LEN];
    for i in 0..N / 4 {
        output[5 * i] = w.0[4 * i] as u8;
        output[5 * i + 1] = ((w.0[4 * i] >> 8) | (w.0[4 * i + 1] << 2)) as u8;
        output[5 * i + 2] = ((w.0[4 * i + 1] >> 6) | (w.0[4 * i + 2] << 4)) as u8;
        output[5 * i + 3] = ((w.0[4 * i + 2] >> 4) | (w.0[4 * i + 3] << 6)) as u8;
        output[5 * i + 4] = (w.0[4 * i + 3] >> 2) as u8;
    }
    output
}

/// As defined in Algorithm 17, this gives the length of a packed bitstring representing a polynomial
/// whose coefficients have been rounded to \[-eta, eta], which is 32*bitlen(2*eta).
pub const fn bitlen_eta(eta: usize) -> usize {
    match eta {
        2 => 32 * 3,
        4 => 32 * 4,
        _ => panic!("Invalid eta value"),
    }
}

/// A variant of Algorithm 17 BitPack specific to a=eta, b=eta
/// Encodes a polynomial 𝑤 into a byte string.
/// Input: 𝑎, 𝑏 ∈ ℕ and 𝑤 ∈ 𝑅 such that the coefficients of 𝑤 are all in \[−eta, eta].
/// Output: A byte string of length 32 ⋅ bitlen (𝑎 + 𝑏).

// the hope here is that the compiler will aggressively inline this function,
// and optimize away the branching.
#[inline(always)]
pub(crate) fn bit_pack_eta<const ETA: usize>(w: &Polynomial, r: &mut [u8]) {
    debug_assert!(r.len() >= bitlen_eta(ETA));
    // let mut r: [u8; bitlen_eta(ETA)] = [0; bitlen_eta(ETA)];

    // temp swap space
    let mut t: [u8; 8] = [0; 8];

    match ETA {
        // MLDSA44 and MLDSA87
        2 => {
            let eta: i32 = 2;
            for i in 0..N / 8 {
                t[0] = (eta - w.0[8 * i]) as u8;
                t[1] = (eta - w.0[8 * i + 1]) as u8;
                t[2] = (eta - w.0[8 * i + 2]) as u8;
                t[3] = (eta - w.0[8 * i + 3]) as u8;
                t[4] = (eta - w.0[8 * i + 4]) as u8;
                t[5] = (eta - w.0[8 * i + 5]) as u8;
                t[6] = (eta - w.0[8 * i + 6]) as u8;
                t[7] = (eta - w.0[8 * i + 7]) as u8;

                r[3 * i] = t[0] | (t[1] << 3) | (t[2] << 6);
                r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
                r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
            }
        }
        // MLDSA65
        4 => {
            let eta: i32 = 4;
            for i in 0..N / 2 {
                t[0] = (eta - w.0[2 * i]) as u8;
                t[1] = (eta - w.0[2 * i + 1]) as u8;
                r[i] = t[0] | t[1] << 4;
            }
        }
        _ => panic!("Invalid eta value"),
    }

    // r
}

/// A variant of Algorithm 17 BitPack specific to packing the t0 polynomial with a=2^{d-1}-1, b=2^{d-1}
/// Encodes a polynomial 𝑤 into a byte string.
/// Input: 𝑎, 𝑏 ∈ ℕ and 𝑤 ∈ 𝑅 such that the coefficients of 𝑤 are all in \[−eta, eta].
/// Output: A byte string of length 32 ⋅ bitlen (𝑎 + 𝑏).
pub(crate) fn bit_pack_t0(t0: &Polynomial) -> [u8; POLY_T0PACKED_LEN] {
    let mut r = [0u8; POLY_T0PACKED_LEN];

    let mut t = [0; 8];
    for i in 0..N / 8 {
        t[0] = (1 << (d - 1)) - t0.0[8 * i];
        t[1] = (1 << (d - 1)) - t0.0[8 * i + 1];
        t[2] = (1 << (d - 1)) - t0.0[8 * i + 2];
        t[3] = (1 << (d - 1)) - t0.0[8 * i + 3];
        t[4] = (1 << (d - 1)) - t0.0[8 * i + 4];
        t[5] = (1 << (d - 1)) - t0.0[8 * i + 5];
        t[6] = (1 << (d - 1)) - t0.0[8 * i + 6];
        t[7] = (1 << (d - 1)) - t0.0[8 * i + 7];

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
pub(crate) fn bitpack_gamma1<const POLY_Z_PACKED_LEN: usize, const GAMMA1: i32>(
    z: &Polynomial,
) -> [u8; POLY_Z_PACKED_LEN] {
    let mut r = [0u8; POLY_Z_PACKED_LEN];

    let mut t: [u32; 4] = [0; 4];
    match GAMMA1 {
        MLDSA44_GAMMA1 => {
            for i in 0..N / 4 {
                t[0] = (GAMMA1 - z.0[4 * i]) as u32;
                t[1] = (GAMMA1 - z.0[4 * i + 1]) as u32;
                t[2] = (GAMMA1 - z.0[4 * i + 2]) as u32;
                t[3] = (GAMMA1 - z.0[4 * i + 3]) as u32;

                r[9 * i] = t[0] as u8;
                r[9 * i + 1] = (t[0] >> 8) as u8;
                r[9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)) as u8;
                r[9 * i + 3] = (t[1] >> 6) as u8;
                r[9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)) as u8;
                r[9 * i + 5] = (t[2] >> 4) as u8;
                r[9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)) as u8;
                r[9 * i + 7] = (t[3] >> 2) as u8;
                r[9 * i + 8] = (t[3] >> 10) as u8;
            }
        }
        // MLDSA-65 and 87 have the same GAMMA1 value
        MLDSA65_GAMMA1 => {
            for i in 0..N / 2 {
                t[0] = (GAMMA1 - z.0[2 * i]) as u32;
                t[1] = (GAMMA1 - z.0[2 * i + 1]) as u32;

                r[5 * i] = t[0] as u8;
                r[5 * i + 1] = (t[0] >> 8) as u8;
                r[5 * i + 2] = ((t[0] >> 16) | (t[1] << 4)) as u8;
                r[5 * i + 3] = (t[1] >> 4) as u8;
                r[5 * i + 4] = (t[1] >> 12) as u8;
            }
        }
        _ => {
            panic!("Invalid gamma1 value")
        }
    }

    r
}

/// A specific instantiation of Algorithm 18 SimpleBitUnpack(v, 𝑏) with the constants set for unpacking the t1 vector
/// Input: 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen 𝑏.
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [0, 2𝑐 − 1], where 𝑐 = bitlen 𝑏.
/// When 𝑏 + 1 is a power of 2, the coefficients are in [0, 𝑏].
///
/// Note: caller is responsible for ensuring correct input array size
pub(crate) fn simple_bit_unpack_t1(v: &[u8; POLY_T1PACKED_LEN]) -> Polynomial {
    // debug_assert_eq!(v.len(), POLY_T1PACKED_LEN);

    let mut w = Polynomial::new();

    for i in 0..N / 4 {
        w.0[4 * i] = ((v[5 * i] as i32) | ((v[5 * i + 1] as i32) << 8)) & 0x3FF;
        w.0[4 * i + 1] = (((v[5 * i + 1] as i32) >> 2) | ((v[5 * i + 2] as i32) << 6)) & 0x3FF;
        w.0[4 * i + 2] = (((v[5 * i + 2] as i32) >> 4) | ((v[5 * i + 3] as i32) << 4)) & 0x3FF;
        w.0[4 * i + 3] = (((v[5 * i + 3] as i32) >> 6) | ((v[5 * i + 4] as i32) << 2)) & 0x3FF;
    }

    w
}

/// A variant of Algorithm 19 BitUnpack specific to a=eta, b=eta
/// Input: 𝑎, 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen (𝑎 + 𝑏).
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [𝑏 − 2𝑐 + 1, 𝑏], where 𝑐 = bitlen (𝑎 + 𝑏).
/// When 𝑎 + 𝑏 + 1 is a power of 2, the coefficients are in [−𝑎, 𝑏].
///
/// Note: caller is responsible for ensuring correct input array size

// the hope here is that the compiler will aggressively inline this function,
// and optimize away the branching.
#[inline(always)]
pub(crate) fn bit_unpack_eta<const ETA: usize>(v: &[u8]) -> Polynomial {
    debug_assert_eq!(v.len(), bitlen_eta(ETA));

    let mut w = Polynomial::new();

    match ETA {
        // MLDSA44 and MLDSA87
        2 => {
            let eta: i32 = 2;
            for i in 0..N / 8 {
                w.0[8 * i] = (v[3 * i] & 7) as i32;
                w.0[8 * i + 1] = ((v[3 * i] >> 3) & 7) as i32;
                w.0[8 * i + 2] = ((v[3 * i] >> 6) | (v[3 * i + 1] << 2) & 7) as i32;
                w.0[8 * i + 3] = ((v[3 * i + 1] >> 1) & 7) as i32;
                w.0[8 * i + 4] = ((v[3 * i + 1] >> 4) & 7) as i32;
                w.0[8 * i + 5] = ((v[3 * i + 1] >> 7) | (v[3 * i + 2] << 1) & 7) as i32;
                w.0[8 * i + 6] = ((v[3 * i + 2] >> 2) & 7) as i32;
                w.0[8 * i + 7] = ((v[3 * i + 2] >> 5) & 7) as i32;

                w.0[8 * i] = eta - w.0[8 * i];
                w.0[8 * i + 1] = eta - w.0[8 * i + 1];
                w.0[8 * i + 2] = eta - w.0[8 * i + 2];
                w.0[8 * i + 3] = eta - w.0[8 * i + 3];
                w.0[8 * i + 4] = eta - w.0[8 * i + 4];
                w.0[8 * i + 5] = eta - w.0[8 * i + 5];
                w.0[8 * i + 6] = eta - w.0[8 * i + 6];
                w.0[8 * i + 7] = eta - w.0[8 * i + 7];
            }
        }
        // MLDSA65
        4 => {
            let eta: i32 = 4;
            for i in 0..N / 2 {
                w.0[2 * i] = (v[i] & 0x0F) as i32;
                w.0[2 * i + 1] = (v[i] >> 4) as i32;

                w.0[2 * i] = eta - w.0[2 * i];
                w.0[2 * i + 1] = eta - w.0[2 * i + 1];
            }
        }
        _ => panic!("Invalid eta value"),
    }

    w
}

/// A variant of Algorithm 19 BitUnpack specific to unpacking the t0 polynomial with a=2^{d-1}-1, b=2^{d-1}
/// Input: 𝑎, 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen (𝑎 + 𝑏).
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [𝑏 − 2𝑐 + 1, 𝑏], where 𝑐 = bitlen (𝑎 + 𝑏).
/// When 𝑎 + 𝑏 + 1 is a power of 2, the coefficients are in [−𝑎, 𝑏].
pub(crate) fn bit_unpack_t0(a: &[u8; POLY_T0PACKED_LEN]) -> Polynomial {
    let mut t0 = Polynomial::new();

    for i in 0..N / 8 {
        t0.0[8 * i] = ((a[13 * i] as i32) | ((a[13 * i + 1] as i32) << 8)) & 0x1FFF;
        t0.0[8 * i + 1] = ((((a[13 * i + 1] as i32) >> 5) | (a[13 * i + 2] as i32) << 3)
            | ((a[13 * i + 3] as i32) << 11))
            & 0x1FFF;
        t0.0[8 * i + 2] = (((a[13 * i + 3] as i32) >> 2) | ((a[13 * i + 4] as i32) << 6)) & 0x1FFF;
        t0.0[8 * i + 3] = ((((a[13 * i + 4] as i32) >> 7) | (a[13 * i + 5] as i32) << 1)
            | ((a[13 * i + 6] as i32) << 9))
            & 0x1FFF;
        t0.0[8 * i + 4] = ((((a[13 * i + 6] as i32) >> 4) | (a[13 * i + 7] as i32) << 4)
            | ((a[13 * i + 8] as i32) << 12))
            & 0x1FFF;
        t0.0[8 * i + 5] = (((a[13 * i + 8] as i32) >> 1) | ((a[13 * i + 9] as i32) << 7)) & 0x1FFF;
        t0.0[8 * i + 6] = ((((a[13 * i + 9] as i32) >> 6) | (a[13 * i + 10] as i32) << 2)
            | ((a[13 * i + 11] as i32) << 10))
            & 0x1FFF;
        t0.0[8 * i + 7] =
            (((a[13 * i + 11] as i32) >> 3) | ((a[13 * i + 12] as i32) << 5)) & 0x1FFF;

        t0.0[8 * i] = (1 << (d - 1)) - t0.0[8 * i];
        t0.0[8 * i + 1] = (1 << (d - 1)) - t0.0[8 * i + 1];
        t0.0[8 * i + 2] = (1 << (d - 1)) - t0.0[8 * i + 2];
        t0.0[8 * i + 3] = (1 << (d - 1)) - t0.0[8 * i + 3];
        t0.0[8 * i + 4] = (1 << (d - 1)) - t0.0[8 * i + 4];
        t0.0[8 * i + 5] = (1 << (d - 1)) - t0.0[8 * i + 5];
        t0.0[8 * i + 6] = (1 << (d - 1)) - t0.0[8 * i + 6];
        t0.0[8 * i + 7] = (1 << (d - 1)) - t0.0[8 * i + 7];
    }

    t0
}

/// A variant of Algorithm 19 BitUnpack specific to a=𝛾1 − 1, b=𝛾1
/// Input: 𝑎, 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen (𝑎 + 𝑏).
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [𝑏 − 2𝑐 + 1, 𝑏], where 𝑐 = bitlen (𝑎 + 𝑏).
/// When 𝑎 + 𝑏 + 1 is a power of 2, the coefficients are in [−𝑎, 𝑏].
///
/// Note: caller is responsible for ensuring correct input array size

// the hope here is that the compiler will aggressively inline this function,
// and optimize away the branching.
#[inline(always)]
pub(crate) fn bit_unpack_gamma1<const GAMMA1: i32>(v: &[u8]) -> Polynomial {
    let mut w = Polynomial::new();

    match GAMMA1 {
        MLDSA44_GAMMA1 => {
            // const gamma1: i32 = 1<<17;
            for i in 0..N / 4 {
                w.0[4 * i] = (((v[9 * i] as i32) | ((v[9 * i + 1] as i32) << 8))
                    | ((v[9 * i + 2] as i32) << 16))
                    & 0x3FFFF;
                w.0[4 * i + 1] = ((((v[9 * i + 2] as i32) >> 2) | ((v[9 * i + 3] as i32) << 6))
                    | ((v[9 * i + 4] as i32) << 14))
                    & 0x3FFFF;
                w.0[4 * i + 2] = ((((v[9 * i + 4] as i32) >> 4) | ((v[9 * i + 5] as i32) << 4))
                    | ((v[9 * i + 6] as i32) << 12))
                    & 0x3FFFF;
                w.0[4 * i + 3] = ((((v[9 * i + 6] as i32) >> 6) | ((v[9 * i + 7] as i32) << 2))
                    | ((v[9 * i + 8] as i32) << 10))
                    & 0x3FFFF;

                w.0[4 * i] = GAMMA1 - w.0[4 * i];
                w.0[4 * i + 1] = GAMMA1 - w.0[4 * i + 1];
                w.0[4 * i + 2] = GAMMA1 - w.0[4 * i + 2];
                w.0[4 * i + 3] = GAMMA1 - w.0[4 * i + 3];
            }
        }
        // MLDSA-65 and 87 have the same GAMMA1 value
        MLDSA65_GAMMA1 => {
            // const gamma1: i32 = 1<<19;
            for i in 0..N / 2 {
                w.0[2 * i] = (((v[5 * i] as i32) | ((v[5 * i + 1] as i32) << 8))
                    | ((v[5 * i + 2] as i32) << 16))
                    & 0xFFFFF;
                w.0[2 * i + 1] = ((((v[5 * i + 2] as i32) >> 4) | ((v[5 * i + 3] as i32) << 4))
                    | ((v[5 * i + 4] as i32) << 12))
                    & 0xFFFFF;

                w.0[2 * i] = GAMMA1 - w.0[2 * i];
                w.0[2 * i + 1] = GAMMA1 - w.0[2 * i + 1];
            }
        }
        _ => {
            panic!("Invalid gamma1 value")
        }
    };

    w
}

/// Algorithm 26 sigEncode(̃𝑐_tilde, 𝐳, 𝐡)
/// Encodes a signature into a byte string.
/// Input: 𝑐_tilde ∈ 𝔹𝜆/4, 𝐳 ∈ 𝑅ℓ with coefficients in [−𝛾1 + 1, 𝛾1], 𝐡 ∈ 𝑅𝑘
/// Output: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
///
/// Returns the number of bytes written to the output buffer.
pub(crate) fn sig_encode<
    const GAMMA1: i32,
    const k: usize,
    const l: usize,
    const LAMBDA_over_4: usize,
    const OMEGA: i32,
    const POLY_Z_PACKED_LEN: usize,
    const SIG_LEN: usize,
>(
    c_tilde: &[u8; LAMBDA_over_4],
    z: &Vector<l>,
    h: &Vector<k>,
    output: &mut [u8; SIG_LEN],
) -> usize {
    let mut pos = 0;

    output[..LAMBDA_over_4].copy_from_slice(c_tilde);
    pos += LAMBDA_over_4;

    for i in 0..l {
        output[pos..pos + POLY_Z_PACKED_LEN]
            .copy_from_slice(&bitpack_gamma1::<POLY_Z_PACKED_LEN, GAMMA1>(&z.vec[i]));
        pos += POLY_Z_PACKED_LEN;
    }

    // This inlines Algorithm 20 HintBitPack(𝐡)

    let mut m: usize = 0;
    for i in 0..k {
        for j in 0..N {
            if h.vec[i].0[j] != 0 {
                output[pos + m] = j as u8;
                m += 1;
            }
            output[pos + OMEGA as usize + i] = m as u8;
        }
    }

    SIG_LEN
}

/// Algorithm 27 sigDecode(𝜎)
/// Reverses the procedure sigEncode.
/// Input: Signature 𝜎 ∈ 𝔹𝜆/4+ℓ⋅32⋅(1+bitlen (𝛾1−1))+𝜔+𝑘.
/// Output: 𝑐 ∈ 𝔹𝜆/4, 𝐳 ∈ 𝑅ℓ with coefficients in \[−𝛾1 + 1, 𝛾1], 𝐡 ∈ 𝑅𝑘, or ⊥.
///   Output: (c_tilde, z, h)
pub(crate) fn sig_decode<
    const GAMMA1: i32,
    const k: usize,
    const l: usize,
    const LAMBDA_over_4: usize,
    const OMEGA: i32,
    const POLY_Z_PACKED_LEN: usize,
    const SIG_LEN: usize,
>(
    sig: &[u8; SIG_LEN],
) -> Result<([u8; LAMBDA_over_4], Vector<l>, Vector<k>), ()> {
    let mut c_tilde = [0u8; LAMBDA_over_4];
    let mut z: Vector<l> = Vector::<l>::new();
    let mut h: Vector<k> = Vector::<k>::new();

    let mut pos: usize = 0;

    // todo -- compare against nursery impl (mldsa::sign_verify) to see if I can
    // todo -- import some optimization

    c_tilde.copy_from_slice(&sig[..LAMBDA_over_4]);
    pos += LAMBDA_over_4;

    for i in 0..l {
        z.vec[i] = bit_unpack_gamma1::<GAMMA1>(&sig[pos..pos + POLY_Z_PACKED_LEN]);
        pos += POLY_Z_PACKED_LEN;
    }

    // This inlines Algorithm 21 HintBitUnpack(𝑦)

    // 2: Index ← 0
    //  ▷ Index for reading the first 𝜔 bytes of 𝑦
    let mut idx = 0usize;

    // 3: for 𝑖 from 0 to 𝑘 − 1 do
    //  ▷ reconstruct 𝐡[𝑖]
    for i in 0..k {
        // 4: if 𝑦[𝜔 + 𝑖] < Index or 𝑦[𝜔 + 𝑖] > 𝜔 then return ⊥
        if sig[pos + (OMEGA as usize) + i] < (idx as u8)
            || sig[pos + (OMEGA as usize) + i] > OMEGA as u8
        {
            return Err(());
        }

        // 6: First ← Index
        // 7: while Index < 𝑦[𝜔 + 𝑖] do
        //   ▷ 𝑦[𝜔 + 𝑖] says how far one can advance Index
        for j in idx..sig[pos + OMEGA as usize + i] as usize {
            // 8: if Index > First then
            // 9:   if 𝑦[Index − 1] ≥ 𝑦[Index] then return ⊥
            //       ▷ malformed input
            if j > idx && sig[pos + j - 1] >= sig[pos + j] {
                return Err(());
            }
            // 12: 𝐡[𝑖]_𝑦[Index] ← 1
            h.vec[i].0[sig[pos + j] as usize] = 1;

            // 13: Index ← Index + 1
            //  > done by for loop
        }

        idx = sig[pos + OMEGA as usize + i] as usize;
    }

    // ▷ read any leftover bytes in the first 𝜔 bytes of 𝑦 for malformed (nonzero) bytes
    for j in idx..OMEGA as usize {
        if sig[pos + j] != 0 {
            return Err(());
        }
    }

    Ok((c_tilde, z, h))
}

/// Algorithm 29 SampleInBall(𝜌)
/// Samples a polynomial 𝑐 ∈ 𝑅 with coefficients from {−1, 0, 1} and Hamming weight 𝜏 ≤ 64.
/// Input: A seed 𝜌 ∈ 𝔹𝜆/4
/// Output: A polynomial 𝑐 in 𝑅.
pub(crate) fn sample_in_ball<const LAMBDA_over_4: usize, const TAU: i32>(
    rho: &[u8; LAMBDA_over_4],
) -> Polynomial {
    // 1: 𝑐 ← 0
    let mut c = Polynomial::new();

    // 2: ctx ← H.Init()
    // 3: ctx ← H.Absorb(ctx, 𝜌)
    // 4: (ctx, 𝑠) ← H.Squeeze(ctx, 8)
    let mut h = H::new();
    h.absorb(rho);
    let mut s = [0u8; 8];
    h.squeeze_out(&mut s);

    // 5: ℎ ← BytesToBits(𝑠)
    //   ▷ ℎ is a bit string of length 64
    let mut signs: u64 = 0;
    for (i, item) in s.iter().enumerate().take(8) {
        signs |= (*item as u64) << (8 * i);
    }

    // 6: for 𝑖 from 256 − 𝜏 to 255 do

    // let mut pos = 8;
    // let mut b;
    let mut j = [0u8];
    for i in (N - TAU as usize)..N {
        // 7: (ctx, 𝑗) ← H.Squeeze(ctx, 1)
        // Note: you would think that this would be faster to pre-squeeze a buffer outside the loop, but in testing it
        //       doesn't make a difference.
        h.squeeze_out(&mut j);

        // 8: while 𝑗 > 𝑖 do
        while j[0] as usize > i {
            // ▷ rejection sampling in {0, … , 𝑖}
            // 9: (ctx, 𝑗) ← H.Squeeze(ctx, 1)
            h.squeeze_out(&mut j);
        }

        // 11: 𝑐𝑖 ← 𝑐𝑗
        c.0[i] = c.0[j[0] as usize];

        // 12: 𝑐𝑗 ← (−1)^ℎ[𝑖+𝜏−256]
        c.0[j[0] as usize] = (1u64.wrapping_sub(2 * (signs & 1))) as i32;
        signs >>= 1;
    }

    // check post-condition
    // coefficients from {−1, 0, 1} and Hamming weight 𝜏 ≤ 64.
    #[cfg(debug_assertions)]
    {
        let mut hamming_weight: i32 = 0;
        for i in 0..N {
            debug_assert!((-1..=1).contains(&c.0[i]));
            if c.0[i] != 0 {
                hamming_weight += 1;
            }
        }
        debug_assert!(hamming_weight > 0);
        debug_assert!(hamming_weight <= 64);
    }

    c
}

/// Algorithm 30 RejNTTPoly(𝜌)
/// This is supposed to take a rho: [u8; 34], which is: 𝜌||IntegerToBytes(𝑠, 1)||IntegerToBytes(𝑟, 1)
/// but to avoid needing to copy bytes and allocate more memory,
/// we'll split that into a [u8;32] and a [u8;2]
pub(crate) fn rej_ntt_poly(rho: &[u8; 32], nonce: &[u8; 2]) -> Polynomial {
    let mut w_hat = Polynomial::new();
    let mut j: usize = 0;
    let mut g = G::new();
    g.absorb(rho);
    g.absorb(nonce);

    // size doesn't really matter, so long as it's a multiple of 3.
    // 288 seemed to be the sweet spot from playing with benchmarks
    // It's probably around the average rejection rate, and 288 is a multiple of both 3 (required for this alg)
    // and 8 (efficient for SHAKE).
    let mut s = [0u8; 288];
    g.squeeze_out(&mut s);
    let mut idx: usize = 0;

    while j < N {
        if idx == s.len() {
            g.squeeze_out(&mut s);
            idx = 0;
        }
        w_hat.0[j] = match coeff_from_three_bytes(&s[idx..idx + 3].try_into().unwrap()) {
            Ok(c) => c,
            Err(_) => {
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
/// This is supposed to take a rho: [u8; 66], which is: 𝜌||IntegerToBytes(𝑠, 1)||IntegerToBytes(𝑟, 1)
/// but to avoid needing to copy bytes and allocate more memory,
/// we'll split that into a [u8;64] and a [u8;2]
pub(crate) fn rej_bounded_poly<const ETA: usize>(rho: &[u8; 64], nonce: &[u8; 2]) -> Polynomial {
    let mut a = Polynomial::new();
    let mut j: usize = 0;
    let mut h = H::new();
    h.absorb(rho);
    h.absorb(nonce);

    // size doesn't really matter
    // 312 seemed to be the sweet spot from playing with benchmarks
    // maybe something to do with the average rejection rate?
    // Also, 312 is a multiple of 8 (efficient for SHAKE)
    let mut z_arr = [0u8; 312];
    h.squeeze_out(&mut z_arr);
    let mut idx: usize = 0;

    while j < N {
        let z0 = coeff_from_half_byte::<ETA>(z_arr[idx] & 0x0F); // equiv to % 16 (but faster, and more importantly, constant-time)
        let z1 = coeff_from_half_byte::<ETA>(z_arr[idx] >> 4); // equiv to div_floor(16) (but faster, and more importantly, constant-time)

        if z0.is_ok() {
            a.0[j] = z0.unwrap();
            j += 1;
        } /* else: do nothing */
        if z1.is_ok() && j < 256 {
            a.0[j] = z1.unwrap();
            j += 1;
        } /* else: do nothing */

        idx += 1;
        if idx == z_arr.len() {
            h.squeeze_out(&mut z_arr);
            idx = 0;
        }
    }

    a
}

/// Algorithm 32 ExpandA(𝜌)
/// Samples a 𝑘 × ℓ matrix 𝐀̂ of elements of 𝑇𝑞.
/// in other words: derives the public matrix from the public seed.
/// Input: A seed 𝜌 ∈ 𝔹32 .̂
/// Output: Matrix Â ∈ (𝑇𝑞)𝑘×ℓ .
pub(crate) fn expandA<const k: usize, const l: usize>(rho: &[u8; 32]) -> Matrix<k, l> {
    let mut A_hat = Matrix::<k, l>::new();

    for r in 0..k {
        for s in 0..l {
            A_hat.matrix[r][s] = rej_ntt_poly(rho, &[s as u8, r as u8]);
        }
    }

    A_hat
}

/// Algorithm 33 ExpandS(𝜌)
/// Samples vectors 𝐬1 ∈ 𝑅ℓ and 𝐬2 ∈ 𝑅𝑘 , each with polynomial coordinates whose coefficients are
/// in the interval \[−𝜂, 𝜂].
/// Input: A seed 𝜌 ∈ 𝔹64 .
/// Output: Vectors 𝐬1, 𝐬2 of polynomials in 𝑅
pub(crate) fn expandS<const k: usize, const l: usize, const ETA: usize>(
    rho: &[u8; 64],
) -> (Vector<l>, Vector<k>) {
    let mut s1 = Vector::<l>::new();
    let mut s2 = Vector::<k>::new();

    for r in 0..l {
        s1.vec[r] = rej_bounded_poly::<ETA>(rho, &(r as u16).to_le_bytes());
    }

    for r in 0..k {
        s2.vec[r] = rej_bounded_poly::<ETA>(rho, &(r as u16 + l as u16).to_le_bytes());
    }

    (s1, s2)
}

/// Implements the meta-function described in FIPS 204 section 7.4 for applying power_2_round to a vector.
/// ((𝐫1\[𝑖])𝑗, (𝐫0\[𝑖])𝑗) = Power2Round((𝐫\[𝑖])𝑗).
pub(crate) fn power_2_round_vec<const LEN: usize>(v: &Vector<LEN>) -> (Vector<LEN>, Vector<LEN>) {
    let mut r1 = Vector::<LEN>::new();
    let mut r0 = Vector::<LEN>::new();

    for i in 0..LEN {
        for j in 0..N {
            (r1.vec[i].0[j], r0.vec[i].0[j]) = power_2_round(v.vec[i].0[j]);
        }
    }

    (r1, r0)
}

/// Algorithm 34 ExpandMask(𝜌, 𝜇)
/// Samples a vector 𝐲 ∈ 𝑅ℓ such that each polynomial 𝐲[𝑟] has coefficients between −𝛾1 + 1 and 𝛾1.
/// Input: A seed 𝜌 ∈ 𝔹64 and a nonnegative integer 𝜇.
/// Output: Vector 𝐲 ∈ 𝑅ℓ .
pub(crate) fn expand_mask<const l: usize, const GAMMA1: i32, const GAMMA1_MASK_LEN: usize>(
    rho: &[u8; 64],
    mu: u16,
) -> Vector<l> {
    let mut y = Vector::<l>::new();

    // 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
    //  ▷ 𝛾1 is always a power of 2
    // 32c = GAMMA1_MASK_LEN;

    for r in 0..l {
        // 3: 𝜌′ ← 𝜌||IntegerToBytes(𝜇 + 𝑟, 2)
        // 4: 𝑣 ← H(𝜌′, 32𝑐)
        let mut h = H::new();
        h.absorb(rho);
        h.absorb(&(mu + (r as u16)).to_le_bytes());
        let mut v = [0u8; GAMMA1_MASK_LEN];
        h.squeeze_out(&mut v);

        // 5: 𝐲[𝑟] ← BitUnpack(𝑣, 𝛾1 − 1, 𝛾1)
        y.vec[r] = bit_unpack_gamma1::<GAMMA1>(&v);
    }

    y
}

/// Algorithm 35 Power2Round(𝑟)
/// Decomposes 𝑟 into (𝑟1, 𝑟0) such that 𝑟 ≡ 𝑟1 2^𝑑 + 𝑟0 mod 𝑞.
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integers (𝑟1, 𝑟0).
pub(crate) fn power_2_round(r: i32) -> (i32, i32) {
    const u: i32 = (1 << (d - 1)) - 1;
    const v: i32 = -1 << d;

    let t = r + u;
    let r0 = r - (t & v);

    (t >> d, r0)
}

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

/// Algorithm 36 Decompose(𝑟)
/// Decomposes 𝑟 into (𝑟1, 𝑟0) such that 𝑟 ≡ 𝑟1(2𝛾2) + 𝑟0 mod 𝑞.
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integers (𝑟1, 𝑟0).
// the hope here is that the compiler will aggressively inline this function,
// and optimize away the branching.
#[inline(always)]
pub(crate) fn decompose<const GAMMA2: i32>(r: i32) -> (i32, i32) {
    // 1: 𝑟+ ← 𝑟 mod 𝑞
    // 2: 𝑟0 ← 𝑟+ mod±(2𝛾2)
    // 3: if 𝑟+ − 𝑟0 = 𝑞 − 1 then
    // 4:   𝑟1 ← 0
    // 5:   𝑟0 ← 𝑟0 − 1
    // 6: else 𝑟1 ← (𝑟+ − 𝑟0)/(2𝛾2)
    // 7: end if
    // 8: return (𝑟1, 𝑟0)

    // By the powers of someone much more clever than me, this is equivalent.

    let mut r1: i32;
    let mut r0 = (r + 127) >> 7;

    match GAMMA2 {
        MLDSA44_GAMMA2 => {
            // (q - 1) / 88
            r0 = (r0 * 11275 + (1 << 23)) >> 24;
            r0 ^= ((43 - r0) >> 31) & r0;
        }
        // ML-DSA65 and 87 have the same GAMMA2
        MLDSA65_GAMMA2 => {
            // (q - 1) / 32;
            r0 = (r0 * 1025 + (1 << 21)) >> 22;
            r0 &= 15;
        }
        _ => {
            // this branch should never compile
            unimplemented!()
        }
    }

    let g = GAMMA2;
    r1 = r - r0 * 2 * GAMMA2;
    r1 -= (((q - 1) / 2 - r1) >> 31) & q;

    (r0, r1)
}

/// Algorithm 37 HighBits(𝑟)
/// Returns 𝑟1 from the output of Decompose (𝑟).
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integer 𝑟1.
pub(crate) fn high_bits<const GAMMA2: i32>(r: i32) -> i32 {
    // 1: (𝑟1, 𝑟0) ← Decompose(𝑟)
    // 2: return 𝑟1
    let (r1, _) = decompose::<GAMMA2>(r);
    r1
}

/// Algorithm 38 LowBits(𝑟)
/// Returns 𝑟0 from the output of Decompose (𝑟).
/// Input: 𝑟 ∈ ℤ𝑞.
/// Output: Integer 𝑟0.
pub(crate) fn low_bits<const GAMMA2: i32>(r: i32) -> i32 {
    // 1: (𝑟1, 𝑟0) ← Decompose(𝑟)
    // 2: return 𝑟0
    let (_, r0) = decompose::<GAMMA2>(r);
    r0
}

/// Algorithm 39 MakeHint(𝑧, 𝑟)
/// Computes hint bit indicating whether adding 𝑧 to 𝑟 alters the high bits of 𝑟.
/// Input: 𝑧, 𝑟 ∈ ℤ𝑞.
/// Output: Boolean.
pub(crate) fn make_hint<const GAMMA2: i32>(z: i32, r: i32) -> i32 {
    // // 1: 𝑟1 ← HighBits(𝑟)
    // let r1 = high_bits::<GAMMA2>(r);
    //
    // // 2: 𝑣1 ← HighBits(𝑟 + 𝑧)
    // let v1 = high_bits::<GAMMA2>(r + z);
    //
    // // 3: return [[𝑟1 ≠ 𝑣1]]
    // if r1 != v1 { 1 } else { 0 }

    // By the powers of someone much more clever than me, this is equivalent.

    if z <= GAMMA2 || z > q - GAMMA2 || (z == q - GAMMA2 && r == 0)
    {
        0
    } else {
        1
    }
}

/// Creates the hint vector from two Vector<k>'s, and also returns its hamming weight (ie the number of 1's).
pub(crate) fn make_hint_vecs<const k: usize, const GAMMA2: i32>(
    r: &Vector<k>,
    s: &Vector<k>,
) -> (Vector<k>, i32) {
    let mut out = Vector::<k>::new();
    let mut count = 0i32;

    for i in 0..k {
        let (w, c) = r.vec[i].make_hint::<GAMMA2>(&s.vec[i]);
        out.vec[i] = w;
        count += c;
    }

    (out, count)
}

/// Algorithm 40 UseHint(ℎ, 𝑟)
/// Returns the high bits of 𝑟 adjusted according to hint ℎ.
/// Input: Boolean ℎ, 𝑟 ∈ ℤ𝑞.
/// Output: 𝑟1 ∈ ℤ with 0 ≤ 𝑟1 ≤ (𝑞−1) / 2*gamma2).
pub(super) fn use_hint<const GAMMA2: i32>(a: i32, hint: i32) -> i32 {
    let (a0, a1) = decompose::<GAMMA2>(a);

    if hint == 0 {
        return a0;
    }

    debug_assert!(hint == 1);

    match GAMMA2 {
        MLDSA44_GAMMA2 => {
            if a1 > 0 {
                if a0 == 43 { 0 } else { a0 + 1 }
            } else {
                if a0 == 0 { 43 } else { a0 - 1 }
            }
        }
        // ML-DSA65 and 87 have the same GAMMA2
        MLDSA65_GAMMA2 => {
            if a1 > 0 {
                (a0 + 1) & 15
            } else {
                (a0 - 1) & 15
            }
        }
        _ => {
            panic!("Invalid GAMMA2 value")
        }
    }
}

pub(crate) fn use_hint_polys<const GAMMA2: i32>(
    wp_approx: &Polynomial,
    h: &Polynomial,
    out: &mut Polynomial,
) {
    for i in 0..N {
        out.0[i] = use_hint::<GAMMA2>(wp_approx.0[i], h.0[i]);
    }
}

pub(crate) fn use_hint_vecs<const k: usize, const GAMMA2: i32>(
    h: &Vector<k>,
    wp_approx: &Vector<k>,
) -> Vector<k> {
    let mut out = Vector::<k>::new();
    for i in 0..k {
        use_hint_polys::<GAMMA2>(&wp_approx.vec[i], &h.vec[i], &mut out.vec[i]);
    }

    out
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

/// Algorithm 41 NTT(𝑤)
/// Computes the NTT.
/// Input: Polynomial 𝑤(𝑋)
/// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞.
/// Output: 𝑤_hat = (𝑤_hat\[0], ..., 𝑤_hat\[255]) ∈ 𝑇𝑞.
///
/// Note: by convention, variables holding the output of the NTT function should be named "_ntt"
/// to indicate that they are in the NTT domain (sometimes called the frequency domain), not the natural domain.
/// I considered using the rust type system to enforce this, but it seemed like overkill, cause that's what
/// NIST test vectors are for.
///
/// Design choice: don't do the NTT in-place, but copy data to a new array.
/// This uses slightly more memory and requires a copy, but makes the code easier to read
/// and less likely to contain a bug. But this optimization could be considered in the future.
pub(crate) fn ntt(w: &Polynomial) -> Polynomial {
    let mut w_ntt = w.clone();

    let mut m: usize = 0;
    let mut len: usize = 128;

    while len >= 1 {
        let mut start: usize = 0;
        while start < N {
            m += 1;
            let z: i32 = ZETAS[m];

            for j in start..start + len {
                let t = polynomial::montgomery_reduce(z as i64 * w_ntt.0[j + len] as i64);
                w_ntt.0[j + len] = w_ntt.0[j] - t; // '% q' not strictly needed cause it gets reduced at some point later. Removing it gave +5% in benchmarking
                w_ntt.0[j] = w_ntt.0[j] + t; // '% q' not strictly needed
            }
            start = start + 2 * len;
        }
        len >>= 1;
    }

    w_ntt
}

/// Algorithm 42 NTT−1(𝑤)̂
/// Computes the inverse of the NTT.
/// Input: ̂̂ ̂ 𝑤 = (𝑤\[0], … , 𝑤\[255]) ∈ 𝑇𝑞.
/// Output: Polynomial 𝑤(𝑋) = ∑255
/// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞
pub(crate) fn inv_ntt(w_hat: &Polynomial) -> Polynomial {
    let mut w = w_hat.clone();

    let mut m: usize = N;
    let mut len: usize = 1;

    while len < N {
        let mut start: usize = 0;
        while start < N {
            m -= 1;
            let z = (-1) * ZETAS[m];

            // j = start;
            // while j < start + len {
            for j in start..start + len {
                // 𝑡 ← 𝑤𝑗
                let t: i32 = w.0[j];

                // 𝑤𝑗 ← (𝑡 + 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                w.0[j] = t + w.0[j + len];

                // 𝑤𝑗+𝑙𝑒𝑛 ← (𝑡 − 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                w.0[j + len] = t - w.0[j + len];

                // 𝑤𝑗+𝑙𝑒𝑛 ← (𝑧 ⋅ 𝑤𝑗+𝑙𝑒𝑛) mod 𝑞
                w.0[j + len] = polynomial::montgomery_reduce(z as i64 * w.0[j + len] as i64);
                print!("");
            }
            start = start + 2 * len; // could be optimized to save the multiply-by-two since j finishes as `start + len`. That said 2* is just << 1, which is basically free.
        }
        len <<= 1;
    }

    // f = 256^-1 mod q
    // const f: i64 = 8347681;
    // bc-java uses this value rather than the one in FIPS 204
    const f: i64 = 41978;
    for j in 0..N {
        // equiv. to the global constant N
        w.0[j] = polynomial::montgomery_reduce(f * w.0[j] as i64);
    }

    w
}
