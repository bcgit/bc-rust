//! Implements auxiliary functions for ML-DSA as defined in Section 7 of FIPS 204.

use crate::matrix::{Matrix, Vector};
use crate::mldsa::{G, H};
use crate::polynomial::{Polynomial};
use crate::{MLDSAParams, q, polynomial, d, N, POLY_T1PACKED_LEN, POLY_T0PACKED_LEN};
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
pub(crate) fn coeff_from_half_byte<PARAMS: MLDSAParams>(b: u8) -> Result<i32, ()> {
    // todo: there's no way this is constant time:
    // todo: the if statement might not be so bad because the alternative is rejection,
    // todo: but that % is a problem.
    // todo: what does openssl or rust crypto do?
    if PARAMS::ETA == 2 && b < 15 {
        Ok(2 - (b % 5) as i32) // todo: is constant-time?
    }
    else {
        if PARAMS::ETA == 4 && b < 9 { Ok(4 - b as i32) }
        else { Err(()) }
    }
}


/// A specific instantiation of Algorithm 16 SimpleBitPack(𝑤, 𝑏) with the constants set for packing the t1 vector
///  Encodes a polynomial 𝑤 into a byte string.
/// Input: 𝑏 ∈ ℕ and 𝑤 ∈ 𝑅 such that the coefficients of 𝑤 are all in [0, 𝑏].
/// Output: A byte string of length 32 ⋅ bitlen 𝑏.
pub(crate) fn simple_bit_pack_t1(w: &Polynomial) -> [u8; POLY_T1PACKED_LEN] {
    let mut output = [0u8; POLY_T1PACKED_LEN];
    for i in 0..N/4 {
        output[5 * i] = w.0[4 * i] as u8;
        output[5 * i + 1] = ((w.0[4 * i] >> 8) | (w.0[4 * i + 1] << 2)) as u8;
        output[5 * i + 2] =
            ((w.0[4 * i + 1] >> 6) | (w.0[4 * i + 2] << 4)) as u8;
        output[5 * i + 3] =
            ((w.0[4 * i + 2] >> 4) | (w.0[4 * i + 3] << 6)) as u8;
        output[5 * i + 4] = (w.0[4 * i + 3] >> 2) as u8;
    }
    output
}

/// As defined in Algorithm 17, this gives the length of a packed bitstring representing a polynomial
/// whose coefficients have been rounded to \[-eta, eta], which is 32*bitlen(2*eta).
pub const fn bitlen_eta(eta: usize) -> usize {
    match eta {
        2 => 32*3,
        4 => 32*4,
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
            for i in 0..N/8 {
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
        },
        // MLDSA65
        4 => {
            let eta: i32 = 4;
            for i in 0..N/2 {
                t[0] = (eta - w.0[2 * i]) as u8;
                t[1] = (eta - w.0[2 * i + 1]) as u8;
                r[i] = t[0] | t[1] << 4;
            }
        },
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
    for i in 0..N/8 {
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

/// A specific instantiation of Algorithm 18 SimpleBitUnpack(v, 𝑏) with the constants set for unpacking the t1 vector
/// Input: 𝑏 ∈ ℕ and a byte string 𝑣 of length 32 ⋅ bitlen 𝑏.
/// Output: A polynomial 𝑤 ∈ 𝑅 with coefficients in [0, 2𝑐 − 1], where 𝑐 = bitlen 𝑏.
/// When 𝑏 + 1 is a power of 2, the coefficients are in [0, 𝑏].
///
/// Note: caller is responsible for ensuring correct input array size
pub(crate) fn simple_bit_unpack_t1(v: &[u8; POLY_T1PACKED_LEN]) -> Polynomial {
    // debug_assert_eq!(v.len(), POLY_T1PACKED_LEN);

    let mut w = Polynomial::new();

    for i in 0..N/4 {
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
            for i in 0..N/8 {
                w.0[8 * i] =      (v[3 * i] & 7) as i32;
                w.0[8 * i + 1] = ((v[3 * i] >> 3) & 7) as i32;
                w.0[8 * i + 2] = ((v[3 * i] >> 6) | (v[3 * i + 1] << 2) & 7) as i32;
                w.0[8 * i + 3] = ((v[3 * i + 1] >> 1) & 7) as i32;
                w.0[8 * i + 4] = ((v[3 * i + 1] >> 4) & 7) as i32;
                w.0[8 * i + 5] = ((v[3 * i + 1] >> 7) | (v[3 * i + 2] << 1) & 7) as i32;
                w.0[8 * i + 6] = ((v[3 * i + 2] >> 2) & 7) as i32;
                w.0[8 * i + 7] = ((v[3 * i + 2] >> 5) & 7) as i32;

                w.0[8 * i] = eta -     w.0[8 * i];
                w.0[8 * i + 1] = eta - w.0[8 * i + 1];
                w.0[8 * i + 2] = eta - w.0[8 * i + 2];
                w.0[8 * i + 3] = eta - w.0[8 * i + 3];
                w.0[8 * i + 4] = eta - w.0[8 * i + 4];
                w.0[8 * i + 5] = eta - w.0[8 * i + 5];
                w.0[8 * i + 6] = eta - w.0[8 * i + 6];
                w.0[8 * i + 7] = eta - w.0[8 * i + 7];
            }
        },
        // MLDSA65
        4 => {
            let eta: i32 = 4;
            for i in 0..N/2 {
                w.0[2 * i] = (v[i] & 0x0F) as i32;
                w.0[2 * i + 1] = (v[i] >> 4) as i32;

                w.0[2 * i] = eta - w.0[2 * i];
                w.0[2 * i + 1] = eta - w.0[2 * i + 1];
            }
        },
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

    for i in 0..N/8 {
        t0.0[8 * i] = ((a[13 * i] as i32) | ((a[13 * i + 1] as i32) << 8)) & 0x1FFF;
        t0.0[8 * i + 1] = ((((a[13 * i + 1] as i32) >> 5)
            | (a[13 * i + 2] as i32) << 3)
            | ((a[13 * i + 3] as i32) << 11))
            & 0x1FFF;
        t0.0[8 * i + 2] = (((a[13 * i + 3] as i32) >> 2)
            | ((a[13 * i + 4] as i32) << 6))
            & 0x1FFF;
        t0.0[8 * i + 3] = ((((a[13 * i + 4] as i32) >> 7)
            | (a[13 * i + 5] as i32) << 1)
            | ((a[13 * i + 6] as i32) << 9))
            & 0x1FFF;
        t0.0[8 * i + 4] = ((((a[13 * i + 6] as i32) >> 4)
            | (a[13 * i + 7] as i32) << 4)
            | ((a[13 * i + 8] as i32) << 12))
            & 0x1FFF;
        t0.0[8 * i + 5] = (((a[13 * i + 8] as i32) >> 1)
            | ((a[13 * i + 9] as i32) << 7))
            & 0x1FFF;
        t0.0[8 * i + 6] = ((((a[13 * i + 9] as i32) >> 6)
            | (a[13 * i + 10] as i32) << 2)
            | ((a[13 * i + 11] as i32) << 10))
            & 0x1FFF;
        t0.0[8 * i + 7] = (((a[13 * i + 11] as i32) >> 3)
            | ((a[13 * i + 12] as i32) << 5))
            & 0x1FFF;

        t0.0[8 * i] = (1 << (d - 1)) -     t0.0[8 * i];
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

/// Algorithm 30 RejNTTPoly(𝜌)
/// This is supposed to take a rho: [u8; 34], which is: 𝜌||IntegerToBytes(𝑠, 1)||IntegerToBytes(𝑟, 1)
/// but to avoid needing to copy bytes and allocate more memory,
/// we'll split that into a [u8;32] and a [u8;2]
pub(crate) fn rej_ntt_poly(
    rho: &[u8; 32],
    nonce: &[u8; 2],
) -> Polynomial {
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
        if idx == s.len() { g.squeeze_out(&mut s); idx = 0;}
        w_hat.0[j] = match coeff_from_three_bytes(&s[idx..idx+3].try_into().unwrap()) {
            Ok(c) => { c },
            Err(_) => {
                // those three bytes were out of range for a coefficient, so go again with the next three bytes
                // from the SHAKE stream.
                idx += 3;
                continue
            },
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
pub(crate) fn rej_bounded_poly<PARAMS: MLDSAParams>(
    rho: &[u8; 64],
    nonce: &[u8; 2],
) -> Polynomial {
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
        let z0 = coeff_from_half_byte::<PARAMS>(z_arr[idx] & 0x0F); // equiv to % 16 (but faster, and more importantly, constant-time)
        let z1 = coeff_from_half_byte::<PARAMS>(z_arr[idx] >> 4); // equiv to div_floor(16) (but faster, and more importantly, constant-time)

        if z0.is_ok() {
            a.0[j] = z0.unwrap();
            j += 1;
        } /* else: do nothing */
        if z1.is_ok() && j < 256 {
            a.0[j] = z1.unwrap();
            j += 1;
        } /* else: do nothing */

        idx += 1;
        if idx == z_arr.len() { h.squeeze_out(&mut z_arr); idx = 0;}
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
pub(crate) fn expandS<const k: usize, const l: usize, PARAMS: MLDSAParams>(
    rho: &[u8; 64],
) -> (Vector::<l>, Vector::<k>) {
    let mut s1 = Vector::<l>::new();
    let mut s2 = Vector::<k>::new();

    for r in 0..l {
        s1.vec[r] = rej_bounded_poly::<PARAMS>(rho, &(r as u16).to_le_bytes());
    }

    for r in 0..k {
        s2.vec[r] = rej_bounded_poly::<PARAMS>(rho, &(r as u16 + l as u16).to_le_bytes());
    }

    (s1, s2)
}

/// Implements the meta-function described in FIPS 204 section 7.4 for applying power_2_round to a vector.
/// ((𝐫1\[𝑖])𝑗, (𝐫0\[𝑖])𝑗) = Power2Round((𝐫\[𝑖])𝑗).
pub(crate) fn power_2_round_vec<const LEN: usize>(
    v: &Vector<LEN>
) -> (Vector<LEN>, Vector<LEN>) {
    let mut r1 = Vector::<LEN>::new();
    let mut r0 = Vector::<LEN>::new();

    for i in 0 .. LEN {
        for j in 0 .. N {
            (r1.vec[i].0[j], r0.vec[i].0[j]) = power_2_round(v.vec[i].0[j]);
        }
    }

    (r1, r0)
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

    (t>>d, r0)
}

#[test]
// FIPS 204 describes the output as easy to check:
// Decomposes 𝑟 into (𝑟1, 𝑟0) such that 𝑟 ≡ 𝑟1 2^𝑑 + 𝑟0 mod 𝑞.
fn test_power_2_round() {

    test(1);
    test(q-3);
    test(q);
    test(q+3);

    fn test(r: i32) {
        let (r1, r0) = power_2_round(r);
        let mut res = ((r1<<d) + r0) % q;
        if res < 0 { res += q; }
        assert_eq!(r%q, res);
    }
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
pub(crate) fn ntt_vec<const LEN: usize>(
    s: &Vector<LEN>,
) -> Vector<LEN> {
    let mut s_hat = Vector::<LEN>::new();

    for i in 0..LEN {
        s_hat.vec[i] = ntt(&s.vec[i]);
    }

    s_hat
}

/// I think there is an omission in FIPS 204 in that Algorithm 41 NTT is defined for a single polynomial,
/// but then is called with vectors of polynomials or matrices of polynomials with some hand-wany wording
/// in section 2.5 about doing the NTT "entry-wise".
///
/// Anyway, this fills in the missing overloads of NTT to act on a matrix.
/// TODO: this one might not be used?
pub(crate) fn ntt_matrix<const l: usize, const k: usize>(
    A: &Matrix<l,k>,
) -> Matrix<l,k> {
    let mut A_hat = Matrix::<l,k>::new();

    for i in 0..k {
        for j in 0..l {
            A_hat.matrix[i][j] = ntt(&A.matrix[i][j]);
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
                w_ntt.0[j] = w_ntt.0[j] + t;  // '% q' not strictly needed
            }
            start = start + 2 * len;
        }
        len >>= 1;
    }

    w_ntt
}


/// I think there is an omission in FIPS 204 in that Algorithm 41 NTT is defined for a single polynomial,
/// but then is called with vectors of polynomials or matrices of polynomials with some hand-wany wording
/// in section 2.5 about doing the NTT "entry-wise".
///
/// Anyway, this fills in the missing overloaded version of NTT to act on a vector.
pub(crate) fn inv_ntt_vec<const LEN: usize>(
    s_hat: &Vector<LEN>,
) -> Vector<LEN> {
    let mut s = Vector::<LEN>::new();

    for i in 0..LEN {
        s.vec[i] = inv_ntt(&s_hat.vec[i]);
    }

    s
}

/// I think there is an omission in FIPS 204 in that Algorithm 41 NTT is defined for a single polynomial,
/// but then is called with vectors of polynomials or matrices of polynomials with some hand-wany wording
/// in section 2.5 about doing the NTT "entry-wise".
///
/// Anyway, this fills in the missing overloads of NTT to act on a matrix.
/// TODO: this one might not be used?
pub(crate) fn inv_ntt_matrix<const l: usize, const k: usize>(
    A_hat: &Matrix<l,k>,
) -> Matrix<l,k> {
    let mut A = Matrix::<l,k>::new();

    for i in 0..k {
        for j in 0..l {
            A.matrix[i][j] = inv_ntt(&A_hat.matrix[i][j]);
        }
    }

    A
}

/// Algorithm 42 NTT−1(𝑤)̂
/// Computes the inverse of the NTT.
/// Input: ̂̂ ̂ 𝑤 = (𝑤\[0], … , 𝑤\[255]) ∈ 𝑇𝑞.
/// Output: Polynomial 𝑤(𝑋) = ∑255
/// 𝑗=0 𝑤𝑗𝑋𝑗 ∈ 𝑅𝑞
pub(crate) fn inv_ntt(w_hat: &Polynomial) -> Polynomial {
    // todo: optimize to do this in-place?
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
                w.0[j + len] =
                    polynomial::montgomery_reduce(z as i64 * w.0[j + len] as i64);
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
