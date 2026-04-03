//! Implements auxiliary functions for ML-DSA as defined in Section 7 of FIPS 204.

// use crate::matrix::{Matrix, Vector};
use crate::mldsa::{G, H};
use crate::mldsa::{
    MLDSA44_GAMMA1, MLDSA44_GAMMA2, MLDSA65_GAMMA1, MLDSA65_GAMMA2, N,
    POLY_T1PACKED_LEN, d, q,
};
use crate::polynomial::Polynomial;
use bouncycastle_core_interface::traits::XOF;

/// Algorithm 14 CoeffFromThreeBytes(𝑏0, 𝑏1, 𝑏2)
/// Output: An integer modulo 𝑞 or ⊥.
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
    debug_assert_eq!(r.len(), bitlen_eta(ETA));

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
}

/// A variant of Algorithm 17 specific to packing z in the signature value in \[−𝛾1 + 1, 𝛾1].
pub(crate) fn bitpack_gamma1<const POLY_Z_PACKED_LEN: usize, const GAMMA1: i32>(
    z: &Polynomial,
    out: &mut [u8; POLY_Z_PACKED_LEN]) {
    let mut t: [u32; 4] = [0; 4];
    match GAMMA1 {
        MLDSA44_GAMMA1 => {
            for i in 0..N / 4 {
                t[0] = (GAMMA1 - z.0[4 * i]) as u32;
                t[1] = (GAMMA1 - z.0[4 * i + 1]) as u32;
                t[2] = (GAMMA1 - z.0[4 * i + 2]) as u32;
                t[3] = (GAMMA1 - z.0[4 * i + 3]) as u32;

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
        // MLDSA-65 and 87 have the same GAMMA1 value
        MLDSA65_GAMMA1 => {
            for i in 0..N / 2 {
                t[0] = (GAMMA1 - z.0[2 * i]) as u32;
                t[1] = (GAMMA1 - z.0[2 * i + 1]) as u32;

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

/// Part of unpacking the sig value
pub(crate) fn unpack_c_tilde<
    const LAMBDA_over_4: usize,
>(sig: &[u8]) -> &[u8; LAMBDA_over_4] {
    sig[..LAMBDA_over_4].try_into().unwrap()
}
/// Part of unpacking the sig value
pub(crate) fn unpack_z_row<
    const GAMMA1: i32,
    const BETA: i32,
    const LAMBDA_over_4: usize,
    const POLY_Z_PACKED_LEN: usize,
    const SIG_LEN: usize,
>(
    idx: usize,
    sig: &[u8; SIG_LEN],
) -> Result<Polynomial, ()> {
    // assert: idx < l

    // skip to the start of the z's
    let pos = LAMBDA_over_4;
    let z = bit_unpack_gamma1::<GAMMA1>(
        &sig[pos + idx * POLY_Z_PACKED_LEN..pos + (idx + 1) * POLY_Z_PACKED_LEN]);

    // Perform the norm check from
    // Alg 8; Line 13 (first half) return [[ ||𝐳||∞ < 𝛾1 − 𝛽]]
    if z.check_norm(GAMMA1 - BETA) { Err(()) } else { Ok(z) }
}
/// Part of unpacking the sig value
pub(crate) fn unpack_h_row<
    const GAMMA1: i32,
    const k: usize,
    const l: usize,
    const OMEGA: i32,
    const LAMBDA_over_4: usize,
    const POLY_Z_PACKED_LEN: usize,
    const SIG_LEN: usize,
>(
    row: usize,
    sig: &[u8; SIG_LEN],
) -> Option<Polynomial> {
    debug_assert!(row < k);

    let mut h = Polynomial::new();

    // skip over the other stuff in the encoded sig value
    let pos = LAMBDA_over_4 + l * POLY_Z_PACKED_LEN;


    // This inlines Algorithm 21 HintBitUnpack(𝑦)

    // 2: Index ← 0
    //  ▷ Index for reading the first 𝜔 bytes of 𝑦
    // let mut idx = 0usize;
    // This row calc is a bit weird because technically it's supposed to be done at the end
    // of the previous loop
    let idx = if row == 0 { 0 } else { sig[pos + OMEGA as usize + row-1] as usize };

    // 3: for 𝑖 from 0 to 𝑘 − 1 do
    //  ▷ reconstruct 𝐡[𝑖]
    // for i in 0..k {
    // 4: if 𝑦[𝜔 + 𝑖] < Index or 𝑦[𝜔 + 𝑖] > 𝜔 then return ⊥
    if sig[pos + (OMEGA as usize) + row] < (idx as u8)
        || sig[pos + (OMEGA as usize) + row] > OMEGA as u8
    {
        return None;
    }

    // 6: First ← Index
    // 7: while Index < 𝑦[𝜔 + 𝑖] do
    //   ▷ 𝑦[𝜔 + 𝑖] says how far one can advance Index
    for j in idx..sig[pos + OMEGA as usize + row] as usize {
        // 8: if Index > First then
        // 9:   if 𝑦[Index − 1] ≥ 𝑦[Index] then return ⊥
        //       ▷ malformed input
        if j > idx && sig[pos + j - 1] >= sig[pos + j] {
            return None;
        }
        // 12: 𝐡[𝑖]_𝑦[Index] ← 1
        h.0[sig[pos + j] as usize] = 1;

        // 13: Index ← Index + 1
        //  > done by for loop
    }

    // ▷ read any leftover bytes in the first 𝜔 bytes of 𝑦 for malformed (nonzero) bytes
    if row == k - 1 {
        let idx = sig[pos + OMEGA as usize + row] as usize;
        for j in idx..OMEGA as usize {
            if sig[pos + j] != 0 {
                return None;
            }
        }
    }

    Some(h)
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

/// Algorithm 34 ExpandMask(𝜌, 𝜇)
/// Samples a vector 𝐲 ∈ 𝑅ℓ such that each polynomial 𝐲[𝑟] has coefficients between −𝛾1 + 1 and 𝛾1.
/// Input: A seed 𝜌 ∈ 𝔹64 and a nonnegative integer 𝜇.
/// Output: Vector 𝐲 ∈ 𝑅ℓ .
pub(crate) fn expand_mask_poly<const GAMMA1: i32, const GAMMA1_MASK_LEN: usize>(
    rho: &[u8; 64],
    nonce: u16,
) -> Polynomial {
    // 1: 𝑐 ← 1 + bitlen (𝛾1 − 1)
    //  ▷ 𝛾1 is always a power of 2
    // 3: 𝜌′ ← 𝜌||IntegerToBytes(𝜇 + 𝑟, 2)
    // 32c = GAMMA1_MASK_LEN;
    // 4: 𝑣 ← H(𝜌′, 32𝑐)
    let mut h = H::new();
    h.absorb(rho);
    h.absorb(&nonce.to_le_bytes());
    let mut v = [0u8; GAMMA1_MASK_LEN];
    h.squeeze_out(&mut v);
    bit_unpack_gamma1::<GAMMA1>(&v)
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
