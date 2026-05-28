//! Implements auxiliary functions for ML-DSA as defined in Section 7 of FIPS 204.

use crate::mlkem::{N, q, q_inv};
use crate::polynomial::{Polynomial};
use bouncycastle_core::traits::XOF;
use bouncycastle_sha3::{SHAKE128, SHAKE256};

/// Algorithm 5 ByteEncode_d(𝐹)
/// Encodes an array of 𝑑-bit integers into a byte array for 1 ≤ 𝑑 ≤ 12.
/// Input: integer array 𝐹 ∈ ℤ_M^256 , where 𝑚 = 2^𝑑 if 𝑑 < 12, and 𝑚 = 𝑞 if 𝑑 = 12.
/// Output: byte array 𝐵 ∈ 𝔹32𝑑 .
pub(crate) fn byte_encode<const d: usize, const PACK_LEN: usize>(F: &Polynomial) -> [u8; PACK_LEN] {
    debug_assert_eq!(PACK_LEN, 32 * d);

    let mut B = [0u8; PACK_LEN];

    for i in 0 .. N {
        let mut alpha = F[i];

        // For efficiency, the library is happy to work with values outside the range [0..q],
        // but we need to reduce it for the canonical encoding.
        alpha = barrett_reduce(alpha);

        for j in 0..d {
            // alpha % 2, but without using % for constant-time reasons
            let tmp = (alpha & 1) as u8;

            // 4: 𝑏[𝑖⋅𝑑 + 𝑗] ← 𝑎 mod 2
            //  constant-time note: yes, % is not constant-time,
            //   but all of the values in (i*d + j) % 8 are loop indices and not part of the secret key.
            B[(i*d + j)/8] |= tmp << ((i*d + j) % 8);


            // 5: 𝑎 ← (𝑎 − 𝑏[𝑖⋅𝑑 + 𝑗])/2
            //   ▷ note 𝑎 − 𝑏[𝑖⋅𝑑 + 𝑗] is always even
            //
            // Deviation from the FIPS:
            //   the direct translation to rust would be:
            //     alpha = (alpha - tmp as i16) >> 1;
            //   but since 𝑏[𝑖⋅𝑑 + 𝑗] is a single bit, and 𝑎 − 𝑏[𝑖⋅𝑑 + 𝑗] is always even,
            //   and we're about to shift off the last bit anyway, this is literally equivalent to "alpha >> 1".
            alpha >>= 1;
        }
    }

    B
}

/// Algorithm 6 ByteDecode_d(𝐵)
/// Decodes a byte array into an array of 𝑑-bit integers for 1 ≤ 𝑑 ≤ 12.
/// Input: byte array 𝐵 ∈ 𝔹32𝑑 .
/// Output: integer array 𝐹 ∈ ℤ256 , where 𝑚 = 2𝑑 if 𝑑 < 12 and 𝑚 = 𝑞 if 𝑑 = 12.
pub(crate) fn byte_decode<const d: usize, const PACK_LEN: usize>(B: &[u8; PACK_LEN]) -> Polynomial {
    debug_assert_eq!(PACK_LEN, 32 * d);

    let mut F = Polynomial::new();

    for i in 0..N {
        // 3: F[i] = SUM_j=0..d-1{ 𝑏[𝑖 ⋅ 𝑑 + 𝑗] ⋅ 2𝑗 } mod m
        for j in 0..d {
            // select the next bit, according to bitcount, then shift it up by j
            F[i] |= (((B[(i*d + j)/8] >> (i*d + j)%8) & 1) as i16) << j; // there's supposed to be a `mod m` here, but that shouldn't matter; we'll check it below anyway.
        }
        // assert the mod m
        debug_assert!(F[i] >= 0);
        debug_assert!(F[i] <= if d<12 {2<<d} else { q });
    }

    F
}

/// Algorithm 7 SampleNTT(𝐵)
/// Takes a 32-byte seed and two indices as input and outputs a pseudorandom element of 𝑇𝑞.
/// Input: byte array 𝐵 ∈ 𝔹34 . ▷ a 32-byte seed along with two indices
/// Output: array 𝑎_hat ∈ ℤ256 ▷ the coefficients of the NTT of a polynomial
pub(crate) fn sample_ntt(rho: &[u8; 32], nonce: &[u8; 2]) -> Polynomial {
    let mut a_hat = Polynomial::new();

    // 1: ctx ← XOF.Init()
    // 2: ctx ← XOF.Absorb(ctx, 𝐵) ▷ input the given byte array into XOF
    let mut xof = SHAKE128::new();
    xof.absorb(rho);
    xof.absorb(nonce);

    // 3: 𝑗 ← 0
    let mut j = 0usize;

    // SHAKE is fairly inefficient if you just squeeze 3 bytes at a time, so we'll do a block.
    // size doesn't really matter, so long as it's a multiple of 3.
    // 288 seemed to be the sweet spot from playing with benchmarks
    // It's probably around the average rejection rate, and 288 is a multiple of both 3 (required for this alg)
    // and 8 (efficient for SHAKE).
    let mut C = [0u8; 288];
    xof.squeeze_out(&mut C);
    let mut idx: usize = 0;

    // 4: while 𝑗 < 256 do
    while j < N {
        // 5: (ctx, 𝐶) ← XOF.Squeeze(ctx, 3)
        //   ▷ get a fresh 3-byte array 𝐶 from XOF
        if idx == C.len() {
            xof.squeeze_out(&mut C);
            idx = 0;
        }

        // 6: 𝑑1 ← 𝐶[0] + 256 ⋅ (𝐶[1] mod 16)
        //  ▷ 0 ≤ 𝑑1 < 2^12
        let d1: i16 = (C[idx+0] as i16) | ((C[idx+1] as i32)  << 8) as i16 & 0xFFF;
        debug_assert!(d1 < 2 << 12);

        // 7: 𝑑2 ← ⌊𝐶[1]/16⌋ + 16 ⋅ 𝐶[2]
        //  ▷ 0 ≤ 𝑑2 < 2^12
        let d2: i16 = ((C[idx+1] as i16) >> 4) | ((C[idx+2] as i32) << 4) as i16 & 0xFFF;
        debug_assert!(d2 < 2 << 12);

        // 8: if 𝑑1 < 𝑞 then
        // 9:   𝑎_hat[𝑗] ← 𝑑1 ̂
        //         ▷ 𝑎_hat ∈ ℤ256
        // 10:  𝑗 ← 𝑗 + 1
        // 11: end if
        if d1 < q {
            a_hat[j] = d1;
            j += 1;
        }

        // 12: if 𝑑2 < 𝑞 and 𝑗 < 256 then
        // 13:  𝑎[𝑗] ← 𝑑2
        // 14:  𝑗 ← 𝑗 + 1
        // 15: end if
        if d2 < q && j < N {
            a_hat[j] = d2;
            j += 1;
        }

        idx += 3;
    }

    a_hat
}

/// Algorithm 8 SamplePolyCBD (𝐵)𝜂
/// Takes a seed as input and outputs a pseudorandom sample from the distribution D𝜂(𝑅𝑞).
/// Input: byte array 𝐵 ∈ 𝔹64𝜂 .
/// Output: array 𝑓 ∈ ℤ256  ▷ the coefficients of the sampled polynomial
pub(crate) fn sample_poly_cbd<const eta: i16>(bytes: &[u8]) -> Polynomial {
    debug_assert_eq!(bytes.len(), 64 * eta as usize);

    let mut f = Polynomial::new();

    match eta {
        2 => {
            for i in 0..N/8 {
                let t = u32::from_le_bytes(bytes[4*i .. 4*i + 4].try_into().unwrap());
                let mut d = t & 0x55555555;
                d += (t >> 1) & 0x55555555;
                for j in 0..8usize {
                    let a = ((d >> (4 * j)) & 0x3) as i16;
                    let b = ((d >> (4 * j + eta as usize)) & 0x3) as i16;
                    f[8 * i + j] = a - b;

                    // ▷ 0 ≤ 𝑓[𝑖] ≤ 𝜂 or 𝑞 − 𝜂 ≤ 𝑓[𝑖] ≤ 𝑞 − 1
                    //  this version is in [-eta, eta] instead of [0..eta] \U [q-eta..q-1]
                    debug_assert!(-eta <= f[8 * i + j] && f[8 * i + j] <= eta);
                }
            }
        }
        3 => {
            for i in 0..N/4 {
                let t = little_endian_to_u24(bytes, 3 * i);
                let mut d = t & 0x00249249;
                d += (t >> 1) & 0x00249249;
                d += (t >> 2) & 0x00249249;
                for j in 0..4usize {
                    let a = ((d >> (6 * j)) & 0x7) as i16;
                    let b = ((d >> (6 * j + eta as usize)) & 0x7) as i16;
                    f[4 * i + j] = a - b;

                    // ▷ 0 ≤ 𝑓[𝑖] ≤ 𝜂 or 𝑞 − 𝜂 ≤ 𝑓[𝑖] ≤ 𝑞 − 1
                    //  this version is in [-eta, eta] instead of [0..eta] \U [q-eta..q-1]
                    debug_assert!(-eta <= f[4 * i + j] && f[4 * i + j] <= eta);
                }
            }
        }
        _ => unreachable!("Wrong Eta"),
    }

    f
}

/// SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
/// Performs both the PRF and SamplePolyCBD steps
pub(crate) fn sample_poly_CBD<const eta: i16>(b: &[u8; 32], n: u8) -> Polynomial {

    // Alg 13: 9: 𝐬[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
    //  ▷ 𝐬[𝑖] ∈ ℤ256 sampled from CBD
    match eta {
        2 => {
            let buf = {
                let mut xof = SHAKE256::new();
                xof.absorb(b);
                xof.absorb(&n.to_le_bytes());

                let mut buf = [0u8; 2 * 64];
                xof.squeeze_out(&mut buf);
                buf
            };

            sample_poly_cbd::<eta>(&buf)
        },
        3 => {
            let buf = {
                let mut xof = SHAKE256::new();
                xof.absorb(b);
                xof.absorb(&n.to_le_bytes());
                let mut buf = [0u8; 3 * 64];
                xof.squeeze_out(&mut buf);
                buf
            };

            sample_poly_cbd::<eta>(&buf)
        },
        _ => unreachable!()
    }
}

fn little_endian_to_u24(bs: &[u8], off: usize) -> u32 {
    let mut n = bs[off] as u32;
    n |= (bs[off + 1] as u32) << 8;
    n | (bs[off + 2] as u32) << 16
}

pub(crate) const ZETAS: [i16; 128] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 573,
    2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652,
    2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239,
    3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226, 430, 555,
    843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322,
    2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819,
    2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

pub(crate) const ZETAS_INV: [i16; 128] = [
    1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535, 1278, 1530, 1185,
    1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465, 1285, 2007, 2719, 2726, 2232, 2512,
    75, 156, 3000, 2911, 2980, 872, 2685, 1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676,
    1755, 460, 291, 235, 3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275,
    2652, 1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853, 1860, 3203,
    1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552, 2677, 2106, 1571, 205, 2918,
    1542, 2721, 2597, 2312, 681, 130, 1602, 1871, 829, 2946, 3065, 1325, 2756, 1861, 1474, 1202,
    2367, 3147, 1752, 2707, 171, 3127, 3042, 1907, 1836, 1517, 359, 758, 1441,
];

pub(crate) fn mul_mont(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

pub(crate) fn montgomery_reduce(a: i32) -> i16 {
    let u = a.wrapping_mul(q_inv) as i16;
    let mut t = (u as i32) * q as i32;
    t = a - t;
    t >>= 16;
    t as i16
}

pub(crate) fn barrett_reduce(a: i16) -> i16 {
    let v = (((1u32 << 26) + ((q / 2) as u32)) / (q as u32)) as i16;
    let t = (((v as i32) * (a as i32)) >> 26) as i16;
    a - (((t as i32) * q as i32) as i16)
}

pub(super) fn cond_sub_q(a: i16) -> i16 {
    let tmp = a - q;
    tmp + ((tmp >> 15) & q)
}


/// Multiplication of polynomials in Zq\[X]/(X^2-zeta)
/// used for multiplication of elements in Rq in NTT domain
///
/// Borrowed from:
/// https://github.com/pq-crystals/kyber/blob/main/ref/ntt.c#L139
pub(crate) fn ntt_base_mult(r: &mut [i16], off: usize, a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) {
    let mut out_val0 = mul_mont(a1, b1);
    out_val0 = mul_mont(out_val0, zeta);
    out_val0 += mul_mont(a0, b0);
    r[off] = out_val0;

    let mut out_val1 = mul_mont(a0, b1);
    out_val1 += mul_mont(a1, b0);
    r[off + 1] = out_val1;
}
