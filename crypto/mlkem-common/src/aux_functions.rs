//! The auxiliary algorithms of FIPS 203 Section 4 on single polynomials: ByteEncode and
//! ByteDecode (Algorithms 5-6) and SampleNTT and SamplePolyCBD (Algorithms 7-8). Anything over a
//! whole vector or matrix is the business of the crate that holds vectors.

use crate::polynomial::{Polynomial, barrett_reduce, cond_sub_q};
use crate::{N, q};
use bouncycastle_core::traits::{Hash, XOF, XOFSqueezer};
use bouncycastle_sha3::{SHAKE128, SHAKE256};

/// Algorithm 5 ByteEncode_d(𝐹)
/// Encodes an array of 𝑑-bit integers into a byte array for 1 ≤ 𝑑 ≤ 12.
/// Input: integer array 𝐹 ∈ ℤ_M^256, where 𝑚 = 2^𝑑 if 𝑑 < 12, and 𝑚 = 𝑞 if 𝑑 = 12.
/// Output: byte array 𝐵 ∈ 𝔹32𝑑.
///
/// Writes into `B`, which is zeroed first; see [`byte_encode`] for the form that returns it.
pub fn byte_encode_out<const d: usize, const PACK_LEN: usize>(
    F: &Polynomial,
    B: &mut [u8; PACK_LEN],
) {
    debug_assert_eq!(PACK_LEN, 32 * d);
    B.fill(0);

    for i in 0..N {
        let mut alpha = F[i];

        // The arithmetic leaves coefficients unreduced; the encoding needs the canonical
        // representative. barrett_reduce gives [0, q], with q for a negative multiple of q (an
        // unreduced NTT output can be one), and cond_sub_q folds that to 0.
        alpha = barrett_reduce(alpha);
        alpha = cond_sub_q(alpha);

        for j in 0..d {
            // alpha % 2, but without using % for constant-time reasons
            //  although "& 1" may lead to other, more subtle timing issues. Research topic.
            let tmp = (alpha & 1) as u8;

            // 4: 𝑏[𝑖⋅𝑑 + 𝑗] ← 𝑎 mod 2
            //  constant-time note: yes, % is not constant-time,
            //   but all of the values in (i*d + j) % 8 are loop indices and not part of the secret key.
            B[(i * d + j) / 8] |= tmp << ((i * d + j) % 8);

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
}

/// [`byte_encode_out`] into a fresh array.
#[must_use]
pub fn byte_encode<const d: usize, const PACK_LEN: usize>(F: &Polynomial) -> [u8; PACK_LEN] {
    let mut B = [0u8; PACK_LEN];
    byte_encode_out::<d, PACK_LEN>(F, &mut B);
    B
}

/// Algorithm 6 ByteDecode_d(𝐵)
/// Decodes a byte array into an array of 𝑑-bit integers for 1 ≤ 𝑑 ≤ 12.
/// Input: byte array 𝐵 ∈ 𝔹32𝑑 .
/// Output: integer array 𝐹 ∈ ℤ256 , where 𝑚 = 2𝑑 if 𝑑 < 12 and 𝑚 = 𝑞 if 𝑑 = 12.
pub fn byte_decode<const d: usize, const PACK_LEN: usize>(B: &[u8; PACK_LEN]) -> Polynomial {
    debug_assert_eq!(PACK_LEN, 32 * d);

    let mut F = Polynomial::new();

    for i in 0..N {
        // 3: F[i] = SUM_j=0..d-1{ 𝑏[𝑖 ⋅ 𝑑 + 𝑗] ⋅ 2𝑗 } mod m
        for j in 0..d {
            // select the next bit, according to bitcount, then shift it up by j
            // The `mod m` of line 3 is not applied: for 𝑑 < 12 the sum cannot reach 2^𝑑, and for
            // 𝑑 = 12 the callers check the coefficient against 𝑞 themselves (Section 7.2).
            F[i] |= (((B[(i * d + j) / 8] >> ((i * d + j) % 8)) & 1) as i16) << j;
        }
        debug_assert!(F[i] >= 0);
    }

    F
}

/// Algorithm 7 SampleNTT(𝐵)
/// Takes a 32-byte seed and two indices as input and outputs a pseudorandom element of 𝑇𝑞.
/// Input: byte array 𝐵 ∈ 𝔹34 . ▷ a 32-byte seed along with two indices
/// Output: array 𝑎_hat ∈ ℤ256 ▷ the coefficients of the NTT of a polynomial
pub fn sample_ntt(rho: &[u8; 32], nonce: &[u8; 2]) -> Polynomial {
    let mut a_hat = Polynomial::new();

    // 1: ctx ← XOF.Init()
    // 2: ctx ← XOF.Absorb(ctx, 𝐵) ▷ input the given byte array into XOF
    let mut xof = SHAKE128::new();
    xof.do_update(rho);
    xof.do_update(nonce);

    // 3: 𝑗 ← 0
    let mut j = 0usize;

    // SHAKE is fairly inefficient if you just squeeze 3 bytes at a time, therefore a block is squeezed here.
    // Size is not an important factor, so long as it's a multiple of 3.
    // 216 was the sweet spot in benchmarking.
    // It is probably around the average rejection rate, and 216 is a multiple of both 3 (required for this alg)
    // and 8 (efficient for SHAKE).
    let mut C = [0u8; 216];
    let mut xof = xof.into_squeezer();
    xof.do_output_out(&mut C);
    let mut idx: usize = 0;

    // 4: while 𝑗 < 256 do
    while j < N {
        // 5: (ctx, 𝐶) ← XOF.Squeeze(ctx, 3)
        //   ▷ get a fresh 3-byte array 𝐶 from XOF
        if idx == C.len() {
            xof.do_output_out(&mut C);
            idx = 0;
        }

        // 6: 𝑑1 ← 𝐶[0] + 256 ⋅ (𝐶[1] mod 16)
        //  ▷ 0 ≤ 𝑑1 < 2^12
        let d1: i16 = (C[idx] as i16) | ((C[idx + 1] as i32) << 8) as i16 & 0xFFF;
        debug_assert!(d1 < 1 << 12);

        // 7: 𝑑2 ← ⌊𝐶[1]/16⌋ + 16 ⋅ 𝐶[2]
        //  ▷ 0 ≤ 𝑑2 < 2^12
        let d2: i16 = ((C[idx + 1] as i16) >> 4) | ((C[idx + 2] as i32) << 4) as i16 & 0xFFF;
        debug_assert!(d2 < 1 << 12);

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
pub fn sample_poly_cbd(bytes: &[u8], eta: i16) -> Polynomial {
    debug_assert_eq!(bytes.len(), 64 * eta as usize);

    let mut f = Polynomial::new();

    match eta {
        2 => {
            for i in 0..N / 8 {
                let t = u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap());
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
            for i in 0..N / 4 {
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
pub fn sample_poly_CBD(b: &[u8; 32], n: u8, eta: i16) -> Polynomial {
    // Alg 13: 9: 𝐬[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝜎, 𝑁 ))
    //  ▷ 𝐬[𝑖] ∈ ℤ256 sampled from CBD
    match eta {
        2 => {
            let buf = {
                let mut xof = SHAKE256::new();
                xof.do_update(b);
                xof.do_update(&n.to_le_bytes());

                let mut buf = [0u8; 2 * 64];
                let mut xof = xof.into_squeezer();
                xof.do_output_out(&mut buf);
                buf
            };

            sample_poly_cbd(&buf, eta)
        }
        3 => {
            let buf = {
                let mut xof = SHAKE256::new();
                xof.do_update(b);
                xof.do_update(&n.to_le_bytes());
                let mut buf = [0u8; 3 * 64];
                let mut xof = xof.into_squeezer();
                xof.do_output_out(&mut buf);
                buf
            };

            sample_poly_cbd(&buf, eta)
        }
        _ => unreachable!(),
    }
}

fn little_endian_to_u24(bs: &[u8], off: usize) -> u32 {
    let mut n = bs[off] as u32;
    n |= (bs[off + 1] as u32) << 8;
    n | (bs[off + 2] as u32) << 16
}
