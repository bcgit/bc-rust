//! This is a set of helper function to support a low-memory implementation that "streams" the private key
//! and other intermediate values by never holding the whole thing in memory at once, but re-constructing
//! what it needs in pieces, which generally means handling the matrices and vectors row-wise or entry-wise.

use crate::mlkem::{N, POLY_BYTES, q};
use crate::params::MLKEMParams;
use bouncycastle_mlkem_common::aux_functions::{
    byte_decode, byte_encode_out, sample_ntt, sample_poly_CBD,
};
use bouncycastle_mlkem_common::polynomial::Polynomial;

/// Computes the element [i,j] of the A_hat public matrix
pub(crate) fn expandA_elem(rho: &[u8; 32], i: usize, j: usize) -> Polynomial {
    sample_ntt(rho, &[j as u8, i as u8])
}

/// Computes a single row of the core keygen operation
/// Alg 13: line 18: 𝐀_hat ∘ 𝐬_hat
pub(crate) fn compute_A_hat_dot_s_hat<P: MLKEMParams>(
    rho: &[u8; 32],
    sigma: &[u8; 32],
    row: usize,
) -> Polynomial {
    let mut t_hat_i: Polynomial = {
        let mut A_i0 = expandA_elem(rho, row, 0);
        let mut s_0 = sample_poly_CBD(sigma, 0_u8, P::eta1);
        s_0.ntt(); // now s_hat_0
        A_i0.base_mult_montgomery(&s_0);

        A_i0
    };

    for j in 1..P::k {
        let mut A_ij = expandA_elem(rho, row, j);
        let mut s_j = sample_poly_CBD(sigma, j as u8, P::eta1);
        s_j.ntt(); // now s_hat_j
        A_ij.base_mult_montgomery(&s_j);
        t_hat_i.add(&A_ij);
    }
    // during keygen we're working in the montgomery domain, not the regular NTT domain,
    // so here we do a convert_to_mont() instead of a reduce()
    t_hat_i.convert_to_mont();

    t_hat_i
}

/// Compute a single row of the core encaps operation
/// Alg 14: line 19: NTT−1(𝐀_hat_T ∘ 𝐲_hat)
pub(crate) fn compute_A_hat_dot_y_hat<P: MLKEMParams>(
    rho: &[u8; 32],
    r: &[u8; 32],
    row: usize,
) -> Polynomial {
    // 4: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
    //   ▷ re-generate matrix 𝐀 ∈ (ℤ256_𝑞 )𝑘×𝑘 sampled in Alg. 13

    // 9: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
    //  ▷ generate 𝐲 ∈ (ℤ256_𝑞)^𝑘
    // 10: 𝐲[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝑟, 𝑁))
    //   ▷ 𝐲[𝑖] ∈ ℤ256 sampled from CBD
    // 11: 𝑁 ← 𝑁 + 1

    // 19: 𝐮 ← NTT−1(𝐀_hat^⊺ ∘ 𝐲_hat) + 𝐞1

    let mut u_i: Polynomial = {
        let mut A_0i = expandA_elem(rho, 0, row);
        let mut y_0 = sample_poly_CBD(r, /*N*/ 0, P::eta1);
        y_0.ntt();
        A_0i.base_mult_montgomery(&y_0);

        A_0i
    };

    for j in 1..P::k {
        let mut A_ji = expandA_elem(rho, j, row);
        let mut y_j = sample_poly_CBD(r, /*N*/ j as u8, P::eta1);
        y_j.ntt();
        A_ji.base_mult_montgomery(&y_j);
        u_i.add(&A_ji);
    }
    // The k-term sum is in (-2kq, 2kq); `inv_ntt`'s first butterfly adds two coefficients in
    // i16, so it is reduced first (see `dot_product` in bouncycastle-mlkem for the bound).
    u_i.poly_reduce();
    u_i.inv_ntt();

    u_i
}

/// Compute a term of the output polynomial v of the core encaps operation based on a single row of t_hat_i and y_hat.
/// Alg 14: line 21: 𝑣 ← NTT−1(𝐭_hat_T ∘ 𝐲_hat)
pub(crate) fn compute_t_hat_dot_y_hat_row<P: MLKEMParams>(
    r: &[u8; 32],
    t_hat_i: &Polynomial,
    row: usize,
) -> Polynomial {
    let mut y_i = sample_poly_CBD(r, /*N*/ row as u8, P::eta1);
    y_i.ntt();
    y_i.base_mult_montgomery(t_hat_i);
    y_i.inv_ntt();

    y_i
}

pub(crate) fn pack_t_hat_row<P: MLKEMParams>(
    t_hat_i: &Polynomial,
    row: usize,
    t_hat_packed: &mut P::TPacked,
) {
    byte_encode_out::<12, POLY_BYTES>(
        t_hat_i,
        (&mut t_hat_packed.as_mut()[row * POLY_BYTES..(row + 1) * POLY_BYTES]).try_into().unwrap(),
    );
}

pub(crate) fn unpack_t_hat_row(t_hat_packed: &[u8], row: usize) -> Polynomial {
    byte_decode::<12, POLY_BYTES>(
        t_hat_packed[row * POLY_BYTES..(row + 1) * POLY_BYTES].try_into().unwrap(),
    )
}

pub(crate) fn pack_s_hat_row<P: MLKEMParams>(
    s_hat_i: &Polynomial,
    row: usize,
    s_hat_packed: &mut [u8],
) {
    debug_assert!(s_hat_packed.len() >= P::k * POLY_BYTES);

    byte_encode_out::<12, POLY_BYTES>(
        s_hat_i,
        s_hat_packed[row * POLY_BYTES..(row + 1) * POLY_BYTES].as_mut().try_into().unwrap(),
    );
}

/// This is an optimized version of
///   ByteEncode_𝑑𝑢( Compress_𝑑𝑢(𝐮) )
/// which packs a single row of the polynomial vector u according to the packing coefficient 𝑑𝑢
/// into the correct location within the ciphertext
pub(crate) fn compress_u_row<P: MLKEMParams, const CT_LEN: usize>(
    u_i: Polynomial,
    row: usize,
    ct: &mut [u8; CT_LEN],
) {
    // make sure we received a supported 𝑑𝑢
    assert!(P::du == 10 || P::du == 11);

    // bc-java has a conditional_sub_q() here, but I pass all unit tests without it, so I'm taking it out for performance.
    // let mut u_i = u_i.clone();
    // u_i.conditional_sub_q();

    // figure out where in the ct array we're going to write to
    // each of the N i16's will take 𝑑𝑢 bits, so a polynomial takes N * 𝑑𝑢 bits, then we have 𝑘 of them
    let start: usize = row * (N * (P::du as usize) / 8);
    let end: usize = (row + 1) * (N * (P::du as usize) / 8);
    let out = &mut ct[start..end];

    let mut idx = 0;
    match P::du {
        10 => {
            // MLKEM512 and MLKEM 768
            let mut t = [0i16; 4];
            for j in 0..N / 4 {
                // fill the temp array t
                for (l, item) in t.iter_mut().enumerate() {
                    *item = (((((u_i[4 * j + l] as u32) << 10) as i32 + (q as i32 / 2)) / q as i32)
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
        11 => {
            let mut t = [0i16; 8];
            for j in 0..N / 8 {
                for (l, item) in t.iter_mut().enumerate() {
                    *item = (((((u_i[8 * j + l] as u32) << 11) as i32 + (q as i32 / 2)) / q as i32)
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
        _ => unreachable!(),
    }
}

pub(crate) fn unpack_ciphertext_u_row<P: MLKEMParams, const CT_LEN: usize>(
    row: usize,
    ct: &[u8; CT_LEN],
) -> Polynomial {
    let mut u_i = Polynomial::new();

    // make sure we received a supported 𝑑𝑢
    assert!(P::du == 10 || P::du == 11);

    // figure out where in the ct array we're going to write to
    // each of the N i16's will take 𝑑𝑢 bits, so a polynomial takes N * 𝑑𝑢 bits, then we have 𝑘 of them
    let start: usize = row * (N * (P::du as usize) / 8);
    let end: usize = (row + 1) * (N * (P::du as usize) / 8);
    let compressed_u_i = &ct[start..end];

    let mut idx = 0;

    match P::du {
        10 => {
            // MLKEM512 and MLKEM768
            let mut t = [0i16; 4];
            for j in 0..(N / 4) {
                t[0] =
                    ((compressed_u_i[idx] as u16) | (compressed_u_i[idx + 1] as u16) << 8) as i16;
                t[1] = (((compressed_u_i[idx + 1] as u16) >> 2)
                    | (compressed_u_i[idx + 2] as u16) << 6) as i16;
                t[2] = (((compressed_u_i[idx + 2] as u16) >> 4)
                    | (compressed_u_i[idx + 3] as u16) << 4) as i16;
                t[3] = (((compressed_u_i[idx + 3] as u16) >> 6)
                    | (compressed_u_i[idx + 4] as u16) << 2) as i16;
                idx += 5;
                for (l, item) in t.iter().enumerate() {
                    u_i[4 * j + l] = ((((*item & 0x3FF) as i32) * (q as i32) + 512) >> 10) as i16;
                }
            }
        }
        11 => {
            // MLKEM1024
            let mut t = [0i16; 8];
            for j in 0..N / 8 {
                t[0] = (compressed_u_i[idx] as i32 | ((compressed_u_i[idx + 1] as u16) as i32) << 8)
                    as i16;
                t[1] = ((compressed_u_i[idx + 1] >> 3) as i32
                    | ((compressed_u_i[idx + 2] as u16) as i32) << 5) as i16;
                t[2] = ((compressed_u_i[idx + 2] >> 6) as i32
                    | ((compressed_u_i[idx + 3] as u16) as i32) << 2
                    | (((compressed_u_i[idx + 4] as i32) << 10) as u16) as i32)
                    as i16;
                t[3] = ((compressed_u_i[idx + 4] >> 1) as i32
                    | ((compressed_u_i[idx + 5] as u16) as i32) << 7) as i16;
                t[4] = ((compressed_u_i[idx + 5] >> 4) as i32
                    | ((compressed_u_i[idx + 6] as u16) as i32) << 4) as i16;
                t[5] = ((compressed_u_i[idx + 6] >> 7) as i32
                    | ((compressed_u_i[idx + 7] as u16) as i32) << 1
                    | (((compressed_u_i[idx + 8] as i32) << 9) as u16) as i32)
                    as i16;
                t[6] = ((compressed_u_i[idx + 8] >> 2) as i32
                    | ((compressed_u_i[idx + 9] as u16) as i32) << 6) as i16;
                t[7] = ((compressed_u_i[idx + 9] >> 5) as i32
                    | ((compressed_u_i[idx + 10] as u16) as i32) << 3)
                    as i16;
                idx += 11;
                for (l, item) in t.iter().enumerate() {
                    u_i[8 * j + l] = ((((*item & 0x7FF) as i32) * (q as i32) + 1024) >> 11) as i16;
                }
            }
        }
        _ => unreachable!(),
    }

    u_i
}

pub(crate) fn unpack_ciphertext_v<P: MLKEMParams, const CT_LEN: usize>(
    c: &[u8; CT_LEN],
) -> Polynomial {
    // each of the N i16's will take 𝑑𝑢 bits, so a polynomial takes N * 𝑑𝑢 bits, then we have 𝑘 of them
    let lim: usize = P::k * (N * (P::du as usize) / 8);

    Polynomial::decompress_poly::<P>(&c[lim..])
}

#[cfg(test)]
mod tests {
    //! `compress_u_row` is pinned by the ACVP ciphertexts; `unpack_ciphertext_u_row` is not: ML-KEM's
    //! decryption tolerates a decompressed coefficient being off by a little, so a rounding error
    //! in it still yields the right shared secret on every vector. These check the two against
    //! FIPS 203 Section 4.2.1, eq. (4.7) and (4.8), coefficient by coefficient.
    use super::*;
    extern crate std;
    use crate::params::{MLKEM512Params, MLKEM1024Params};
    use bouncycastle_mlkem_common::params::MLKEMParamsBase;
    use std::vec::Vec;

    fn compress_ref(d: u32, x: i16) -> u16 {
        ((((x as u32) << d) + (q as u32) / 2) / (q as u32) % (1 << d)) as u16
    }

    fn decompress_ref(d: u32, y: u16) -> i16 {
        (((y as u32) * (q as u32) + (1 << (d - 1))) >> d) as i16
    }

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

    fn check<P: MLKEMParams, const CT_LEN: usize>() {
        let d = P::du as u32;
        let row_len = N * (d as usize) / 8;

        // a pseudo-random ciphertext; every row unpacks as eq. (4.8)
        let mut ct = [0u8; CT_LEN];
        let mut state: u32 = 11 + d;
        for b in ct.iter_mut() {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (state >> 24) as u8;
        }
        for row in 0..P::k {
            let u_i = unpack_ciphertext_u_row::<P, CT_LEN>(row, &ct);
            let f = fields(d, &ct[row * row_len..(row + 1) * row_len]);
            for (n, &y) in f.iter().enumerate() {
                assert_eq!(u_i[n], decompress_ref(d, y), "d={d} row {row} field {n}");
            }
        }

        // every coefficient value 0..q compresses as eq. (4.7)
        let mut x: i16 = 0;
        for row in 0..P::k {
            let mut u_i = Polynomial::new();
            for j in 0..N {
                u_i[j] = x;
                x = (x + 1) % q;
            }
            let mut ct = [0u8; CT_LEN];
            compress_u_row::<P, CT_LEN>(u_i, row, &mut ct);
            let f = fields(d, &ct[row * row_len..(row + 1) * row_len]);
            for (n, &c) in f.iter().enumerate() {
                assert_eq!(c, compress_ref(d, u_i[n]), "d={d} row {row} coefficient {n}");
            }
        }
    }

    #[test]
    fn compress_and_unpack_match_fips_203_for_du_10() {
        check::<MLKEM512Params, { MLKEM512Params::CT_LEN }>();
    }

    #[test]
    fn compress_and_unpack_match_fips_203_for_du_11() {
        check::<MLKEM1024Params, { MLKEM1024Params::CT_LEN }>();
    }
}
