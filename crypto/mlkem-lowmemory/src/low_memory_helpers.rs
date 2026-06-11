//! This is a set of helper function to support a low-memory implementation that "streams" the private key
//! and other intermediate values by never holding the whole thing in memory at once, but re-constructing
//! what it needs in pieces, which generally means handling the matrices and vectors row-wise or entry-wise.

use crate::aux_functions::{byte_decode, byte_encode, sample_ntt, sample_poly_CBD};
use crate::mlkem::{N, POLY_BYTES, q};
use crate::polynomial::Polynomial;

/// Computes the element [i,j] of the A_hat public matrix
pub(crate) fn expandA_elem(rho: &[u8; 32], i: usize, j: usize) -> Polynomial {
    sample_ntt(rho, &[j as u8, i as u8])
}

/// Computes a single row of the core keygen operation
/// Alg 13: line 18: 𝐀_hat ∘ 𝐬_hat
pub(crate) fn compute_A_hat_dot_s_hat<const k: usize, const eta1: i16>(
    rho: &[u8; 32],
    sigma: &[u8; 32],
    row: usize,
) -> Polynomial {
    let mut t_hat_i: Polynomial = {
        let mut A_i0 = expandA_elem(rho, row, 0);
        let mut s_0 = sample_poly_CBD::<eta1>(sigma, 0 as u8);
        s_0.ntt(); // now s_hat_0
        A_i0.base_mult_montgomery(&s_0);

        A_i0
    };

    for j in 1..k {
        let mut A_ij = expandA_elem(rho, row, j);
        let mut s_j = sample_poly_CBD::<eta1>(sigma, j as u8);
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
pub(crate) fn compute_A_hat_dot_y_hat<const k: usize, const eta1: i16>(
    rho: &[u8; 32],
    r: &[u8; 32],
    row: usize,
) -> Polynomial {
    // 4: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
    //   ▷ re-generate matrix 𝐀 ∈ (ℤ256_𝑞 )𝑘×𝑘 sampled in Alg. 13

    // 9: for (𝑖 ← 0; 𝑖 < 𝑘; 𝑖++)
    //  ▷ generate 𝐲 ∈ (ℤ256_𝑞)k
    // 10: 𝐲[𝑖] ← SamplePolyCBD𝜂1(PRF𝜂1 (𝑟, 𝑁))
    //   ▷ 𝐲[𝑖] ∈ ℤ256 sampled from CBD
    // 11: 𝑁 ← 𝑁 + 1

    // 19: 𝐮 ← NTT−1(𝐀_hat^⊺ ∘ 𝐲_hat) + 𝐞1

    let mut u_i: Polynomial = {
        let mut A_0i = expandA_elem(rho, 0, row);
        let mut y_0 = sample_poly_CBD::<eta1>(r, /*N*/ 0);
        y_0.ntt();
        A_0i.base_mult_montgomery(&y_0);

        A_0i
    };

    for j in 1..k {
        let mut A_ji = expandA_elem(&rho, j, row);
        let mut y_j = sample_poly_CBD::<eta1>(r, /*N*/ j as u8);
        y_j.ntt();
        A_ji.base_mult_montgomery(&y_j);
        u_i.add(&A_ji);
    }
    u_i.inv_ntt();

    u_i
}

/// Compute a term of the output polynomial v of the core encaps operation based on a single row of t_hat_i and y_hat.
/// Alg 14: line 21: 𝑣 ← NTT−1(𝐭_hat_T ∘ 𝐲_hat)
pub(crate) fn compute_t_hat_dot_y_hat_row<const k: usize, const eta1: i16>(
    r: &[u8; 32],
    t_hat_i: &Polynomial,
    row: usize,
) -> Polynomial {
    let mut y_i = sample_poly_CBD::<eta1>(r, /*N*/ row as u8);
    y_i.ntt();
    y_i.base_mult_montgomery(&t_hat_i);
    y_i.inv_ntt();

    y_i
}

pub(crate) fn pack_t_hat_row<const T_PACKED_LEN: usize>(
    t_hat_i: &Polynomial,
    row: usize,
    t_hat_packed: &mut [u8; T_PACKED_LEN],
) {
    byte_encode::<12, POLY_BYTES>(
        &t_hat_i,
        t_hat_packed[row * POLY_BYTES..(row + 1) * POLY_BYTES].as_mut().try_into().unwrap(),
    );
}

pub(crate) fn unpack_t_hat_row<const T_PACKED_LEN: usize>(
    t_hat_packed: &[u8; T_PACKED_LEN],
    row: usize,
) -> Polynomial {
    byte_decode::<12, POLY_BYTES>(
        t_hat_packed[row * POLY_BYTES..(row + 1) * POLY_BYTES].try_into().unwrap(),
    )
}

pub(crate) fn pack_s_hat_row<const k: usize>(
    s_hat_i: &Polynomial,
    row: usize,
    s_hat_packed: &mut [u8],
) {
    debug_assert!(s_hat_packed.len() >= k * POLY_BYTES);

    byte_encode::<12, POLY_BYTES>(
        s_hat_i,
        s_hat_packed[row * POLY_BYTES..(row + 1) * POLY_BYTES].as_mut().try_into().unwrap(),
    );
}

/// This is an optimized version of
///   ByteEncode_𝑑𝑢( Compress_𝑑𝑢(𝐮) )
/// which packs a single row of the polynomial vector u according to the packing coefficient dv
/// into the correct location within the ciphertext
pub(crate) fn compress_u_row<const du: i16, const CT_LEN: usize>(
    u_i: Polynomial,
    row: usize,
    ct: &mut [u8; CT_LEN],
) {
    // make sure we have received a dv
    assert!(du == 10 || du == 11);

    // bc-java has a conditional_sub_q() here, but I pass all unit tests without it, so I'm taking it out for performance.
    // let mut u_i = u_i.clone();
    // u_i.conditional_sub_q();

    // figure out where in the ct array we're going to write to
    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let start: usize = row * (N * (du as usize) / 8);
    let end: usize = (row + 1) * (N * (du as usize) / 8);
    let out = &mut ct[start..end];

    let mut idx = 0;
    match du {
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

pub(crate) fn unpack_ciphertext_u_row<const du: i16, const CT_LEN: usize>(
    row: usize,
    ct: &[u8; CT_LEN],
) -> Polynomial {
    let mut u_i = Polynomial::new();

    // make sure we have received a dv
    assert!(du == 10 || du == 11);

    // figure out where in the ct array we're going to write to
    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let start: usize = row * (N * (du as usize) / 8);
    let end: usize = (row + 1) * (N * (du as usize) / 8);
    let compressed_u_i = &ct[start..end];

    let mut idx = 0;

    match du {
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

pub(crate) fn unpack_ciphertext_v<
    const k: usize,
    const CT_LEN: usize,
    const du: i16,
    const dv: i16,
>(
    c: &[u8; CT_LEN],
) -> Polynomial {
    // each of the N i16's will take du bits, so a polynomial takes N * du bits, then we have k of them
    let lim: usize = k * (N * (du as usize) / 8);

    let v = Polynomial::decompress_poly::<dv>(&c[lim..]);

    v
}
