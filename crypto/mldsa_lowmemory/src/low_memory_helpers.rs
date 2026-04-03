//! This is a set of helper function to support a low-memory implementation that "streams" the private key
//! and other intermediate values by never holding the whole thing in memory at once, but re-constructing
//! what it needs in pieces, which generally means handling the matrices and vectors row-wise or entry-wise.

use bouncycastle_core_interface::errors::SignatureError;
use crate::mldsa::{d};
use crate::aux_functions::{bit_unpack_eta, bitlen_eta, expand_mask_poly, rej_ntt_poly, unpack_z_row};
use crate::polynomial::Polynomial;

/// Compute a row of the core signing operation
/// Alg 7: 12: 𝐰 ← NTT−1(𝐀_hat ∘ NTT(𝐲))
pub(crate) fn compute_w_row<const l: usize, const GAMMA1: i32, const GAMMA1_MASK_LEN: usize>(
    rho: &[u8; 32],
    rho_p_p: &[u8; 64],
    kappa: u16,
    row: usize,
) -> Polynomial {
    let mut y_hat = expand_mask_poly::<GAMMA1, GAMMA1_MASK_LEN>(rho_p_p, kappa);
    y_hat.ntt();
    let mut acc = rej_ntt_poly(rho, &[0u8, row as u8]);
    acc.multiply_ntt(&y_hat);

    for col in 1..l {
        y_hat = expand_mask_poly::<GAMMA1, GAMMA1_MASK_LEN>(rho_p_p, kappa + col as u16);
        y_hat.ntt();
        let mut tmp = rej_ntt_poly(rho, &[col as u8, row as u8]);
        tmp.multiply_ntt(&y_hat);
        acc.add_ntt(&tmp);
    }

    acc.inv_ntt();
    acc.conditional_add_q();
    acc
}

/// Algorithm 8 Line 9
pub(crate) fn compute_wp_approx_row<
    const GAMMA1: i32,
    const BETA: i32,
    const l: usize,
    const POLY_Z_PACKED_LEN: usize,
    const LAMBDA_over_4: usize,
    const SIG_LEN: usize
>(
    rho: &[u8; 32],
    sig: &[u8; SIG_LEN],
    t1: &Polynomial,
    c: &Polynomial,
    idx: usize) -> Result<Polynomial, ()> {
    // Algorithm 8: line 9: 𝐰′_approx ← NTT−1(𝐀_hat ∘ NTT(𝐳) − NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑))
    //   broken out for clarity:
    //   NTT−1(
    //      𝐀_hat ∘ NTT(𝐳) −
    //                  NTT(𝑐) ∘ NTT(𝐭1 ⋅ 2^𝑑)
    //   )
    // ▷ 𝐰'_approx = 𝐀𝐳 − 𝑐𝐭1 ⋅ 2^𝑑

    let mut z_i = unpack_z_row::<GAMMA1, BETA, LAMBDA_over_4, POLY_Z_PACKED_LEN, SIG_LEN>(0, sig)?;
    z_i.ntt();
    let mut Az_acc = rej_ntt_poly(rho, &[0u8, idx as u8]);
    Az_acc.multiply_ntt(&z_i);

    for col in 1..l {
        z_i = unpack_z_row::<GAMMA1, BETA, LAMBDA_over_4, POLY_Z_PACKED_LEN, SIG_LEN>(col, sig)?;
        z_i.ntt();

        // [Optimization Note]:
        // this is reconstructing a row of the public matrix A_hat,
        // which nobody is proposing to keep in memory.
        let mut tmp = rej_ntt_poly(rho, &[col as u8, idx as u8]);
        tmp.multiply_ntt(&z_i);
        Az_acc.add_ntt(&tmp);
    }

    let ct1 = {
        let mut t1_i = t1.clone();
        t1_i.shift_left::<d>();
        t1_i.ntt();
        let mut c = c.clone();
        c.ntt();
        t1_i.multiply_ntt(&c);
        t1_i
    };

    Az_acc.sub(&ct1);
    Az_acc.inv_ntt();
    Az_acc.conditional_add_q();

    Ok(Az_acc)
}

pub(crate) fn compute_z_component<
    const GAMMA1: i32, const GAMMA1_MASK_LEN: usize, const BETA: i32,
>(
    s1: &Polynomial,
    rho_p_p: &[u8; 64],
    c_hat: &Polynomial,
    kappa: u16,
    col: usize,
) -> Result<Option<Polynomial>, SignatureError> {
    let y = expand_mask_poly::<GAMMA1, GAMMA1_MASK_LEN>(rho_p_p, kappa + col as u16);
    let mut s1_hat = s1.clone();
    s1_hat.ntt();
    s1_hat.multiply_ntt(c_hat);
    let mut cs1 = s1_hat; // rename
    cs1.inv_ntt();
    let mut z = cs1;
    z.add_ntt(&y);

    if z.check_norm(GAMMA1 - BETA) { Ok(None) } else { Ok(Some(z)) }
}

pub(crate) fn compute_w0cs2_component<
    const GAMMA2: i32,
    const BETA: i32,
>(
    s2: &Polynomial,
    w: &Polynomial,
    c_hat: &Polynomial,
) -> Option<Polynomial> {
    let mut s2_hat = s2.clone();
    s2_hat.ntt();
    s2_hat.multiply_ntt(c_hat);
    let mut cs2 = s2_hat; // rename
    cs2.inv_ntt();

    let mut w0cs2 = w.clone();
    w0cs2.low_bits::<GAMMA2>();
    w0cs2.sub(&cs2);
    if w0cs2.check_norm(GAMMA2 - BETA) { None } else { Some(w0cs2) }
}

pub(crate) fn compute_ct0_component<
    const GAMMA2: i32,
>(
    t0_row: &Polynomial,
    c_hat: &Polynomial,
) -> Option<Polynomial> {
    let mut t0_hat = t0_row.clone();
    t0_hat.ntt();
    t0_hat.multiply_ntt(c_hat);
    let mut ct0 = t0_hat; // rename
    ct0.inv_ntt();

    if ct0.check_norm(GAMMA2) { None } else { Some(ct0) }
}

pub(crate) fn s_unpack<const eta: usize>(s_packed: &[u8], idx: usize) -> Polynomial {
    bit_unpack_eta::<eta>(&s_packed[idx * bitlen_eta(eta)..(idx + 1) * bitlen_eta(eta)])
}
